r"""
recon.py - full LAN reconnaissance suite (bugfixed, stealth-optimized)

MODES:
  stealth     passive only + optional external lookups
  normal      active but throttled
  aggressive  full active (all audits, AXFR, active OS)

STEALTH FLAGS:
  --paranoid            passive only, no external, no mDNS, long pauses
  --aggressive-timing   skip human pauses (fast test)
  --quiet               fewer stderr messages
  --no-tls-audit        skip TLS weakness check
  --no-http-audit       skip HTTP security audit

BUGFIXES IN THIS VERSION (8):
  1. scan_host: detect_product_version wrapped in try/except — bad regex no longer skips whole host
  2. _extract_domain: requires FQDN (dot); whoami /upn + nltest /dsgetdc fallbacks
  3. mdns_deep_enum: early return if AsyncSniffer.running is False (no wasted probes)
  4. _run_external_lookups: warns when BGP target is RFC1918
  5. main(): validates --public-ip IPv4, warns on --sniff > 1800s
  6. recon(): fixed 'other adapters' filter, sorts hosts before JSON dump, per-host scan progress
  7. diff_runs: MAC/vendor/hostname change detection (device swap)
  8. export_csv: explicit QUOTE_MINIMAL

PREVIOUS FIXES (retained):
  - TLS weakness: 2 handshakes not 4
  - HTTP audit: HEAD not GET
  - printer_enum: only open ports, HEAD for IPP
  - port scan: 1 worker always
  - mDNS: LIGHT list in normal, FULL in aggressive
  - NVD_LOCK prevents rate limit race
  - LLDP only attached to gateway (CSV correct)
  - HTTP audit: unverified ctx for self-signed
  - snmp_uptime_human: both formats
  - SIP/printer gated to aggressive
  - CSV: tls_weak=None safe
  - diff before json.dump
  - datetime.fromtimestamp(tz=utc)
  - Kerberos uses internal DNS

Usage:
  python recon.py --paranoid --sniff 600 --json --csv
  python recon.py --mode stealth --sniff 300 --json --csv
  python recon.py --mode normal --delay 2000 --json
  python recon.py --mode aggressive --json --csv --diff logs\recon_OLD.json

Requires:
  pip install psutil scapy pysnmp requests
  Npcap (WinPcap API-compatible mode), Admin
"""

import argparse
import concurrent.futures
import csv
import ipaddress
import json
import os
import random
import re
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

try:
    import psutil
except ImportError:
    sys.exit("missing: pip install psutil")

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

try:
    from scapy.all import (
        ARP, Ether, IP, IPv6, ICMP, UDP, TCP, DNS, DNSQR, DNSRR,
        DHCP, BOOTP, conf, get_if_list, IFACES, Raw, sendp, srp, srp1, sr,
        sniff as sc_sniff, AsyncSniffer
    )
    HAVE_SCAPY = True
except ImportError:
    HAVE_SCAPY = False

try:
    from pysnmp.hlapi import (
        SnmpEngine, CommunityData, UdpTransportTarget, ContextData,
        ObjectType, ObjectIdentity, getCmd, nextCmd
    )
    HAVE_SNMP = True
except ImportError:
    HAVE_SNMP = False


LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
CVE_CACHE_FILE = os.path.join(LOG_DIR, "cve_cache.json")
IS_WIN = os.name == "nt"
NO_WINDOW = 0x08000000 if IS_WIN else 0
MODE_DELAY_MS = {"stealth": 0, "normal": 800, "aggressive": 0}

_AGGRESSIVE_TIMING = [False]
_PUBLIC_IP_OVERRIDE = [None]
_CRT_DOMAIN_OVERRIDE = [None]
_QUIET = [False]
_PARANOID = [False]

_IPCFG = {"text": None, "parsed": None, "lock": threading.Lock()}

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
]
ACCEPT_LANGS = ["en-US,en;q=0.9", "pl-PL,pl;q=0.9,en;q=0.8", "en-GB,en;q=0.9"]


def _ua(): return random.choice(USER_AGENTS)
def _accept_lang(): return random.choice(ACCEPT_LANGS)


SYN_PROFILES = {
    "windows": {"ttl": 128, "window": 64240,
                "options": [("MSS", 1460), ("SAckOK", b""), ("WScale", 8)]},
    "linux": {"ttl": 64, "window": 29200,
              "options": [("MSS", 1460), ("SAckOK", b""),
                          ("Timestamp", (random.randint(100000, 900000), 0)),
                          ("NOP", None), ("WScale", 7)]},
    "macos": {"ttl": 64, "window": 65535,
              "options": [("MSS", 1460), ("NOP", None), ("WScale", 6),
                          ("NOP", None), ("NOP", None), ("SAckOK", b""),
                          ("Timestamp", (random.randint(100000, 900000), 0))]},
}


def _random_syn_profile():
    return random.choice(list(SYN_PROFILES.values()))


def _ipconfig_text():
    with _IPCFG["lock"]:
        if _IPCFG["text"] is None:
            _IPCFG["text"] = run("ipconfig /all")
        return _IPCFG["text"]


def _ipconfig_parsed():
    with _IPCFG["lock"]:
        if _IPCFG["parsed"] is None:
            _IPCFG["parsed"] = _parse_ipconfig(_ipconfig_text())
        return _IPCFG["parsed"]


class _Tee(object):
    def __init__(self, original, logfile):
        self.original = original
        self.logfile = logfile
    def write(self, data):
        try: self.original.write(data)
        except Exception: pass
        try:
            self.logfile.write(data); self.logfile.flush()
        except Exception: pass
    def flush(self):
        try: self.original.flush()
        except Exception: pass
        try: self.logfile.flush()
        except Exception: pass
    def isatty(self):
        try: return self.original.isatty()
        except Exception: return False


def _start_logging():
    os.makedirs(LOG_DIR, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOG_DIR, "recon_{}.txt".format(stamp))
    try:
        f = open(path, "w", encoding="utf-8")
    except Exception:
        return None
    sys.stdout = _Tee(sys.__stdout__, f)
    sys.stderr = _Tee(sys.__stderr__, f)
    return path


RESULTS = {
    "timestamp": None, "mode": None, "paranoid": False,
    "network": {}, "link": {}, "link_type": None,
    "lldp_cdp": {}, "dhcp": {},
    "wifi": {"connected": {}, "networks_in_range": []},
    "hosts": [],
    "ssdp": [], "mdns": [], "mdns_deep": [], "upnp_igd": {}, "dns_srv": [],
    "arp_spoof": [], "dhcp_servers_all": [], "rogue_dhcp": False,
    "crt_sh": [], "bgp": {}, "snmp_traps": [], "dns_axfr": {},
    "public_ip": None, "domain": None,
    "kerberos_realm": None, "ldap_anon": {}, "ntp": {},
    "dns_wildcard": None,
    "diff_old_path": None, "diff_added": [], "diff_removed": [],
}
RESULTS_LOCK = threading.Lock()


def _result_set(key, value):
    with RESULTS_LOCK:
        RESULTS[key] = value


def run(cmd, timeout=20):
    try:
        out = subprocess.run(cmd, shell=True, capture_output=True,
                             timeout=timeout, creationflags=NO_WINDOW)
        raw = out.stdout or b""
        for enc in ("utf-8", "cp1250", "cp1252", "latin-1"):
            try:
                return raw.decode(enc)
            except Exception:
                continue
        return ""
    except Exception:
        return ""


def is_ipv4(s):
    try:
        socket.inet_aton(s)
        return len(s.split(".")) == 4 and all(0 <= int(p) <= 255 for p in s.split("."))
    except Exception:
        return False


def now_local_iso():
    return datetime.now(timezone.utc).astimezone().isoformat()


def human_pause():
    if _AGGRESSIVE_TIMING[0]:
        return
    if _PARANOID[0]:
        time.sleep(random.uniform(3.0, 8.0))
        return
    time.sleep(random.uniform(0.5, 2.0))


def sleep_delay(ms):
    if _AGGRESSIVE_TIMING[0]:
        return
    if ms <= 0:
        time.sleep(random.uniform(0.02, 0.15))
        return
    base = ms / 1000.0
    jitter = random.uniform(-0.2, 0.5) * base
    time.sleep(max(0.05, base + jitter))


def iter_ifaces():
    if not HAVE_SCAPY:
        return
    try:
        vals = IFACES.values() if hasattr(IFACES, "values") else IFACES
        for i in vals:
            yield i
    except Exception:
        return


def iface_obj_field(obj, field):
    try:
        return getattr(obj, field, None)
    except Exception:
        return None


def find_iface_by_any_name(target):
    if not HAVE_SCAPY or not target:
        return None
    tlow = target.lower()
    for i in iter_ifaces():
        name = iface_obj_field(i, "name") or ""
        net = iface_obj_field(i, "network_name") or ""
        rep = str(i)
        if target in (name, net, rep):
            return i
        if tlow in (name.lower(), net.lower(), rep.lower()):
            return i
    for i in iter_ifaces():
        name = (iface_obj_field(i, "name") or "").lower()
        net = (iface_obj_field(i, "network_name") or "").lower()
        if tlow and (tlow in name or tlow in net):
            return i
    return None


def iface_ipv4_list(obj):
    out = []
    try:
        ips = getattr(obj, "ips", None) or {}
        v4 = ips.get(4)
        if v4:
            if isinstance(v4, (list, tuple)):
                out.extend(str(x) for x in v4)
            else:
                out.append(str(v4))
    except Exception:
        pass
    return out


OUI_DB = {
    "AC:15:A2": "TP-Link", "00:1A:2B": "Cisco", "00:1B:54": "Cisco",
    "00:0C:29": "VMware", "00:50:56": "VMware", "08:00:27": "VirtualBox",
    "00:15:5D": "Microsoft Hyper-V", "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
    "F0:18:98": "Apple", "3C:22:FB": "Apple", "9C:FC:01": "Apple",
    "00:25:00": "Apple", "14:7D:DA": "Apple",
    "00:21:CC": "Samsung", "34:23:BA": "Samsung",
    "00:0F:B5": "Netgear", "00:14:6C": "Netgear",
    "00:50:BA": "D-Link", "00:05:5D": "D-Link",
    "3C:D9:2B": "HP", "00:1B:78": "HP",
    "00:0C:42": "MikroTik", "2C:C8:1B": "MikroTik",
    "00:27:22": "Ubiquiti", "24:A4:3C": "Ubiquiti",
    "00:00:0C": "Cisco", "00:1C:0E": "Cisco", "00:1C:0F": "Cisco",
    "00:1C:57": "Cisco", "00:1C:58": "Cisco",
    "00:50:0F": "Cisco", "00:50:14": "Cisco",
    "00:90:21": "Cisco", "00:90:2B": "Cisco",
    "00:A0:C9": "Intel", "00:AA:00": "Intel", "00:11:11": "Intel",
    "00:1B:21": "Intel", "00:1F:3B": "Intel",
}


def oui_lookup(mac):
    if not mac:
        return None
    return OUI_DB.get(":".join(mac.upper().replace("-", ":").split(":")[:3]))


def _load_cve_cache():
    try:
        if os.path.exists(CVE_CACHE_FILE):
            with open(CVE_CACHE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return {}


def _save_cve_cache(cache):
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        with open(CVE_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2, ensure_ascii=False)
    except Exception:
        pass


_CVE_CACHE = _load_cve_cache()
_NVD_LAST = [0.0]
_NVD_MIN = 6.5
_NVD_LOCK = threading.Lock()


def _nvd_rate_limit():
    with _NVD_LOCK:
        el = time.time() - _NVD_LAST[0]
        if el < _NVD_MIN:
            time.sleep(_NVD_MIN - el)
        _NVD_LAST[0] = time.time()


def _cve_matches_version(cve_entry, version):
    try:
        for conf in cve_entry.get("configurations", []):
            for node in conf.get("nodes", []):
                for cm in node.get("cpeMatch", []):
                    if version.lower() in (cm.get("criteria") or "").lower():
                        return True
    except Exception:
        pass
    return False


def nvd_lookup(product, version):
    if not HAVE_REQUESTS or not product or not version:
        return []
    key = "{}|{}".format(product.lower(), version.lower())
    if key in _CVE_CACHE:
        return _CVE_CACHE[key]
    _nvd_rate_limit()
    url = ("https://services.nvd.nist.gov/rest/json/cves/2.0"
           "?keywordSearch={}&resultsPerPage=100".format(
               urllib.request.quote("{} {}".format(product, version))))
    results = []
    try:
        r = requests.get(url, timeout=30)
        if r.status_code != 200:
            _CVE_CACHE[key] = []
            _save_cve_cache(_CVE_CACHE)
            return []
        for v in r.json().get("vulnerabilities", []):
            cve = v.get("cve", {})
            desc = next((d["value"] for d in cve.get("descriptions", [])
                         if d.get("lang") == "en"), "")
            if version.lower() not in desc.lower() and \
               not _cve_matches_version(cve, version):
                continue
            score = sev = None
            for mk in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                m = cve.get("metrics", {}).get(mk, [])
                if m:
                    cd = m[0].get("cvssData", {})
                    score = cd.get("baseScore")
                    sev = cd.get("baseSeverity")
                    break
            results.append({"id": cve.get("id", ""),
                            "cvss": "{} {}".format(score, sev or "").strip(),
                            "score": score, "desc": desc[:200]})
    except Exception:
        pass
    results.sort(key=lambda x: x.get("score") or 0, reverse=True)
    _CVE_CACHE[key] = results
    _save_cve_cache(_CVE_CACHE)
    return results


CISCO_IOS_RE = re.compile(r"Cisco IOS(?: XE| XR)? Software.*?Version\s+([\d.()A-Za-z]+)", re.I)
LINUX_KERNEL_RE = re.compile(r"Linux\s+\S+\s+([\d.]+)")
STATIC_FINGERPRINTS = [
    {"pattern": r"SSH-[\d.]+-dropbear[_\s]?([\d.]+)", "product": "dropbear ssh"},
    {"pattern": r"SSH-[\d.]+-OpenSSH[_\s]?([\d.p]+)", "product": "openssh"},
    {"pattern": r"220.*vsFTPd\s+([\d.]+)", "product": "vsftpd"},
    {"pattern": r"Server:\s*Apache/([\d.]+)", "product": "apache http server"},
    {"pattern": r"Server:\s*nginx/([\d.]+)", "product": "nginx"},
    {"pattern": r"MiniDLNA/([\d.]+)", "product": "minidlna"},
]


def detect_product_version(text):
    if not text:
        return []
    out = []
    for fp in STATIC_FINGERPRINTS:
        m = re.search(fp["pattern"], text, re.I)
        if m and m.groups():
            out.append((fp["product"], m.group(1)))
    m = CISCO_IOS_RE.search(text)
    if m:
        out.append(("cisco ios", m.group(1)))
    m = LINUX_KERNEL_RE.search(text)
    if m:
        out.append(("linux kernel", m.group(1)))
    m = re.search(r"Windows Server (\d{4}(?:\sR2)?)", text, re.I)
    if m:
        out.append(("windows server", m.group(1)))
    return out


def iface_link_type(desc):
    if not desc:
        return "UNKNOWN"
    low = desc.lower()
    if any(h in low for h in ("wi-fi", "wifi", "wireless", "802.11", "wlan")):
        return "WIFI"
    if any(h in low for h in ("vmware", "virtualbox", "hyper-v", "vethernet",
                               "virtual", "hyperv", "pseudo", "tap-", "tun",
                               "wsl", "loopback")):
        return "VIRTUAL"
    if any(h in low for h in ("ethernet", "gbe", "realtek pcie", "i219",
                               "i225", "i350", "broadcom netxtreme",
                               "aquantia", "gigabit")):
        return "ETHERNET"
    return "UNKNOWN"


def enumerate_active_adapters():
    out = []
    for a in _ipconfig_parsed():
        if a["disconnected"] or not a["ipv4"] or not a["gateway"]:
            continue
        out.append({
            "name": a["name"], "ip": a["ipv4"][0], "gateway": a["gateway"][0],
            "dns": a["dns"], "link": iface_link_type(a["name"]),
        })
    return out


def detect_lan_without_internet():
    cands = enumerate_active_adapters()
    if not cands:
        return None, None
    rank = {"ETHERNET": 0, "WIFI": 1, "UNKNOWN": 2, "VIRTUAL": 3}
    cands.sort(key=lambda a: rank.get(a["link"], 9))
    best = cands[0]
    npcap = _map_ip_npcap(best["ip"])
    if npcap:
        return npcap, "LAN fallback (no internet route) -> {} ({})".format(
            best["name"], best["link"])
    return None, None


def _detect_route():
    if not HAVE_SCAPY:
        return None, None
    avail = set(get_if_list())
    for t in ["8.8.8.8", "1.1.1.1"]:
        try:
            r = conf.route.route(t)
        except Exception:
            continue
        if not r:
            continue
        iface = r[0] if len(r) >= 1 else None
        gw = r[2] if len(r) >= 3 else None
        if not iface or iface in ("lo", "lo0", "\\Device\\NPF_Loopback"):
            continue
        if iface in avail:
            return iface, "scapy route to {} via gw {}".format(t, gw)
        obj = find_iface_by_any_name(iface)
        if obj:
            return (iface_obj_field(obj, "network_name") or iface,
                    "scapy route to {} (iface {})".format(t, iface))
    return None, None


def _detect_ps():
    if not IS_WIN:
        return None, None
    ps = ("Get-NetRoute -DestinationPrefix '0.0.0.0/0' -EA SilentlyContinue | "
          "Where-Object { $_.NextHop -ne '0.0.0.0' } | Sort-Object RouteMetric | "
          "Select-Object -First 1 | ForEach-Object { $_.InterfaceIndex }")
    idx = run('powershell -NoProfile -Command "{}"'.format(ps)).strip()
    if not idx or not idx.split()[0].isdigit():
        return None, None
    idx = idx.split()[0]
    ps2 = "Get-NetAdapter -InterfaceIndex {} -EA SilentlyContinue | Select-Object -First 1 -ExpandProperty Name"
    an = run('powershell -NoProfile -Command "{}"'.format(ps2.format(idx))).strip()
    if not an:
        return None, None
    for i in iter_ifaces():
        desc = (iface_obj_field(i, "description") or "").lower()
        name = (iface_obj_field(i, "name") or "").lower()
        net = iface_obj_field(i, "network_name") or ""
        if an.lower() in desc or desc in an.lower() or an.lower() in name:
            return net or name, "powershell adapter '{}'".format(an)
    return None, None


def _parse_ipconfig(text):
    adapters = []
    current = None
    for line in (text or "").splitlines():
        if not line.strip():
            continue
        s = line.strip()
        if line[0] not in (" ", "\t") and s.endswith(":"):
            if current is not None:
                adapters.append(current)
            current = {"name": s[:-1].strip(), "ipv4": [], "gateway": [],
                       "dns": [], "dhcp": None, "disconnected": False}
            continue
        if current is None:
            continue
        low = s.lower()
        if ("media state" in low and "disconnected" in low) or \
           ("stan" in low and "roz" in low and "czony" in low):
            current["disconnected"] = True
            continue
        if "ipv4" in low and ("address" in low or "adres" in low):
            val = s.split(":", 1)[-1].strip().split("(")[0].strip()
            if val and is_ipv4(val):
                current["ipv4"].append(val)
        elif "gateway" in low or "brama" in low:
            val = s.split(":", 1)[-1].strip()
            if val and is_ipv4(val):
                current["gateway"].append(val)
        elif "dhcp" in low:
            val = s.split(":", 1)[-1].strip()
            if val and is_ipv4(val):
                current["dhcp"] = val
        elif "dns" in low:
            val = s.split(":", 1)[-1].strip()
            if val and is_ipv4(val):
                current["dns"].append(val)
    if current is not None:
        adapters.append(current)
    return adapters


def _map_ip_npcap(ip):
    if not HAVE_SCAPY:
        return None
    for i in iter_ifaces():
        if ip in iface_ipv4_list(i):
            return iface_obj_field(i, "network_name") or iface_obj_field(i, "name")
    return None


def _detect_ipcfg():
    cands = [a for a in _ipconfig_parsed()
             if not a["disconnected"] and a["ipv4"] and a["gateway"]]
    if not cands:
        return None, None
    virtual = ("vethernet", "virtualbox", "vmware", "hyper-v", "wsl",
               "loopback", "tap-", "tun", "default switch")
    cands.sort(key=lambda a: (1 if any(h in a["name"].lower() for h in virtual) else 0,
                               -len(a["ipv4"]), a["name"].lower()))
    for ip in cands[0]["ipv4"]:
        m = _map_ip_npcap(ip)
        if m:
            return m, "ipconfig adapter '{}'".format(cands[0]["name"])
    return None, None


def _detect_probe():
    if not HAVE_SCAPY:
        return None, None
    best, bestn = None, -1
    for iface in get_if_list():
        if "Loopback" in iface:
            continue
        try:
            n = len(sc_sniff(iface=iface, timeout=1, count=10, store=True))
        except Exception:
            continue
        if n > bestn:
            bestn, best = n, iface
        if n >= 10:
            break
    if bestn > 0:
        return best, "traffic probe ({} pkts)".format(bestn)
    return None, None


def pick_card(verbose=True):
    if not HAVE_SCAPY:
        return None, "scapy not installed", None

    steps = [
        ("scapy route", _detect_route),
        ("powershell default route", _detect_ps),
        ("ipconfig gateway", _detect_ipcfg),
        ("traffic probe", _detect_probe),
        ("LAN fallback (no internet)", detect_lan_without_internet),
    ]
    if verbose and not _QUIET[0]:
        print("detecting network card...")
        actives = enumerate_active_adapters()
        if actives:
            print("  active adapters with gateway:")
            for a in actives:
                print("    [{}] {:<30} ip={:<16} gw={}".format(
                    a["link"], a["name"][:30], a["ip"], a["gateway"]))
            print()

    for label, fn in steps:
        if verbose and not _QUIET[0]:
            print("  trying: {}".format(label))
        try:
            result = fn()
            iface, reason = result[0], result[1]
        except Exception as e:
            if verbose and not _QUIET[0]:
                print("    error: {}".format(e))
            continue
        if iface:
            desc = get_iface_desc(iface)
            link_type = iface_link_type(desc)
            if verbose and not _QUIET[0]:
                print("    -> {}".format(iface))
                print("    type: {} ({})".format(link_type, desc))
            return iface, reason, link_type
        if verbose and not _QUIET[0]:
            print("    no result")
    return None, "no method worked", None


def get_iface_desc(iface):
    obj = find_iface_by_any_name(iface)
    if obj:
        return iface_obj_field(obj, "description") or iface_obj_field(obj, "name") or "-"
    return "-"


def is_wireless(desc):
    if not desc:
        return False
    return any(h in desc.lower() for h in ("wi-fi", "wifi", "wireless", "802.11", "wlan"))


def get_my_network(iface):
    info = {"iface": iface, "ip": None, "netmask": None, "subnet": None,
            "gateway": None, "dns": []}
    if not HAVE_SCAPY:
        return info
    obj = find_iface_by_any_name(iface)
    if obj:
        ips = iface_ipv4_list(obj)
        if ips:
            info["ip"] = ips[0]
    if info["ip"]:
        try:
            for pname, addrs in psutil.net_if_addrs().items():
                for a in addrs:
                    if a.family == socket.AF_INET and a.address == info["ip"]:
                        info["netmask"] = a.netmask
                        break
                if info["netmask"]:
                    break
        except Exception:
            pass
    if info["ip"] and not info["netmask"]:
        try:
            desc = get_iface_desc(iface).lower()
            for pname, addrs in psutil.net_if_addrs().items():
                if pname.lower() in desc or desc in pname.lower():
                    for a in addrs:
                        if a.family == socket.AF_INET:
                            info["ip"] = info["ip"] or a.address
                            info["netmask"] = a.netmask
                            break
                    if info["netmask"]:
                        break
        except Exception:
            pass
    if info["ip"] and info["netmask"]:
        try:
            info["subnet"] = str(ipaddress.IPv4Network(
                "{}/{}".format(info["ip"], info["netmask"]), strict=False))
        except Exception:
            pass
    try:
        r = conf.route.route("8.8.8.8")
        if r and len(r) >= 3:
            info["gateway"] = r[2]
    except Exception:
        pass
    if not info["gateway"]:
        for a in _ipconfig_parsed():
            if a["gateway"]:
                info["gateway"] = a["gateway"][0]
                break
    try:
        for a in _ipconfig_parsed():
            if info["ip"] and info["ip"] in a["ipv4"]:
                info["dns"] = a["dns"]
                break
    except Exception:
        pass
    return info


def link_info(ip):
    out = {}
    try:
        stats = psutil.net_if_stats()
        for pname, alist in psutil.net_if_addrs().items():
            if not any(a.family == socket.AF_INET and a.address == ip for a in alist):
                continue
            if pname in stats:
                s = stats[pname]
                out = {"iface_name": pname, "speed_mbps": s.speed,
                       "is_up": s.isup, "mtu": s.mtu,
                       "duplex": "full" if s.duplex == 2 else (
                           "half" if s.duplex == 1 else "unknown")}
            break
    except Exception:
        pass
    return out if out else None


OS_DB_SYN = [
    (64, 29200, ["mss", "sackOK", "TS", "nop", "ws"], "Linux 5.x/6.x"),
    (64, 29200, ["mss", "nop", "nop", "sackOK", "TS", "nop", "ws"], "Linux 4.x"),
    (64, 5840, ["mss", "nop", "nop", "sackOK", "TS", "nop", "nop"], "Linux 3.x"),
    (128, 8192, ["mss", "nop", "ws", "nop", "nop", "sackOK"], "Windows 7"),
    (128, 64240, ["mss", "nop", "ws", "nop", "nop", "sackOK"], "Windows 10/11"),
    (64, 65535, ["mss", "nop", "ws", "nop", "nop", "TS", "sackOK"], "iOS/macOS"),
    (64, 65535, ["mss", "nop", "nop", "sackOK", "nop", "nop", "ws"], "Android"),
]
OS_DB_SYNACK = [
    (64, 28960, ["mss", "sackOK", "TS", "nop", "ws"], "Linux 5.x/6.x"),
    (64, 29200, ["mss", "nop", "nop", "sackOK", "TS", "nop", "ws"], "Linux 4.x"),
    (128, 8192, ["mss", "nop", "ws", "nop", "nop", "sackOK", "nop", "nop"], "Windows Server"),
    (128, 64240, ["mss", "nop", "ws", "nop", "nop", "sackOK"], "Windows 10/11"),
    (64, 65535, ["mss", "nop", "nop", "sackOK", "nop", "nop", "ws"], "macOS"),
    (255, 4128, ["mss", "nop", "nop", "sackOK"], "Cisco IOS"),
    (255, 4128, ["mss", "nop", "sackOK"], "Cisco NX-OS"),
]


def _decode_tcp_options(pkt):
    if not HAVE_SCAPY or not pkt.haslayer(TCP):
        return []
    try:
        opts = pkt[TCP].options
        if not opts:
            return []
        names = []
        for opt in opts:
            if isinstance(opt, tuple) and opt:
                names.append(str(opt[0]))
            elif isinstance(opt, str):
                names.append(opt)
        return names
    except Exception:
        return []


def _normalize_opts(raw):
    norm = []
    for o in raw:
        low = o.lower()
        if "mss" in low: norm.append("mss")
        elif "sack" in low: norm.append("sackOK")
        elif "timestamp" in low or low == "ts": norm.append("TS")
        elif "nop" in low: norm.append("nop")
        elif "wscale" in low or low == "ws": norm.append("ws")
        else: norm.append(o)
    return norm


def _match_os(ttl, window, norm, db):
    best = None
    best_score = 0
    for d_ttl, d_win, d_opts, d_os in db:
        score = 0
        if d_ttl == ttl: score += 3
        elif abs(d_ttl - ttl) <= 4: score += 1
        if d_win == window: score += 3
        elif abs(d_win - window) <= 200: score += 2
        elif abs(d_win - window) <= max(d_win * 0.05, 1000): score += 1
        score += sum(1 for a, b in zip(norm, d_opts) if a == b)
        if score > best_score:
            best_score = score
            best = (d_os, ttl, window)
    return best if best_score >= 4 else None


def passive_os_fingerprint(pkt):
    if not HAVE_SCAPY or not pkt.haslayer(IP) or not pkt.haslayer(TCP):
        return None
    try:
        tcp = pkt[TCP]
        flags = int(tcp.flags)
        if not (flags & 0x02):
            return None
        is_ack = bool(flags & 0x10)
        norm = _normalize_opts(_decode_tcp_options(pkt))
        return _match_os(int(pkt[IP].ttl), int(tcp.window), norm,
                          OS_DB_SYNACK if is_ack else OS_DB_SYN)
    except Exception:
        return None


def tcp_uptime_from_packet(pkt):
    if not HAVE_SCAPY or not pkt.haslayer(IP) or not pkt.haslayer(TCP):
        return None
    try:
        opts = pkt[TCP].options
        if not opts:
            return None
        for opt in opts:
            if isinstance(opt, tuple) and len(opt) >= 2 and str(opt[0]).lower() == "timestamp":
                tsval = opt[1][0] if isinstance(opt[1], tuple) else opt[1]
                if not isinstance(tsval, int):
                    continue
                uptime_s = tsval / 1000.0
                if 120 <= uptime_s <= 60 * 60 * 24 * 365 * 10:
                    return (int(uptime_s), pkt[IP].src)
    except Exception:
        pass
    return None


def format_uptime(seconds):
    if seconds is None:
        return "?"
    d = seconds // 86400
    h = (seconds % 86400) // 3600
    m = (seconds % 3600) // 60
    if d > 0: return "{}d {}h".format(d, h)
    if h > 0: return "{}h {}m".format(h, m)
    return "{}m".format(m)


def passive_listen(iface, seconds=90, watch_snmp_traps=False):
    if not HAVE_SCAPY:
        return None
    found = {
        "arp": {}, "arp_spoof": [], "dhcp_offers": [], "dhcp_servers_all": [],
        "rogue_dhcp": False, "lldp": None, "cdp": None,
        "mdns": [], "ssdp": [], "dns_queries": [], "dns_answers": [],
        "tls_sni": [], "http_host": [], "netbios": [], "llmnr": [],
        "tcp_os": {}, "tcp_uptime": {}, "snmp_traps": [],
    }
    seen = {k: set() for k in ["mdns", "ssdp", "sni", "http", "dns", "llmnr",
                                "spoof", "nbios", "traps"]}
    arp_ip_to_mac = {}
    dhcp_servers = set()

    def parse_lldp(raw):
        try:
            if len(raw) < 2:
                return
            info = {}
            idx = 0
            while idx + 2 <= len(raw):
                hdr = int.from_bytes(raw[idx:idx+2], "big")
                t = (hdr >> 9) & 0x7F
                l = hdr & 0x1FF
                idx += 2
                if idx + l > len(raw):
                    break
                val = raw[idx:idx+l]
                idx += l
                if t == 0:
                    break
                if t == 1 and len(val) >= 1:
                    info["chassis_id"] = _decode_id(val[1:])
                elif t == 2 and len(val) >= 1:
                    info["port_id"] = _decode_id(val[1:])
                elif t == 4:
                    info["port_desc"] = val.decode("utf-8", errors="ignore")
                elif t == 5:
                    info["system_name"] = val.decode("utf-8", errors="ignore")
                elif t == 6:
                    info["system_description"] = val.decode("utf-8", errors="ignore")
                elif t == 8 and len(val) >= 2:
                    if val[1] == 1 and val[0] >= 2:
                        info["management_ip"] = ".".join(str(b) for b in val[2:2+4])
                elif t == 127 and len(val) >= 6 and val[0:3] == b"\x00\x80\xc2":
                    subtype = val[3]
                    if subtype == 1:
                        info["vlan_pvid"] = int.from_bytes(val[4:6], "big")
                    elif subtype == 3:
                        nl = val[4]
                        try:
                            info["vlan_name"] = val[5:5+nl].decode("utf-8", errors="ignore")
                        except Exception:
                            pass
            if info:
                found["lldp"] = info
        except Exception:
            pass

    def parse_cdp(data):
        try:
            if len(data) < 4:
                return
            info = {}
            idx = 4
            while idx + 4 <= len(data):
                t = int.from_bytes(data[idx:idx+2], "big")
                l = int.from_bytes(data[idx+2:idx+4], "big")
                idx += 4
                if l < 4 or idx + l - 4 > len(data):
                    break
                val = data[idx:idx+l-4]
                idx += l - 4
                if t == 1:
                    info["device_id"] = val.decode("latin-1", errors="ignore")
                elif t == 3:
                    info["port_id"] = val.decode("latin-1", errors="ignore")
                elif t == 5:
                    info["version"] = val.decode("latin-1", errors="ignore")
                elif t == 6:
                    info["platform"] = val.decode("latin-1", errors="ignore")
                elif t == 14 and len(val) >= 2:
                    info["native_vlan"] = int.from_bytes(val, "big")
            if info:
                found["cdp"] = info
        except Exception:
            pass

    def on_pkt(pkt):
        try:
            if pkt.haslayer(Ether):
                et = pkt[Ether].type
                if et == 0x88CC and pkt.haslayer(Raw):
                    parse_lldp(bytes(pkt[Raw]))
                elif et == 0x0000 and pkt.haslayer(Raw):
                    raw = bytes(pkt[Raw])
                    if len(raw) >= 8 and raw[0:3] == b"\xaa\xaa\x03" \
                            and raw[3:8] == b"\x00\x00\x0c\x20\x00":
                        parse_cdp(raw[8:])
        except Exception:
            pass
        try:
            if pkt.haslayer(ARP):
                arp = pkt[ARP]
                if int(arp.op) == 2:
                    ip, mac = arp.psrc, arp.hwsrc
                    prev = arp_ip_to_mac.get(ip)
                    if prev and prev != mac:
                        key = (ip, prev, mac)
                        if key not in seen["spoof"]:
                            seen["spoof"].add(key)
                            found["arp_spoof"].append({
                                "ip": ip, "old_mac": prev, "new_mac": mac})
                    arp_ip_to_mac[ip] = mac
                    found["arp"][ip] = mac
                elif int(arp.op) == 1 and arp.psrc not in ("0.0.0.0", ""):
                    found["arp"][arp.psrc] = arp.hwsrc
        except Exception:
            pass
        try:
            if pkt.haslayer(DHCP) and pkt.haslayer(IP):
                msg_type = None
                for opt in pkt[DHCP].options:
                    if isinstance(opt, tuple) and opt[0] == "message-type":
                        msg_type = opt[1]
                        break
                if msg_type == 2:
                    sid = pkt[IP].src
                    dhcp_servers.add(sid)
                    entry = {"server_ip": sid,
                             "your_ip": pkt[BOOTP].yiaddr if pkt.haslayer(BOOTP) else None,
                             "options": {}}
                    for opt in pkt[DHCP].options:
                        if isinstance(opt, tuple) and len(opt) >= 2:
                            entry["options"][opt[0]] = opt[1]
                    if not any(e["server_ip"] == sid for e in found["dhcp_offers"]):
                        found["dhcp_offers"].append(entry)
                    found["dhcp_servers_all"] = sorted(dhcp_servers)
                    found["rogue_dhcp"] = len(dhcp_servers) > 1
        except Exception:
            pass
        try:
            if pkt.haslayer(UDP) and pkt.haslayer(DNS):
                try:
                    sp = int(pkt[UDP].sport)
                    dp = int(pkt[UDP].dport)
                except Exception:
                    sp = dp = 0
                src = pkt[IP].src if pkt.haslayer(IP) else None
                dns = pkt[DNS]
                if dns.qr == 0 and dns.qd and 53 in (sp, dp):
                    name = _qname(dns.qd)
                    if name and name not in seen["dns"]:
                        seen["dns"].add(name)
                        found["dns_queries"].append({"host": name, "src": src})
                if 5353 in (sp, dp) and dns.qr == 1:
                    rr = dns.an
                    g = 0
                    while rr is not None and g < 10:
                        g += 1
                        try:
                            name = rr.rrname
                            if isinstance(name, bytes):
                                name = name.decode(errors="ignore")
                            rdata = rr.rdata
                            if isinstance(rdata, bytes):
                                rdata = rdata.decode(errors="ignore")
                            key = (src, str(name))
                            if key not in seen["mdns"]:
                                seen["mdns"].add(key)
                                found["mdns"].append({
                                    "ip": src, "name": str(name).rstrip("."),
                                    "data": str(rdata).rstrip(".")})
                        except Exception:
                            pass
                        nxt = getattr(rr, "payload", None)
                        if nxt is None or isinstance(nxt, DNS):
                            break
                        rr = nxt
                if 5355 in (sp, dp) and dns.qr == 0 and dns.qd:
                    name = _qname(dns.qd)
                    if name and name not in seen["llmnr"]:
                        seen["llmnr"].add(name)
                        found["llmnr"].append({"host": name, "src": src})
        except Exception:
            pass
        try:
            if pkt.haslayer(UDP) and pkt.haslayer(Raw):
                try:
                    sp = int(pkt[UDP].sport)
                    dp = int(pkt[UDP].dport)
                except Exception:
                    sp = dp = 0
                if 1900 in (sp, dp):
                    text = bytes(pkt[Raw]).decode("utf-8", errors="ignore")
                    if text.startswith(("NOTIFY", "HTTP/1.1")):
                        src = pkt[IP].src if pkt.haslayer(IP) else None
                        server = nt = None
                        for line in text.splitlines():
                            low = line.lower()
                            if low.startswith("server:"):
                                server = line.split(":", 1)[1].strip()
                            elif low.startswith(("nt:", "st:")):
                                nt = line.split(":", 1)[1].strip()
                        key = (src, server, nt)
                        if key not in seen["ssdp"]:
                            seen["ssdp"].add(key)
                            found["ssdp"].append({"ip": src, "server": server, "nt": nt})
                if 137 in (sp, dp):
                    src = pkt[IP].src if pkt.haslayer(IP) else None
                    if src and src not in seen["nbios"]:
                        seen["nbios"].add(src)
                        found["netbios"].append({"src": src})
                if watch_snmp_traps and 162 in (sp, dp):
                    src = pkt[IP].src if pkt.haslayer(IP) else None
                    payload = bytes(pkt[Raw])[:100].hex()
                    key = (src, payload)
                    if key not in seen["traps"]:
                        seen["traps"].add(key)
                        found["snmp_traps"].append({"src": src, "hex": payload})
        except Exception:
            pass
        try:
            if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                payload = bytes(pkt[Raw])
                if len(payload) >= 6 and payload[0] == 0x16 and payload[1] == 0x03:
                    sni = _parse_sni(payload)
                    if sni and sni not in seen["sni"]:
                        seen["sni"].add(sni)
                        dst = pkt[IP].dst if pkt.haslayer(IP) else None
                        found["tls_sni"].append({"sni": sni, "dst": dst})
                else:
                    text = payload.decode("latin-1", errors="ignore")
                    if text.startswith(("GET ", "POST ", "HEAD ")):
                        for line in text.split("\r\n"):
                            if line.lower().startswith("host:"):
                                host = line.split(":", 1)[1].strip()
                                if host not in seen["http"]:
                                    seen["http"].add(host)
                                    dst = pkt[IP].dst if pkt.haslayer(IP) else None
                                    found["http_host"].append({"host": host, "dst": dst})
                                break
        except Exception:
            pass
        try:
            os_hint = passive_os_fingerprint(pkt)
            if os_hint:
                src = pkt[IP].src if pkt.haslayer(IP) else None
                if src and src not in found["tcp_os"]:
                    found["tcp_os"][src] = {
                        "os": os_hint[0], "ttl": os_hint[1], "window": os_hint[2]}
            up = tcp_uptime_from_packet(pkt)
            if up and up[1] not in found["tcp_uptime"]:
                found["tcp_uptime"][up[1]] = up[0]
        except Exception:
            pass

    if not _QUIET[0]:
        print("passive listening {}s...".format(seconds), file=sys.stderr)
    try:
        sc_sniff(iface=iface, timeout=seconds, prn=on_pkt, store=False)
    except Exception as e:
        if not _QUIET[0]:
            print("  sniff error: {}".format(e), file=sys.stderr)
    return found


def _qname(q):
    if q is None:
        return None
    try:
        n = q.qname
        if isinstance(n, bytes):
            n = n.decode(errors="ignore")
        return str(n).rstrip(".")
    except Exception:
        return None


def _decode_id(b):
    try:
        s = b.decode("ascii", errors="ignore").strip("\x00").strip()
        if s and all(32 <= ord(c) < 127 for c in s):
            return s
    except Exception:
        pass
    if len(b) == 6:
        return ":".join("{:02x}".format(x) for x in b)
    return b.hex()


def _parse_sni(payload):
    try:
        idx = 5
        if idx >= len(payload) or payload[idx] != 0x01:
            return None
        idx += 4 + 2 + 32
        if idx >= len(payload):
            return None
        sid_len = payload[idx]
        idx += 1 + sid_len
        if idx + 2 > len(payload):
            return None
        cs_len = int.from_bytes(payload[idx:idx+2], "big")
        idx += 2 + cs_len
        if idx >= len(payload):
            return None
        cm_len = payload[idx]
        idx += 1 + cm_len
        if idx + 2 > len(payload):
            return None
        ext_total = int.from_bytes(payload[idx:idx+2], "big")
        idx += 2
        end = min(idx + ext_total, len(payload))
        while idx + 4 <= end:
            et = int.from_bytes(payload[idx:idx+2], "big")
            el = int.from_bytes(payload[idx+2:idx+4], "big")
            idx += 4
            if idx + el > len(payload):
                return None
            if et == 0x0000 and el >= 5:
                block = payload[idx:idx+el]
                nlen = int.from_bytes(block[3:5], "big")
                return block[5:5+nlen].decode(errors="ignore")
            idx += el
    except Exception:
        return None
    return None


def arp_sweep(subnet, iface, delay_ms=0, max_hosts=512):
    if not HAVE_SCAPY:
        return []
    try:
        net = ipaddress.IPv4Network(subnet, strict=False)
    except Exception:
        return []
    hosts = [str(h) for h in net.hosts()]
    if len(hosts) > max_hosts:
        hosts = hosts[:max_hosts]
    out = []
    for i in range(0, len(hosts), 16):
        chunk = hosts[i:i+16]
        try:
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=chunk)
            ans, _ = srp(pkt, iface=iface, timeout=1, verbose=False)
            for _, rcv in ans:
                out.append({"ip": rcv[ARP].psrc, "mac": rcv[ARP].hwsrc})
        except Exception:
            continue
        if not _AGGRESSIVE_TIMING[0]:
            time.sleep(random.uniform(0.03, 0.1))
        if delay_ms > 0:
            sleep_delay(delay_ms)
    return out


TOP_PORTS_50 = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 135: "msrpc", 139: "netbios", 143: "imap",
    389: "ldap", 443: "https", 445: "smb", 464: "kpasswd", 515: "lpd",
    631: "ipp", 636: "ldaps", 993: "imaps", 995: "pop3s", 1433: "mssql",
    3306: "mysql", 3389: "rdp", 5060: "sip", 5061: "sip-tls",
    5432: "postgres", 5900: "vnc", 8000: "http-alt", 8080: "http-alt",
    8081: "http-alt", 8443: "https-alt", 8888: "http-alt",
    9090: "http-alt", 9100: "printer-jd", 10000: "webmin",
}
TOP_PORTS_20 = {k: TOP_PORTS_50[k] for k in [
    21, 22, 23, 53, 80, 110, 139, 143, 443, 445, 993, 995,
    3306, 3389, 5060, 5432, 8080, 8443, 9090, 9100]}
PRINTER_PORTS = (9100, 631, 515)


def grab_banner(ip, port, timeout=2.5):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        if s.connect_ex((ip, port)) != 0:
            s.close()
            return None
        b = b""
        if port in (80, 8000, 8080, 8081, 8888, 9090):
            try:
                s.sendall(("GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\n"
                           "Accept: */*\r\nAccept-Language: {}\r\n"
                           "Connection: close\r\n\r\n").format(
                               ip, _ua(), _accept_lang()).encode())
            except Exception:
                pass
        try:
            s.settimeout(timeout)
            d = s.recv(2048)
            if d:
                b = d
        except Exception:
            pass
        if not b and not _AGGRESSIVE_TIMING[0]:
            time.sleep(random.uniform(0.05, 0.15))
        s.close()
        if b:
            return b.decode("latin-1", errors="ignore").strip()
    except Exception:
        pass
    return None


def tls_weakness(ip, port=443, timeout=4):
    result = {"protocols": {}, "weak": [], "cert": {}, "score": 0}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = socket.create_connection((ip, port), timeout=timeout)
        ss = ctx.wrap_socket(s, server_hostname=ip)
        best_proto = ss.version()
        best_cipher = ss.cipher()
        result["protocols"][best_proto] = best_cipher[0] if best_cipher else "?"

        try:
            cert = ss.getpeercert()
            if cert:
                subj = dict(x[0] for x in cert.get("subject", []))
                result["cert"]["subject"] = subj
                result["cert"]["issuer"] = dict(x[0] for x in cert.get("issuer", []))
                result["cert"]["notAfter"] = cert.get("notAfter")
                result["cert"]["san"] = cert.get("subjectAltName", [])
                if subj.get("commonName") == result["cert"]["issuer"].get("commonName"):
                    result["weak"].append("self-signed certificate")
                try:
                    exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")\
                        .replace(tzinfo=timezone.utc)
                    days = (exp - datetime.now(timezone.utc)).days
                    result["cert"]["days_left"] = days
                    if days < 0:
                        result["weak"].append("CERT EXPIRED")
                    elif days < 30:
                        result["weak"].append("cert expires in {} days".format(days))
                except Exception:
                    pass
        except Exception:
            pass
        ss.close()
    except Exception:
        return None

    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        ctx.maximum_version = ssl.TLSVersion.TLSv1
        s = socket.create_connection((ip, port), timeout=timeout)
        ss = ctx.wrap_socket(s, server_hostname=ip)
        cipher = ss.cipher()
        result["protocols"]["TLSv1.0"] = cipher[0] if cipher else "?"
        result["weak"].append("supports TLSv1.0")
        ss.close()
    except Exception:
        pass

    result["score"] = max(0, 100 - len(result["weak"]) * 20)
    return result


def _unverified_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def http_security_audit(ip, port=80, scheme="http", timeout=3):
    checks = {
        "Strict-Transport-Security": "HSTS missing",
        "Content-Security-Policy": "CSP missing",
        "X-Frame-Options": "clickjacking protection missing",
        "X-Content-Type-Options": "MIME sniffing protection missing",
        "Referrer-Policy": "referrer policy missing",
        "Permissions-Policy": "permissions policy missing",
    }
    result = {"present": {}, "missing": [], "score": 0}
    try:
        url = "{}://{}:{}/".format(scheme, ip, port)
        req = urllib.request.Request(url, method="HEAD")
        req.add_header("User-Agent", _ua())
        if scheme == "https":
            resp = urllib.request.urlopen(req, timeout=timeout,
                                           context=_unverified_ctx())
        else:
            resp = urllib.request.urlopen(req, timeout=timeout)
        headers = {k.lower(): v for k, v in resp.headers.items()}
        resp.close()
        for h, msg in checks.items():
            if h.lower() in headers:
                result["present"][h] = headers[h.lower()]
            else:
                result["missing"].append(msg)
        result["score"] = max(0, 100 - len(result["missing"]) * 15)
    except Exception:
        return None
    return result


def smb_negotiate(ip, port=445, timeout=3):
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        smb = (b"\x00\x00\x00\x85" + b"\xffSMB" + b"\x72" +
               b"\x00\x00\x00\x00" + b"\x18" + b"\x53\xc8" +
               b"\x00\x00" + b"\x00"*8 + b"\x00\x00" +
               b"\x00\x00" + b"\x00\x00" + b"\x00\x00" + b"\x00\x00" + b"\x00" +
               b"\x62\x00" + b"\x02NT LM 0.12\x00" +
               b"\x02SMB 2.002\x00" + b"\x02SMB 2.???\x00")
        s.sendall(smb)
        s.settimeout(timeout)
        d = s.recv(1024)
        s.close()
        if not d or len(d) < 8:
            return None
        r = {}
        magic = d[4:8]
        if magic == b"\xffSMB":
            r["version"] = "SMB1"
            try:
                wc = d[32]
                bo = 33 + wc*2
                bc = int.from_bytes(d[bo:bo+2], "little")
                body = d[bo+2:bo+2+bc]
                if body:
                    osl = body[0]
                    r["server_os"] = body[1:1+osl].decode("latin-1", errors="ignore")
            except Exception:
                pass
        elif magic == b"\xfeSMB":
            r["version"] = "SMB2/3"
        else:
            r["version"] = "unknown"
        return r
    except Exception:
        return None


def scan_host(ip, port_map, do_nvd=True, delay_ms=0, audit_tls=True, audit_http=True):
    """FIX: detect_product_version wrapped in try/except — bad regex no longer skips host."""
    ports_out = []
    port_list = list(port_map.keys())
    random.shuffle(port_list)
    for port in port_list:
        banner = grab_banner(ip, port)
        sleep_delay(delay_ms)
        if banner is None:
            continue
        entry = {"port": port, "service": port_map.get(port, "?"),
                 "banner": banner[:300], "products": [], "extra": {}}
        try:
            for prod, ver in detect_product_version(banner):
                cves = nvd_lookup(prod, ver) if do_nvd else []
                entry["products"].append({"product": prod, "version": ver, "cves": cves})
        except Exception:
            pass
        if port in (443, 8443) and audit_tls:
            try:
                entry["extra"]["tls_weak"] = tls_weakness(ip, port)
            except Exception:
                pass
        elif port == 445:
            try:
                s = smb_negotiate(ip, port)
                if s:
                    entry["extra"]["smb"] = s
                    if s.get("server_os") and do_nvd:
                        try:
                            for prod, ver in detect_product_version(s["server_os"]):
                                entry["products"].append({
                                    "product": prod, "version": ver,
                                    "cves": nvd_lookup(prod, ver)})
                        except Exception:
                            pass
            except Exception:
                pass
        if audit_http:
            try:
                if port in (80, 8080, 8000, 8888):
                    entry["extra"]["http_sec"] = http_security_audit(ip, port, "http")
                elif port in (443, 8443):
                    entry["extra"]["http_sec"] = http_security_audit(ip, port, "https")
            except Exception:
                pass
        ports_out.append(entry)
    return ports_out


SNMP_OIDS = {
    "sysDescr": "1.3.6.1.2.1.1.1.0", "sysObjectID": "1.3.6.1.2.1.1.2.0",
    "sysUpTime": "1.3.6.1.2.1.1.3.0", "sysContact": "1.3.6.1.2.1.1.4.0",
    "sysName": "1.3.6.1.2.1.1.5.0", "sysLocation": "1.3.6.1.2.1.1.6.0",
}


def snmp_probe(ip, community="public", timeout=2):
    if not HAVE_SNMP:
        return None
    out = {}
    for label, oid in SNMP_OIDS.items():
        try:
            ei, es, _, vb = next(getCmd(
                SnmpEngine(),
                CommunityData(community, mpModel=1),
                UdpTransportTarget((ip, 161), timeout=timeout, retries=0),
                ContextData(), ObjectType(ObjectIdentity(oid))))
            if ei or es:
                continue
            for _, v in vb:
                out[label] = str(v)
        except Exception:
            continue
    return out if out else None


def snmp_uptime_human(sysuptime_str):
    if not sysuptime_str:
        return None
    secs = None
    s = str(sysuptime_str)
    try:
        if "day" in s.lower():
            days_m = re.search(r"(\d+)\s*day", s, re.I)
            hms_m = re.search(r"(\d+):(\d+):(\d+)", s)
            d = int(days_m.group(1)) if days_m else 0
            h = int(hms_m.group(1)) if hms_m else 0
            mi = int(hms_m.group(2)) if hms_m else 0
            sc = int(hms_m.group(3)) if hms_m else 0
            secs = d * 86400 + h * 3600 + mi * 60 + sc
        else:
            m = re.search(r"(\d+)", s.replace(",", ""))
            if m:
                secs = int(m.group(1)) / 100.0
    except Exception:
        return None
    if secs is None:
        return None
    days = secs / 86400
    return {"human": format_uptime(int(secs)),
            "days": round(days, 1),
            "warning": ("device up {} (stale firmware?)".format(
                format_uptime(int(secs))) if days > 730 else None)}


def snmp_walk(ip, base_oid, community="public", max_rows=100, timeout=2):
    if not HAVE_SNMP:
        return []
    out = []
    try:
        for ei, es, _, vb in nextCmd(
                SnmpEngine(),
                CommunityData(community, mpModel=1),
                UdpTransportTarget((ip, 161), timeout=timeout, retries=0),
                ContextData(), ObjectType(ObjectIdentity(base_oid)),
                lexicographicMode=False):
            if ei or es:
                break
            for name, val in vb:
                out.append((str(name), str(val)))
                if len(out) >= max_rows:
                    return out
    except Exception:
        pass
    return out


def snmp_walk_interfaces(ip, community="public"):
    idxs = snmp_walk(ip, "1.3.6.1.2.1.2.2.1.1", community, max_rows=64)
    out = []
    for _, v in idxs:
        try:
            pi = int(v)
        except Exception:
            continue
        info = {"idx": pi}
        d = snmp_walk(ip, "1.3.6.1.2.1.2.2.1.2.{}".format(pi), community, max_rows=1)
        if d:
            info["descr"] = d[0][1]
        m = snmp_walk(ip, "1.3.6.1.2.1.2.2.1.6.{}".format(pi), community, max_rows=1)
        if m:
            info["mac"] = m[0][1]
        out.append(info)
    return out


def snmp_walk_arp(ip, community="public"):
    out = []
    for oid, val in snmp_walk(ip, "1.3.6.1.2.1.4.22.1.2", community, max_rows=256):
        try:
            parts = oid.split(".")[-4:]
            if len(parts) == 4:
                out.append({"ip": ".".join(parts), "mac": val})
        except Exception:
            pass
    return out


def upnp_igd_query(router_ip, timeout=3):
    r = {"control_url": None, "external_ip": None}
    try:
        with urllib.request.urlopen(
                "http://{}:1900/gatedesc.xml".format(router_ip),
                timeout=timeout) as resp:
            xml = resp.read()
        root = ET.fromstring(xml)
        ctrl = None
        for svc in root.iter("{urn:schemas-upnp-org:device-1-0}service"):
            st = svc.find("{urn:schemas-upnp-org:device-1-0}serviceType")
            if st is not None and "WANIPConnection" in (st.text or ""):
                c = svc.find("{urn:schemas-upnp-org:device-1-0}controlURL")
                if c is not None and c.text:
                    ctrl = c.text.strip()
                    break
        if not ctrl:
            return r
        r["control_url"] = ctrl
        if not ctrl.startswith("http"):
            ctrl = "http://{}{}".format(router_ip, ctrl)
        body = (b'<?xml version="1.0"?>'
                b'<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
                b's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
                b'<s:Body><u:GetExternalIPAddress '
                b'xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"/>'
                b'</s:Body></s:Envelope>')
        req = urllib.request.Request(ctrl, data=body, method="POST")
        req.add_header("Content-Type", 'text/xml; charset="utf-8"')
        req.add_header("SOAPAction",
                       '"urn:schemas-upnp-org:service:WANIPConnection:1#GetExternalIPAddress"')
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            text = resp.read().decode("utf-8", errors="ignore")
        m = re.search(r"<NewExternalIPAddress>([^<]+)</NewExternalIPAddress>", text)
        if m:
            r["external_ip"] = m.group(1)
    except Exception:
        pass
    return r


def dns_srv_enum(domain, dns_server=None, timeout=2):
    if not HAVE_SCAPY or not domain:
        return []
    out = []
    for srv in ["_ldap._tcp", "_kerberos._tcp", "_gc._tcp", "_sip._udp"]:
        q = "{}.{}".format(srv, domain)
        try:
            pkt = IP(dst=dns_server or "8.8.8.8") / UDP(dport=53) / DNS(
                rd=1, qd=DNSQR(qname=q, qtype="SRV"))
            ans = sr1(pkt, timeout=timeout, verbose=False)
            sleep_delay(200)
            if not ans or not ans.haslayer(DNS):
                continue
            rr = ans[DNS].an
            g = 0
            while rr is not None and g < 10:
                g += 1
                try:
                    if int(rr.type) == 33:
                        tgt = rr.rdata.target
                        if isinstance(tgt, bytes):
                            tgt = tgt.decode(errors="ignore")
                        out.append({"srv": srv, "domain": domain,
                                    "target": str(tgt).rstrip("."),
                                    "port": rr.rdata.port})
                except Exception:
                    pass
                nxt = getattr(rr, "payload", None)
                if nxt is None or isinstance(nxt, DNS):
                    break
                rr = nxt
        except Exception:
            continue
    return out


def dns_wildcard_check(domain, dns_server=None, timeout=3):
    if not HAVE_SCAPY or not domain:
        return None
    try:
        random_sub = "nonexistent-{}.{}".format(random.randint(100000, 999999), domain)
        pkt = IP(dst=dns_server or "8.8.8.8") / UDP(dport=53) / DNS(
            rd=1, qd=DNSQR(qname=random_sub, qtype="A"))
        ans = sr1(pkt, timeout=timeout, verbose=False)
        if not ans or not ans.haslayer(DNS):
            return {"wildcard": False}
        dns = ans[DNS]
        if dns.ancount and dns.ancount > 0:
            ips = []
            rr = dns.an
            g = 0
            while rr is not None and g < 10:
                g += 1
                try:
                    if int(rr.type) == 1:
                        ips.append(str(rr.rdata))
                except Exception:
                    pass
                nxt = getattr(rr, "payload", None)
                if nxt is None or isinstance(nxt, DNS):
                    break
                rr = nxt
            if ips:
                return {"wildcard": True, "resolves_to": ips}
        return {"wildcard": False}
    except Exception:
        return None


def _encode_dns_name(name):
    out = b""
    for part in name.rstrip(".").split("."):
        out += bytes([len(part)]) + part.encode("ascii")
    return out + b"\x00"


def _recv_exact(sock, n, deadline):
    buf = b""
    while len(buf) < n and time.time() < deadline:
        try:
            chunk = sock.recv(n - len(buf))
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
    return buf


def dns_zone_transfer(domain, dns_server, timeout=5):
    result = {"attempted": True, "success": False, "records": [], "soa_count": 0}
    if not domain or not dns_server:
        result["attempted"] = False
        return result
    try:
        qid = random.randint(1, 65535)
        question = _encode_dns_name(domain) + struct.pack(">HH", 252, 1)
        header = struct.pack(">HHHHHH", qid, 0, 1, 0, 0, 0)
        msg = header + question
        sock = socket.create_connection((dns_server, 53), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(struct.pack(">H", len(msg)) + msg)
        deadline = time.time() + timeout
        while time.time() < deadline:
            prefix = _recv_exact(sock, 2, deadline)
            if len(prefix) < 2:
                break
            mlen = struct.unpack(">H", prefix)[0]
            if mlen == 0 or mlen > 65000:
                break
            body = _recv_exact(sock, mlen, deadline)
            if len(body) < mlen:
                break
            result["records"].append({"len": len(body)})
            try:
                if b"\x00\x06" in body:
                    result["soa_count"] += 1
            except Exception:
                pass
            if result["soa_count"] >= 2:
                break
        sock.close()
        if result["records"]:
            result["success"] = True
    except Exception as e:
        result["error"] = str(e)
    return result


MDNS_SERVICES_FULL = [
    "_services._dns-sd._udp.local", "_http._tcp.local", "_https._tcp.local",
    "_ipp._tcp.local", "_printer._tcp.local", "_afpovertcp._tcp.local",
    "_smb._tcp.local", "_ssh._tcp.local", "_airplay._tcp.local",
    "_raop._tcp.local", "_googlecast._tcp.local", "_homekit._tcp.local",
    "_hap._tcp.local", "_workstation._tcp.local",
]
MDNS_SERVICES_LIGHT = [
    "_services._dns-sd._udp.local", "_ipp._tcp.local",
    "_airplay._tcp.local", "_googlecast._tcp.local", "_smb._tcp.local",
]


def mdns_deep_enum(iface, timeout=8, mode="aggressive"):
    """FIX: early return if sniffer.running is False (no wasted probes)."""
    if not HAVE_SCAPY:
        return []
    services = MDNS_SERVICES_FULL if mode == "aggressive" else MDNS_SERVICES_LIGHT
    if not _QUIET[0]:
        print("mDNS deep enum ({}s, {} services)...".format(timeout, len(services)),
              file=sys.stderr)
    results = []
    seen = set()
    start = time.time()

    def on_pkt(pkt):
        try:
            if pkt.haslayer(DNS) and pkt[DNS].qr == 1:
                src = pkt[IP].src if pkt.haslayer(IP) else None
                rr = pkt[DNS].an
                g = 0
                while rr is not None and g < 20:
                    g += 1
                    try:
                        rtype = int(rr.type)
                        name = rr.rrname
                        if isinstance(name, bytes):
                            name = name.decode(errors="ignore")
                        name = str(name).rstrip(".")
                        entry = {"ip": src, "name": name, "type": rtype}
                        if rtype == 12:
                            data = rr.rdata
                            if isinstance(data, bytes):
                                data = data.decode(errors="ignore")
                            entry["ptr"] = str(data).rstrip(".")
                        elif rtype == 33:
                            entry["srv_target"] = str(rr.rdata.target).rstrip(".")
                            entry["srv_port"] = rr.rdata.port
                            entry["srv_priority"] = rr.rdata.priority
                            entry["srv_weight"] = rr.rdata.weight
                        elif rtype == 16:
                            try:
                                txts = []
                                for t in rr.rdata:
                                    if isinstance(t, bytes):
                                        t = t.decode(errors="ignore")
                                    txts.append(str(t))
                                entry["txt"] = txts
                            except Exception:
                                pass
                        elif rtype in (1, 28):
                            entry["addr"] = str(rr.rdata)
                        key = (src, name, str(entry))
                        if key not in seen:
                            seen.add(key)
                            results.append(entry)
                    except Exception:
                        pass
                    nxt = getattr(rr, "payload", None)
                    if nxt is None or isinstance(nxt, DNS):
                        break
                    rr = nxt
        except Exception:
            pass

    sniffer = None
    try:
        sniffer = AsyncSniffer(iface=iface, filter="udp port 5353",
                                prn=on_pkt, store=False)
        sniffer.start()
        time.sleep(0.2)
        if not sniffer.running:
            try:
                sniffer.stop()
            except Exception:
                pass
            return []
    except Exception:
        return []
    try:
        for svc in services:
            if time.time() - start >= timeout - 0.5:
                break
            try:
                pkt = (Ether(dst="01:00:5e:00:00:fb") /
                       IP(dst="224.0.0.251", ttl=255) /
                       UDP(sport=5353, dport=5353) /
                       DNS(id=0, qr=0, qdcount=1,
                           qd=DNSQR(qname=svc, qtype="PTR", qclass=0x0001)))
                sendp(pkt, iface=iface, verbose=False)
                if not _AGGRESSIVE_TIMING[0]:
                    time.sleep(random.uniform(0.3, 0.8))
            except Exception:
                pass
        remaining = timeout - (time.time() - start)
        if remaining > 0:
            time.sleep(remaining)
    finally:
        if sniffer is not None:
            try:
                sniffer.stop()
            except Exception:
                pass
    return list(results)


def ntp_query(ip, timeout=2):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(b"\x1b" + b"\x00" * 47, (ip, 123))
        data, _ = s.recvfrom(512)
        s.close()
        if len(data) < 48:
            return None
        stratum = data[1]
        poll = data[2]
        precision = data[3]
        root_delay = struct.unpack(">I", data[4:8])[0] / 65536.0
        root_disp = struct.unpack(">I", data[8:12])[0] / 65536.0
        ref_id = data[12:16]
        tx_sec = struct.unpack(">I", data[40:44])[0]
        epoch = tx_sec - 2208988800
        return {
            "ip": ip, "stratum": stratum, "poll": poll, "precision": precision,
            "root_delay_ms": round(root_delay * 1000, 2),
            "root_dispersion_ms": round(root_disp * 1000, 2),
            "ref_id": ref_id.hex(),
            "ref_id_ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in ref_id),
            "server_time_utc": (datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()
                                if epoch > 0 else None),
            "clock_skew_s": round(time.time() - epoch, 1) if epoch > 0 else None,
        }
    except Exception:
        return None


def kerberos_realm(domain, dns_server=None, timeout=3):
    if not HAVE_SCAPY or not domain:
        return None
    try:
        q = "_kerberos._udp.{}".format(domain)
        pkt = IP(dst=dns_server or "8.8.8.8") / UDP(dport=53) / DNS(
            rd=1, qd=DNSQR(qname=q, qtype="TXT"))
        ans = sr1(pkt, timeout=timeout, verbose=False)
        if not ans or not ans.haslayer(DNS):
            return None
        rr = ans[DNS].an
        g = 0
        while rr is not None and g < 10:
            g += 1
            try:
                if int(rr.type) == 16:
                    txt = rr.rdata
                    if isinstance(txt, bytes):
                        txt = txt.decode(errors="ignore")
                    elif isinstance(txt, list):
                        txt = "".join(t.decode() if isinstance(t, bytes) else str(t)
                                       for t in txt)
                    return str(txt).strip('"')
            except Exception:
                pass
            nxt = getattr(rr, "payload", None)
            if nxt is None or isinstance(nxt, DNS):
                break
            rr = nxt
    except Exception:
        pass
    return None


def ldap_anon_bind(ip, port=389, timeout=3):
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        msg = b"\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00"
        s.sendall(msg)
        s.settimeout(timeout)
        resp = s.recv(1024)
        s.close()
        if len(resp) > 10 and b"\x61" in resp:
            idx = resp.find(b"\x61")
            if idx + 5 < len(resp):
                rc_idx = resp.find(b"\x0a\x01", idx)
                if rc_idx > 0 and rc_idx + 2 < len(resp):
                    return resp[rc_idx + 2] == 0
        return False
    except Exception:
        return False


def crt_sh_lookup(domain, timeout=20, max_results=500):
    if not HAVE_REQUESTS or not domain:
        return []
    try:
        r = requests.get(
            "https://crt.sh/?q=%25.{}&output=json&exclude=expired".format(domain),
            timeout=timeout, headers={"User-Agent": _ua()})
        if r.status_code != 200:
            return []
        data = r.json()
    except Exception:
        return []
    domains = set()
    for entry in data:
        name = entry.get("name_value", "")
        for line in str(name).split("\n"):
            line = line.strip().lower().rstrip(",").strip(".")
            if line and line != domain and "*" not in line:
                domains.add(line)
                if len(domains) >= max_results:
                    break
        if len(domains) >= max_results:
            break
    return sorted(domains)


def bgp_lookup(ip_or_prefix, timeout=15):
    if not HAVE_REQUESTS or not ip_or_prefix:
        return {}
    try:
        r = requests.get(
            "https://stat.ripe.net/data/prefix-overview/data.json",
            params={"resource": ip_or_prefix}, timeout=timeout,
            headers={"User-Agent": _ua()})
        if r.status_code != 200:
            return {}
        data = r.json().get("data", {})
        return {"prefix": data.get("resource"),
                "asns": [{"asn": a.get("asn"), "holder": a.get("holder")}
                         for a in data.get("asns", [])]}
    except Exception:
        return {}


def get_public_ip(timeout=5):
    if not HAVE_REQUESTS:
        return None
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip",
                "https://ipinfo.io/ip"):
        try:
            r = requests.get(url, timeout=timeout, headers={"User-Agent": _ua()})
            if r.status_code == 200:
                ip = r.text.strip()
                if is_ipv4(ip):
                    return ip
        except Exception:
            continue
    return None


def sip_scan(ip, port=5060, timeout=2):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        msg = ("OPTIONS sip:probe@{} SIP/2.0\r\n"
               "Via: SIP/2.0/UDP {}\r\n"
               "From: <sip:probe@{}>;tag=recon\r\n"
               "To: <sip:probe@{}>\r\n"
               "Call-ID: recon@recon\r\n"
               "CSeq: 1 OPTIONS\r\n"
               "Contact: <sip:probe@{}>\r\n"
               "Max-Forwards: 70\r\n"
               "User-Agent: recon\r\n"
               "Content-Length: 0\r\n\r\n").format(ip, ip, ip, ip, ip)
        s.sendto(msg.encode(), (ip, port))
        try:
            data, _ = s.recvfrom(2048)
            text = data.decode("latin-1", errors="ignore")
            server = None
            for line in text.splitlines():
                if line.lower().startswith("server:"):
                    server = line.split(":", 1)[1].strip()
            return {"port": port, "server": server}
        except socket.timeout:
            return None
        finally:
            s.close()
    except Exception:
        return None


def printer_enum(ip, timeout=2, open_ports=None):
    if open_ports is None:
        open_ports = set(PRINTER_PORTS)
    out = {"ipp": None, "jetdirect": None, "lpd": None}
    if 9100 in open_ports:
        try:
            s = socket.create_connection((ip, 9100), timeout=timeout)
            s.sendall(b"\x1b%-12345X@PJL INFO ID\r\n\x1b%-12345X")
            s.settimeout(timeout)
            d = s.recv(512)
            s.close()
            if d:
                out["jetdirect"] = d.decode("latin-1", errors="ignore").strip()[:300]
        except Exception:
            pass
    if 631 in open_ports:
        try:
            s = socket.create_connection((ip, 631), timeout=timeout)
            s.sendall(("HEAD / HTTP/1.0\r\nHost: {}\r\nUser-Agent: {}\r\n\r\n")
                       .format(ip, _ua()).encode())
            s.settimeout(timeout)
            d = s.recv(512)
            s.close()
            if d:
                out["ipp"] = d.decode("latin-1", errors="ignore")[:200]
        except Exception:
            pass
    if 515 in open_ports:
        try:
            s = socket.create_connection((ip, 515), timeout=timeout)
            s.sendall(b"\x03recon\n")
            s.settimeout(timeout)
            d = s.recv(512)
            s.close()
            if d:
                out["lpd"] = d.decode("latin-1", errors="ignore")[:200]
        except Exception:
            pass
    return out if any(v for v in out.values()) else None


def nmap_os_detect(ip, timeout=3):
    if not HAVE_SCAPY:
        return None
    result = {}
    prof = _random_syn_profile()
    try:
        pkt = IP(dst=ip, ttl=prof["ttl"]) / TCP(
            dport=80, flags="S", window=prof["window"], options=prof["options"])
        ans = sr1(pkt, timeout=timeout, verbose=False)
        if ans and ans.haslayer(IP):
            ttl = int(ans[IP].ttl)
            if ttl <= 64:
                init, hint = 64, "Linux/Unix"
            elif ttl <= 128:
                init, hint = 128, "Windows"
            else:
                init, hint = 255, "Network device"
            result.update({"ttl": ttl, "initial_ttl": init,
                           "hops_inferred": init - ttl,
                           "hint": "{} (ttl {} -> initial {})".format(hint, ttl, init)})
            if ans.haslayer(TCP):
                result["window"] = int(ans[TCP].window)
            elif ans.haslayer(ICMP):
                result["icmp_type"] = int(ans[ICMP].type)
                result["note"] = "port filtered"
    except Exception:
        pass
    return result if result else None


def reverse_dns(ip, timeout=0.7):
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None
    finally:
        socket.setdefaulttimeout(old)


def reverse_dns_batch(ips, workers=4, timeout=0.7):
    out = {}
    if not ips:
        return out

    def _one(ip):
        return ip, reverse_dns(ip, timeout)

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        fs = [ex.submit(_one, ip) for ip in ips]
        for fut in concurrent.futures.as_completed(fs):
            try:
                ip, name = fut.result()
                out[ip] = name
            except Exception:
                continue
    return out


def netbios_name(ip):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1.0)
        q = struct.pack(">HHHHHH", 0x1234, 0x0000, 1, 0, 0, 0)
        q += b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01"
        s.sendto(q, (ip, 137))
        d, _ = s.recvfrom(1024)
        s.close()
        if len(d) < 57:
            return None
        for i in range(d[56]):
            b = 57 + i * 18
            if b + 18 > len(d):
                break
            n = d[b:b+15].decode("ascii", errors="ignore").strip()
            if n and n != "\x00":
                return n
    except Exception:
        return None


def wifi_info():
    if not IS_WIN:
        return None
    text = run("netsh wlan show interfaces")
    if not text or "no wireless" in text.lower():
        return None
    info = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        k, _, v = line.partition(":")
        k = k.strip().lower()
        v = v.strip()
        if k == "ssid" and "ssid" not in info:
            info["ssid"] = v
        elif k == "bssid":
            info["bssid"] = v
        elif k in ("signal", "sygnal", "sygnał"):
            info["signal"] = v
        elif k in ("channel", "kanal", "kanał"):
            info["channel"] = v
        elif k in ("authentication", "uwierzytelnianie"):
            info["auth"] = v
        elif k in ("cipher", "szyfrowanie"):
            info["cipher"] = v
    return info if info else None


def http_enum(ip, port=80, timeout=2):
    r = {"port": port, "headers": {}, "paths": []}
    base = "http://{}:{}/".format(ip, port)
    for path in ["/robots.txt", "/server-status", "/admin"]:
        try:
            method = "GET" if path == "/robots.txt" else "HEAD"
            req = urllib.request.Request(base.rstrip("/") + path, method=method)
            req.add_header("User-Agent", _ua())
            req.add_header("Accept-Language", _accept_lang())
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                r["paths"].append({"path": path, "status": resp.status})
                if path == "/robots.txt" and resp.status == 200:
                    try:
                        r["robots"] = resp.read(2048).decode("utf-8", errors="ignore")
                    except Exception:
                        pass
            time.sleep(random.uniform(0.1, 0.3))
        except urllib.error.HTTPError as e:
            r["paths"].append({"path": path, "status": e.code})
        except Exception:
            pass
    try:
        req = urllib.request.Request(base, method="HEAD")
        req.add_header("User-Agent", _ua())
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            r["headers"] = dict(resp.headers)
    except Exception:
        pass
    return r if r["paths"] or r["headers"] else None


def diff_runs(old_path):
    """FIX: MAC/vendor/hostname change detection (device swap)."""
    try:
        with open(old_path, "r", encoding="utf-8") as f:
            old = json.load(f)
    except Exception as e:
        print("cannot load {}: {}".format(old_path, e), file=sys.stderr)
        return

    def host_map(data):
        return {h.get("ip"): h for h in data.get("hosts", []) if h.get("ip")}

    def cve_count(host):
        total = 0
        for p in host.get("ports", []):
            for pr in p.get("products", []):
                total += len(pr.get("cves", []))
        return total

    old_hosts = host_map(old)
    new_hosts = host_map(RESULTS)
    old_ips = set(old_hosts.keys())
    new_ips = set(new_hosts.keys())
    added = sorted(new_ips - old_ips)
    removed = sorted(old_ips - new_ips)

    print("=== DIFF vs {} ===".format(old_path))
    print("old: {}  new: {}".format(old.get("timestamp", "?"),
                                     RESULTS.get("timestamp", "?")))
    print()
    print("hosts: {} -> {}".format(len(old_ips), len(new_ips)))

    if added:
        print()
        print("[+] {} new hosts:".format(len(added)))
        for ip in sorted(added, key=lambda x: ipaddress.IPv4Address(x)):
            h = new_hosts[ip]
            print("  {:<16} {:<18} {}".format(ip, h.get("mac", "?"),
                                                h.get("vendor", "?")))
    if removed:
        print()
        print("[-] {} hosts gone:".format(len(removed)))
        for ip in sorted(removed, key=lambda x: ipaddress.IPv4Address(x)):
            print("  {}".format(ip))

    print()
    print("=== per-host changes ===")
    for ip in sorted(new_ips & old_ips, key=lambda x: ipaddress.IPv4Address(x)):
        oh = old_hosts[ip]
        nh = new_hosts[ip]
        omac = (oh.get("mac") or "").lower()
        nmac = (nh.get("mac") or "").lower()
        ohost = (oh.get("rdns") or oh.get("netbios") or "").lower()
        nhost = (nh.get("rdns") or nh.get("netbios") or "").lower()
        ovendor = oh.get("vendor") or ""
        nvendor = nh.get("vendor") or ""
        old_ports = {p["port"] for p in oh.get("ports", [])}
        new_ports = {p["port"] for p in nh.get("ports", [])}
        po = new_ports - old_ports
        pd = old_ports - new_ports
        oc = cve_count(oh)
        nc = cve_count(nh)

        has_changes = (omac != nmac or ohost != nhost or
                        ovendor != nvendor or po or pd or oc != nc)
        if not has_changes:
            continue
        print("  {}".format(ip))
        if omac != nmac and omac and nmac:
            print("    ! MAC CHANGED: {} -> {} (possible device swap)".format(omac, nmac))
        if ovendor != nvendor and ovendor and nvendor:
            print("    vendor: {} -> {}".format(ovendor, nvendor))
        if ohost != nhost and (ohost or nhost):
            print("    hostname: {} -> {}".format(ohost or "-", nhost or "-"))
        if po:
            print("    + ports: {}".format(sorted(po)))
        if pd:
            print("    - ports: {}".format(sorted(pd)))
        if oc != nc:
            print("    CVE: {} -> {}".format(oc, nc))

    _result_set("diff_old_path", old_path)
    _result_set("diff_added", added)
    _result_set("diff_removed", removed)


def export_csv(path=None):
    """FIX: explicit QUOTE_MINIMAL."""
    if not path:
        os.makedirs(LOG_DIR, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(LOG_DIR, "recon_{}.csv".format(stamp))
    try:
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
            w.writerow(["ip", "mac", "vendor", "hostname", "os_passive",
                        "ports_open", "ports_list", "cve_count",
                        "tls_weak_count", "http_sec_score", "vuln_total",
                        "snmp_name", "snmp_uptime", "lldp_vlan"])
            for h in RESULTS.get("hosts", []):
                ports = h.get("ports", [])
                cve_count = 0
                tls_weak = 0
                http_scores = []
                for p in ports:
                    for pr in p.get("products", []):
                        cve_count += len(pr.get("cves", []))
                    ex = p.get("extra", {}) or {}
                    tw = ex.get("tls_weak")
                    if tw:
                        tls_weak += len((tw or {}).get("weak", []))
                    hs = ex.get("http_sec")
                    if hs and hs.get("score") is not None:
                        http_scores.append(hs["score"])
                http_score = min(http_scores) if http_scores else ""
                vuln_total = cve_count + tls_weak + (
                    100 - http_score if isinstance(http_score, int) else 0)
                snmp = h.get("snmp") or {}
                lldp = h.get("lldp") or {}
                w.writerow([
                    h.get("ip", ""), h.get("mac", ""),
                    h.get("vendor", "") or "",
                    h.get("rdns", "") or h.get("netbios", "") or "",
                    (h.get("os_passive") or {}).get("os", ""),
                    len(ports),
                    ",".join(str(p["port"]) for p in ports),
                    cve_count, tls_weak,
                    http_score if http_score != "" else "",
                    vuln_total,
                    snmp.get("sysName", ""),
                    snmp.get("sysUpTime", ""),
                    lldp.get("vlan_pvid", "") if lldp else "",
                ])
        return path
    except Exception as e:
        print("CSV write failed: {}".format(e), file=sys.stderr)
        return None


def print_host_ports(ip, ports):
    if not ports:
        print("  {}: (no ports open)".format(ip))
        return
    print("  {}:".format(ip))
    for p in ports:
        print("    {:<6} {:<10} {}".format(
            p["port"], p["service"],
            p["banner"][:70] if p["banner"] else "-"))
        for pr in p.get("products", []):
            print("           -> {} {}".format(pr["product"], pr["version"]))
            for cve in pr.get("cves", [])[:5]:
                print("              [{}] {} {}".format(
                    cve.get("cvss", "?"), cve["id"], cve["desc"][:90]))
        ex = p.get("extra", {})
        if "smb" in ex:
            s = ex["smb"]
            print("           [smb] {} {}".format(
                s.get("version"), s.get("server_os") or ""))
        if "tls_weak" in ex and ex["tls_weak"]:
            t = ex["tls_weak"]
            protos = [k for k, v in t.get("protocols", {}).items() if v]
            print("           [tls] supports: {}".format(", ".join(protos)))
            print("           [tls] score: {}/100".format(t.get("score", 0)))
            for w in t.get("weak", []):
                print("           [tls] WEAK: {}".format(w))
        if "http_sec" in ex and ex["http_sec"]:
            hs = ex["http_sec"]
            print("           [http-sec] score: {}/100".format(hs.get("score", 0)))
            for m in hs.get("missing", []):
                print("           [http-sec] MISSING: {}".format(m))


def _print_passive(passive):
    if not passive:
        print("  (nothing captured)")
        return
    if passive.get("lldp"):
        print("\n  [LLDP switch neighbor]")
        for k, v in passive["lldp"].items():
            print("    {:<18} : {}".format(k, v))
        _result_set("lldp_cdp", {"lldp": passive["lldp"], "cdp": passive.get("cdp")})
    elif passive.get("cdp"):
        print("\n  [CDP switch neighbor]")
        for k, v in passive["cdp"].items():
            print("    {:<18} : {}".format(k, v))
        _result_set("lldp_cdp", {"lldp": None, "cdp": passive["cdp"]})
    if passive.get("arp_spoof"):
        print("\n  [!!! ARP SPOOF DETECTED ({}) !!!]".format(
            len(passive["arp_spoof"])))
        for s in passive["arp_spoof"]:
            print("    {} changed from {} to {}".format(
                s["ip"], s["old_mac"], s["new_mac"]))
        _result_set("arp_spoof", passive["arp_spoof"])
    if passive.get("dhcp_servers_all"):
        _result_set("dhcp_servers_all", passive["dhcp_servers_all"])
    if passive.get("rogue_dhcp"):
        print("\n  [!!! ROGUE DHCP — multiple servers !!!]")
        for s in passive.get("dhcp_servers_all", []):
            print("    DHCP server: {}".format(s))
        _result_set("rogue_dhcp", True)
    if passive.get("dhcp_offers"):
        print("\n  [DHCP offers]")
        for o in passive["dhcp_offers"]:
            print("    server={} your_ip={}".format(
                o.get("server_ip"), o.get("your_ip")))
        _result_set("dhcp", {"offers": passive["dhcp_offers"]})
    if passive.get("arp"):
        print("\n  [ARP neighbors ({})]".format(len(passive["arp"])))
        for ip, mac in sorted(passive["arp"].items(),
                                key=lambda x: ipaddress.IPv4Address(x[0])):
            print("    {:<16} {:<18} {}".format(ip, mac, oui_lookup(mac) or "?"))
    if passive.get("tcp_os"):
        print("\n  [Passive OS ({})]".format(len(passive["tcp_os"])))
        for ip, h in passive["tcp_os"].items():
            print("    {:<16} {} (ttl={} win={})".format(
                ip, h["os"], h["ttl"], h["window"]))
    if passive.get("tcp_uptime"):
        print("\n  [TCP uptime heuristic]")
        for ip, s in passive["tcp_uptime"].items():
            print("    {:<16} up ~ {}".format(ip, format_uptime(s)))
    if passive.get("mdns"):
        print("\n  [mDNS ({})]".format(len(passive["mdns"])))
        for m in passive["mdns"][:20]:
            print("    {}  {} -> {}".format(m["ip"], m["name"], m["data"]))
        _result_set("mdns", passive["mdns"])
    if passive.get("ssdp"):
        print("\n  [SSDP]")
        for s in passive["ssdp"][:20]:
            print("    {}  {}".format(s["ip"], s.get("server") or "-"))
        _result_set("ssdp", passive["ssdp"])
    if passive.get("tls_sni"):
        print("\n  [TLS SNI]")
        for s in passive["tls_sni"][:30]:
            print("    {}  ({})".format(s["sni"], s["dst"]))
    if passive.get("dns_queries"):
        print("\n  [DNS queries]")
        seen = set()
        for q in passive["dns_queries"][:40]:
            if q["host"] in seen:
                continue
            seen.add(q["host"])
            print("    {}".format(q["host"]))
    if passive.get("snmp_traps"):
        print("\n  [SNMP traps]")
        for t in passive["snmp_traps"][:10]:
            print("    {} {}".format(t["src"], t["hex"][:60]))
        _result_set("snmp_traps", passive["snmp_traps"])


def _extract_domain():
    """FIX: requires FQDN; whoami /upn + nltest /dsgetdc fallbacks."""
    if _CRT_DOMAIN_OVERRIDE[0]:
        return _CRT_DOMAIN_OVERRIDE[0]

    def _valid(d):
        return d and "." in d and not d.startswith(".") and d not in ("local",)

    for line in _ipconfig_text().splitlines():
        low = line.lower()
        if "connection-specific dns suffix" in low or "sufiks dns" in low:
            parts = line.split(":")
            if len(parts) > 1:
                d = parts[-1].strip().strip(",").strip(".")
                if _valid(d):
                    return d
    for line in _ipconfig_text().splitlines():
        low = line.lower()
        if "dns suffix search list" in low:
            parts = line.split(":")
            if len(parts) > 1:
                first = parts[-1].strip().split(",")[0].strip().strip(".")
                if _valid(first):
                    return first

    if IS_WIN:
        try:
            out = run("whoami /upn").strip()
            if "@" in out and not out.lower().startswith("error"):
                d = out.split("@", 1)[1].strip().lower()
                if _valid(d):
                    return d
        except Exception:
            pass
        try:
            out = run("nltest /dsgetdc: 2>nul").strip()
            m = re.search(r"DC:\s*\\\\(\S+)", out, re.I)
            if m:
                dc = m.group(1)
                if "." in dc:
                    parts = dc.split(".", 1)
                    if len(parts) == 2 and _valid(parts[1]):
                        return parts[1].lower()
        except Exception:
            pass

    return None


def _run_external_lookups(net, do_crt, do_bgp):
    """FIX: warns if BGP target is RFC1918."""
    if do_bgp:
        target = _PUBLIC_IP_OVERRIDE[0] or get_public_ip() or net.get("gateway")
        if target:
            private = False
            try:
                ip_obj = ipaddress.IPv4Address(target)
                private = ip_obj.is_private
            except Exception:
                pass
            if private:
                print("warning: BGP target {} is private (RFC1918). "
                      "RIPEstat will not resolve it.".format(target),
                      file=sys.stderr)
            print("=== BGP / AS lookup for {} ===".format(target))
            b = bgp_lookup(target)
            if b.get("asns"):
                print("  prefix : {}".format(b.get("prefix")))
                for a in b["asns"]:
                    print("  AS{}  {}".format(a["asn"], a["holder"]))
                _result_set("bgp", b)
            else:
                print("  (no result)")
            _result_set("public_ip", target)
            print()
    if do_crt:
        domain = _extract_domain()
        if domain:
            print("=== crt.sh subdomains for {} ===".format(domain))
            _result_set("domain", domain)
            subs = crt_sh_lookup(domain)
            if subs:
                for s in subs[:60]:
                    print("  {}".format(s))
                if len(subs) > 60:
                    print("  ... and {} more".format(len(subs) - 60))
                _result_set("crt_sh", subs)
            else:
                print("  (no results)")
            print()


def recon(iface_override=None, subnet_override=None,
          mode="stealth", delay_ms=None, sniff_seconds=90,
          do_nvd=True, do_crt=True, do_bgp=True, do_snmp_traps=True,
          max_hosts=512, do_tls_audit=True, do_http_audit=True):

    if delay_ms is None:
        delay_ms = MODE_DELAY_MS.get(mode, 0)
    print("=== MODE: {} (delay {}ms) ===".format(mode.upper(), delay_ms))
    if _PARANOID[0]:
        print("=== PARANOID: passive only, no external, no mDNS, long pauses ===")
    print()
    _result_set("timestamp", now_local_iso())
    _result_set("mode", mode)
    _result_set("paranoid", _PARANOID[0])

    if iface_override:
        iface = iface_override
        reason = "manual --iface"
        link_type = iface_link_type(get_iface_desc(iface))
    else:
        iface, reason, link_type = pick_card(verbose=True)
    if not iface:
        sys.exit("cannot pick a card: {}".format(reason))

    net = get_my_network(iface)
    if subnet_override:
        net["subnet"] = subnet_override
    desc = get_iface_desc(iface)
    wireless = (link_type == "WIFI")

    print("=== MY NETWORK ===")
    print("  interface : {}".format(iface))
    print("  desc      : {}".format(desc))
    print("  type      : {}".format(link_type))
    print("  reason    : {}".format(reason))
    print("  my ip     : {}".format(net["ip"] or "-"))
    print("  subnet    : {}".format(net["subnet"] or "-"))
    print("  gateway   : {}".format(net["gateway"] or "-"))
    if net.get("dns"):
        print("  dns       : {}".format(", ".join(net["dns"])))
    print()
    _result_set("network", net)
    _result_set("link_type", link_type)

    # FIX: filter 'other adapters' by net["ip"] truthy check
    others = [a for a in enumerate_active_adapters()
              if net.get("ip") and a["ip"] != net["ip"]]
    if others and not _QUIET[0]:
        print("  other active adapters (not scanned):")
        for a in others:
            print("    [{}] {:<30} ip={:<16} gw={}".format(
                a["link"], a["name"][:30], a["ip"], a["gateway"]))
        print()

    if link_type == "ETHERNET":
        li = link_info(net["ip"]) if net["ip"] else None
        if li:
            print("=== LINK (ethernet) ===")
            for k, v in li.items():
                print("  {:<10} : {}".format(k, v))
            print()
            _result_set("link", li)

    if wireless:
        w = wifi_info()
        if w:
            _result_set("wifi", {"connected": w, "networks_in_range": []})
            print("=== WIFI ===")
            for k, v in w.items():
                print("  {:<10} : {}".format(k, v))
            print()

    human_pause()
    capture_seconds = sniff_seconds if mode == "stealth" else 30
    print("=== PASSIVE CAPTURE ({}s) ===".format(capture_seconds))
    passive = passive_listen(iface, seconds=capture_seconds,
                             watch_snmp_traps=do_snmp_traps)
    _print_passive(passive)

    if mode == "stealth":
        if _PARANOID[0]:
            print("(paranoid: skipping external lookups)")
            return
        _run_external_lookups(net, do_crt, do_bgp)
        return

    if not net.get("subnet"):
        print("no subnet — pass --subnet")
        _run_external_lookups(net, do_crt, do_bgp)
        return

    human_pause()
    print()
    print("=== ARP SWEEP ({}) ===".format(net["subnet"]))
    hosts = arp_sweep(net["subnet"], iface, delay_ms=delay_ms, max_hosts=max_hosts)
    hosts.sort(key=lambda h: ipaddress.IPv4Address(h["ip"]))
    print("found {} hosts".format(len(hosts)))

    if not _QUIET[0]:
        print("resolving names...", file=sys.stderr)
    rdns_map = reverse_dns_batch([h["ip"] for h in hosts], workers=4)
    for h in hosts:
        h["rdns"] = rdns_map.get(h["ip"])
        h["netbios"] = netbios_name(h["ip"]) if not h["rdns"] else None
        h["vendor"] = oui_lookup(h["mac"])
        if passive and passive.get("tcp_os", {}).get(h["ip"]):
            h["os_passive"] = passive["tcp_os"][h["ip"]]
        if h["ip"] == net.get("gateway") and passive and passive.get("lldp"):
            h["lldp"] = passive["lldp"]

    for h in hosts:
        label = h["rdns"] or h["netbios"] or "?"
        vendor = h.get("vendor") or "?"
        os_hint = ""
        if h.get("os_passive"):
            os_hint = " [{}]".format(h["os_passive"]["os"])
        marker = ""
        if h["ip"] == net.get("gateway"):
            marker = "  <- gateway"
        elif h["ip"] == net.get("ip"):
            marker = "  <- you"
        print("  {:<16} {:<18} {:<20} {:<16}{}{}".format(
            h["ip"], h["mac"], label[:20], vendor[:16], os_hint, marker))
    print()

    if _PARANOID[0]:
        mdns_deep = []
    else:
        human_pause()
        print("=== mDNS deep enum (SRV + TXT) ===")
        mdns_deep = mdns_deep_enum(iface, timeout=8, mode=mode)
        if mdns_deep:
            for m in mdns_deep[:30]:
                print("  {}  {}".format(m.get("ip"), m.get("name")))
                if m.get("srv_target"):
                    print("    srv: {}:{}".format(m["srv_target"], m.get("srv_port")))
                if m.get("txt"):
                    print("    txt: {}".format(", ".join(m["txt"][:5])))
            _result_set("mdns_deep", mdns_deep)
        else:
            print("  (no responses)")
        print()

    if HAVE_SNMP and not _PARANOID[0]:
        targets = hosts if mode == "aggressive" else (
            [h for h in hosts if h["ip"] == net.get("gateway")])
        if targets:
            human_pause()
            print("=== SNMP probe on {} host(s) ===".format(len(targets)))
            for h in targets:
                res = snmp_probe(h["ip"])
                sleep_delay(delay_ms)
                if not res:
                    continue
                h["snmp"] = res
                print("  {}:".format(h["ip"]))
                for k, v in res.items():
                    print("    {:<12} : {}".format(k, v))
                if res.get("sysUpTime"):
                    up = snmp_uptime_human(res["sysUpTime"])
                    if up:
                        print("    {:<12} : {}".format("uptime", up["human"]))
                        if up["warning"]:
                            print("    WARNING: {}".format(up["warning"]))
                if res.get("sysDescr") and do_nvd:
                    for prod, ver in detect_product_version(res["sysDescr"]):
                        for c in nvd_lookup(prod, ver)[:5]:
                            print("    -> [{}] {} {}".format(
                                c.get("cvss", "?"), c["id"], c["desc"][:90]))
                if mode == "aggressive":
                    ifs = snmp_walk_interfaces(h["ip"])
                    if ifs:
                        h["snmp_interfaces"] = ifs
                        print("    [interfaces]")
                        for i in ifs[:20]:
                            print("      idx={} descr={} mac={}".format(
                                i.get("idx"), i.get("descr"), i.get("mac")))
                    arp_tab = snmp_walk_arp(h["ip"])
                    if arp_tab:
                        h["snmp_arp"] = arp_tab
                        print("    [arp table]")
                        for e in arp_tab[:30]:
                            print("      {}  {}".format(e["ip"], e["mac"]))
            print()

    gw = net.get("gateway")
    if gw and not _PARANOID[0]:
        human_pause()
        print("=== UPnP IGD ({}) ===".format(gw))
        igd = upnp_igd_query(gw)
        _result_set("upnp_igd", igd)
        if igd.get("external_ip"):
            print("  external IP : {}".format(igd["external_ip"]))
        if igd.get("control_url"):
            print("  control url : {}".format(igd["control_url"]))
        if not igd.get("external_ip") and not igd.get("control_url"):
            print("  (no IGD response)")
        print()

    if mode == "aggressive" and not _PARANOID[0]:
        human_pause()
        print("=== NTP enumeration ===")
        for h in hosts:
            r = ntp_query(h["ip"], timeout=1)
            sleep_delay(delay_ms)
            if r:
                print("  {}: stratum={} ref={} skew={}s".format(
                    h["ip"], r["stratum"], r["ref_id_ascii"],
                    r.get("clock_skew_s", "?")))
                h["ntp"] = r
        print()

    if net.get("dns") and not _PARANOID[0]:
        domain = _extract_domain()
        if domain and domain not in ("local", ""):
            human_pause()
            print("=== DNS SRV enum ({}) ===".format(domain))
            srv = dns_srv_enum(domain,
                                dns_server=net["dns"][0] if net["dns"] else None)
            for s in srv:
                print("  {} -> {}:{}".format(s["srv"], s["target"], s["port"]))
            _result_set("dns_srv", srv)
            print()

            print("=== DNS wildcard check ({}) ===".format(domain))
            wc = dns_wildcard_check(domain,
                                     dns_server=net["dns"][0] if net["dns"] else None)
            if wc:
                _result_set("dns_wildcard", wc)
                if wc.get("wildcard"):
                    print("  WILDCARD ACTIVE — resolves to {}".format(
                        ", ".join(wc.get("resolves_to", []))))
                else:
                    print("  no wildcard")
            print()

            if mode == "aggressive":
                print("=== Kerberos realm ===")
                realm = kerberos_realm(domain,
                                        dns_server=net["dns"][0] if net["dns"] else None)
                if realm:
                    print("  realm: {}".format(realm))
                    _result_set("kerberos_realm", realm)
                else:
                    print("  (none)")
                print()

                print("=== LDAP anonymous bind ===")
                for h in hosts:
                    if not any(p["port"] in (389, 636) for p in h.get("ports", [])):
                        continue
                    ok = ldap_anon_bind(h["ip"], 389)
                    print("  {}:389 anonymous bind -> {}".format(
                        h["ip"], "ALLOWED" if ok else "denied"))
                    h["ldap_anon"] = {"allowed": ok}
                    _result_set("ldap_anon", h["ldap_anon"])
                print()

                print("=== DNS zone transfer (AXFR) ===")
                zr = dns_zone_transfer(domain, net["dns"][0])
                if zr.get("success"):
                    print("  SUCCESS! {} messages, SOA={}".format(
                        len(zr["records"]), zr["soa_count"]))
                    _result_set("dns_axfr", zr)
                else:
                    print("  rejected (expected) — {}".format(
                        zr.get("error", "no data")))
                print()

    human_pause()
    port_map = TOP_PORTS_20 if mode == "normal" else TOP_PORTS_50
    workers = 1
    print("=== TCP PORT SCAN ({} ports, {} thread) + CVE + TLS + HTTP ===".format(
        len(port_map), workers))
    audit = mode == "aggressive"
    audit_tls = audit and do_tls_audit
    audit_http = audit and do_http_audit

    # FIX: progress per host on stderr
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        fs = {ex.submit(scan_host, h["ip"], port_map, do_nvd, delay_ms,
                        audit_tls, audit_http): h for h in hosts}
        done = 0
        total = len(hosts)
        for fut in concurrent.futures.as_completed(fs):
            h = fs[fut]
            try:
                ports = fut.result()
            except Exception:
                ports = []
            h["ports"] = ports
            done += 1
            if not _QUIET[0]:
                print("  [{}/{}] scanned {}".format(done, total, h["ip"]),
                      file=sys.stderr)
            print_host_ports(h["ip"], ports)
    print()

    if mode == "aggressive" and not _PARANOID[0]:
        human_pause()
        print("=== Active OS detection ===")
        for h in hosts:
            od = nmap_os_detect(h["ip"])
            sleep_delay(delay_ms)
            if od:
                h["os_active"] = od
                print("  {}: {}".format(h["ip"], od.get("hint", "?")))
        print()

    if mode == "aggressive":
        human_pause()
        print("=== SIP / VoIP scan ===")
        for h in hosts:
            if any(p["port"] in (5060, 5061) for p in h.get("ports", [])):
                r = sip_scan(h["ip"], 5060)
                sleep_delay(delay_ms)
                if r:
                    print("  {}:5060  {}".format(h["ip"], r.get("server") or "?"))
                    h["sip"] = r
        print()

    if mode == "aggressive":
        human_pause()
        print("=== Printer enum ===")
        for h in hosts:
            if not h.get("ports"):
                continue
            open_ports = {p["port"] for p in h["ports"]}
            if not open_ports & set(PRINTER_PORTS):
                continue
            r = printer_enum(h["ip"], open_ports=open_ports)
            sleep_delay(delay_ms)
            if r:
                print("  {}:".format(h["ip"]))
                for k, v in r.items():
                    if v:
                        print("    [{}] {}".format(k, v[:100]))
                h["printer"] = r
        print()

    if mode == "aggressive":
        human_pause()
        print("=== HTTP enum ===")
        for h in hosts:
            for p in h.get("ports", []):
                if p["service"] not in ("http", "http-alt"):
                    continue
                r = http_enum(h["ip"], p["port"])
                sleep_delay(delay_ms)
                if r:
                    print("  {}:{}".format(h["ip"], p["port"]))
                    for path in r.get("paths", []):
                        print("    {:<20} {}".format(path["path"],
                                                       path.get("status")))
                    if r.get("robots"):
                        print("    [robots.txt]")
                        for line in r["robots"].splitlines()[:6]:
                            print("      {}".format(line))
            print()

    # FIX: sort hosts before JSON dump
    with RESULTS_LOCK:
        hosts.sort(key=lambda h: ipaddress.IPv4Address(h["ip"]) if h.get("ip") else 0)
        RESULTS["hosts"] = hosts
    _run_external_lookups(net, do_crt, do_bgp)


def main():
    ap = argparse.ArgumentParser(description="Full LAN recon suite (bugfixed)")
    ap.add_argument("--iface")
    ap.add_argument("--subnet")
    ap.add_argument("--mode", choices=["stealth", "normal", "aggressive"],
                    default="stealth")
    ap.add_argument("--delay", type=int, default=None)
    ap.add_argument("--sniff", type=int, default=90)
    ap.add_argument("--max-hosts", type=int, default=512)
    ap.add_argument("--no-nvd", "--no-cve", action="store_true", dest="no_nvd",
                    help="skip NVD CVE lookup")
    ap.add_argument("--no-crt", action="store_true")
    ap.add_argument("--no-bgp", action="store_true")
    ap.add_argument("--no-tls-audit", action="store_true",
                    help="skip TLS weakness check")
    ap.add_argument("--no-http-audit", action="store_true",
                    help="skip HTTP security audit")
    ap.add_argument("--public-ip", help="override public IP for BGP")
    ap.add_argument("--crt-domain", help="override domain for crt.sh")
    ap.add_argument("--aggressive-timing", action="store_true",
                    help="skip human pauses (fast test runs)")
    ap.add_argument("--paranoid", action="store_true",
                    help="maximum stealth: passive only, no external, no mDNS, long pauses")
    ap.add_argument("--quiet", action="store_true",
                    help="fewer progress messages")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--csv", action="store_true")
    ap.add_argument("--diff", metavar="OLD.json",
                    help="compare with previous run")
    args = ap.parse_args()

    # FIX: validate --public-ip, warn on long --sniff
    if args.public_ip and not is_ipv4(args.public_ip):
        print("error: --public-ip '{}' is not a valid IPv4".format(args.public_ip),
              file=sys.stderr)
        sys.exit(2)
    if args.sniff > 1800:
        print("warning: --sniff {}s is over 30 minutes. "
              "Pass --sniff explicitly if intended.".format(args.sniff),
              file=sys.stderr)

    if args.aggressive_timing:
        _AGGRESSIVE_TIMING[0] = True
    if args.public_ip:
        _PUBLIC_IP_OVERRIDE[0] = args.public_ip
    if args.crt_domain:
        _CRT_DOMAIN_OVERRIDE[0] = args.crt_domain
    if args.quiet:
        _QUIET[0] = True
    if args.paranoid:
        _PARANOID[0] = True
        _QUIET[0] = True
        args.no_crt = True
        args.no_bgp = True
        args.mode = "stealth"

    if not HAVE_SCAPY:
        sys.exit("scapy not installed: pip install scapy")
    if not HAVE_SNMP:
        print("warning: pysnmp missing", file=sys.stderr)
    if not HAVE_REQUESTS:
        print("warning: requests missing", file=sys.stderr)

    log_path = _start_logging()
    if log_path:
        print("logging to: {}".format(log_path))

    try:
        recon(
            iface_override=args.iface, subnet_override=args.subnet,
            mode=args.mode, delay_ms=args.delay, sniff_seconds=args.sniff,
            do_nvd=not args.no_nvd, do_crt=not args.no_crt,
            do_bgp=not args.no_bgp, max_hosts=args.max_hosts,
            do_tls_audit=not args.no_tls_audit,
            do_http_audit=not args.no_http_audit,
        )
    finally:
        print()
        print("=== DONE ===")
        if log_path:
            print("full log: {}".format(log_path))

        # diff BEFORE json so results land in file
        if args.diff:
            try:
                diff_runs(args.diff)
            except Exception as e:
                print("diff failed: {}".format(e), file=sys.stderr)

        if args.json:
            os.makedirs(LOG_DIR, exist_ok=True)
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            jp = os.path.join(LOG_DIR, "recon_{}.json".format(stamp))
            try:
                with open(jp, "w", encoding="utf-8") as f:
                    json.dump(RESULTS, f, indent=2, ensure_ascii=False, default=str)
                print("json: {}".format(jp))
            except Exception as e:
                print("json failed: {}".format(e))

        if args.csv:
            cp = export_csv()
            if cp:
                print("csv: {}".format(cp))


if __name__ == "__main__":
    main()
