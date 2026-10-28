r"""
recon.py - LAN reconnaissance with stealth / normal / aggressive modes

Modes:
  --mode stealth    (default) PURE PASSIVE. Only listens. No ARP sweep,
                    no port scan, no SNMP, no traceroute. Captures LLDP/CDP,
                    DHCP, mDNS, SSDP, ARP traffic already in the air.
                    Zero outgoing probes. Invisible in network.
  --mode normal     moderate. ARP sweep with delays, top 20 ports,
                    SNMP probe only on gateway, no SNMP walk, no traceroute,
                    no HTTP enum. Slow, less signature.
  --mode aggressive full scan (previous behavior): ARP sweep, top ~50 ports,
                    SNMP walk, HTTP enum, traceroute, NVD live.

Extra:
  --delay N         milliseconds between active probes (default per mode:
                    stealth=0, normal=800, aggressive=0)
  --sniff SECONDS   stealth capture duration (default 90)

Output:
  TXT log: logs/recon_YYYYMMDD_HHMMSS.txt
  JSON:    logs/recon_YYYYMMDD_HHMMSS.json (--json)

Requires:
  pip install psutil scapy pysnmp requests
  Npcap (WinPcap API-compatible mode)
  Admin
"""

import argparse
import concurrent.futures
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
        ARP, Ether, IP, IPv6, ICMP, UDP, TCP, DNS, DNSQR, DHCP, BOOTP,
        conf, get_if_list, IFACES, Raw, srp, srp1, sr, sniff as sc_sniff
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

# default delay per mode (ms between active probes)
MODE_DELAY_MS = {"stealth": 0, "normal": 800, "aggressive": 0}
MODE_PORTS = {"stealth": 0, "normal": 20, "aggressive": 52}


# ============================================================
# Tee
# ============================================================

class _Tee(object):
    def __init__(self, original, logfile):
        self.original = original
        self.logfile = logfile
    def write(self, data):
        try: self.original.write(data)
        except Exception: pass
        try:
            self.logfile.write(data)
            self.logfile.flush()
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


# ============================================================
# RESULTS
# ============================================================

RESULTS = {
    "timestamp": None, "mode": None,
    "network": {}, "link": {}, "lldp_cdp": {}, "dhcp": {},
    "wifi": {"connected": {}, "networks_in_range": []},
    "hosts": [],
    "ssdp": [], "mdns": [], "upnp_igd": {}, "dns_srv": [],
}
RESULTS_LOCK = threading.Lock()


def _result_set(key, value):
    with RESULTS_LOCK:
        RESULTS[key] = value


# ============================================================
# helpers
# ============================================================

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


def sleep_delay(ms):
    """Sleep ms + small random jitter so probes don't fire at exact intervals."""
    if ms <= 0:
        # tiny random delay still, to avoid burst signatures
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


# ============================================================
# OUI (compact)
# ============================================================

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
    "00:1C:57": "Cisco", "00:1C:58": "Cisco", "00:1C:B0": "Cisco",
    "00:1C:B1": "Cisco", "00:1C:F6": "Cisco", "00:1C:F9": "Cisco",
    "00:50:0F": "Cisco", "00:50:14": "Cisco", "00:50:2A": "Cisco",
    "00:50:40": "Cisco", "00:50:53": "Cisco", "00:50:54": "Cisco",
    "00:50:73": "Cisco", "00:50:80": "Cisco", "00:50:A2": "Cisco",
    "00:50:A7": "Cisco", "00:50:BD": "Cisco", "00:50:D1": "Cisco",
    "00:50:E2": "Cisco", "00:50:F0": "Cisco", "00:60:09": "Cisco",
    "00:60:2F": "Cisco", "00:60:3E": "Cisco", "00:60:47": "Cisco",
    "00:60:5C": "Cisco", "00:60:70": "Cisco", "00:60:83": "Cisco",
    "00:90:21": "Cisco", "00:90:2B": "Cisco", "00:90:5F": "Cisco",
    "00:90:6D": "Cisco", "00:90:6F": "Cisco", "00:90:7F": "Cisco",
    "00:90:86": "Cisco", "00:90:92": "Cisco", "00:90:A6": "Cisco",
    "00:90:AB": "Cisco", "00:90:B1": "Cisco", "00:90:BF": "Cisco",
    "00:90:D9": "Cisco", "00:90:F2": "Cisco",
    "00:A0:C9": "Intel", "00:AA:00": "Intel", "00:AA:01": "Intel",
    "00:AA:02": "Intel", "00:03:47": "Intel", "00:04:23": "Intel",
    "00:0E:0C": "Intel", "00:0E:35": "Intel", "00:11:11": "Intel",
    "00:12:F0": "Intel", "00:13:02": "Intel", "00:13:20": "Intel",
    "00:13:CE": "Intel", "00:13:E8": "Intel", "00:15:00": "Intel",
    "00:15:17": "Intel", "00:16:6F": "Intel", "00:16:76": "Intel",
    "00:16:EA": "Intel", "00:16:EB": "Intel", "00:18:DE": "Intel",
    "00:19:D1": "Intel", "00:19:D2": "Intel", "00:1B:21": "Intel",
    "00:1B:77": "Intel", "00:1C:B3": "Intel", "00:1D:09": "Intel",
    "00:1D:E0": "Intel", "00:1D:E1": "Intel", "00:1E:64": "Intel",
    "00:1E:65": "Intel", "00:1E:67": "Intel", "00:1F:3B": "Intel",
    "00:1F:3C": "Intel", "00:21:5C": "Intel", "00:21:5D": "Intel",
    "00:21:6A": "Intel", "00:21:6B": "Intel", "00:22:FA": "Intel",
    "00:22:FB": "Intel", "00:23:14": "Intel", "00:23:15": "Intel",
    "00:23:6C": "Intel", "00:23:6D": "Intel", "00:24:D6": "Intel",
    "00:24:D7": "Intel", "00:26:C6": "Intel", "00:26:C7": "Intel",
    "00:27:10": "Intel", "00:27:0E": "Intel",
}


def oui_lookup(mac):
    if not mac:
        return None
    norm = mac.upper().replace("-", ":")
    prefix = ":".join(norm.split(":")[:3])
    return OUI_DB.get(prefix)


# ============================================================
# CVE cache + NVD
# ============================================================

def load_cve_cache():
    try:
        if os.path.exists(CVE_CACHE_FILE):
            with open(CVE_CACHE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return {}


def save_cve_cache(cache):
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        with open(CVE_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2, ensure_ascii=False)
    except Exception:
        pass


_CVE_CACHE = load_cve_cache()
_NVD_LAST = [0.0]
_NVD_MIN_INTERVAL = 6.5


def _nvd_rate_limit():
    elapsed = time.time() - _NVD_LAST[0]
    if elapsed < _NVD_MIN_INTERVAL:
        time.sleep(_NVD_MIN_INTERVAL - elapsed)
    _NVD_LAST[0] = time.time()


def nvd_lookup(product, version):
    if not HAVE_REQUESTS or not product or not version:
        return []
    key = "{}|{}".format(product.lower(), version.lower())
    if key in _CVE_CACHE:
        return _CVE_CACHE[key]
    _nvd_rate_limit()
    keyword = "{} {}".format(product, version)
    url = ("https://services.nvd.nist.gov/rest/json/cves/2.0"
           "?keywordSearch={}&resultsPerPage=100".format(
               urllib.request.quote(keyword)))
    results = []
    try:
        r = requests.get(url, timeout=30)
        if r.status_code != 200:
            _CVE_CACHE[key] = []
            save_cve_cache(_CVE_CACHE)
            return []
        data = r.json()
        for v in data.get("vulnerabilities", []):
            cve = v.get("cve", {})
            cid = cve.get("id", "")
            desc = next((d["value"] for d in cve.get("descriptions", [])
                         if d.get("lang") == "en"), "")
            metrics = cve.get("metrics", {})
            score = None; sev = None
            for mk in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if mk in metrics and metrics[mk]:
                    m = metrics[mk][0]
                    cd = m.get("cvssData", {})
                    score = cd.get("baseScore")
                    sev = cd.get("baseSeverity") or m.get("baseSeverity")
                    break
            ver_mentioned = version.lower() in desc.lower()
            cpe_match = False
            for conf in cve.get("configurations", []):
                for node in conf.get("nodes", []):
                    for cm in node.get("cpeMatch", []):
                        if version.lower() in cm.get("criteria", "").lower():
                            cpe_match = True; break
                    if cpe_match: break
                if cpe_match: break
            if not (ver_mentioned or cpe_match):
                continue
            results.append({"id": cid,
                            "cvss": "{} {}".format(score, sev or "").strip(),
                            "score": score, "desc": desc[:200]})
    except Exception:
        pass
    results.sort(key=lambda x: x.get("score") or 0, reverse=True)
    _CVE_CACHE[key] = results
    save_cve_cache(_CVE_CACHE)
    return results


CISCO_IOS_RE = re.compile(
    r"Cisco IOS(?: XE| XR)? Software.*?Version\s+([\d.()A-Za-z]+)", re.IGNORECASE)
CISCO_NXOS_RE = re.compile(
    r"Cisco NX-OS.*?version\s+([\d.()A-Za-z]+)", re.IGNORECASE)
CISCO_MODEL_RE = re.compile(r"(C\d{4}[A-Z]?|ISR\s?\d+|ASR\s?\d+)", re.IGNORECASE)
LINUX_KERNEL_RE = re.compile(r"Linux\s+\S+\s+([\d.]+)")


def parse_sysdescr(sysdescr):
    if not sysdescr:
        return []
    out = []
    m = CISCO_IOS_RE.search(sysdescr)
    if m:
        mm = CISCO_MODEL_RE.search(sysdescr)
        model = mm.group(1) if mm else "IOS"
        out.append(("cisco ios {}".format(model.lower()), m.group(1)))
    m = CISCO_NXOS_RE.search(sysdescr)
    if m:
        mm = CISCO_MODEL_RE.search(sysdescr)
        model = mm.group(1) if mm else "NX-OS"
        out.append(("cisco nx-os {}".format(model.lower()), m.group(1)))
    m = LINUX_KERNEL_RE.search(sysdescr)
    if m:
        out.append(("linux kernel", m.group(1)))
    m = re.search(r"Windows Server (\d{4}(?:\sR2)?)", sysdescr, re.IGNORECASE)
    if m:
        out.append(("windows server", m.group(1)))
    return out


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
        m = re.search(fp["pattern"], text, re.IGNORECASE)
        if m and m.groups():
            out.append((fp["product"], m.group(1)))
    out.extend(parse_sysdescr(text))
    return out


# ============================================================
# card detection
# ============================================================

def detect_via_scapy_route():
    if not HAVE_SCAPY:
        return None, None
    avail = set(get_if_list())
    for target in ["8.8.8.8", "1.1.1.1", "208.67.222.222"]:
        try:
            route = conf.route.route(target)
        except Exception:
            continue
        if not route:
            continue
        iface = route[0] if len(route) >= 1 else None
        gw = route[2] if len(route) >= 3 else None
        if not iface or iface in ("lo", "lo0", "\\Device\\NPF_Loopback"):
            continue
        if iface in avail:
            return iface, "scapy route to {} via gw {} on {}".format(target, gw, iface)
        obj = find_iface_by_any_name(iface)
        if obj:
            return (iface_obj_field(obj, "network_name") or iface,
                    "scapy route to {} (iface {})".format(target, iface))
    return None, None


def detect_via_powershell():
    if not HAVE_SCAPY or not IS_WIN:
        return None, None
    ps = ("Get-NetRoute -DestinationPrefix '0.0.0.0/0' "
          "-ErrorAction SilentlyContinue | Where-Object { $_.NextHop -ne '0.0.0.0' } | "
          "Sort-Object RouteMetric | Select-Object -First 1 | "
          "ForEach-Object { $_.InterfaceIndex }")
    idx = run('powershell -NoProfile -Command "{}"'.format(ps)).strip()
    if not idx or not idx.split()[0].isdigit():
        return None, None
    idx = idx.split()[0]
    ps2 = ("Get-NetAdapter -InterfaceIndex {} -ErrorAction SilentlyContinue | "
           "Select-Object -First 1 -ExpandProperty Name")
    an = run('powershell -NoProfile -Command "{}"'.format(ps2.format(idx))).strip()
    if not an:
        return None, None
    for i in iter_ifaces():
        desc = iface_obj_field(i, "description") or ""
        name = iface_obj_field(i, "name") or ""
        net = iface_obj_field(i, "network_name") or ""
        if an.lower() in desc.lower() or desc.lower() in an.lower() \
           or an.lower() in name.lower():
            return net or name, "powershell adapter '{}'".format(an)
    return None, None


def _parse_ipconfig_full():
    adapters = []
    current = None
    for line in run("ipconfig /all").splitlines():
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
           ("stan" in low and "no" in low and "cz" in low):
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


def _map_ip_to_npcap(ip):
    if not HAVE_SCAPY:
        return None
    for i in iter_ifaces():
        if ip in iface_ipv4_list(i):
            return iface_obj_field(i, "network_name") or iface_obj_field(i, "name")
    return None


def detect_via_ipconfig():
    if not HAVE_SCAPY:
        return None, None
    cands = [a for a in _parse_ipconfig_full()
             if not a["disconnected"] and a["ipv4"] and a["gateway"]]
    if not cands:
        return None, None
    virtual = ("vethernet", "virtualbox", "vmware", "hyper-v",
               "wsl", "loopback", "tap-", "tun", "default switch")
    cands.sort(key=lambda a: (1 if any(h in a["name"].lower() for h in virtual) else 0,
                               -len(a["ipv4"]), a["name"].lower()))
    for ip in cands[0]["ipv4"]:
        m = _map_ip_to_npcap(ip)
        if m:
            return m, "ipconfig adapter '{}' ({})".format(cands[0]["name"], ip)
    return None, None


def probe_traffic():
    if not HAVE_SCAPY:
        return None, None
    best, bestn = None, -1
    for iface in get_if_list():
        if "Loopback" in iface:
            continue
        try:
            n = len(sc_sniff(iface=iface, timeout=2, count=10, store=True))
        except Exception:
            n = -1
        if n > bestn:
            bestn, best = n, iface
        if n >= 10:
            break
    if bestn > 0:
        return best, "traffic probe: {} ({} pkts)".format(best, bestn)
    return None, None


def pick_card(verbose=True):
    if not HAVE_SCAPY:
        return None, "scapy not installed"
    steps = [("scapy route", detect_via_scapy_route),
             ("powershell", detect_via_powershell),
             ("ipconfig", detect_via_ipconfig),
             ("traffic probe", probe_traffic)]
    if verbose:
        print("detecting network card...")
    for label, fn in steps:
        if verbose:
            print("  trying: {}".format(label))
        try:
            iface, reason = fn()
        except Exception as e:
            if verbose:
                print("    error: {}".format(e))
            continue
        if iface:
            if verbose:
                print("    -> {}".format(iface))
            return iface, reason
        if verbose:
            print("    no result")
    return None, "no detection method worked"


# ============================================================
# network info
# ============================================================

def get_my_network(iface):
    info = {"iface": iface, "ip": None, "netmask": None,
            "subnet": None, "gateway": None, "dns": []}
    if not HAVE_SCAPY:
        return info
    obj = find_iface_by_any_name(iface)
    if obj is not None:
        ips = iface_ipv4_list(obj)
        if ips:
            info["ip"] = ips[0]
    if info["ip"]:
        try:
            for pname, addrs in psutil.net_if_addrs().items():
                for a in addrs:
                    if a.family == socket.AF_INET and a.address == info["ip"]:
                        info["netmask"] = a.netmask
                        try:
                            info["subnet"] = str(ipaddress.IPv4Network(
                                "{}/{}".format(info["ip"], a.netmask), strict=False))
                        except Exception:
                            pass
                        break
                if info["netmask"]:
                    break
        except Exception:
            pass
    try:
        route = conf.route.route("8.8.8.8")
        if route and len(route) >= 3:
            info["gateway"] = route[2]
    except Exception:
        pass
    if not info["gateway"]:
        for a in _parse_ipconfig_full():
            if a["gateway"]:
                info["gateway"] = a["gateway"][0]
                break
    try:
        for a in _parse_ipconfig_full():
            if info["ip"] and info["ip"] in a["ipv4"]:
                info["dns"] = a["dns"]
                break
    except Exception:
        pass
    return info


def get_iface_desc(iface):
    obj = find_iface_by_any_name(iface)
    if obj is not None:
        return iface_obj_field(obj, "description") or iface_obj_field(obj, "name") or "-"
    return "-"


def is_wireless_iface(desc):
    if not desc:
        return False
    low = desc.lower()
    return any(h in low for h in ("wi-fi", "wifi", "wireless", "802.11", "wlan"))


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


# ============================================================
# Passive listeners (used in all modes, but dominant in stealth)
# ============================================================

def passive_listen(iface, seconds=90):
    """
    Pure passive. Capture traffic for N seconds, parse:
      ARP (who is asking, who answers) -> infer neighbors
      DHCP (offers, ACKs) -> infer DHCP server, our subnet
      LLDP/CDP -> switch info
      mDNS / SSDP notifications -> services advertised
      DNS -> recently visited domains
      HTTP Host -> visited sites
      TLS SNI -> HTTPS hosts
    Returns dict.
    """
    if not HAVE_SCAPY:
        return None

    found = {
        "arp": {},
        "dhcp_offers": [],
        "lldp": None, "cdp": None,
        "mdns": [],
        "ssdp": [],
        "dns_queries": [],
        "dns_answers": [],
        "tls_sni": [],
        "http_host": [],
        "netbios": [],
        "llmnr": [],
    }
    seen_mdns = set()
    seen_ssdp = set()
    seen_sni = set()
    seen_http = set()
    seen_dns = set()
    seen_llmnr = set()

    def parse_lldp_raw(raw):
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
                    alen = val[0]
                    if alen >= 2 and val[1] == 1:
                        info["management_ip"] = ".".join(str(b) for b in val[2:2+4])
            if info:
                found["lldp"] = info
        except Exception:
            pass

    def parse_cdp_raw(data):
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
            if info:
                found["cdp"] = info
        except Exception:
            pass

    def on_pkt(pkt):
        try:
            if pkt.haslayer(Ether):
                et = pkt[Ether].type
                if et == 0x88CC and pkt.haslayer(Raw):
                    parse_lldp_raw(bytes(pkt[Raw]))
                elif et == 0x0000 and pkt.haslayer(Raw):
                    raw = bytes(pkt[Raw])
                    if len(raw) >= 8 and raw[0:3] == b"\xaa\xaa\x03" \
                            and raw[3:8] == b"\x00\x00\x0c\x20\x00":
                        parse_cdp_raw(raw[8:])
        except Exception:
            pass

        try:
            if pkt.haslayer(ARP):
                arp = pkt[ARP]
                found["arp"][arp.psrc] = arp.hwsrc
        except Exception:
            pass

        try:
            if pkt.haslayer(DHCP):
                msg_type = None
                for opt in pkt[DHCP].options:
                    if isinstance(opt, tuple) and opt[0] == "message-type":
                        msg_type = opt[1]
                        break
                if msg_type == 2 and pkt.haslayer(IP):  # DHCP OFFER
                    entry = {"server_ip": pkt[IP].src,
                             "your_ip": pkt[BOOTP].yiaddr if pkt.haslayer(BOOTP) else None}
                    for opt in pkt[DHCP].options:
                        if isinstance(opt, tuple) and len(opt) >= 2:
                            entry[opt[0]] = opt[1]
                    if entry["server_ip"] not in [e["server_ip"] for e in found["dhcp_offers"]]:
                        found["dhcp_offers"].append(entry)
        except Exception:
            pass

        try:
            if pkt.haslayer(UDP) and pkt.haslayer(DNS):
                dns = pkt[DNS]
                src = pkt[IP].src if pkt.haslayer(IP) else None
                if dns.qr == 0 and dns.qd is not None:
                    name = _qname(dns.qd)
                    if name and name not in seen_dns:
                        seen_dns.add(name)
                        found["dns_queries"].append({"host": name, "src": src})
                elif dns.qr == 1:
                    qname = _qname(dns.qd) if dns.qd is not None else None
                    rr = dns.an
                    g = 0
                    while rr is not None and g < 10:
                        g += 1
                        try:
                            if int(rr.type) in (1, 28):
                                ip = str(rr.rdata)
                                found["dns_answers"].append(
                                    {"host": qname, "ip": ip, "src": src})
                        except Exception:
                            pass
                        nxt = getattr(rr, "payload", None)
                        if nxt is None or isinstance(nxt, DNS):
                            break
                        rr = nxt
            # mDNS
            if pkt.haslayer(UDP) and pkt.haslayer(DNS):
                try:
                    sp = int(pkt[UDP].sport); dp = int(pkt[UDP].dport)
                except Exception:
                    sp = dp = 0
                if 5353 in (sp, dp) and pkt[DNS].qr == 1:
                    src = pkt[IP].src if pkt.haslayer(IP) else None
                    rr = pkt[DNS].an
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
                            if key not in seen_mdns:
                                seen_mdns.add(key)
                                found["mdns"].append({"ip": src, "name": str(name),
                                                      "data": str(rdata)})
                        except Exception:
                            pass
                        nxt = getattr(rr, "payload", None)
                        if nxt is None or isinstance(nxt, DNS):
                            break
                        rr = nxt
                # LLMNR (5355)
                if 5355 in (sp, dp) and pkt[DNS].qr == 0 and pkt[DNS].qd:
                    name = _qname(pkt[DNS].qd)
                    if name and name not in seen_llmnr:
                        seen_llmnr.add(name)
                        found["llmnr"].append({"host": name,
                                               "src": pkt[IP].src if pkt.haslayer(IP) else None})
        except Exception:
            pass

        try:
            if pkt.haslayer(UDP) and pkt.haslayer(Raw):
                try:
                    sp = int(pkt[UDP].sport); dp = int(pkt[UDP].dport)
                except Exception:
                    sp = dp = 0
                if 1900 in (sp, dp):
                    text = bytes(pkt[Raw]).decode("utf-8", errors="ignore")
                    if text.startswith(("NOTIFY", "HTTP/1.1")):
                        src = pkt[IP].src if pkt.haslayer(IP) else None
                        server = None
                        nt = None
                        for line in text.splitlines():
                            low = line.lower()
                            if low.startswith("server:"):
                                server = line.split(":", 1)[1].strip()
                            elif low.startswith(("nt:", "st:")):
                                nt = line.split(":", 1)[1].strip()
                        key = (src, server, nt)
                        if key not in seen_ssdp:
                            seen_ssdp.add(key)
                            found["ssdp"].append({"ip": src, "server": server, "nt": nt})
                # netbios NS
                if 137 in (sp, dp):
                    src = pkt[IP].src if pkt.haslayer(IP) else None
                    if src and src not in [e["src"] for e in found["netbios"]]:
                        found["netbios"].append({"src": src})
        except Exception:
            pass

        try:
            if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                payload = bytes(pkt[Raw])
                if len(payload) >= 6 and payload[0] == 0x16 and payload[1] == 0x03:
                    sni = _parse_sni(payload)
                    if sni and sni not in seen_sni:
                        seen_sni.add(sni)
                        dst = pkt[IP].dst if pkt.haslayer(IP) else None
                        found["tls_sni"].append({"sni": sni, "dst": dst})
                else:
                    try:
                        text = payload.decode("latin-1", errors="ignore")
                    except Exception:
                        text = ""
                    if text.startswith(("GET ", "POST ", "HEAD ")):
                        for line in text.split("\r\n"):
                            if line.lower().startswith("host:"):
                                host = line.split(":", 1)[1].strip()
                                if host not in seen_http:
                                    seen_http.add(host)
                                    dst = pkt[IP].dst if pkt.haslayer(IP) else None
                                    found["http_host"].append({"host": host, "dst": dst})
                                break
        except Exception:
            pass

    print("passive listening {}s (no probes sent)...".format(seconds), file=sys.stderr)
    try:
        sc_sniff(iface=iface, timeout=seconds, prn=on_pkt, store=False)
    except Exception as e:
        print("  sniff error: {}".format(e), file=sys.stderr)

    return found


def _qname(q):
    if q is None:
        return None
    try:
        name = q.qname
        if isinstance(name, bytes):
            name = name.decode(errors="ignore")
        return str(name).rstrip(".")
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
        sid_len = payload[idx]; idx += 1 + sid_len
        if idx + 2 > len(payload):
            return None
        cs_len = int.from_bytes(payload[idx:idx+2], "big"); idx += 2 + cs_len
        if idx >= len(payload):
            return None
        cm_len = payload[idx]; idx += 1 + cm_len
        if idx + 2 > len(payload):
            return None
        ext_total = int.from_bytes(payload[idx:idx+2], "big"); idx += 2
        end = min(idx + ext_total, len(payload))
        while idx + 4 <= end:
            et = int.from_bytes(payload[idx:idx+2], "big")
            el = int.from_bytes(payload[idx+2:idx+4], "big")
            idx += 4
            if idx + el > len(payload):
                return None
            if et == 0x0000 and el >= 5:
                block = payload[idx:idx+el]
                name_len = int.from_bytes(block[3:5], "big")
                return block[5:5+name_len].decode(errors="ignore")
            idx += el
    except Exception:
        return None
    return None


# ============================================================
# Active probes (used only in normal / aggressive)
# ============================================================

def arp_sweep(subnet, iface, delay_ms=0):
    if not HAVE_SCAPY:
        return []
    try:
        net = ipaddress.IPv4Network(subnet, strict=False)
    except Exception:
        return []
    hosts = [str(h) for h in net.hosts()]
    if len(hosts) > 512:
        hosts = hosts[:512]
    out = []
    for i in range(0, len(hosts), 32):
        chunk = hosts[i:i+32]
        try:
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=chunk)
            answered, _ = srp(pkt, iface=iface, timeout=2, verbose=False)
            for _, rcv in answered:
                out.append({"ip": rcv[ARP].psrc, "mac": rcv[ARP].hwsrc})
        except Exception:
            continue
        sleep_delay(delay_ms)
    return out


def grab_banner(ip, port, timeout=2.0):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        if s.connect_ex((ip, port)) != 0:
            s.close(); return None
        banner = b""
        if port in (80, 8000, 8080, 8081, 8888, 9090):
            try:
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            except Exception:
                pass
        try:
            s.settimeout(timeout)
            data = s.recv(1024)
            if data:
                banner = data
        except Exception:
            pass
        s.close()
        if banner:
            return banner.decode("latin-1", errors="ignore").strip()
    except Exception:
        pass
    return None


TOP_PORTS_50 = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 135: "msrpc", 139: "netbios",
    143: "imap", 443: "https", 445: "smb", 515: "lpd", 631: "ipp",
    993: "imaps", 995: "pop3s", 1433: "mssql", 3306: "mysql",
    3389: "rdp", 5432: "postgres", 5900: "vnc", 8000: "http-alt",
    8080: "http-alt", 8081: "http-alt", 8443: "https-alt",
    8888: "http-alt", 9090: "http-alt", 9100: "printer", 10000: "webmin",
    1080: "socks", 1611: "?",
    2375: "docker", 2376: "docker-tls", 3128: "squid",
    4444: "?", 5000: "upnp", 5060: "sip", 5061: "sip-tls",
    5222: "xmpp", 5357: "wsd", 5672: "amqp",
    6379: "redis", 6443: "k8s", 7001: "weblogic",
    8009: "ajp", 8082: "http-alt", 8161: "activemq",
    8880: "http-alt", 9000: "php-fpm", 9091: "http-alt",
    9200: "elasticsearch", 9300: "elasticsearch",
    10001: "?",
}

TOP_PORTS_20 = {k: TOP_PORTS_50[k] for k in [
    21, 22, 23, 53, 80, 110, 139, 143, 443, 445,
    993, 995, 1433, 3306, 3389, 5432, 8080, 8443, 9090, 9100]}


def scan_host(ip, port_map, do_nvd=True, delay_ms=0):
    ports_out = []
    for port in port_map:
        banner = grab_banner(ip, port)
        sleep_delay(delay_ms)
        if banner is None:
            continue
        entry = {"port": port, "service": port_map.get(port, "?"),
                 "banner": banner[:300], "products": [], "extra": {}}
        for prod, ver in detect_product_version(banner):
            cves = nvd_lookup(prod, ver) if do_nvd else []
            entry["products"].append({"product": prod, "version": ver, "cves": cves})
        if port in (443, 8443):
            t = tls_fingerprint(ip, port)
            if t:
                entry["extra"]["tls"] = t
        elif port == 445:
            s = smb_negotiate(ip, port)
            if s:
                entry["extra"]["smb"] = s
                if s.get("server_os") and do_nvd:
                    for prod, ver in detect_product_version(s["server_os"]):
                        entry["products"].append({
                            "product": prod, "version": ver,
                            "cves": nvd_lookup(prod, ver)})
        ports_out.append(entry)
    return ports_out


def tls_fingerprint(ip, port, timeout=3):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = socket.create_connection((ip, port), timeout=timeout)
        ss = ctx.wrap_socket(sock, server_hostname=ip)
        result = {"tls_version": ss.version(),
                  "cipher": ss.cipher()[0] if ss.cipher() else None}
        try:
            cert = ss.getpeercert()
            if cert:
                result["subject"] = dict(x[0] for x in cert.get("subject", []))
                result["issuer"] = dict(x[0] for x in cert.get("issuer", []))
                result["notAfter"] = cert.get("notAfter")
        except Exception:
            pass
        ss.close()
        return result
    except Exception:
        return None


def smb_negotiate(ip, port=445, timeout=3):
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        smb = (b"\x00\x00\x00\x85" + b"\xffSMB" + b"\x72" +
               b"\x00\x00\x00\x00" + b"\x18" + b"\x53\xc8" +
               b"\x00\x00" + b"\x00"*8 + b"\x00\x00" + b"\x00\x00" +
               b"\x00\x00" + b"\x00\x00" + b"\x00\x00" + b"\x00" +
               b"\x62\x00" + b"\x02NT LM 0.12\x00" + b"\x02SMB 2.002\x00" +
               b"\x02SMB 2.???\x00")
        sock.sendall(smb)
        sock.settimeout(timeout)
        data = sock.recv(1024)
        sock.close()
        if not data or len(data) < 8:
            return None
        r = {}
        magic = data[4:8]
        if magic == b"\xffSMB":
            r["version"] = "SMB1"
            try:
                wc = data[32]
                bc_off = 33 + wc*2
                bc = int.from_bytes(data[bc_off:bc_off+2], "little")
                body = data[bc_off+2:bc_off+2+bc]
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


SNMP_OIDS = {
    "sysDescr": "1.3.6.1.2.1.1.1.0",
    "sysObjectID": "1.3.6.1.2.1.1.2.0",
    "sysUpTime": "1.3.6.1.2.1.1.3.0",
    "sysContact": "1.3.6.1.2.1.1.4.0",
    "sysName": "1.3.6.1.2.1.1.5.0",
    "sysLocation": "1.3.6.1.2.1.1.6.0",
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
                ContextData(),
                ObjectType(ObjectIdentity(oid))))
            if ei or es:
                continue
            for _, v in vb:
                out[label] = str(v)
        except Exception:
            continue
    return out if out else None


def snmp_walk(ip, base_oid, community="public", max_rows=100, timeout=2):
    if not HAVE_SNMP:
        return []
    out = []
    try:
        for ei, es, _, vb in nextCmd(
                SnmpEngine(),
                CommunityData(community, mpModel=1),
                UdpTransportTarget((ip, 161), timeout=timeout, retries=0),
                ContextData(),
                ObjectType(ObjectIdentity(base_oid)),
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
    if not HAVE_SNMP:
        return []
    indexes = snmp_walk(ip, "1.3.6.1.2.1.2.2.1.1", community, max_rows=64)
    out = []
    for _, v in indexes:
        try:
            port_idx = int(v)
        except Exception:
            continue
        info = {"idx": port_idx}
        d = snmp_walk(ip, "1.3.6.1.2.1.2.2.1.2.{}".format(port_idx), community, max_rows=1)
        if d:
            info["descr"] = d[0][1]
        m = snmp_walk(ip, "1.3.6.1.2.1.2.2.1.6.{}".format(port_idx), community, max_rows=1)
        if m:
            info["mac"] = m[0][1]
        op = snmp_walk(ip, "1.3.6.1.2.1.2.2.1.8.{}".format(port_idx), community, max_rows=1)
        if op:
            info["oper_status"] = op[0][1]
        out.append(info)
    return out


def snmp_walk_arp(ip, community="public"):
    if not HAVE_SNMP:
        return []
    out = []
    walk = snmp_walk(ip, "1.3.6.1.2.1.4.22.1.2", community, max_rows=256)
    for oid, val in walk:
        try:
            ip_parts = oid.split(".")[-4:]
            if len(ip_parts) == 4:
                out.append({"ip": ".".join(ip_parts), "mac": val})
        except Exception:
            pass
    return out


def http_enum(ip, port=80, timeout=2):
    result = {"port": port, "headers": {}, "paths": []}
    base = "http://{}:{}/".format(ip, port)
    for path in ["/robots.txt", "/server-status", "/admin"]:
        try:
            req = urllib.request.Request(base.rstrip("/") + path, method="HEAD")
            req.add_header("User-Agent", "Mozilla/5.0")
            with urllib.request.urlopen(req, timeout=timeout) as r:
                result["paths"].append({"path": path, "status": r.status})
                if path == "/robots.txt" and r.status == 200:
                    try:
                        with urllib.request.urlopen(
                                urllib.request.Request(
                                    base.rstrip("/") + path,
                                    headers={"User-Agent": "Mozilla/5.0"}),
                                timeout=timeout) as rr:
                            result["robots"] = rr.read(2048).decode("utf-8", errors="ignore")
                    except Exception:
                        pass
        except urllib.error.HTTPError as e:
            result["paths"].append({"path": path, "status": e.code})
        except Exception:
            pass
    try:
        req = urllib.request.Request(base, method="HEAD")
        req.add_header("User-Agent", "Mozilla/5.0")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            result["headers"] = dict(r.headers)
    except Exception:
        pass
    return result if result["paths"] or result["headers"] else None


def upnp_igd_query(router_ip, timeout=3):
    result = {"control_url": None, "external_ip": None}
    try:
        with urllib.request.urlopen(
                "http://{}:1900/gatedesc.xml".format(router_ip), timeout=timeout) as r:
            xml = r.read()
        root = ET.fromstring(xml)
        ctrl = None
        for svc in root.iter("{urn:schemas-upnp-org:device-1-0}service"):
            st = svc.find("{urn:schemas-upnp-org:device-1-0}serviceType")
            if st is not None and "WANIPConnection" in (st.text or ""):
                c = svc.find("{urn:schemas-upnp-org:device-1-0}controlURL")
                if c is not None and c.text:
                    ctrl = c.text.strip(); break
        if not ctrl:
            return result
        result["control_url"] = ctrl
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
        with urllib.request.urlopen(req, timeout=timeout) as r:
            resp = r.read().decode("utf-8", errors="ignore")
        m = re.search(r"<NewExternalIPAddress>([^<]+)</NewExternalIPAddress>", resp)
        if m:
            result["external_ip"] = m.group(1)
    except Exception:
        pass
    return result


def dns_srv_enum(domain, dns_server=None, timeout=2):
    if not HAVE_SCAPY or not domain:
        return []
    results = []
    for srv in ["_ldap._tcp", "_kerberos._tcp", "_gc._tcp", "_sip._udp"]:
        qname = "{}.{}".format(srv, domain)
        try:
            pkt = IP(dst=dns_server or "8.8.8.8") / UDP(dport=53) / DNS(
                rd=1, qd=DNSQR(qname=qname, qtype="SRV"))
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
                        target = rr.rdata.target
                        if isinstance(target, bytes):
                            target = target.decode(errors="ignore")
                        results.append({"srv": srv, "domain": domain,
                                        "target": str(target).rstrip("."),
                                        "port": rr.rdata.port,
                                        "priority": rr.rdata.priority})
                except Exception:
                    pass
                nxt = getattr(rr, "payload", None)
                if nxt is None or isinstance(nxt, DNS):
                    break
                rr = nxt
        except Exception:
            continue
    return results


def reverse_dns(ip, timeout=0.7):
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None
    finally:
        socket.setdefaulttimeout(old)


def netbios_name(ip):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)
        q = struct.pack(">HHHHHH", 0x1234, 0x0000, 1, 0, 0, 0)
        q += b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01"
        sock.sendto(q, (ip, 137))
        data, _ = sock.recvfrom(1024)
        sock.close()
        if len(data) < 57:
            return None
        for i in range(data[56]):
            base = 57 + i * 18
            if base + 18 > len(data):
                break
            name = data[base:base+15].decode("ascii", errors="ignore").strip()
            if name and name != "\x00":
                return name
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
        if ":" not in line: continue
        k, _, v = line.partition(":")
        k = k.strip().lower(); v = v.strip()
        if k == "ssid" and "ssid" not in info: info["ssid"] = v
        elif k == "bssid": info["bssid"] = v
        elif k in ("signal", "sygnal", "sygnał"): info["signal"] = v
        elif k in ("channel", "kanal", "kanał"): info["channel"] = v
        elif k in ("authentication", "uwierzytelnianie"): info["auth"] = v
        elif k in ("cipher", "szyfrowanie"): info["cipher"] = v
    return info if info else None


# ============================================================
# report
# ============================================================

def print_host_ports(ip, ports):
    if not ports:
        print("  {}: (no ports open)".format(ip))
        return
    print("  {}:".format(ip))
    for p in ports:
        print("    {:<6} {:<10} {}".format(p["port"], p["service"],
                                           p["banner"][:70] if p["banner"] else "-"))
        for pr in p.get("products", []):
            print("           -> {} {}".format(pr["product"], pr["version"]))
            for cve in pr.get("cves", [])[:8]:
                print("              [{}] {} {}".format(
                    cve.get("cvss", "?"), cve["id"], cve["desc"][:90]))
        ex = p.get("extra", {})
        if "tls" in ex:
            t = ex["tls"]
            print("           [tls] {} {}".format(t.get("tls_version"), t.get("cipher")))
        if "smb" in ex:
            s = ex["smb"]
            print("           [smb] {}".format(s.get("version")))
            if s.get("server_os"):
                print("           [smb] server_os={}".format(s["server_os"]))


def recon(iface_override=None, subnet_override=None,
          mode="stealth", delay_ms=None, sniff_seconds=90, do_nvd=True):

    if delay_ms is None:
        delay_ms = MODE_DELAY_MS.get(mode, 0)

    print("=== MODE: {} (delay {}ms between probes) ===".format(
        mode.upper(), delay_ms))
    print()
    _result_set("timestamp", now_local_iso())
    _result_set("mode", mode)

    if iface_override:
        iface = iface_override
        reason = "manual --iface"
    else:
        iface, reason = pick_card(verbose=True)
    if not iface:
        sys.exit("cannot pick a card: {}".format(reason))

    net = get_my_network(iface)
    if subnet_override:
        net["subnet"] = subnet_override
    desc = get_iface_desc(iface)
    wireless = is_wireless_iface(desc)

    print()
    print("=== MY NETWORK ===")
    print("  interface : {}".format(iface))
    print("  desc      : {}".format(desc))
    print("  type      : {}".format("WIRELESS" if wireless else "ETHERNET"))
    print("  reason    : {}".format(reason))
    print("  my ip     : {}".format(net["ip"] or "-"))
    print("  subnet    : {}".format(net["subnet"] or "-"))
    print("  gateway   : {}".format(net["gateway"] or "-"))
    if net.get("dns"):
        print("  dns       : {}".format(", ".join(net["dns"])))
    print()
    _result_set("network", net)

    if not wireless:
        li = link_info(net["ip"]) if net["ip"] else None
        if li:
            print("=== LINK ===")
            for k, v in li.items():
                print("  {:<10} : {}".format(k, v))
            print()
            _result_set("link", li)

    if wireless:
        w = wifi_info()
        if w:
            _result_set("wifi", {"connected": w, "networks_in_range": []})
            print("=== WIFI (connected) ===")
            for k, v in w.items():
                print("  {:<10} : {}".format(k, v))
            print()

    # ===== Stealth: passive only =====
    if mode == "stealth":
        print("=== PASSIVE CAPTURE ({}s, no probes) ===".format(sniff_seconds))
        passive = passive_listen(iface, seconds=sniff_seconds)
        if not passive:
            print("  (nothing captured)")
            return

        if passive.get("lldp") or passive.get("cdp"):
            print()
            print("  [switch neighbor]")
            if passive.get("lldp"):
                print("    LLDP:")
                for k, v in passive["lldp"].items():
                    print("      {:<18} : {}".format(k, v))
            if passive.get("cdp"):
                print("    CDP:")
                for k, v in passive["cdp"].items():
                    print("      {:<18} : {}".format(k, v))
            _result_set("lldp_cdp", {"lldp": passive["lldp"], "cdp": passive["cdp"]})

        if passive.get("dhcp_offers"):
            print()
            print("  [DHCP offers seen]")
            for o in passive["dhcp_offers"]:
                print("    server {}  your_ip {}".format(
                    o.get("server_ip"), o.get("your_ip")))
                for k, v in o.items():
                    if k not in ("server_ip", "your_ip"):
                        print("      {:<16} : {}".format(k, v))
            _result_set("dhcp", {"passive_offers": passive["dhcp_offers"]})

        if passive.get("arp"):
            print()
            print("  [ARP neighbors inferred ({})]".format(len(passive["arp"])))
            for ip, mac in sorted(passive["arp"].items(),
                                   key=lambda x: ipaddress.IPv4Address(x[0])):
                vendor = oui_lookup(mac) or "?"
                print("    {:<16} {:<18} {}".format(ip, mac, vendor))

        if passive.get("mdns"):
            print()
            print("  [mDNS ({})]".format(len(passive["mdns"])))
            for m in passive["mdns"][:20]:
                print("    {}  {} -> {}".format(m["ip"], m["name"], m["data"]))
            _result_set("mdns", passive["mdns"])

        if passive.get("ssdp"):
            print()
            print("  [SSDP ({})]".format(len(passive["ssdp"])))
            for s in passive["ssdp"][:20]:
                print("    {}  {}".format(s["ip"], s.get("server") or "-"))
            _result_set("ssdp", passive["ssdp"])

        if passive.get("dns_queries"):
            print()
            print("  [DNS queries ({})]".format(len(passive["dns_queries"])))
            seen = set()
            for q in passive["dns_queries"][:40]:
                if q["host"] in seen:
                    continue
                seen.add(q["host"])
                print("    {}".format(q["host"]))

        if passive.get("tls_sni"):
            print()
            print("  [TLS SNI ({})]".format(len(passive["tls_sni"])))
            for s in passive["tls_sni"][:40]:
                print("    {}  ({})".format(s["sni"], s["dst"]))

        if passive.get("http_host"):
            print()
            print("  [HTTP Host ({})]".format(len(passive["http_host"])))
            for s in passive["http_host"][:40]:
                print("    {}  ({})".format(s["host"], s["dst"]))

        if passive.get("llmnr"):
            print()
            print("  [LLMNR queries ({})]".format(len(passive["llmnr"])))
            for s in passive["llmnr"][:20]:
                print("    {}  ({})".format(s["host"], s["src"]))

        if passive.get("netbios"):
            print()
            print("  [NetBIOS traffic from ({})]".format(len(passive["netbios"])))
            for s in passive["netbios"][:20]:
                print("    {}".format(s["src"]))

        return

    # ===== normal or aggressive: active probes =====
    if not net.get("subnet"):
        print("no subnet — pass --subnet")
        return

    print("=== ARP SWEEP ({}) ===".format(net["subnet"]))
    print("sweeping... (delay {}ms between batches)".format(delay_ms),
          file=sys.stderr)
    hosts = arp_sweep(net["subnet"], iface, delay_ms=delay_ms)
    hosts.sort(key=lambda h: ipaddress.IPv4Address(h["ip"]))
    print("found {} hosts:".format(len(hosts)))
    for h in hosts:
        h["rdns"] = reverse_dns(h["ip"])
        h["netbios"] = netbios_name(h["ip"]) if not h["rdns"] else None
        h["vendor"] = oui_lookup(h["mac"])
    for h in hosts:
        label = h["rdns"] or h["netbios"] or "?"
        vendor = h.get("vendor") or "?"
        marker = ""
        if h["ip"] == net.get("gateway"):
            marker = "  <- gateway"
        elif h["ip"] == net.get("ip"):
            marker = "  <- you"
        print("  {:<16} {:<18} {:<20} {}{}".format(
            h["ip"], h["mac"], label[:20], vendor[:24], marker))
    print()

    # SNMP: only gateway in normal, everyone in aggressive
    if HAVE_SNMP:
        targets = []
        if mode == "aggressive":
            targets = hosts
        else:  # normal
            if net.get("gateway"):
                targets = [h for h in hosts if h["ip"] == net["gateway"]]
        if targets:
            print("=== SNMP probe (public) on {} host(s) ===".format(len(targets)))
            print("probing...", file=sys.stderr)
            for h in targets:
                res = snmp_probe(h["ip"])
                sleep_delay(delay_ms)
                if not res:
                    continue
                h["snmp"] = res
                print("  {}:".format(h["ip"]))
                for k, v in res.items():
                    print("    {:<12} : {}".format(k, v))
                if res.get("sysDescr") and do_nvd:
                    for prod, ver in detect_product_version(res["sysDescr"]):
                        print("    -> {} {}".format(prod, ver))
                        for c in nvd_lookup(prod, ver)[:8]:
                            print("       [{}] {} {}".format(
                                c.get("cvss", "?"), c["id"], c["desc"][:90]))
                # SNMP walk: aggressive only
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

    # UPnP IGD on gateway
    gw = net.get("gateway")
    if gw:
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

    # Port scan
    port_map = TOP_PORTS_20 if mode == "normal" else TOP_PORTS_50
    print("=== TCP PORT SCAN ({} ports{}) + CVE ===".format(
        len(port_map), ", delay {}ms".format(delay_ms) if delay_ms else ""))
    print("scanning...", file=sys.stderr)
    workers = 1 if mode == "normal" else 4
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        fs = {ex.submit(scan_host, h["ip"], port_map, do_nvd, delay_ms): h
              for h in hosts}
        for fut in concurrent.futures.as_completed(fs):
            h = fs[fut]
            try:
                ports = fut.result()
            except Exception:
                ports = []
            h["ports"] = ports
            print_host_ports(h["ip"], ports)
    print()

    # HTTP enum: aggressive only
    if mode == "aggressive":
        print("=== HTTP enum ===")
        for h in hosts:
            for p in h.get("ports", []):
                if p["service"] not in ("http", "http-alt"):
                    continue
                res = http_enum(h["ip"], p["port"])
                sleep_delay(delay_ms)
                if res:
                    print("  {}:{}".format(h["ip"], p["port"]))
                    for path in res.get("paths", []):
                        print("    {:<20} {}".format(path["path"], path.get("status")))
                    if res.get("robots"):
                        print("    [robots.txt]")
                        for line in res["robots"].splitlines()[:8]:
                            print("      {}".format(line))
            print()

    # DNS SRV: normal+aggressive
    if net.get("dns"):
        domain = None
        try:
            r = run("ipconfig /all")
            m = re.search(r"(?:DNS Suffix|Suffix)\s*[.:]+\s*(\S+)", r)
            if m:
                domain = m.group(1).strip(".")
        except Exception:
            pass
        if domain and domain not in ("local", ""):
            print("=== DNS SRV enum (domain: {}) ===".format(domain))
            srv = dns_srv_enum(domain, dns_server=net["dns"][0] if net["dns"] else None)
            if srv:
                for s in srv:
                    print("  {} -> {}:{}".format(s["srv"], s["target"], s["port"]))
                _result_set("dns_srv", srv)
            else:
                print("  (no SRV records)")
            print()

    with RESULTS_LOCK:
        RESULTS["hosts"] = hosts


def main():
    ap = argparse.ArgumentParser(description="LAN recon with stealth/normal/aggressive")
    ap.add_argument("--iface")
    ap.add_argument("--subnet")
    ap.add_argument("--mode", choices=["stealth", "normal", "aggressive"],
                    default="stealth",
                    help="stealth (passive only) = default")
    ap.add_argument("--delay", type=int, default=None,
                    help="ms between active probes (default: mode-based)")
    ap.add_argument("--sniff", type=int, default=90,
                    help="stealth capture seconds (default 90)")
    ap.add_argument("--no-nvd", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    if not HAVE_SCAPY:
        sys.exit("scapy not installed: pip install scapy")
    if not HAVE_SNMP:
        print("warning: pysnmp missing, SNMP skipped", file=sys.stderr)
    if not HAVE_REQUESTS:
        print("warning: requests missing, NVD skipped", file=sys.stderr)

    log_path = _start_logging()
    if log_path:
        print("logging to: {}".format(log_path))

    try:
        recon(
            iface_override=args.iface,
            subnet_override=args.subnet,
            mode=args.mode,
            delay_ms=args.delay,
            sniff_seconds=args.sniff,
            do_nvd=not args.no_nvd,
        )
    finally:
        print()
        print("=== DONE ===")
        if log_path:
            print("full log saved to: {}".format(log_path))
        if args.json:
            os.makedirs(LOG_DIR, exist_ok=True)
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            jp = os.path.join(LOG_DIR, "recon_{}.json".format(stamp))
            try:
                with open(jp, "w", encoding="utf-8") as f:
                    json.dump(RESULTS, f, indent=2, ensure_ascii=False, default=str)
                print("json saved to: {}".format(jp))
            except Exception as e:
                print("json save failed: {}".format(e))


if __name__ == "__main__":
    main()