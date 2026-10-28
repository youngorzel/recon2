r"""
netcollect_auto.py - network collector that PICKS ITS OWN CARD

No configuration. Figures out which card carries the real internet path.

Detection order (tries each until one works):
  1. scapy routing table  (conf.route.route -> iface)
  2. PowerShell Get-NetRoute -> Get-NetAdapter -> Npcap
  3. ipconfig /all parse -> IPv4 match -> Npcap
  4. 2-second traffic probe per iface

Modes:
  python netcollect_auto.py                 # snapshot
  python netcollect_auto.py snapshot --loop 60
  python netcollect_auto.py sniff
  python netcollect_auto.py sniff --loop
  python netcollect_auto.py list
  python netcollect_auto.py detect          # only run detection

Requires:
  pip install psutil scapy
  Npcap with WinPcap API-compatible mode
  Admin for full PIDs + sniffing

Logs -> ./logs/
"""

import argparse
import json
import os
import socket
import subprocess
import sys
import time
import traceback
from datetime import datetime, timezone

try:
    import psutil
except ImportError:
    sys.exit("missing: pip install psutil")

try:
    from scapy.all import (
        sniff as sc_sniff, get_if_list, IFACES, conf,
        IP, IPv6, TCP, UDP, DNS, DNSQR, DNSRR, Raw
    )
    HAVE_SCAPY = True
except ImportError:
    HAVE_SCAPY = False


LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
IS_WIN = os.name == "nt"
NO_WINDOW = 0x08000000 if IS_WIN else 0


# ============================================================
# helpers
# ============================================================

def run(cmd, timeout=20):
    try:
        out = subprocess.run(
            cmd, shell=True, capture_output=True, timeout=timeout,
            creationflags=NO_WINDOW
        )
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
        parts = s.split(".")
        return len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts)
    except Exception:
        return False


def now_local_iso():
    return datetime.now(timezone.utc).astimezone().isoformat()


def iter_ifaces():
    """Yield NetworkInterface objects from scapy.IFACES, safely."""
    if not HAVE_SCAPY:
        return
    try:
        values = IFACES.values() if hasattr(IFACES, "values") else IFACES
        for i in values:
            yield i
    except Exception:
        return


def npcap_names():
    if not HAVE_SCAPY:
        return set()
    try:
        return set(get_if_list())
    except Exception:
        return set()


# ============================================================
# DETECTION
# ============================================================

def detect_via_scapy_route():
    """Ask scapy which interface it would use to reach a public IP."""
    if not HAVE_SCAPY:
        return None, None
    available = npcap_names()
    targets = ["8.8.8.8", "1.1.1.1", "208.67.222.222"]
    for target in targets:
        try:
            route = conf.route.route(target)
        except Exception:
            continue
        if not route:
            continue
        iface = route[0] if len(route) >= 1 else None
        gateway = route[2] if len(route) >= 3 else None
        if not iface or iface in ("lo", "lo0", "\\Device\\NPF_Loopback"):
            continue
        if iface in available:
            return iface, "scapy route to {} via gateway {} on iface {}".format(
                target, gateway, iface)
        # try mapping friendly name to Npcap device
        mapped = _map_friendly_to_npcap(iface)
        if mapped:
            return mapped, "scapy route -> {} (mapped from friendly name {})".format(
                mapped, iface)
    return None, None


def _map_friendly_to_npcap(name):
    if not HAVE_SCAPY or not name:
        return None
    for i in iter_ifaces():
        try:
            desc = (getattr(i, "description", "") or "").lower()
            iname = (getattr(i, "name", "") or "").lower()
        except Exception:
            continue
        low = name.lower()
        if low in desc or desc in low or low in iname or iname in low:
            return getattr(i, "name", None)
    return None


def detect_via_powershell():
    """Ask Windows for the default route's adapter, then map to Npcap."""
    if not HAVE_SCAPY or not IS_WIN:
        return None, None
    ps = (
        "Get-NetRoute -DestinationPrefix '0.0.0.0/0' "
        "-ErrorAction SilentlyContinue | "
        "Where-Object { $_.NextHop -ne '0.0.0.0' } | "
        "Sort-Object RouteMetric | Select-Object -First 1 | "
        "ForEach-Object { $_.InterfaceIndex }"
    )
    idx = run('powershell -NoProfile -Command "{}"'.format(ps)).strip()
    if not idx or not idx.split()[0].isdigit():
        return None, None
    idx = idx.split()[0]

    ps2 = (
        "Get-NetAdapter -InterfaceIndex {} -ErrorAction SilentlyContinue | "
        "Select-Object -First 1 -ExpandProperty Name"
    )
    adapter_name = run(
        'powershell -NoProfile -Command "{}"'.format(ps2.format(idx))
    ).strip()
    if not adapter_name:
        return None, None

    for i in iter_ifaces():
        try:
            desc = (getattr(i, "description", "") or "")
            name = (getattr(i, "name", "") or "")
        except Exception:
            continue
        dlow = desc.lower()
        alow = adapter_name.lower()
        if alow in dlow or dlow in alow:
            return name, "powershell default route -> adapter '{}' -> Npcap '{}'".format(
                adapter_name, desc or name)

    # last try: match adapter IPv4 to Npcap iface IPs via psutil
    try:
        for pname, addr_list in psutil.net_if_addrs().items():
            if adapter_name.lower() in pname.lower() or pname.lower() in adapter_name.lower():
                for a in addr_list:
                    if a.family == socket.AF_INET:
                        mapped = _map_ip_to_npcap(a.address)
                        if mapped:
                            return mapped, "powershell adapter '{}' IPv4 {} -> Npcap".format(
                                adapter_name, a.address)
    except Exception:
        pass
    return None, None


def _map_ip_to_npcap(ip):
    if not HAVE_SCAPY:
        return None
    for i in iter_ifaces():
        try:
            ips = getattr(i, "ips", None) or {}
        except Exception:
            continue
        flat = []
        for v in ips.values():
            if isinstance(v, (list, tuple)):
                flat.extend(str(x) for x in v)
            else:
                flat.append(str(v))
        if ip in flat:
            return getattr(i, "name", None)
    return None


def _parse_ipconfig_full():
    adapters = []
    current = None
    for line in run("ipconfig /all").splitlines():
        if not line.strip():
            continue
        stripped = line.strip()

        if line[0] not in (" ", "\t") and stripped.endswith(":"):
            if current is not None:
                adapters.append(current)
            current = {
                "name": stripped[:-1].strip(),
                "ipv4": [], "gateway": [], "dns": [],
                "dhcp": None, "disconnected": False,
            }
            continue
        if current is None:
            continue

        low = stripped.lower()

        if ("media state" in low and "disconnected" in low) or \
           ("stan" in low and "no" in low and "cz" in low):
            current["disconnected"] = True
            continue

        if "ipv4" in low and ("address" in low or "adres" in low):
            val = stripped.split(":", 1)[-1].strip().split("(")[0].strip()
            if val and is_ipv4(val):
                current["ipv4"].append(val)
        elif "gateway" in low or "brama" in low:
            val = stripped.split(":", 1)[-1].strip()
            if val and is_ipv4(val):
                current["gateway"].append(val)
        elif "dhcp" in low:
            val = stripped.split(":", 1)[-1].strip()
            if val and is_ipv4(val):
                current["dhcp"] = val
        elif "dns" in low:
            val = stripped.split(":", 1)[-1].strip()
            if val and is_ipv4(val):
                current["dns"].append(val)
        else:
            if current["dns"] and stripped and stripped[0].isdigit():
                tok = stripped.split()[0]
                if is_ipv4(tok) and tok not in current["dns"]:
                    current["dns"].append(tok)

    if current is not None:
        adapters.append(current)
    return adapters


def detect_via_ipconfig():
    if not HAVE_SCAPY:
        return None, None
    adapters = _parse_ipconfig_full()
    candidates = [
        a for a in adapters
        if not a["disconnected"] and a["ipv4"] and a["gateway"]
    ]
    if not candidates:
        return None, None

    virtual_hints = ("vethernet", "virtualbox", "vmware", "hyper-v",
                     "wsl", "loopback", "tap-", "tun", "default switch")

    def score(a):
        n = a["name"].lower()
        pen = 1 if any(h in n for h in virtual_hints) else 0
        return (pen, -len(a["ipv4"]), n)

    candidates.sort(key=score)
    best = candidates[0]
    for ip in best["ipv4"]:
        mapped = _map_ip_to_npcap(ip)
        if mapped:
            return mapped, "ipconfig adapter '{}' ({}) -> Npcap".format(
                best["name"], ip)
    return None, None


def probe_traffic():
    if not HAVE_SCAPY:
        return None, None
    best, best_n = None, -1
    for iface in get_if_list():
        if "Loopback" in iface:
            continue
        try:
            pkts = sc_sniff(iface=iface, timeout=2, count=10, store=True)
            n = len(pkts)
        except Exception:
            n = -1
        if n > best_n:
            best_n, best = n, iface
        if n >= 10:
            break
    if best_n > 0:
        return best, "traffic probe: {} captured {} pkts".format(best, best_n)
    return None, None


def pick_card(verbose=True):
    if not HAVE_SCAPY:
        return None, "scapy not installed"
    steps = [
        ("scapy routing table", detect_via_scapy_route),
        ("PowerShell Get-NetRoute", detect_via_powershell),
        ("ipconfig /all", detect_via_ipconfig),
        ("traffic probe", probe_traffic),
    ]
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
    return None, "all detection methods returned nothing"


# ============================================================
# SNAPSHOT MODE
# ============================================================

def get_adapters():
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    parsed = {a["name"]: a for a in _parse_ipconfig_full()}

    out = []
    for name, addr_list in addrs.items():
        macs, ipv4s, ipv6s = [], [], []
        for a in addr_list:
            if a.family == psutil.AF_LINK:
                macs.append(a.address)
            elif a.family == socket.AF_INET:
                ipv4s.append({"addr": a.address, "netmask": a.netmask})
            elif a.family == socket.AF_INET6:
                ipv6s.append(a.address)

        src = parsed.get(name)
        if src is None:
            for k, v in parsed.items():
                if name.lower() in k.lower() or k.lower() in name.lower():
                    src = v
                    break

        out.append({
            "name": name,
            "up": stats[name].isup if name in stats else None,
            "speed_mbps": stats[name].speed if name in stats else None,
            "mac": macs,
            "ipv4": ipv4s,
            "ipv6": ipv6s,
            "gateway": src["gateway"] if src else [],
            "dhcp_server": src["dhcp"] if src else None,
            "dns_servers": src["dns"] if src else [],
        })
    return out


def get_connections():
    out = []
    try:
        conns = psutil.net_connections(kind="inet")
    except Exception:
        return out
    for c in conns:
        proc_name = None
        if c.pid:
            try:
                proc_name = psutil.Process(c.pid).name()
            except Exception:
                proc_name = None
        out.append({
            "proto": "tcp" if c.type == socket.SOCK_STREAM else "udp",
            "local": "{}:{}".format(c.laddr.ip, c.laddr.port) if c.laddr else None,
            "remote": "{}:{}".format(c.raddr.ip, c.raddr.port) if c.raddr else None,
            "status": c.status,
            "pid": c.pid,
            "process": proc_name,
        })
    return out


def get_arp():
    out = []
    for line in run("arp -a").splitlines():
        parts = line.split()
        if len(parts) >= 3 and is_ipv4(parts[0]):
            out.append({"ip": parts[0], "mac": parts[1], "type": parts[2]})
    return out


def get_dns_cache():
    out = []
    name = None
    for line in run("ipconfig /displaydns").splitlines():
        s = line.strip()
        if not s or s.startswith("-"):
            continue
        low = s.lower()
        if "record name" in low or "nazwa rekordu" in low:
            name = s.split(":", 1)[-1].strip()
            continue
        if name:
            for token in s.replace(":", " ").split():
                if is_ipv4(token) and token != "0.0.0.0":
                    out.append({"host": name, "ip": token})
                    name = None
                    break
    return out


def snapshot():
    return {
        "timestamp": now_local_iso(),
        "host": {"hostname": socket.gethostname(), "fqdn": socket.getfqdn()},
        "adapters": get_adapters(),
        "connections": get_connections(),
        "arp": get_arp(),
        "dns_cache": get_dns_cache(),
    }


def write_snapshot(data, tag=None):
    os.makedirs(LOG_DIR, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if tag:
        stamp = "{}_{}".format(stamp, tag)
    jp = os.path.join(LOG_DIR, "net_{}.json".format(stamp))
    tp = os.path.join(LOG_DIR, "net_{}.txt".format(stamp))

    with open(jp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    with open(tp, "w", encoding="utf-8") as f:
        f.write("snapshot: {}\n".format(data["timestamp"]))
        f.write("host: {}  ({})\n\n".format(
            data["host"]["fqdn"], data["host"]["hostname"]))

        f.write("=== ADAPTERS ===\n")
        for a in data["adapters"]:
            f.write("[{}]  up={}  speed={}\n".format(
                a["name"], a["up"], a["speed_mbps"]))
            f.write("  mac: {}\n".format(", ".join(a["mac"]) or "-"))
            for ip in a["ipv4"]:
                f.write("  ipv4: {} / {}\n".format(ip["addr"], ip["netmask"]))
            for ip in a["ipv6"]:
                f.write("  ipv6: {}\n".format(ip))
            f.write("  gateway: {}\n".format(", ".join(a["gateway"]) or "-"))
            f.write("  dhcp: {}\n".format(a["dhcp_server"] or "-"))
            f.write("  dns: {}\n\n".format(", ".join(a["dns_servers"]) or "-"))

        f.write("=== CONNECTIONS ===\n")
        for c in sorted(data["connections"],
                        key=lambda x: (x["proto"], x["remote"] or "")):
            f.write("{}  {} -> {}  [{}]  pid={}  {}\n".format(
                c["proto"], c["local"], c["remote"],
                c["status"], c["pid"], c["process"]))

        f.write("\n=== ARP ===\n")
        for e in data["arp"]:
            f.write("{:<16} {:<20} {}\n".format(e["ip"], e["mac"], e["type"]))

        f.write("\n=== DNS CACHE ===\n")
        for e in data["dns_cache"]:
            f.write("{} -> {}\n".format(e["host"], e["ip"]))

    return jp, tp


# ============================================================
# SNIFF MODE
# ============================================================

SNIFF_IFACE = None


def log_event(evt):
    os.makedirs(LOG_DIR, exist_ok=True)
    day = datetime.now().strftime("%Y%m%d")
    path = os.path.join(LOG_DIR, "sniff_{}.jsonl".format(day))
    evt["ts"] = now_local_iso()
    evt["iface"] = SNIFF_IFACE
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(evt, ensure_ascii=False) + "\n")
    label = evt.get("host") or evt.get("sni") or evt.get("dst") or ""
    print("[{}] {}".format(evt["type"], label), flush=True)


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


def parse_dns(pkt):
    if not pkt.haslayer(DNS):
        return
    dns = pkt[DNS]
    if dns.qr == 0 and dns.qd is not None:
        name = _qname(dns.qd)
        if name:
            log_event({
                "type": "dns_query",
                "host": name,
                "qtype": int(dns.qd.qtype) if hasattr(dns.qd, "qtype") else None,
                "src": pkt[IP].src if pkt.haslayer(IP) else None,
            })
    elif dns.qr == 1:
        qname = _qname(dns.qd) if dns.qd is not None else None
        rr = dns.an
        guard = 0
        while rr is not None and guard < 50:
            guard += 1
            try:
                rtype = int(rr.type)
            except Exception:
                rtype = -1
            if rtype in (1, 28):
                try:
                    ip = str(rr.rdata)
                except Exception:
                    ip = None
                if ip:
                    log_event({"type": "dns_answer", "host": qname, "ip": ip})
            nxt = getattr(rr, "payload", None)
            if nxt is None or isinstance(nxt, DNS):
                break
            rr = nxt


def parse_tls_sni(pkt):
    if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
        return
    try:
        payload = bytes(pkt[Raw])
    except Exception:
        return
    if len(payload) < 9 or payload[0] != 0x16 or payload[1] != 0x03:
        return
    try:
        idx = 5
        if payload[idx] != 0x01:
            return
        idx += 4
        idx += 2
        idx += 32
        if idx >= len(payload):
            return
        sid_len = payload[idx]
        idx += 1 + sid_len
        if idx + 2 > len(payload):
            return
        cs_len = int.from_bytes(payload[idx:idx+2], "big")
        idx += 2 + cs_len
        if idx >= len(payload):
            return
        cm_len = payload[idx]
        idx += 1 + cm_len
        if idx + 2 > len(payload):
            return
        ext_total = int.from_bytes(payload[idx:idx+2], "big")
        idx += 2
        end = min(idx + ext_total, len(payload))
        while idx + 4 <= end:
            etype = int.from_bytes(payload[idx:idx+2], "big")
            elen = int.from_bytes(payload[idx+2:idx+4], "big")
            idx += 4
            if idx + elen > len(payload):
                return
            if etype == 0x0000 and elen >= 5:
                sni_block = payload[idx:idx+elen]
                name_len = int.from_bytes(sni_block[3:5], "big")
                name = sni_block[5:5+name_len].decode(errors="ignore")
                if name:
                    log_event({
                        "type": "tls_sni",
                        "sni": name,
                        "dst": pkt[IP].dst if pkt.haslayer(IP) else None,
                        "dport": int(pkt[TCP].dport),
                    })
                return
            idx += elen
    except Exception:
        return


def parse_http_host(pkt):
    if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
        return
    try:
        sport = int(pkt[TCP].sport)
        dport = int(pkt[TCP].dport)
    except Exception:
        return
    if 80 not in (sport, dport):
        return
    try:
        text = bytes(pkt[Raw]).decode("latin-1", errors="ignore")
    except Exception:
        return
    if not text.startswith(("GET ", "POST ", "HEAD ", "PUT ", "DELETE ",
                            "OPTIONS ", "PATCH ")):
        return
    for line in text.split("\r\n"):
        if line.lower().startswith("host:"):
            log_event({
                "type": "http_host",
                "host": line.split(":", 1)[1].strip(),
                "dst": pkt[IP].dst if pkt.haslayer(IP) else None,
            })
            return


def parse_syn(pkt):
    try:
        if pkt.haslayer(TCP):
            flags = int(pkt[TCP].flags)
            if (flags & 0x02) and not (flags & 0x10):
                log_event({
                    "type": "tcp_syn",
                    "dst": pkt[IP].dst if pkt.haslayer(IP) else None,
                    "dport": int(pkt[TCP].dport),
                })
    except Exception:
        return


def handle(pkt):
    try:
        if pkt.haslayer(UDP) and pkt.haslayer(DNS):
            parse_dns(pkt)
        if pkt.haslayer(TCP):
            parse_tls_sni(pkt)
            parse_http_host(pkt)
            parse_syn(pkt)
    except Exception:
        pass


def do_sniff(args):
    global SNIFF_IFACE
    if not HAVE_SCAPY:
        sys.exit("sniff mode needs scapy: pip install scapy")

    if args.iface:
        iface = args.iface
        reason = "manual --iface override"
    else:
        iface, reason = pick_card(verbose=True)
        if not iface:
            sys.exit(
                "could not pick a card. reason: {}\n"
                "run 'python netcollect_auto.py list' and use --iface manually.".format(reason)
            )

    SNIFF_IFACE = iface
    flt = args.filter or "ip or ip6"

    print()
    print("picked card : {}".format(iface))
    print("reason      : {}".format(reason))
    print("filter      : '{}'".format(flt))
    print("logs        : {}".format(LOG_DIR))
    print("ctrl-c to stop\n")

    try:
        while True:
            try:
                sc_sniff(iface=iface, filter=flt, prn=handle,
                         store=False, timeout=60)
            except KeyboardInterrupt:
                raise
            if not args.loop:
                return
    except KeyboardInterrupt:
        print("\nstopped.")
    except OSError as e:
        sys.exit("sniff failed: {}\nNpcap installed? running as admin?".format(e))
    except Exception as e:
        traceback.print_exc()
        sys.exit("unexpected: {}".format(e))


# ============================================================
# MAIN
# ============================================================

def list_interfaces():
    if not HAVE_SCAPY:
        sys.exit("scapy not installed: pip install scapy")
    print("Npcap interfaces:")
    for i in get_if_list():
        desc = ""
        try:
            if i in IFACES:
                desc = IFACES[i].description or ""
        except Exception:
            pass
        print("  {}   {}".format(i, desc))

    iface, reason = pick_card(verbose=True)
    print()
    if iface:
        print("selected card : {}".format(iface))
        print("reason        : {}".format(reason))
    else:
        print("selected card : none")
        print("reason        : {}".format(reason))


def main():
    ap = argparse.ArgumentParser(
        description="network collector that auto-selects the internet card"
    )
    ap.add_argument("mode", nargs="?", default="snapshot",
                    choices=["snapshot", "sniff", "list", "detect"])
    ap.add_argument("--loop", nargs="?", const=0, type=int, default=None)
    ap.add_argument("--filter", default=None)
    ap.add_argument("--iface", help="override auto-selection for this run")
    args = ap.parse_args()

    if args.mode == "list":
        list_interfaces()
        return

    if args.mode == "detect":
        iface, reason = pick_card(verbose=True)
        print()
        print("result: {}".format(iface or "none"))
        print("reason: {}".format(reason))
        return

    if args.mode == "sniff":
        do_sniff(args)
        return

    if args.loop is not None:
        interval = args.loop if args.loop > 0 else 60
        print("snapshot every {}s. ctrl-c to stop.".format(interval))
        try:
            while True:
                snap = snapshot()
                j, t = write_snapshot(snap, tag="loop")
                print("{}  ->  {}".format(
                    snap["timestamp"], os.path.basename(t)))
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\nstopped.")
        return

    snap = snapshot()
    j, t = write_snapshot(snap)
    print("wrote {}".format(j))
    print("wrote {}".format(t))


if __name__ == "__main__":
    main()