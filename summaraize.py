r"""
summarize.py - summarize netcollect_auto.py sniff logs (with reverse DNS)

Reads logs/sniff_*.jsonl and prints:
  - every unique hostname seen (dns + sni + http_host) with its IPs
  - every unique destination IP with reverse DNS name
  - per-type counts

Usage:
  python summarize.py                  # all log files in ./logs/
  python summarize.py --today          # only today's log
  python summarize.py --type tls_sni   # only this event type
  python summarize.py --host microsoft # only hostnames containing substring
  python summarize.py --no-rdns        # skip reverse DNS (fast)

Reverse DNS:
  - threaded (10 workers), 0.7s timeout per lookup
  - cached per run in a local dict
  - failures show as "-" instead of crashing
"""

import argparse
import concurrent.futures
import glob
import json
import os
import socket
import sys
from collections import Counter, defaultdict
from datetime import datetime


LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
RDNS_TIMEOUT = 0.7
RDNS_WORKERS = 10


def load_events(pattern):
    events = []
    for path in sorted(glob.glob(pattern)):
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        events.append(json.loads(line))
                    except Exception:
                        continue
        except Exception:
            continue
    return events


def summarize(events, host_filter=None):
    by_type = Counter()
    hosts = Counter()
    dest_ips = Counter()
    dns_map = defaultdict(set)
    sni_to_dst = defaultdict(set)

    for e in events:
        t = e.get("type", "?")
        by_type[t] += 1

        host = e.get("host")
        if host:
            if host_filter and host_filter.lower() not in host.lower():
                pass
            else:
                hosts[host] += 1

        sni = e.get("sni")
        if sni:
            if not host_filter or host_filter.lower() in sni.lower():
                hosts[sni] += 1
            dst = e.get("dst")
            if dst:
                sni_to_dst[sni].add(dst)

        dst = e.get("dst") or e.get("ip")
        if dst:
            dest_ips[dst] += 1

        if t == "dns_answer":
            h = e.get("host")
            ip = e.get("ip")
            if h and ip:
                dns_map[h].add(ip)

    return {
        "by_type": by_type,
        "hosts": hosts,
        "dest_ips": dest_ips,
        "dns_map": dns_map,
        "sni_to_dst": sni_to_dst,
    }


def reverse_dns_batch(ips):
    """
    Reverse-resolve a set of IPs concurrently. Returns dict {ip: name or None}.
    """
    results = {}
    if not ips:
        return results

    def resolve(ip):
        old = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(RDNS_TIMEOUT)
            name = socket.gethostbyaddr(ip)[0]
            return ip, name
        except Exception:
            return ip, None
        finally:
            socket.setdefaulttimeout(old)

    with concurrent.futures.ThreadPoolExecutor(max_workers=RDNS_WORKERS) as ex:
        futures = [ex.submit(resolve, ip) for ip in ips]
        for fut in concurrent.futures.as_completed(futures):
            try:
                ip, name = fut.result()
                results[ip] = name
            except Exception:
                continue
    return results


def print_report(s, events_count, rDNS=None):
    print("events total: {}".format(events_count))
    print()
    print("=== EVENT TYPES ===")
    for t, n in s["by_type"].most_common():
        print("  {:<12} {}".format(t, n))
    print()

    print("=== UNIQUE HOSTNAMES ({}) ===".format(len(s["hosts"])))
    for h, n in s["hosts"].most_common():
        ips = s["dns_map"].get(h) or s["sni_to_dst"].get(h) or set()
        ip_str = ", ".join(sorted(ips)) if ips else "-"
        print("  {:<60} hits={:<5} ip={}".format(h, n, ip_str))
    print()

    print("=== UNIQUE DESTINATION IPs ({}) ===".format(len(s["dest_ips"])))
    for ip, n in s["dest_ips"].most_common():
        rdns = ""
        if rDNS is not None:
            name = rDNS.get(ip)
            if name:
                rdns = "  ({})".format(name)
            else:
                rdns = "  (no rdns)"
        print("  {:<20} hits={:<5}{}".format(ip, n, rdns))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--today", action="store_true")
    ap.add_argument("--type", help="filter: only show lines of this type")
    ap.add_argument("--host", help="filter: only hosts containing this substring")
    ap.add_argument("--no-rdns", action="store_true", help="skip reverse DNS")
    args = ap.parse_args()

    if not os.path.isdir(LOG_DIR):
        sys.exit("no logs dir: {}".format(LOG_DIR))

    if args.today:
        day = datetime.now().strftime("%Y%m%d")
        pattern = os.path.join(LOG_DIR, "sniff_{}.jsonl".format(day))
    else:
        pattern = os.path.join(LOG_DIR, "sniff_*.jsonl")

    events = load_events(pattern)
    if args.type:
        events = [e for e in events if e.get("type") == args.type]

    if not events:
        sys.exit("no events found in {}".format(pattern))

    s = summarize(events, host_filter=args.host)

    rDNS = None
    if not args.no_rdns and s["dest_ips"]:
        print("resolving {} destination IPs via reverse DNS...".format(
            len(s["dest_ips"])), file=sys.stderr)
        rDNS = reverse_dns_batch(list(s["dest_ips"].keys()))

    print_report(s, len(events), rDNS)


if __name__ == "__main__":
    main()