#!/usr/bin/env python3

import argparse
import re

def parse_args():
    parser = argparse.ArgumentParser(description="Filter Nmap probes by service and optionally probe name.")
    parser.add_argument("-s", "--services", nargs="+", help="Services to include (default: all)")
    parser.add_argument("-p", "--probes", nargs="+", help="Probes to include (default: all)")
    parser.add_argument("-e", "--exclude-probes", nargs="+", help="Probes to exclude (optional)")
    parser.add_argument("-n", "--no-ssl", action="store_true", help="Don't attempt SSL/TLS connections")
    parser.add_argument("-m", "--no-softmatch", action="store_true", help="Convert 'softmatch' to 'match'")
    parser.add_argument("-k", "--keep-matches", action="store_true", help="Keep all match lines in kept probes (services only select probes)")
    parser.add_argument("-w", "--max-wait", type=int, default=0, help="Cap totalwaitms (ms) on all probes except NULL (default: no change)")
    parser.add_argument("-f", "--probes-file", default="nmap-service-probes", help="Input file path")
    parser.add_argument("-o", "--output", default="nmap-service-probes", help="Output file path")
    return parser.parse_args()


def main():
    args = parse_args()
    services = set(args.services) if args.services else {"*"}
    ssl_probes = {"SSLSessionReq", "TLSSessionReq"}

    allowed_probes = set(args.probes) if args.probes else None
    exclude_probes = set(args.exclude_probes) if args.exclude_probes else None

    def wanted_service(service):
        return (service in services or "*" in services or service == "tcpwrapped" or (
            not args.no_ssl and (service == "ssl" or service.startswith("ssl/") and service[4:] in services)))

    def should_include_probe(probe, match_found):
        if not match_found or (exclude_probes and probe in exclude_probes):
            return False
        if allowed_probes:
            return probe in allowed_probes or (not args.no_ssl and probe in ssl_probes)
        return not args.no_ssl or (probe not in ssl_probes and probe != "SSLv23SessionReq")

    with open(args.probes_file, "r", encoding="utf-8") as f:
        lines = f.readlines()

    # ---- pass 1: split into header lines + probe sections -------------------
    header, sections = [], []   # section = dict(name, lines, match_found, fallbacks)
    cur = None
    for line in lines:
        stripped = line.strip()

        if line.startswith("Probe "):
            parts = line.split()
            cur = {"name": parts[2] if len(parts) > 2 else None, "lines": [line],
                   "match_found": False, "fallbacks": []}
            sections.append(cur)
            continue

        if cur is None:
            if stripped and not stripped.startswith("#"):
                header.append(line)
            continue

        if not stripped or stripped.startswith("#"):
            continue

        parts = stripped.split()
        directive, service = parts[0], parts[1] if len(parts) > 1 else ""

        if directive in {"match", "softmatch"}:
            hit = wanted_service(service)
            if hit:
                cur["match_found"] = True
            if hit or args.keep_matches:
                if args.no_softmatch and directive == "softmatch":
                    line = line.replace("softmatch", "match", 1)
                cur["lines"].append(line)
        elif directive == "fallback":
            cur["fallbacks"] = [t for t in re.split(r"[,\s]+", stripped[len("fallback"):]) if t]
            cur["lines"].append(line)
        elif directive == "totalwaitms" and args.max_wait and cur["name"] != "NULL":
            cur["lines"].append("totalwaitms %d\n" % min(int(parts[1]), args.max_wait))
        elif not (args.no_ssl and directive == "sslports"):
            cur["lines"].append(line)

    # ---- pass 2: choose probes, then pull in fallback targets ---------------
    keep = {id(s) for s in sections if should_include_probe(s["name"], s["match_found"])}
    by_name = {}
    for s in sections:
        by_name.setdefault(s["name"], []).append(s)
    changed = True
    while changed:
        changed = False
        for s in sections:
            if id(s) not in keep:
                continue
            for fb in s["fallbacks"]:
                for t in by_name.get(fb, []):
                    if id(t) not in keep:
                        keep.add(id(t))
                        changed = True
                        print("[i] added fallback probe %s (needed by %s)" % (fb, s["name"]))

    output = list(header)
    for s in sections:
        if id(s) in keep:
            # Probes without an explicit totalwaitms default to 5000 ms in nmap.
            if args.max_wait and s["name"] != "NULL" and not any(l.startswith("totalwaitms") for l in s["lines"]):
                s["lines"].insert(1, "totalwaitms %d\n" % min(5000, args.max_wait))
            output.extend(s["lines"])

    with open(args.output, "w") as f:
        f.writelines(output)

    kept = [s["name"] for s in sections if id(s) in keep]
    print("[+] wrote %s: %d probes: %s" % (args.output, len(kept), " ".join(kept)))


if __name__ == "__main__":
    main()
