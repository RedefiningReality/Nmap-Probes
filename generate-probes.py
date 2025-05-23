#!/usr/bin/env python3

import argparse

def parse_args():
    parser = argparse.ArgumentParser(description="Filter Nmap probes by service and optionally probe name.")
    parser.add_argument("-s", "--services", nargs="+", help="Services to include (default: all)")
    parser.add_argument("-p", "--probes", nargs="+", help="Probes to include (default: all)")
    parser.add_argument("-e", "--exclude-probes", nargs="+", help="Probes to exclude (optional)")
    parser.add_argument("-n", "--no-ssl", action="store_true", help="Don't attempt SSL/TLS connections")
    parser.add_argument("-m", "--no-softmatch", action="store_true", help="Convert 'softmatch' to 'match'")
    parser.add_argument("-f", "--probes-file", default="nmap-service-probes", help="Input file path")
    parser.add_argument("-o", "--output", default="nmap-service-probes", help="Output file path")
    return parser.parse_args()

def main():
    args = parse_args()
    services = set(args.services) if args.services else {"*"}
    ssl_probes = {"SSLSessionReq", "TLSSessionReq"}

    allowed_probes = set(args.probes) if args.probes else None
    exclude_probes = set(args.exclude_probes) if args.exclude_probes else None

    def should_include_probe(probe, match_found):      
        if not match_found or (exclude_probes and probe in exclude_probes):
            return False
        if allowed_probes:
            return probe in allowed_probes or (not args.no_ssl and probe in ssl_probes)
        return not args.no_ssl or (probe not in ssl_probes and probe != "SSLv23SessionReq")

    with open(args.probes_file, "r", encoding="utf-8") as f:
        lines = f.readlines()

    output, section = [], []
    in_probe, match_found, current_probe = False, False, None

    for line in lines:
        stripped = line.strip()

        if line.startswith("Probe "):
            if in_probe and should_include_probe(current_probe, match_found):
                output.extend(section)
            section = [line]
            in_probe, match_found = True, False
            current_probe = line.split()[2] if len(line.split()) > 2 else None
            continue

        if not in_probe:
            if stripped and not stripped.startswith("#"):
                output.append(line)
            continue

        if not stripped or stripped.startswith("#"):
            continue

        parts = stripped.split()
        directive, service = parts[0], parts[1] if len(parts) > 1 else ""

        if directive in {"match", "softmatch"}:
            if service in services or "*" in services or service == "tcpwrapped" or (
                not args.no_ssl and (service == "ssl" or service.startswith("ssl/") and service[4:] in services)
            ):
                if args.no_softmatch and directive == "softmatch":
                    line = line.replace("softmatch", "match", 1)
                section.append(line)
                match_found = True
        elif not (args.no_ssl and directive == "sslports"):
            section.append(line)

    if in_probe and should_include_probe(current_probe, match_found):
        output.extend(section)

    with open(args.output, "w") as f:
        f.writelines(output)

if __name__ == "__main__":
    main()
