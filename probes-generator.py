#!/usr/bin/env python3

import argparse

def parse_args():
    parser = argparse.ArgumentParser(description="Filter Nmap probes by service and optionally probe name.")
    parser.add_argument("services", nargs="+", help="Service names to include (e.g., http ftp ssh)")
    parser.add_argument("-f", "--probes-file", default="nmap-service-probes", help="Input file path")
    parser.add_argument("-o", "--output", default="nmap-service-probes", help="Output file path")
    parser.add_argument("-m", "--no-softmatch", action="store_true", help="Convert 'softmatch' to 'match'")
    parser.add_argument("-p", "--probes", nargs="*", help="List of probe names to include (optional)")
    return parser.parse_args()

def main():
    args = parse_args()
    services = set(args.services)
    allowed_probes = set(args.probes) if args.probes else None

    with open(args.probes_file, "r") as f:
        lines = f.readlines()

    output, section = [], []
    in_probe, match_found, current_probe = False, False, None

    for line in lines:
        stripped = line.strip()

        if line.startswith("Probe "):
            if in_probe and match_found and (not allowed_probes or current_probe in allowed_probes):
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
        if parts[0] in {"match", "softmatch"} and len(parts) > 1 and parts[1] in services:
            if args.no_softmatch and parts[0] == "softmatch":
                line = line.replace("softmatch", "match", 1)
            section.append(line)
            match_found = True
        elif parts[0] not in {"match", "softmatch"}:
            section.append(line)

    if in_probe and match_found and (not allowed_probes or current_probe in allowed_probes):
        output.extend(section)

    with open(args.output, "w") as f:
        f.writelines(output)

if __name__ == "__main__":
    main()
