import argparse

def extract_probe_names(service, probes_path):
    probe_names = []
    
    try:
        with open(probes_path, 'r') as f:
            lines = f.readlines()
        
        probe_name = ''
        for line in lines:
            if line.startswith('Probe'):
                probe_name = line[10:-1].split(' ')[0]
            if (probe_name not in probe_names) and (line.startswith(f'match {service} ') or line.startswith(f'softmatch {service} ')):
                probe_names.append(probe_name)
                
    except FileNotFoundError:
        print(f"Error: The file at {probes_path} was not found.")
        exit(1)
    
    return probe_names

def main():
    # Set up the argument parser
    parser = argparse.ArgumentParser(description="Extract probe names from nmap-service-probes.")
    parser.add_argument('service', type=str, help="The service to match in the nmap-service-probes")
    parser.add_argument("-f", "--probes-file", default="nmap-service-probes", help="nmap-service-probes file path")
    
    # Parse the arguments
    args = parser.parse_args()

    # Extract probe names
    probe_names = extract_probe_names(args.service, args.probes_file)
    
    # Print out the probe names
    print(f"Probes associated with service '{args.service}':")
    for probe in probe_names:
        print(f'- {probe}')

if __name__ == "__main__":
    main()