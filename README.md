# Nmap Service Probes and Generator
Increase service scanning efficiency with custom Nmap service probes.
#### tl;dr
- [The Solution](#The-Solution)
- [Examples](#Examples)
## The Problem
- In large environments, there isn't enough time to fully test every service
  - So, you look for services with common vulnerabilities or misconfigurations
- These services can live on non-default ports
  - When they do, they often get overlooked, making them more likely to be affected (excellent targets)
- **_There's no efficient way to identify services on non-default ports_**
  - Running a basic port scan won't tell you the service on that port
  - Nmap's `-sV` flag correctly identifies the service but with too much overhead:
    - Lots of extra traffic (probes) to identify services you probably don't care about
    - In some cases, even after identifying the service (with a softmatch), it continues probing for its version
    - There's no good distinction between SSL/TLS and non-SSL/TLS variants of services
    - Sure, `--version-intensity` allows you to limit the number of service probes, but it applies globally to all services
## The Solution
Tell Nmap to only look for a particular service/services. You can do this by filtering the nmap-service-probes file so that it only includes relevant lines.
1. Get the latest nmap-service-probes file from GitHub: `wget https://raw.githubusercontent.com/nmap/nmap/refs/heads/master/nmap-service-probes`
2. Identify services you find interesting.
   - For a full list of services: `egrep '^match |^softmatch ' nmap-service-probes | cut -d' ' -f2 | sort -u`
4. (optional) Identify probes (traffic) you want to send.
   - For a full list of probes: `grep -i '^probe ' nmap-service-probes | cut -d' ' -f3 | sort -u`
   - For a list of probes associated with a particular service: `python3 parse-probes.py <service> -f nmap-service-probes`
5. Generate a custom nmap-service-probes file: `python generate-probes.py ... -o custom-probes`
   - If your only goal is to identify the service type, and you don't care about its version, be sure to include `--no-softmatch`
   - If you don't specify probes, the script will include all probes that could help identify the service (containing `match/softmatch <service>`)
   - For TLS/SSL variations,
     - The script will automatically include the following services: `ssl` and `ssl/<service>`
     - The script will automatically include the following probes: `SSLSessionReq` and `TLSSessionReq`
     - Probe `SSLv23SessionReq` is used to detect SSLv2-only services, making it rarely worth the overhead
       - If probes are _not_ explicitly specified (no `-p`) and `--no-ssl` is _not_ set, the script will automatically include this probe. You may exclude it with `-e SSLv23SessionReq`
       - If probes _are_ explicitly specified (`-p`), the script will _not_ include this probe unless it is explicitly listed
   - To avoid TLS/SSL altogether, you may include the `--no-ssl` flag. This will omit the above services/probes and remove all `sslports` directives.
     - If you include `--no-ssl`, you may still explicitly include SSL/TLS services or SSL/TLS probes (with `-p`). However, the `sslports` directive will still be removed.
   - You'll want to include the NULL probe (`NULL`) in most cases. This just grabs the service banner without sending any data.
6. `sudo nmap -sS -p- -sV --versiondb custom-probes ...`
### Background
- Understand how Nmap version scanning works: [https://nmap.org/book/vscan-technique.html](https://nmap.org/book/vscan-technique.html)
- Understand how to work with nmap-service-probes: [https://nmap.org/book/vscan-fileformat.html](https://nmap.org/book/vscan-fileformat.html)
### Limitations
- Nmap does the scan in 2 steps: 1. Identify open ports, 2. Scan services to determine their version.
  - This means that open ports go through the TCP handshake twice. Ideally, this should be combined into a single step.
- You're forced to scan the same ports on every host. I really wish you could provide a hosts file containing ports to scan per host.
- Certain aspects of version scanning, like rarity, timeout values, fallback, etc. can't be modified with the generate-probes.py script.
  - This should be easy to change manually though if you know what you're doing, and in most cases you won't care to.
## Usage
[parse-probes.py](parse-probes.py) ⇒ extract probes used to identify a particular service from nmap-service-probes
- `<service>` (required) ⇒ service to extract probes for
- `-f <probes file>` ⇒ path to nmap-service-probes file (default: `nmap-service-probes` in current directory)

[generate-probes.py](generate-probes.py) ⇒ filter an nmap-service-probes file so that it only includes relevant lines
- `-s <services>` ⇒ services to include (e.g., http ftp ssh)
  - If specified, ONLY these services will be included
  - If not specified, all services will be included. This is useful if you want to limit probes but not service detection.
- `-p <probes>` ⇒ probes to include (e.g. GenericLines GetRequest)
  - Don't forget to include `NULL`
  - If specified, ONLY these probes will be included and only if they would help identify a service (contain `match/softmatch <service>`)
  - If not specified, all probes that could help identify a service (contain `match/softmatch <service>`) will be included. Probes not associated with an included service will be omitted.
- `-e <exclude probes>` ⇒ probes to exclude
  - Takes precedence over everything else, including `-p` and automatic inclusion of SSL/TLS ports
  - For example, `-e SSLv23SessionReq` will remove detection of SSLv2-only services
- `-n` (or `--no-ssl`) ⇒ don't attempt SSL/TLS connections
  - Useful for identifying unencrypted services
- `-m` (or `--no-softmatch`) ⇒ convert all instances of "softmatch" to "match" so that scanning stops once a service type is identified
  - Useful if you don't care about the service's version
- `-f <probes file>` ⇒ path to original nmap-service-probes file (default: `nmap-service-probes` in current directory)
- `-o <output>` ⇒ path to output nmap-service-probes file (default: `nmap-service-probes` in current directory - will overwrite original)
### Examples
The title of this section is "Examples" not "Best Examples" so modify/use at your discretion.  
It may be helpful to exclude `-s` entirely and only limit probes. This way you avoid sending unnecessary probes after matching a different service.
I'm not sure if the benefit of sending fewer probes would outweigh the overhead introduced by extra match checks and will have to do more testing.
#### Common Vulnerable Services - Get Service Version
```bash
wget https://raw.githubusercontent.com/nmap/nmap/refs/heads/master/nmap-service-probes
python generate-probes.py \
  -s http http-proxy ftp ftp-proxy smtp smtp-proxy ssh telnet telnet-proxy vnc vnc-http cisco-smartinstall \
  -p NULL GenericLines GetRequest

# --version-all ensures all the probes above are tried on every port
# It's not necessary here (default scan intensity is 7 and rarity < 7 for all the above probes)
# However, I included it to encourage reading up on --version-intensity <intensity>, --version-light, and --version-all
# https://nmap.org/book/vscan-technique.html
# If you're already explicitly specifying probes to reduce overhead, including --version-all could be a good habit to get into
sudo nmap -n -Pn -sS -p- -sV --versiondb nmap-service-probes --version-all -iL targets.txt -oA common --open
```
#### Web (HTTP/HTTPS) Services - Screenshot
```bash
# efficiently identify web services
wget https://raw.githubusercontent.com/nmap/nmap/refs/heads/master/nmap-service-probes
python generate-probes.py \
  -p NULL GenericLines GetRequest HTTPOptions FourOhFourRequest SSLv23SessionReq \
  --no-softmatch

# Here I explicitly included SSLv23SessionReq to test SSLv2-only services
# However, since its rarity is 8 > default scan intensity of 7, it will only probe common web ports (specified in the ports directive)
# Probes SSLSessionReq and TLSSessionReq were explicitly included and will be attempted on all ports because their rarity is 1 < default scan intensity of 7
# To only scan HTTP (not HTTPS) services, I would include --no-ssl and remove SSLv23SessionReq in the command above
sudo nmap -n -Pn --min-hostgroup 128 -sS -p- --max-retries 0 -sV --versiondb nmap-service-probes -iL targets.txt -oA web --open

# remove irrelevant Windows services
grep -v 'Microsoft HTTPAPI httpd' web.xml > web-clean.xml

# screenshot with gowitness
go install github.com/sensepost/gowitness@latest
gowitness scan nmap --open-only --service-contains http -f web-clean.xml --write-db
gowitness report server
```
#### Services Supporting Unencrypted Connections - Get Service Type
```bash
wget https://raw.githubusercontent.com/nmap/nmap/refs/heads/master/nmap-service-probes
python generate-probes.py \
  -s ftp ftp-proxy smtp smtp-proxy pop3 pop3-proxy pop3pw imap imap-proxy ssh telnet telnet-proxy vnc nuuo-vnc vnc-http \
  --no-ssl
  --no-softmatch
sudo nmap -n -Pn -sS -p- -sV --versiondb nmap-service-probes -iL targets.txt -oA unencrypted --open
```
