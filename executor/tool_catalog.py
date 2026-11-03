
"""
Pentest Master - Extended Kali Tool Catalog v2.

Read-only inventory of security tools.

This module:
- Detects executables using PATH.
- Supports 21 categories.
- Supports alternative binary names.
- Provides JSON output for MCP.
- Never executes discovered tools.
- Never installs packages.
- Never grants execution permissions.
"""

import argparse
import json
import shutil


# Format:
# name | binary names | category | execution class | description
#
# Multiple binary names are separated by commas.
# The first executable found in PATH is selected.
#
# Execution classes are informational:
# local_read, network_probe, security_test, sensitive.
#
# They do NOT grant permission to execute anything.

RAW_TOOLS = """
nmap|nmap|network|network_probe|Port and service inventory
masscan|masscan|network|sensitive|High-speed port enumeration
rustscan|rustscan|network|network_probe|Fast port discovery
naabu|naabu|network|network_probe|Port scanner
unicornscan|unicornscan|network|network_probe|Asynchronous port scanner
zmap|zmap|network|sensitive|Large-scale scanner
fping|fping|network|network_probe|ICMP probing
arp-scan|arp-scan|network|network_probe|ARP host discovery
netdiscover|netdiscover|network|network_probe|ARP discovery
hping3|hping3|network|sensitive|Custom network packets
nping|nping|network|network_probe|Packet generation
dig|dig|network|network_probe|DNS interrogation
host|host|network|network_probe|DNS lookup
nslookup|nslookup|network|network_probe|DNS lookup
traceroute|traceroute|network|network_probe|Route tracing
tracepath|tracepath|network|network_probe|Route tracing
mtr|mtr|network|network_probe|Network diagnosis
ping|ping|network|network_probe|Reachability
socat|socat|network|sensitive|Socket relay
netcat|nc,ncat,netcat|network|sensitive|Socket connectivity
tcpdump|tcpdump|network|sensitive|Packet capture
tshark|tshark|network|local_read|Packet analysis
wireshark|wireshark|network|local_read|Packet analyzer
arping|arping|network|network_probe|ARP requests

smbclient|smbclient|services|network_probe|SMB client
rpcclient|rpcclient|services|network_probe|RPC queries
ldapsearch|ldapsearch|services|network_probe|LDAP queries
snmpwalk|snmpwalk|services|network_probe|SNMP walk
snmpget|snmpget|services|network_probe|SNMP get
onesixtyone|onesixtyone|services|security_test|SNMP testing
ike-scan|ike-scan|services|network_probe|IKE probing
showmount|showmount|services|network_probe|NFS exports
rpcinfo|rpcinfo|services|network_probe|RPC information
redis-cli|redis-cli|services|network_probe|Redis client
mysql|mysql,mariadb|services|network_probe|SQL database client
psql|psql|services|network_probe|PostgreSQL client
mongo|mongosh,mongo|services|network_probe|MongoDB client
ftp|ftp|services|network_probe|FTP client
ssh|ssh|services|sensitive|SSH client
openssl|openssl|services|local_read|TLS and crypto utilities

curl|curl|web|network_probe|HTTP requests
wget|wget|web|network_probe|HTTP downloads
httpx|httpx|web|network_probe|HTTP probing or HTTP client
httprobe|httprobe|web|network_probe|HTTP discovery
whatweb|whatweb|web|network_probe|Web technology fingerprinting
wafw00f|wafw00f|web|network_probe|WAF detection
nikto|nikto|web|security_test|Web server assessment
w3af|w3af|web|security_test|Web auditing framework
wapiti|wapiti|web|security_test|Web application assessment
sslscan|sslscan|web|network_probe|TLS analysis
sslyze|sslyze|web|network_probe|TLS analysis
testssl|testssl.sh,testssl|web|network_probe|TLS testing
websocat|websocat|web|network_probe|WebSocket utility
mitmproxy|mitmproxy|web|sensitive|HTTP interception
mitmdump|mitmdump|web|sensitive|HTTP proxy scripting
burpsuite|burpsuite|web|sensitive|Web testing GUI
zaproxy|zaproxy,zap.sh|web|security_test|OWASP ZAP
wpscan|wpscan|web|security_test|WordPress assessment
joomscan|joomscan|web|security_test|Joomla assessment
droopescan|droopescan|web|security_test|CMS assessment

ffuf|ffuf|content|network_probe|Content discovery
feroxbuster|feroxbuster|content|network_probe|Recursive content discovery
gobuster|gobuster|content|network_probe|Directory and DNS enumeration
dirsearch|dirsearch|content|network_probe|Directory discovery
dirb|dirb|content|network_probe|Content discovery
dirbuster|dirbuster|content|network_probe|Directory testing GUI
wfuzz|wfuzz|content|security_test|Parameter fuzzing
katana|katana|content|network_probe|Web crawling
hakrawler|hakrawler|content|network_probe|Web crawling
gau|gau|content|network_probe|Known URL discovery
waybackurls|waybackurls|content|network_probe|Archived URLs
arjun|arjun|content|network_probe|Parameter discovery
paramspider|paramspider|content|network_probe|Parameter discovery
cewl|cewl|content|network_probe|Wordlist generation
crunch|crunch|content|local_read|Wordlist generation

nuclei|nuclei|vulnerability|security_test|Template assessments
searchsploit|searchsploit|vulnerability|local_read|Exploit database lookup
nmap-nse|nmap|vulnerability|security_test|Nmap scripting support
openvas|gvm-cli,openvas|vulnerability|security_test|Vulnerability framework
lynis|lynis|vulnerability|local_read|Local auditing
trivy|trivy|vulnerability|local_read|Filesystem security scanning
semgrep|semgrep|vulnerability|local_read|Static code analysis
bandit|bandit|vulnerability|local_read|Python security analysis
checkov|checkov|vulnerability|local_read|IaC analysis

sqlmap|sqlmap|sqli|security_test|SQL injection assessment
ghauri|ghauri|sqli|security_test|SQL injection assessment
commix|commix|sqli|security_test|Command injection assessment
nosqlmap|nosqlmap|sqli|security_test|NoSQL injection assessment
mongoaudit|mongoaudit|sqli|security_test|MongoDB security auditing

amass|amass|osint|network_probe|Domain mapping
subfinder|subfinder|osint|network_probe|Subdomain discovery
assetfinder|assetfinder|osint|network_probe|Domain discovery
dnsenum|dnsenum|osint|network_probe|DNS enumeration
dnsrecon|dnsrecon|osint|network_probe|DNS reconnaissance
fierce|fierce|osint|network_probe|DNS reconnaissance
theharvester|theHarvester,theharvester|osint|network_probe|OSINT aggregation
recon-ng|recon-ng|osint|network_probe|OSINT framework
sherlock|sherlock|osint|network_probe|Username research
spiderfoot|spiderfoot,sf.py|osint|network_probe|OSINT framework
whois|whois|osint|network_probe|WHOIS lookup
sublist3r|sublist3r|osint|network_probe|Subdomain discovery

enum4linux-ng|enum4linux-ng|active_directory|network_probe|SMB and RPC enumeration
enum4linux|enum4linux|active_directory|network_probe|SMB and RPC enumeration
nxc|nxc|active_directory|sensitive|NetExec assessment
crackmapexec|crackmapexec|active_directory|sensitive|Network assessment
bloodhound-python|bloodhound-python|active_directory|network_probe|AD data collection
bloodhound|bloodhound|active_directory|local_read|AD graph analysis
bloodhound-ce-python|bloodhound-ce-python|active_directory|network_probe|AD data collection
certipy-ad|certipy-ad,certipy|active_directory|sensitive|AD CS assessment
certi|certi|active_directory|security_test|Certificate analysis
bloodyad|bloodyAD,bloodyad|active_directory|sensitive|AD operations
ldapdomaindump|ldapdomaindump|active_directory|network_probe|LDAP domain inventory
windapsearch|windapsearch|active_directory|network_probe|LDAP enumeration
kerbrute|kerbrute|active_directory|sensitive|Kerberos testing
impacket-GetADUsers|impacket-GetADUsers,GetADUsers.py|active_directory|network_probe|AD user enumeration
impacket-GetUserSPNs|impacket-GetUserSPNs,GetUserSPNs.py|active_directory|sensitive|Kerberos service analysis
impacket-GetNPUsers|impacket-GetNPUsers,GetNPUsers.py|active_directory|sensitive|Kerberos preauth assessment
impacket-getTGT|impacket-getTGT,getTGT.py|active_directory|sensitive|Kerberos ticket request
impacket-getST|impacket-getST,getST.py|active_directory|sensitive|Kerberos service ticket
impacket-secretsdump|impacket-secretsdump,secretsdump.py|active_directory|sensitive|Credential extraction
impacket-ntlmrelayx|impacket-ntlmrelayx,ntlmrelayx.py|active_directory|sensitive|NTLM relay testing
impacket-lookupsid|impacket-lookupsid,lookupsid.py|active_directory|network_probe|SID enumeration
impacket-samrinfo|impacket-samrinfo,samrinfo.py|active_directory|network_probe|SAMR queries
impacket-rpcdump|impacket-rpcdump,rpcdump.py|active_directory|network_probe|RPC endpoints
impacket-smbclient|impacket-smbclient,smbclient.py|active_directory|network_probe|SMB protocol client

impacket-wmiexec|impacket-wmiexec,wmiexec.py|windows|sensitive|WMI execution
impacket-psexec|impacket-psexec,psexec.py|windows|sensitive|Remote service execution
impacket-smbexec|impacket-smbexec,smbexec.py|windows|sensitive|SMB execution
impacket-atexec|impacket-atexec,atexec.py|windows|sensitive|Scheduled execution
impacket-dcomexec|impacket-dcomexec,dcomexec.py|windows|sensitive|DCOM execution
evil-winrm|evil-winrm|windows|sensitive|WinRM interaction
xfreerdp|xfreerdp,xfreerdp3|windows|network_probe|RDP client
rdesktop|rdesktop|windows|network_probe|RDP client
remmina|remmina|windows|network_probe|Remote desktop
smbmap|smbmap|windows|network_probe|SMB share analysis
smbcacls|smbcacls|windows|network_probe|SMB ACL listing
smbget|smbget|windows|network_probe|SMB downloads
regipy|regipy|windows|local_read|Offline registry analysis
chntpw|chntpw|windows|local_read|Offline registry inspection
gpp-decrypt|gpp-decrypt|windows|sensitive|Group Policy Preferences analysis

ligolo-ng|ligolo-proxy,ligolo-ng|pivoting|sensitive|TUN tunneling
ligolo-agent|ligolo-agent|pivoting|sensitive|Ligolo endpoint
chisel|chisel|pivoting|sensitive|TCP tunnels and SOCKS
proxychains4|proxychains4,proxychains|pivoting|sensitive|Proxy wrapper
sshuttle|sshuttle|pivoting|sensitive|SSH-based routed proxy
ssh-tunnel|ssh|pivoting|sensitive|SSH port forwarding
socat-relay|socat|pivoting|sensitive|Socket relay
rinetd|rinetd|pivoting|sensitive|TCP forwarding
redsocks|redsocks|pivoting|sensitive|Transparent proxy
dnscat2|dnscat2|pivoting|sensitive|DNS tunneling
dns2tcp|dns2tcpc,dns2tcpd|pivoting|sensitive|DNS transport
stunnel|stunnel,stunnel4|pivoting|sensitive|TLS tunneling
frpc|frpc|pivoting|sensitive|Reverse proxy client
frps|frps|pivoting|sensitive|Reverse proxy server
openvpn|openvpn|pivoting|sensitive|VPN client
wireguard|wg|pivoting|sensitive|WireGuard configuration
iproute2|ip|pivoting|sensitive|Routing configuration
iptables|iptables|pivoting|sensitive|Firewall and NAT
nft|nft|pivoting|sensitive|Netfilter configuration

msfconsole|msfconsole|exploitation|sensitive|Metasploit framework
msfvenom|msfvenom|exploitation|sensitive|Payload tooling
msfdb|msfdb|exploitation|sensitive|Metasploit database
exploitdb|searchsploit|exploitation|local_read|Exploit references
impacket|impacket-smbclient|exploitation|sensitive|Protocol utilities

hydra|hydra|credentials|sensitive|Authentication testing
medusa|medusa|credentials|sensitive|Authentication testing
ncrack|ncrack|credentials|sensitive|Authentication testing
patator|patator|credentials|sensitive|Authentication testing
hashcat|hashcat|credentials|sensitive|Offline password recovery
john|john|credentials|sensitive|Offline password recovery
hashid|hashid|credentials|local_read|Hash identification
hash-identifier|hash-identifier|credentials|local_read|Hash identification
keepass2john|keepass2john|credentials|local_read|Offline format conversion
ssh2john|ssh2john|credentials|local_read|Offline format conversion
pdf2john|pdf2john|credentials|local_read|Offline format conversion
ophcrack|ophcrack|credentials|sensitive|Password recovery
mimikatz|mimikatz|credentials|sensitive|Windows security research
responder|responder|credentials|sensitive|Network authentication research
bettercap|bettercap|credentials|sensitive|Network assessment

hashdeep|hashdeep|forensics|local_read|Filesystem hashing
bulk-extractor|bulk_extractor|forensics|local_read|Data extraction
foremost|foremost|forensics|local_read|File carving
scalpel|scalpel|forensics|local_read|File carving
volatility3|vol,volatility3|forensics|local_read|Memory forensics
volatility2|volatility|forensics|local_read|Memory forensics
sleuthkit-fls|fls|forensics|local_read|Filesystem analysis
sleuthkit-icat|icat|forensics|local_read|Filesystem analysis
autopsy|autopsy|forensics|local_read|Forensics GUI
exiftool|exiftool|forensics|local_read|Metadata extraction
binwalk|binwalk|forensics|local_read|Firmware analysis
binwalk3|binwalk3|forensics|local_read|Firmware analysis
steghide|steghide|forensics|local_read|Steganography
zsteg|zsteg|forensics|local_read|Steganography
stegseek|stegseek|forensics|local_read|Steganography

xxd|xxd|reverse_engineering|local_read|Hex inspection
hexdump|hexdump|reverse_engineering|local_read|Hex inspection
objdump|objdump|reverse_engineering|local_read|Disassembly
readelf|readelf|reverse_engineering|local_read|ELF metadata
nm|nm|reverse_engineering|local_read|Symbol tables
strings|strings|reverse_engineering|local_read|Printable strings
gdb|gdb|reverse_engineering|sensitive|Native debugging
gdb-multiarch|gdb-multiarch|reverse_engineering|sensitive|Multiarch debugging
radare2|r2,radare2|reverse_engineering|local_read|Binary analysis
rizin|rizin|reverse_engineering|local_read|Binary analysis
cutter|cutter|reverse_engineering|local_read|Reverse engineering GUI
ghidra|ghidra,ghidraRun|reverse_engineering|local_read|Software reverse engineering
jadx|jadx|reverse_engineering|local_read|Android decompilation
apktool|apktool|reverse_engineering|local_read|Android package decoding
r2frida|r2frida|reverse_engineering|sensitive|Dynamic instrumentation
frida|frida,frida-ps|reverse_engineering|sensitive|Dynamic instrumentation
frida-tools|frida-ls-devices|reverse_engineering|sensitive|Instrumentation utilities
angr|angr|reverse_engineering|local_read|Symbolic analysis
checksec|checksec|reverse_engineering|local_read|Binary mitigation checks
pwninit|pwninit|reverse_engineering|local_read|Binary preparation
one_gadget|one_gadget|reverse_engineering|local_read|Gadget analysis
ropper|ropper|reverse_engineering|local_read|ROP gadget analysis
ROPgadget|ROPgadget|reverse_engineering|local_read|ROP gadget analysis
pwndbg|pwndbg|reverse_engineering|local_read|GDB extension
patchelf|patchelf|reverse_engineering|local_read|ELF modification
strace|strace|reverse_engineering|sensitive|System call tracing
ltrace|ltrace|reverse_engineering|sensitive|Library call tracing
upx|upx|reverse_engineering|local_read|Executable packing

exiftool-mobile|exiftool|mobile|local_read|Mobile artifact metadata
adb|adb|mobile|sensitive|Android debugging
fastboot|fastboot|mobile|sensitive|Android management
objection|objection|mobile|sensitive|Mobile instrumentation
mobsf|mobsf|mobile|security_test|Mobile app assessment
apksigner|apksigner|mobile|local_read|APK signatures
aapt|aapt,aapt2|mobile|local_read|APK resources
baksmali|baksmali|mobile|local_read|DEX disassembly
smali|smali|mobile|local_read|DEX assembly
ideviceinfo|ideviceinfo|mobile|network_probe|iOS information
idevicebackup2|idevicebackup2|mobile|sensitive|iOS backup handling

aws-cli|aws|cloud|network_probe|AWS client
azure-cli|az|cloud|network_probe|Azure client
gcloud|gcloud|cloud|network_probe|Google Cloud client
kubectl|kubectl|cloud|sensitive|Kubernetes client
helm|helm|cloud|sensitive|Kubernetes packages
terraform|terraform|cloud|sensitive|Infrastructure automation
pacu|pacu|cloud|sensitive|AWS assessment
prowler|prowler|cloud|network_probe|Cloud posture analysis
scoutsuite|scout,scoutsuite|cloud|network_probe|Cloud posture analysis
cloudfox|cloudfox|cloud|network_probe|Cloud inventory
trufflehog|trufflehog|cloud|local_read|Secret discovery
gitleaks|gitleaks|cloud|local_read|Secret discovery
kube-hunter|kube-hunter|cloud|security_test|Kubernetes assessment

docker|docker|containers|sensitive|Container client
podman|podman|containers|sensitive|Container runtime
buildah|buildah|containers|sensitive|Container builds
skopeo|skopeo|containers|local_read|Image inspection
syft|syft|containers|local_read|Software inventory
grype|grype|containers|local_read|Dependency assessment
hadolint|hadolint|containers|local_read|Dockerfile analysis
kube-bench|kube-bench|containers|local_read|Kubernetes benchmark

wifi-aircrack|aircrack-ng|wireless|sensitive|Wireless assessment
airodump-ng|airodump-ng|wireless|sensitive|Wireless monitoring
aireplay-ng|aireplay-ng|wireless|sensitive|Wireless testing
airmon-ng|airmon-ng|wireless|sensitive|Wireless interface management
reaver|reaver|wireless|sensitive|Wireless WPS testing
bully|bully|wireless|sensitive|Wireless WPS testing
hcxdumptool|hcxdumptool|wireless|sensitive|Wireless capture
hcxpcapngtool|hcxpcapngtool|wireless|local_read|Packet conversion
kismet|kismet|wireless|sensitive|Wireless monitoring
bettercap-wifi|bettercap|wireless|sensitive|Wireless assessment

openssl-crypto|openssl|crypto|local_read|Cryptographic primitives
gpg|gpg|crypto|local_read|OpenPGP
age|age|crypto|local_read|File encryption
hash-identifier-crypto|hash-identifier|crypto|local_read|Hash identification
hashcat-utils|cap2hccapx|crypto|local_read|Hash conversion

python3|python3|processing|local_read|Python interpreter
pip|pip,pip3|processing|sensitive|Python packages
node|node|processing|local_read|JavaScript runtime
npm|npm|processing|sensitive|Node packages
jq|jq|processing|local_read|JSON processing
yq|yq|processing|local_read|YAML processing
rg|rg|processing|local_read|Text search
grep|grep|processing|local_read|Text search
sed|sed|processing|local_read|Text transformation
awk|awk|processing|local_read|Text processing
find|find|processing|local_read|File discovery
file|file|processing|local_read|File identification
sha256sum|sha256sum|processing|local_read|File hashing
7z|7z,7zz|processing|local_read|Archive inspection
unzip|unzip|processing|local_read|ZIP extraction
zip|zip|processing|local_read|ZIP archives
git|git|processing|local_read|Version control
sqlite3|sqlite3|processing|local_read|SQLite utility

pandoc|pandoc|reporting|local_read|Document conversion
wkhtmltopdf|wkhtmltopdf|reporting|local_read|PDF generation
mermaid-cli|mmdc|reporting|local_read|Diagram rendering
asciinema|asciinema|reporting|local_read|Terminal recordings
script|script|reporting|local_read|Terminal recording
"""


def load_definitions():
    tools = []
    seen = set()

    for line_number, raw in enumerate(
        RAW_TOOLS.splitlines(), 1
    ):
        raw = raw.strip()

        if not raw or raw.startswith("#"):
            continue

        fields = [
            part.strip()
            for part in raw.split("|")
        ]

        if len(fields) != 5:
            raise ValueError(
                f"Invalid row {line_number}: {raw}"
            )

        (
            name,
            executables,
            category,
            execution_class,
            description,
        ) = fields

        if not all(fields) or name in seen:
            raise ValueError(
                f"Empty or duplicate tool: {name}"
            )

        seen.add(name)

        tools.append((
            name,
            executables.split(","),
            category,
            execution_class,
            description,
        ))

    return tools


TOOL_DEFINITIONS = load_definitions()

CATEGORIES = sorted({
    item[2]
    for item in TOOL_DEFINITIONS
})


def detect_tools(
    category="all",
    installed_only=False,
    search="",
):
    if (
        category != "all"
        and category not in CATEGORIES
    ):
        raise ValueError(
            "Unknown category. Available: "
            + ", ".join(CATEGORIES)
        )

    tools = []

    for (
        name,
        binaries,
        item_category,
        execution_class,
        description,
    ) in TOOL_DEFINITIONS:

        if (
            category != "all"
            and category != item_category
        ):
            continue

        searchable = (
            name + " " + description + " " + item_category
        )

        if (
            search
            and search.casefold()
            not in searchable.casefold()
        ):
            continue

        found_binary = None
        path = None

        for binary in binaries:
            candidate_path = shutil.which(binary)

            if candidate_path:
                found_binary = binary
                path = candidate_path
                break

        if installed_only and not path:
            continue

        tools.append({
            "name": name,
            "binary": found_binary or binaries[0],
            "candidate_binaries": binaries,
            "category": item_category,
            "description": description,
            "execution_class": execution_class,
            "installed": bool(path),
            "path": path,
            "executable_via_agent": False,
        })

    return {
        "status": "completed",
        "operation": "tool_catalog",
        "exit_code": 0,
        "category": category,
        "total": len(tools),
        "installed": sum(
            1 for tool in tools
            if tool["installed"]
        ),
        "categories": CATEGORIES,
        "tools": tools,
        "note": (
            "Inventory only. Finding an executable "
            "does not authorize its execution or "
            "prove sandbox compatibility."
        ),
    }


def main():
    parser = argparse.ArgumentParser(
        description="Extended Kali tool inventory"
    )

    parser.add_argument(
        "--category",
        default="all",
        choices=["all", *CATEGORIES],
    )

    parser.add_argument(
        "--installed-only",
        action="store_true",
    )

    parser.add_argument(
        "--json",
        action="store_true",
    )

    parser.add_argument(
        "--summary",
        action="store_true",
    )

    parser.add_argument(
        "--search",
        default="",
    )

    args = parser.parse_args()

    result = detect_tools(
        category=args.category,
        installed_only=args.installed_only,
        search=args.search,
    )

    if args.json:
        print(json.dumps(
            result,
            ensure_ascii=False,
            indent=2,
        ))
        return

    print("Pentest Master - Kali Tool Catalog")
    print("Category:", result["category"])
    print(
        "Installed:",
        result["installed"],
        "/",
        result["total"],
    )

    if args.summary:
        for cat in result["categories"]:
            matches = [
                tool
                for tool in result["tools"]
                if tool["category"] == cat
            ]

            if not matches:
                continue

            found = sum(
                tool["installed"]
                for tool in matches
            )

            print(
                f"{cat:20} "
                f"{found:3}/{len(matches):3} installed"
            )

        return

    print()

    for item in result["tools"]:
        state = (
            "FOUND"
            if item["installed"]
            else "MISSING"
        )

        print(
            f"[{state:7}] "
            f"{item['name']:23} "
            f"{item['category']:20} "
            f"{item['execution_class']}"
        )

    print()
    print("Discovery only; no tools were executed.")


if __name__ == "__main__":
    main()
