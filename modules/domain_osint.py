import concurrent.futures
import ipaddress
import json
import socket
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List, Optional

import dns.resolver
import requests
import whois
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn, BarColumn
from rich.panel import Panel
from rich.box import ROUNDED, SQUARE

# Modern minimal color scheme
PRIMARY_BLUE = "#0066cc"  # Deeper blue for main elements
SECONDARY_BLUE = "#4d94ff"  # Lighter blue for secondary elements
WHITE = "#ffffff"  # Pure white

from core.utils import which, run_cmd, grab_banner, fetch_tls_cert, extract_cert_summary

console = Console()

SUPPORTED_RRTYPES = [
    "A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA", "DS", "DNSKEY",
]

@dataclass
class DomainScanner:
    timeout: int = 15
    proxy: Optional[str] = None
    no_axfr: bool = False
    no_scan_ports: bool = False
    top_ports: str = "21,22,23,25,26,53,80,81,110,111,135,139,143,443,445,465,587,995,1723,3306,3389,5900,8080,8443,995,993,5432,3306,2222,2087,2086,2083,2082,2095,2096,8443,8880,8081,8888,9090,1025,1433,1434,1521,3128,3306,4242,4243,4567,5222,5223,5432,6379,7000,7001,8000,8008,8080,8443,8888,9092,9200,9300,10000,11211,27017,28017,49152,49153,49154,49155,49156,49157,50000,6379,2375,2376,6000,13306,3000,4444,5000,5555,5672,5984,6082,8009,8010,8082,8083,8084,8085,8086,8087,8088,8089,8090,8091,8443,9000,9001,9042,9160,9042,9200,9300,11211,11214,11215,27017,27018,27019,28017,50000,50030,50070"
    wordlist: Optional[str] = None
    dns_server: Optional[str] = None

    def scan_whois(self, domain: str) -> dict:
        """Perform WHOIS lookup for a domain"""
        result = {"whois": {}}
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=console,
            transient=True
        ) as progress:
            task = progress.add_task(f"[{PRIMARY_BLUE}]Fetching WHOIS information[/{PRIMARY_BLUE}]")
            
            try:
                w = whois.whois(domain)
                
                # Handle dates - some might be lists, take first non-None value
                def get_date(date_field):
                    if isinstance(date_field, (list, tuple)):
                        return next((d for d in date_field if d is not None), None)
                    return date_field
                
                # Handle statuses - ensure we have a list and clean it up
                def clean_status(status):
                    if not status:
                        return None
                    if isinstance(status, str):
                        return [status]
                    if isinstance(status, (list, tuple)):
                        return [s for s in status if s]
                    return None
                
                whois_info = {
                    "domain_name": self._safe(w.domain_name),
                    "registrar": self._safe(w.registrar),
                    "creation_date": self._safe(get_date(w.creation_date)),
                    "expiration_date": self._safe(get_date(w.expiration_date)),
                    "updated_date": self._safe(get_date(w.updated_date)),
                    "name_servers": list(sorted(set([str(x).lower() for x in (w.name_servers or []) if x]))),
                    "status": clean_status(w.status),
                }
                result["whois"] = whois_info
                
                # Build and display modern table
                table = Table(box=SQUARE)
                table.add_column(f"[{WHITE}]Field[/{WHITE}]")
                table.add_column(f"[{WHITE}]Value[/{WHITE}]")
                
                # Display fields in a specific order with nice formatting
                field_order = [
                    ("domain_name", "Domain Name"),
                    ("registrar", "Registrar"),
                    ("creation_date", "Created"),
                    ("expiration_date", "Expires"),
                    ("updated_date", "Updated"),
                    ("name_servers", "Nameservers"),
                    ("status", "Status")
                ]
                
                for key, display_name in field_order:
                    value = whois_info.get(key)
                    if value:
                        if isinstance(value, list):
                            # Format lists vertically with bullet points
                            formatted_value = "\n• " + "\n• ".join(value)
                        else:
                            formatted_value = str(value)
                        table.add_row(
                            f"[{PRIMARY_BLUE}]{display_name}[/{PRIMARY_BLUE}]",
                            f"[{SECONDARY_BLUE}]{formatted_value}[/{SECONDARY_BLUE}]"
                        )
                
                if table.row_count > 0:
                    console.print()
                    console.print(Panel(table, title=f"[{WHITE}]WHOIS Information[/{WHITE}]", box=SQUARE))
                else:
                    console.print()
                    console.print(Panel(
                        f"[{SECONDARY_BLUE}]No WHOIS information found[/{SECONDARY_BLUE}]",
                        title=f"[{WHITE}]WHOIS Information[/{WHITE}]",
                        box=SQUARE
                    ))
                
            except Exception as e:
                result["whois_error"] = str(e)
                console.print(Panel(
                    f"[{SECONDARY_BLUE}]Error: Could not fetch WHOIS information ({str(e)})[/{SECONDARY_BLUE}]",
                    title=f"[{WHITE}]Error[/{WHITE}]",
                    box=SQUARE
                ))
            
            progress.update(task, completed=100)
        
        return result

    def scan_dns(self, domain: str) -> dict:
        """Perform DNS enumeration for a domain"""
        result = {"dns": {"records": {}}}
        
        resolver = dns.resolver.Resolver()
        if self.dns_server:
            resolver.nameservers = [self.dns_server]
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=console,
            transient=True
        ) as progress:
            task = progress.add_task(
                f"[{PRIMARY_BLUE}]Gathering DNS records[/{PRIMARY_BLUE}]",
                total=len(SUPPORTED_RRTYPES)
            )
            
            dns_table = Table(box=SQUARE)
            dns_table.add_column(f"[{PRIMARY_BLUE}]Record[/{PRIMARY_BLUE}]")
            dns_table.add_column(f"[{PRIMARY_BLUE}]Value[/{PRIMARY_BLUE}]")
            
            for rr in SUPPORTED_RRTYPES:
                progress.update(
                    task,
                    advance=1,
                    description=f"[{PRIMARY_BLUE}]Checking {rr} records[/{PRIMARY_BLUE}]"
                )
                
                recs = self._dig(domain, rr)
                if not recs:
                    recs = self._dns_query(resolver, domain, rr)
                if recs:
                    result["dns"]["records"][rr] = recs
                    dns_table.add_row(
                        f"[{SECONDARY_BLUE}]{rr}[/{SECONDARY_BLUE}]",
                        f"[{WHITE}]{chr(10).join(recs)}[/{WHITE}]"
                    )
        
        if dns_table.row_count > 0:
            console.print()
            console.print(Panel(
                dns_table,
                title=f"[{WHITE}]DNS Records[/{WHITE}]",
                box=SQUARE
            ))
        
        return result

    def scan_ports(self, domain: str) -> dict:
        """Perform port scanning for a domain"""
        result = {"ports": {}}
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=console,
            transient=True
        ) as progress:
            try:
                # First task: Resolving IPs
                ips = set()
                resolver = dns.resolver.Resolver()
                resolve_task = progress.add_task(
                    f"[{PRIMARY_BLUE}]Resolving IP addresses[/{PRIMARY_BLUE}]"
                )

                if self.dns_server:
                    resolver.nameservers = [self.dns_server]
                
                # First resolve IPs
                for rr in ["A", "AAAA"]:
                    try:
                        answers = resolver.resolve(domain, rr)
                        ips.update(str(rdata) for rdata in answers)
                    except Exception:
                        pass
                
                progress.update(resolve_task, completed=100)
                
                if not ips:
                    console.print(Panel(
                        f"[{SECONDARY_BLUE}]Could not resolve domain to IP address[/{SECONDARY_BLUE}]",
                        title=f"[{WHITE}]Error[/{WHITE}]",
                        box=SQUARE
                    ))
                    return result
                
                # Start port scanning
                total_ports = len(ips) * len(self.top_ports.split(","))
                scan_task = progress.add_task(
                    f"[{PRIMARY_BLUE}]Scanning ports[/{PRIMARY_BLUE}]",
                    total=total_ports
                )
                
                scan_table = Table(box=SQUARE)
                scan_table.add_column(f"[{PRIMARY_BLUE}]IP[/{PRIMARY_BLUE}]")
                scan_table.add_column(f"[{PRIMARY_BLUE}]Port[/{PRIMARY_BLUE}]")
                scan_table.add_column(f"[{PRIMARY_BLUE}]Service[/{PRIMARY_BLUE}]")
                scan_table.add_column(f"[{PRIMARY_BLUE}]Details[/{PRIMARY_BLUE}]")
                
                found_open_ports = False
                for ip in ips:
                    result["ports"][ip] = {}
                    for port in map(int, self.top_ports.split(",")):
                        progress.update(
                            scan_task,
                            advance=1,
                            description=f"[{PRIMARY_BLUE}]Checking {ip}:{port}[/{PRIMARY_BLUE}]"
                        )
                        
                        try:
                            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            sock.settimeout(self.timeout)
                            if sock.connect_ex((ip, port)) == 0:
                                found_open_ports = True
                                banner = grab_banner(ip, port, self.timeout)
                                cert = fetch_tls_cert(ip, port) if port in [443, 8443] else None
                                cert_info = extract_cert_summary(cert) if cert else None
                                service_name = banner if banner else "unknown"
                                
                                result["ports"][ip][port] = {
                                    "state": "open",
                                    "service": service_name
                                }
                            
                                details = []
                                if banner:
                                    details.append(banner)
                                if cert_info:
                                    details.append(cert_info)
                                
                                scan_table.add_row(
                                    f"[{SECONDARY_BLUE}]{ip}[/{SECONDARY_BLUE}]",
                                    f"[{WHITE}]{port}[/{WHITE}]",
                                    f"[{SECONDARY_BLUE}]{service_name}[/{SECONDARY_BLUE}]",
                                    f"[{WHITE}]{' '.join(details)}[/{WHITE}]"
                                )
                            sock.close()
                        except Exception:
                            continue
                
                console.print()
                if found_open_ports:
                    console.print(Panel(
                        scan_table,
                        title=f"[{WHITE}]Port Scan Results[/{WHITE}]",
                        box=SQUARE
                    ))
                else:
                    console.print(Panel(
                        f"[{SECONDARY_BLUE}]No open ports found[/{SECONDARY_BLUE}]",
                        title=f"[{WHITE}]Port Scan Results[/{WHITE}]",
                        box=SQUARE
                    ))
            except Exception as e:
                console.print(Panel(
                    f"[{SECONDARY_BLUE}]Error during port scan: {str(e)}[/{SECONDARY_BLUE}]",
                    title=f"[{WHITE}]Error[/{WHITE}]",
                    box=SQUARE
                ))
        
        return result

    def scan(self, domain: str) -> dict:
        """Perform full scan including WHOIS, DNS, and ports"""
        result = {}
        
        # Call individual scan methods with modern styling
        whois_result = self.scan_whois(domain)
        result.update(whois_result)
        
        dns_result = self.scan_dns(domain)
        result.update(dns_result)
        
        if not self.no_scan_ports:
            ports_result = self.scan_ports(domain)
            result.update(ports_result)
        
        # Gather additional information and update result
        # Add summary information
        result["summary"] = {
            "a_records": len(result.get("dns", {}).get("records", {}).get("A", []) or []),
            "subdomains": len(result.get("subdomains", [])),
            "dnssec": result.get("dns", {}).get("dnssec_present", False),
            "open_services": sum(len(p) for p in result.get("ports", {}).values()),
            "whois_registrar": (result.get("whois", {}) or {}).get("registrar"),
        }
        
        # Display final summary
        console.print()
        console.print(Panel(
            "\n".join([
                f"[{SECONDARY_BLUE}]A Records:[/{SECONDARY_BLUE}] [{WHITE}]{result['summary']['a_records']}[/{WHITE}]",
                f"[{SECONDARY_BLUE}]Subdomains:[/{SECONDARY_BLUE}] [{WHITE}]{result['summary']['subdomains']}[/{WHITE}]",
                f"[{SECONDARY_BLUE}]DNSSEC:[/{SECONDARY_BLUE}] [{WHITE}]{'Enabled' if result['summary']['dnssec'] else 'Disabled'}[/{WHITE}]",
                f"[{SECONDARY_BLUE}]Open Services:[/{SECONDARY_BLUE}] [{WHITE}]{result['summary']['open_services']}[/{WHITE}]",
                f"[{SECONDARY_BLUE}]Registrar:[/{SECONDARY_BLUE}] [{WHITE}]{result['summary']['whois_registrar'] or 'Unknown'}[/{WHITE}]"
            ]),
            title=f"[{WHITE}]Domain Scan Summary[/{WHITE}]",
            box=SQUARE
        ))
        # First gather IPs from A and AAAA records
        ips = set()
        for rec in ["A", "AAAA"]:
            ips.update(result.get("dns", {}).get("records", {}).get(rec, []))

            # Start with reverse DNS lookups
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                TimeElapsedColumn(),
                console=console,
                transient=True
            ) as progress:
                task = progress.add_task(f"[{PRIMARY_BLUE}]Performing reverse DNS lookups[/{PRIMARY_BLUE}]")
                rev = {}
                for ip in ips:
                    try:
                        rev[ip] = socket.gethostbyaddr(ip)[0]
                    except Exception:
                        rev[ip] = None
                result["dns"] = result.get("dns", {})
                result["dns"]["reverse"] = rev
                progress.update(task, completed=100)

            # Check DNSSEC
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                TimeElapsedColumn(),
                console=console,
                transient=True
            ) as progress:
                task = progress.add_task(f"[{PRIMARY_BLUE}]Checking DNSSEC[/{PRIMARY_BLUE}]")
                dnssec_present = bool(result.get("dns", {}).get("records", {}).get("DS") or 
                                    result.get("dns", {}).get("records", {}).get("DNSKEY"))
                result["dns"]["dnssec_present"] = dnssec_present
                progress.update(task, completed=100)

            # Zone transfers if enabled
            if not self.no_axfr:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    TimeElapsedColumn(),
                    console=console,
                    transient=True
                ) as progress:
                    task = progress.add_task(f"[{PRIMARY_BLUE}]Checking zone transfers[/{PRIMARY_BLUE}]")
                    axfr_findings = []
                    nameservers = result.get("dns", {}).get("records", {}).get("NS", []) or []
                    
                    for i, ns in enumerate(nameservers):
                        progress.update(task, completed=(i/len(nameservers))*100)
                        host = ns.split()[0].strip(".") if " " in ns else ns.strip(".")
                        ok, out = self._try_axfr(host, domain)
                        if ok:
                            axfr_findings.append({"ns": host, "lines": out.splitlines()[:200]})
                    
                    result["dns"]["axfr"] = axfr_findings
                    progress.update(task, completed=100)

            # Enumerate subdomains
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                TimeElapsedColumn(),
                console=console,
                transient=True
            ) as progress:
                task = progress.add_task(f"[{PRIMARY_BLUE}]Enumerating subdomains[/{PRIMARY_BLUE}]")
                subdomains = self._enum_crtsh(domain)
                
                if self.wordlist:
                    progress.update(task, description=f"[{PRIMARY_BLUE}]Bruteforcing subdomains[/{PRIMARY_BLUE}]")
                    subs = self._brute_subdomains(domain, self.wordlist, dns.resolver.Resolver())
                    subdomains.extend(subs)
                
                result["subdomains"] = sorted(set(subdomains))
                progress.update(task, completed=100)

            # GeoIP lookup
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                TimeElapsedColumn(),
                console=console,
                transient=True
            ) as progress:
                task = progress.add_task(f"[{PRIMARY_BLUE}]Looking up GeoIP information[/{PRIMARY_BLUE}]")
                
                geo = {}
                for i, ip in enumerate(ips):
                    progress.update(task, completed=(i/len(ips))*100)
                    g = self._geoip(ip)
                    if g:
                        geo[ip] = g
                
                result["geoip"] = geo
                progress.update(task, completed=100)

            # HTTP and TLS checks
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                TimeElapsedColumn(),
                console=console,
                transient=True
            ) as progress:
                task = progress.add_task(f"[{PRIMARY_BLUE}]Checking HTTP and TLS[/{PRIMARY_BLUE}]")
                
                try:
                    cert = fetch_tls_cert(domain, 443, timeout=8)
                    result["tls"] = extract_cert_summary(cert)
                except Exception:
                    result["tls"] = {}
                
                progress.update(task, description=f"[{PRIMARY_BLUE}]Fingerprinting HTTP servers[/{PRIMARY_BLUE}]")
                http_fp = self._http_fingerprint(domain)
                result["http"] = http_fp
                
                progress.update(task, completed=100)

        return result

    def _safe(self, v):
        if v is None:
            return None
        if isinstance(v, (list, tuple, set)):
            # Filter out None values and convert remaining to strings
            return [str(x) for x in v if x is not None]
        # Handle date objects by getting just the date part
        if hasattr(v, 'strftime'):
            return v.strftime('%Y-%m-%d')
        return str(v)

    def _dig(self, domain: str, rr: str) -> List[str]:
        if not which("dig"):
            return []
        cmd = ["dig", "+short", rr, domain]
        if self.dns_server:
            cmd = ["dig", f"@{self.dns_server}", rr, domain, "+short"]
        code, out, _ = run_cmd(cmd)
        lines = [l.strip() for l in out.splitlines() if l.strip()]
        return lines

    def _dns_query(self, resolver: dns.resolver.Resolver, domain: str, rr: str) -> List[str]:
        try:
            answers = resolver.resolve(domain, rr, lifetime=self.timeout)
            vals = []
            for r in answers:
                vals.append(r.to_text())
            return vals
        except Exception:
            return []

    def _try_axfr(self, ns_host: str, domain: str):
        if not which("dig"):
            return False, ""
        cmd = ["dig", f"@{ns_host}", domain, "AXFR", "+time=5", "+tries=1"]
        code, out, err = run_cmd(cmd)
        if code == 0 and out and "XFR size" in out:
            return True, out
        return False, out or err

    def _enum_crtsh(self, domain: str) -> List[str]:
        try:
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            r = requests.get(url, timeout=self.timeout)
            if r.status_code != 200:
                return []
            data = r.json()
            subs = []
            for e in data:
                name = e.get("name_value", "")
                for part in name.split("\n"):
                    part = part.strip().lstrip("*.")
                    if part.endswith(domain):
                        subs.append(part)
            return subs
        except Exception:
            return []

    def _brute_subdomains(self, domain: str, wordlist_path: str, resolver: dns.resolver.Resolver) -> List[str]:
        subs = []
        try:
            with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                words = [w.strip() for w in f if w.strip()]
            with concurrent.futures.ThreadPoolExecutor(max_workers=64) as ex:
                futures = {ex.submit(self._resolve_sub, resolver, f"{w}.{domain}"): w for w in words}
                for fut in concurrent.futures.as_completed(futures):
                    val = fut.result()
                    if val:
                        subs.append(val)
        except Exception:
            pass
        return subs

    def _resolve_sub(self, resolver: dns.resolver.Resolver, fqdn: str) -> Optional[str]:
        try:
            resolver.resolve(fqdn, "A", lifetime=min(self.timeout, 5))
            return fqdn
        except Exception:
            return None

    def _geoip(self, ip: str) -> Optional[dict]:
        try:
            r = requests.get(f"https://ipapi.co/{ip}/json/", timeout=8)
            if r.status_code == 200:
                data = r.json()
                return {
                    "ip": ip,
                    "country": data.get("country_name"),
                    "city": data.get("city"),
                    "asn": data.get("asn"),
                    "org": data.get("org"),
                    "latitude": data.get("latitude"),
                    "longitude": data.get("longitude"),
                }
        except Exception:
            return None
        return None

    def _scan_ports(self, ip: str, ports: List[int]) -> Dict[int, dict]:
        findings = {}
        
        # Common service signatures
        SERVICE_PROBES = {
            21: b"220",  # FTP
            22: b"SSH",  # SSH
            25: b"SMTP",  # SMTP
            80: b"GET / HTTP/1.0\r\n\r\n",  # HTTP
            443: b"GET / HTTP/1.0\r\n\r\n",  # HTTPS
            3306: b"\x0a",  # MySQL
            5432: b"\x00\x00\x00\x08\x04\xd2\x16\x2f",  # PostgreSQL
            6379: b"INFO\r\n",  # Redis
            27017: b"\x41\x00\x00\x00",  # MongoDB
        }
        
        # Common service names
        SERVICE_NAMES = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            3306: "MySQL",
            5432: "PostgreSQL",
            6379: "Redis",
            27017: "MongoDB",
            8080: "HTTP-Proxy",
            8443: "HTTPS-Alt",
            3389: "RDP",
            5900: "VNC",
        }

        for p in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                
                if s.connect_ex((ip, p)) == 0:
                    service_info = {
                        "status": "open",
                        "service": SERVICE_NAMES.get(p, "unknown"),
                        "banner": None,
                        "version": None
                    }
                    
                    # Try to get service banner
                    try:
                        if p in SERVICE_PROBES:
                            s.send(SERVICE_PROBES[p])
                        else:
                            s.send(b"\\r\\n")
                        
                        banner = s.recv(1024)
                        decoded_banner = banner.decode(errors='ignore').strip()
                        
                        service_info["banner"] = decoded_banner
                        
                        # Try to extract version information
                        version_info = self._extract_version_info(p, decoded_banner)
                        if version_info:
                            service_info["version"] = version_info
                            
                        # Enhanced HTTP detection
                        if p in [80, 443, 8080, 8443]:
                            try:
                                s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                s2.settimeout(3)
                                s2.connect((ip, p))
                                s2.send(b"HEAD / HTTP/1.1\\r\\nHost: " + ip.encode() + b"\\r\\n\\r\\n")
                                http_resp = s2.recv(1024).decode(errors='ignore')
                                server = self._extract_http_server(http_resp)
                                if server:
                                    service_info["server"] = server
                                s2.close()
                            except:
                                pass
                            
                    except socket.timeout:
                        pass
                    except Exception as e:
                        service_info["error"] = str(e)
                    
                    findings[p] = service_info
                s.close()
            except:
                continue
                
        return findings
        
    def _extract_version_info(self, port: int, banner: str) -> Optional[str]:
        # SSH Version
        if port == 22 and "SSH" in banner:
            ssh_version = banner.split("\\n")[0].strip()
            return ssh_version
            
        # FTP Version
        if port == 21 and "220" in banner:
            ftp_version = banner.split("\\n")[0].strip()
            return ftp_version
            
        # SMTP Version
        if port == 25 and ("SMTP" in banner or "220" in banner):
            smtp_version = banner.split("\\n")[0].strip()
            return smtp_version
            
        # HTTP Server
        if port in [80, 443, 8080, 8443]:
            if "Server:" in banner:
                return banner.split("Server:")[1].split("\\n")[0].strip()
                
        # MySQL Version
        if port == 3306 and banner:
            try:
                return f"MySQL {banner.split(chr(0))[1].split('-')[1].split(chr(10))[0]}"
            except:
                pass
                
        # PostgreSQL Version
        if port == 5432 and banner:
            try:
                return f"PostgreSQL {banner.split(chr(0))[1]}"
            except:
                pass
                
        return None
        
    def _extract_http_server(self, response: str) -> Optional[str]:
        if "Server:" in response:
            server_line = [line for line in response.split("\\n") if "Server:" in line][0]
            return server_line.split("Server:")[1].strip()
        return None

    def _http_fingerprint(self, domain: str) -> dict:
        out = {"http": {}, "https": {}}
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=console,
            transient=True
        ) as progress:
            task = progress.add_task(f"[{PRIMARY_BLUE}]Checking HTTP[/{PRIMARY_BLUE}]", total=2)
            
            try:
                progress.update(task, description=f"[{PRIMARY_BLUE}]Testing HTTP connection[/{PRIMARY_BLUE}]")
                r = requests.get(f"http://{domain}", timeout=6, allow_redirects=True)
                out["http"] = {
                    "status": r.status_code,
                    "final_url": r.url,
                    "server": r.headers.get("Server"),
                    "powered_by": r.headers.get("X-Powered-By"),
                }
                
                # Display HTTP info
                http_table = Table(box=SQUARE)
                http_table.add_column(f"[{PRIMARY_BLUE}]Field[/{PRIMARY_BLUE}]")
                http_table.add_column(f"[{PRIMARY_BLUE}]Value[/{PRIMARY_BLUE}]")
                
                http_table.add_row(f"[{SECONDARY_BLUE}]Status[/{SECONDARY_BLUE}]", f"[{WHITE}]{r.status_code}[/{WHITE}]")
                http_table.add_row(f"[{SECONDARY_BLUE}]URL[/{SECONDARY_BLUE}]", f"[{WHITE}]{r.url}[/{WHITE}]")
                if r.headers.get("Server"):
                    http_table.add_row(f"[{SECONDARY_BLUE}]Server[/{SECONDARY_BLUE}]", f"[{WHITE}]{r.headers['Server']}[/{WHITE}]")
                if r.headers.get("X-Powered-By"):
                    http_table.add_row(f"[{SECONDARY_BLUE}]Powered By[/{SECONDARY_BLUE}]", f"[{WHITE}]{r.headers['X-Powered-By']}[/{WHITE}]")
                
                console.print()
                console.print(Panel(http_table, title=f"[{WHITE}]HTTP Server Information[/{WHITE}]", box=SQUARE))
                
            except Exception:
                pass
            
            progress.update(task, advance=1, description=f"[{PRIMARY_BLUE}]Testing HTTPS connection[/{PRIMARY_BLUE}]")
            
            try:
                r = requests.get(f"https://{domain}", timeout=8, allow_redirects=True)
                out["https"] = {
                    "status": r.status_code,
                    "final_url": r.url,
                    "server": r.headers.get("Server"),
                    "powered_by": r.headers.get("X-Powered-By"),
                }
                
                # Display HTTPS info
                https_table = Table(box=SQUARE)
                https_table.add_column(f"[{PRIMARY_BLUE}]Field[/{PRIMARY_BLUE}]")
                https_table.add_column(f"[{PRIMARY_BLUE}]Value[/{PRIMARY_BLUE}]")
                
                https_table.add_row(f"[{SECONDARY_BLUE}]Status[/{SECONDARY_BLUE}]", f"[{WHITE}]{r.status_code}[/{WHITE}]")
                https_table.add_row(f"[{SECONDARY_BLUE}]URL[/{SECONDARY_BLUE}]", f"[{WHITE}]{r.url}[/{WHITE}]")
                if r.headers.get("Server"):
                    https_table.add_row(f"[{SECONDARY_BLUE}]Server[/{SECONDARY_BLUE}]", f"[{WHITE}]{r.headers['Server']}[/{WHITE}]")
                if r.headers.get("X-Powered-By"):
                    https_table.add_row(f"[{SECONDARY_BLUE}]Powered By[/{SECONDARY_BLUE}]", f"[{WHITE}]{r.headers['X-Powered-By']}[/{WHITE}]")
                
                console.print()
                console.print(Panel(https_table, title=f"[{WHITE}]HTTPS Server Information[/{WHITE}]", box=SQUARE))
                
            except Exception:
                pass
            
            progress.update(task, completed=100)
        
        return out
