# 🔍 SPYLO - Advanced OSINT Framework<div align="center"><div align="center">



<div align="center">  <img src=".github/assets/banner.png" alt="SPYLO Tool Banner" width="800"/>  <img src=".github/assets/banner.png" alt="SPYLO Tool Banner" width="800"/>



![SPYLO Banner](https://img.shields.io/badge/OSINT-Tool-blue?style=flat-square)

![Python Version](https://img.shields.io/badge/Python-3.9%2B-green?style=flat-square)

![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)  <p align="center">  <p align="center">

![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)

    <img src="https://img.shields.io/badge/Python-3.9+-blue.svg" alt="Python Version">    <img src="https://img.shields.io/badge/Python-3.9+-blue.svg" alt="Python Version">

**A powerful and elegant Open Source Intelligence (OSINT) framework for comprehensive domain and username reconnaissance.**

    <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License">    <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License">

```

    ███████╗██████╗ ██╗   ██╗██╗      ██████╗     <img src="https://img.shields.io/badge/OS-Linux%20%7C%20Windows%20%7C%20macOS-brightgreen" alt="OS Support">    <img src="https://img.shields.io/badge/OS-Linux%20%7C%20Windows%20%7C%20macOS-brightgreen" alt="OS Support">

    ██╔════╝██╔══██╗╚██╗ ██╔╝██║     ██╔═══██╗

    ███████╗██████╔╝ ╚████╔╝ ██║     ██║   ██║    <a href="https://twitter.com/S4ddler"><img src="https://img.shields.io/twitter/follow/S4ddler?style=social" alt="Twitter Follow"></a>    <a href="https://twitter.com/S4ddler"><img src="https://img.shields.io/twitter/follow/S4ddler?style=social" alt="Twitter Follow"></a>

    ╚════██║██╔═══╝   ╚██╔╝  ██║     ██║   ██║

    ███████║██║        ██║   ███████╗╚██████╔╝  </p>  </p>

    ╚══════╝╚═╝        ╚═╝   ╚══════╝ ╚═════╝ 

```



</div>  <p align="center">🔍 أداة OSINT قوية وحديثة مع واجهة جميلة لجمع المعلومات والاستطلاع</p>  <p align="center">🔍 A powerful and beautiful OSINT command line tool with modern interface for reconnaissance.</p>



---



## 📖 Overview<pre><pre>



**SPYLO** is a comprehensive OSINT (Open Source Intelligence) framework designed for security researchers, penetration testers, and security professionals to gather intelligence about domains and usernames from open sources. The tool provides an interactive command-line interface with modern UI and powerful reconnaissance capabilities.    ███████╗██████╗ ██╗   ██╗██╗      ██████╗     ███████╗██████╗ ██╗   ██╗██╗      ██████╗ 



### Key Highlights    ██╔════╝██╔══██╗╚██╗ ██╔╝██║     ██╔═══██╗    ██╔════╝██╔══██╗╚██╗ ██╔╝██║     ██╔═══██╗

- 🎯 **Interactive CLI** with intuitive command structure

- 🌐 **Domain Reconnaissance** - DNS, WHOIS, Port Scanning, Subdomain Enumeration    ███████╗██████╔╝ ╚████╔╝ ██║     ██║   ██║    ███████╗██████╔╝ ╚████╔╝ ██║     ██║   ██║

- 👤 **Username Search** - Search across 80+ social platforms

- 📊 **Multiple Output Formats** - JSON, CSV, Markdown, Table Display    ╚════██║██╔═══╝   ╚██╔╝  ██║     ██║   ██║    ╚════██║██╔═══╝   ╚██╔╝  ██║     ██║   ██║

- ⚡ **Concurrent Scanning** - Fast parallel processing

- 🔐 **Security-Focused** - Passive techniques with optional port scanning    ███████║██║        ██║   ███████╗╚██████╔╝    ███████║██║        ██║   ███████╗╚██████╔╝



---    ╚══════╝╚═╝        ╚═╝   ╚══════╝ ╚═════╝     ╚══════╝╚═╝        ╚═╝   ╚══════╝ ╚═════╝ 



## ⚡ Quick Start</pre></pre>



### Prerequisites</div></div>

- Python 3.9 or higher

- pip (Python package manager)

- Internet connection

---

### Installation



```bash

# Clone the repository## 📖 نظرة عامة## 📖 Overview

git clone https://github.com/S4ddler/floppa.git

cd floppa



# Create virtual environment**SPYLO** هي أداة OSINT (Open Source Intelligence) قوية وحديثة مصممة لجمع معلومات شاملة عن النطاقات والمستخدمين. توفر الأداة واجهة تفاعلية سهلة الاستخدام مع العديد من الميزات المتقدمة لأغراض الاستطلاع والأمان.SPYLO is a powerful OSINT (Open Source Intelligence) framework designed for comprehensive domain and username reconnaissance. It provides detailed insights through various modules, helping security researchers and professionals gather intelligence efficiently.

python3 -m venv .venv

source .venv/bin/activate  # On Linux/Mac

# or

.venv\Scripts\activate     # On Windows---## ✨ Features



# Install dependencies

pip install -r requirements.txt

## 🚀 البدء السريع### 🌐 Domain Reconnaissance

# Run SPYLO

python main.py- **DNS Analysis**

```

### المتطلبات  - Comprehensive DNS record enumeration (A, AAAA, CNAME, MX, NS, TXT, SOA, CAA, DS, DNSKEY)

### Basic Usage

- Python 3.9 أو أحدث  - Zone transfer testing

```bash

# Once the program starts, you'll see the interactive shell- pip (مدير الحزم)  - DNSSEC validation

spylo> help                              # Show all commands

- اتصال إنترنت  - Reverse DNS lookups

# Add targets

spylo> add example domain example.com    # Add a domain

spylo> add user1 username johndoe        # Add a username

### التثبيت- **Service Discovery & Port Scanning**

# Scan targets

spylo> scan example                      # Full domain scan  - Smart port scanning with real-time results

spylo> scan example dns                  # DNS enumeration only

spylo> scan example ports                # Port scanning only1. **استنساخ المستودع:**  - Advanced service fingerprinting for common ports:

spylo> scan example whois                # WHOIS lookup only

spylo> scan user1                        # Search for username```bash    - Web servers (HTTP/HTTPS)



# Manage targetsgit clone https://github.com/S4ddler/floppa.git    - SSH servers with version detection

spylo> list                              # List all targets

spylo> del example                       # Delete a targetcd floppa    - FTP services and banner analysis

spylo> clear                             # Clear all targets

```    - Database services (MySQL, PostgreSQL, MongoDB, Redis)

# Exit

spylo> exit    - Mail servers (SMTP, POP3, IMAP)

```

2. **إنشاء بيئة افتراضية:**    - Remote access services (RDP, VNC)

---

```bash    - DNS services

## 🎯 Features

# على Linux/Mac:    - Custom port ranges support

### 🌐 Domain Reconnaissance

python3 -m venv .venv  - Intelligent banner grabbing and analysis

#### DNS Analysis

- **Comprehensive DNS Record Enumeration**: A, AAAA, CNAME, MX, NS, TXT, SOA, CAA, DS, DNSKEYsource .venv/bin/activate  - Service version detection and enumeration

- **Zone Transfer Testing**: AXFR attempts against nameservers

- **DNSSEC Validation**: Check if domain has DNSSEC enabled  - Real-time service identification

- **Reverse DNS Lookup**: Find hostnames from IP addresses

# على Windows:  - TLS/SSL certificate analysis and validation

#### Port Scanning & Service Detection

- **Smart Port Scanning**: Scan common and custom portspython -m venv .venv  - Concurrent scanning for faster results

- **Service Fingerprinting**: Identify services on open ports

  - Web servers (HTTP/HTTPS with version detection).venv\Scripts\activate  - Rate limiting and timeout controls

  - SSH servers with version banners

  - FTP, SMTP, POP3, IMAP detection```

  - Database services (MySQL, PostgreSQL, MongoDB, Redis)

  - Remote access services (RDP, VNC)- **Web Technologies**

- **TLS/SSL Certificate Analysis**: Extract certificate information and validity

- **Banner Grabbing**: Retrieve service banners for version identification3. **تثبيت المكتبات المطلوبة:**  - HTTP/HTTPS server fingerprinting

- **Concurrent Scanning**: Fast parallel port checks

```bash  - Web server version detection

#### WHOIS Information

- Domain registration detailspip install -r requirements.txt  - Technology stack identification

- Registrar information

- Domain creation, expiration, and update dates```

- Nameserver records

- Domain status- **Additional Features**



#### Subdomain Enumeration4. **تشغيل الأداة:**  - Subdomain enumeration via crt.sh

- Certificate Transparency (crt.sh) search

- Wordlist-based brute-forcing```bash  - Custom wordlist support for subdomain brute-forcing

- GeoIP location data for discovered IPs

- Reverse DNS lookupspython main.py  - GeoIP location data



### 👤 Username Reconnaissance```  - WHOIS information gathering



#### Social Media & Platform Search

- **80+ Supported Platforms**:

  - Social Networks: Twitter, Facebook, Instagram, TikTok, LinkedIn, Mastodon, Bluesky---### 👤 Username Reconnaissance

  - Development: GitHub, GitLab, StackOverflow, Dev.to, CodePen, Medium

  - Gaming: Steam, Twitch, Discord, YouTube- **Advanced Social Media Scanning**

  - Security: HackerOne, Bugcrowd, TryHackMe, HackerNews

  - Professional: LinkedIn, Keybase, Academia## 💡 دليل الاستخدام  - Massive sites catalog in JSON format

  - And 50+ more platforms...

  - Adaptive detection rules

#### Advanced Detection

- **Intelligent Detection Rules**: Adaptive response analysis### واجهة سطر الأوامر التفاعلية  - Cross-platform username search

- **Concurrent Scanning**: Fast parallel searches across platforms

- **Proxy Support**: Route requests through proxies  - Social media presence detection

- **User-Agent Rotation**: Rotate browser identities

- **Smart Retry Logic**: Retry on transient failuresتتوفر الأداة بواجهة تفاعلية سهلة الاستخدام. إليك الأوامر الأساسية:  - Profile information gathering

- **Timeout Handling**: Graceful handling of slow responses

- **Performance Features**

### 📊 Output Formats

#### 1️⃣ إضافة أهداف (Targets)  - Asynchronous scanning

Results are automatically saved in the `out/` directory in multiple formats:

  - Smart retries and rate-limit handling

- **JSON**: Structured data for programmatic processing

- **CSV**: Spreadsheet-compatible format```bash  - Proxy support with rotation

- **Markdown**: Documentation-ready reports

- **Table**: Beautiful terminal display# إضافة نطاق  - User-agent rotation



---spylo> add example domain example.com  - Concurrent scanning



## 📋 Command ReferenceAdded domain 'example.com' with alias 'example'



### Target Management## 🚀 Quick Start



| Command | Description | Example |# إضافة اسم مستخدم

|---------|-------------|---------|

| `add <alias> <type> <value>` | Add a new target | `add google domain google.com` |spylo> add user1 username johndoe### Installation

| `del <alias>` | Delete a target | `del google` |

| `list` or `l` | List all targets | `list` |Added username 'johndoe' with alias 'user1'

| `clear` or `c` | Clear all targets | `clear` |

1. Clone the repository:

### Scanning

# استخدام الاختصار 'a'```bash

| Command | Description | Example |

|---------|-------------|---------|spylo> a twitter username elonmuskgit clone https://github.com/S4ddler/floppa.git

| `scan <alias>` | Full reconnaissance scan | `scan google` |

| `scan <alias> dns` | DNS enumeration only | `scan google dns` |```cd floppa

| `scan <alias> ports` | Port scanning only | `scan google ports` |

| `scan <alias> whois` | WHOIS lookup only | `scan google whois` |```

| `s <alias>` | Short form of scan | `s google` |

#### 2️⃣ المسح والاستطلاع

### Settings

2. Create and activate a virtual environment:

| Command | Description | Example |

|---------|-------------|---------|**مسح النطاقات:**```bash

| `set <option> <value>` | Configure setting | `set timeout 30` |

| `config` | Show current configuration | `config` |```bash# Create virtual environment



### Utility# مسح كامل (WHOIS + DNS + Ports)python -m venv .venv



| Command | Description |spylo> scan example

|---------|-------------|

| `help` or `?` | Show help message |# Activate virtual environment

| `exit` or `q` | Exit the program |

# مسح محدد# On macOS/Linux:

---

spylo> scan example dns      # معلومات DNS فقطsource .venv/bin/activate

## ⚙️ Advanced Configuration

spylo> scan example ports    # مسح المنافذ# On Windows:

### Session Settings

spylo> scan example whois    # معلومات WHOIS.venv\Scripts\activate

You can customize SPYLO's behavior using the `set` command:



```bash

# Adjust timeouts# استخدام الاختصار 's'# Install requirements

spylo> set timeout 30              # Request timeout in seconds

spylo> s examplepip install -r requirements.txt

# Use a proxy

spylo> set proxy http://localhost:8080``````



# Control retries

spylo> set retries 5               # Number of retry attempts

**مسح أسماء المستخدمين:**3. Run the tool:

# Customize port scanning

spylo> set top_ports 80,443,22,3306,5432```bash```bash



# Set custom DNS server# البحث عن اسم المستخدم في جميع المنصاتpython main.py

spylo> set dns_server 8.8.8.8

spylo> scan user1```

# Specify wordlist for subdomain brute-forcing

spylo> set wordlist subdomains.txt



# View current configuration# أو## 💡 Usage Examples

spylo> config

```spylo> s user1



---```### Command Line Interface



## 📁 Project Structure



```#### 3️⃣ إدارة الأهدافSPYLO provides an interactive shell with various commands. Here are the most common operations:

floppa/

├── main.py                    # Main program entry point

├── requirements.txt           # Python dependencies

├── README.md                  # This file```bash#### 1. Adding Targets

│

├── core/# عرض جميع الأهداف المضافة

│   ├── reporting.py          # Report generation and export

│   │   ├── save_reports()    # Save results in multiple formatsspylo> list```bash

│   │   ├── print_table_summary()  # Display results

│   │   └── render_markdown() # Convert to Markdown# أو# Add a domain target

│   │

│   └── utils.py              # Utility functionsspylo> lspylo> add example domain example.com

│       ├── grab_banner()     # Extract service banners

│       ├── fetch_tls_cert()  # Retrieve SSL/TLS certificates

│       └── extract_cert_summary() # Parse certificate details

│# حذف جميع الأهداف# Add a username target

├── modules/

│   ├── domain_osint.py       # Domain reconnaissance modulespylo> clearspylo> add johndoe username johndoe

│   │   ├── scan_whois()      # WHOIS lookup

│   │   ├── scan_dns()        # DNS enumeration# أو

│   │   ├── scan_ports()      # Port scanning

│   │   └── scan()            # Full reconnaissancespylo> c# Short form using 'a'

│   │

│   └── username_osint.py     # Username search modulespylo> a twitter username elonmusk

│       ├── scan()            # Search across platforms

│       └── _probe_site()     # Individual platform check# حذف هدف محدد```

│

└── data/spylo> del example

    └── sites.json            # Database of 80+ supported platforms

``````#### 2. Scanning Targets



---



## 🔍 Usage Examples#### 4️⃣ الإعدادات والمساعدة```bash



### Example 1: Full Domain Scan# Full domain scan



```bash```bashspylo> scan example

spylo> add google domain google.com

Added domain 'google.com' with alias 'google'# عرض جميع الأوامر



spylo> scan googlespylo> help# Specific domain scan modules

[Scanning google.com...]

# أوspylo> scan example whois    # WHOIS lookup only

# Displays:

# - WHOIS informationspylo> ?spylo> scan example dns      # DNS enumeration only

# - DNS records (A, AAAA, MX, NS, TXT, etc.)

# - Open ports and servicesspylo> scan example ports    # Port scanning only

# - Subdomains

# - GeoIP information# عرض الإعدادات الحالية

# - SSL certificate details

spylo> config# Username scan (checks all platforms)

✓ Results saved to: out/domain_google.json

```spylo> scan johndoe



### Example 2: Username Search# تغيير إعداد



```bashspylo> set timeout 20# Short form using 's'

spylo> add john username johndoe

Added username 'johndoe' with alias 'john'spylo> s example



spylo> scan john# الخروج من البرنامج```

[Searching johndoe across 80+ platforms...]

spylo> exit

# Results might show:

# - GitHub: https://github.com/johndoe# أو#### 3. Managing Targets

# - Twitter: https://twitter.com/johndoe

# - StackOverflow: https://stackoverflow.com/users/johndoespylo> q

# - LinkedIn: https://linkedin.com/in/johndoe

``````bash

✓ Found 4 accounts | Success Rate: 5.0%

✓ Results saved to: out/username_johndoe.json# List all targets

```

---spylo> list

### Example 3: Targeted Domain Scan with Custom Settings

# or

```bash

spylo> set timeout 30## ✨ الميزات الكاملةspylo> l

spylo> set proxy http://127.0.0.1:8080

spylo> add site domain example.com



spylo> scan site dns### 🌐 استطلاع النطاقات (Domain Reconnaissance)# Clear all targets

[DNS records for example.com]

spylo> clear

spylo> scan site ports

[Port scanning...]#### تحليل DNS ✅# or



spylo> scan site whois- تعداد سجلات DNS شاملة:spylo> c

[WHOIS information...]

```  - **A و AAAA** (IPv4 و IPv6)```



---  - **CNAME, MX, NS, TXT**



## 🔒 Security Considerations  - **SOA, CAA, DS, DNSKEY**#### 4. Getting Help



### Important Notes- اختبارات Zone Transfer (AXFR)



⚠️ **Before using SPYLO, ensure:**- التحقق من DNSSEC```bash



1. **Authorization**: You have explicit permission to scan targets- بحث DNS معكوس (Reverse DNS)# Show all commands

2. **Legal Compliance**: Check local laws and regulations

3. **Respect ToS**: Follow terms of service for each platformspylo> help

4. **Rate Limiting**: Use proxies and delays to avoid blocking

5. **Responsible Disclosure**: Report vulnerabilities responsibly#### مسح المنافذ وخدمات الشبكة ✅# or



### Ethical Usage- مسح ذكي للمنافذ الشهيرةspylo> ?



- SPYLO uses primarily **passive reconnaissance** techniques- كشف الخدمات والإصدارات:

- Optional port scanning is non-intrusive

- No credentials are required or targeted  - 🌐 خوادم الويب (HTTP/HTTPS)# Exit the program

- No data modification is performed

- Use for authorized security assessments only  - 🔐 SSH مع كشف الإصدارspylo> exit



---  - 📂 FTP و Banner Grabbing# or



## 🐛 Troubleshooting  - 🗄️ قواعد البيانات (MySQL, PostgreSQL, MongoDB, Redis)spylo> q



### Common Issues  - 📧 خوادم البريد (SMTP, POP3, IMAP)```



| Issue | Solution |  - 🖥️ خدمات الوصول البعيد (RDP, VNC)

|-------|----------|

| `ModuleNotFoundError` | Run `pip install -r requirements.txt` |- تحليل شهادات TLS/SSLThe tool will guide you through all available options:

| Connection timeout | Increase timeout: `set timeout 30` |

| Rate limited | Use proxy: `set proxy http://...` |- Fingerprinting متقدم للخدمات

| Slow scanning | Enable concurrent scans (automatic) |

| SSL warnings | Can be safely ignored, doesn't affect functionality |- مسح متزامن (Concurrent Scanning)1. **Basic Configuration**



### Getting Help   - Scan type (domain or username)



```bash#### معلومات WHOIS ✅   - Target to scan

# Show all available commands

spylo> help- جمع معلومات تسجيل النطاق   - Output directory



# Show command-specific help- معلومات المسجل (Registrar)   - Output formats

spylo> help scan

- تواريخ الإنشاء والتجديد

# Display current configuration

spylo> config- خوادم الأسماء (Nameservers)2. **Advanced Options**

```

- حالة النطاق   - Proxy settings

---

   - Request timeout

## 📊 Output Examples

#### تعداد النطاقات الفرعية ✅   - Retry attempts

### JSON Output Structure

- البحث عبر crt.sh

```json

{- دعم wordlists مخصصة3. **Module-Specific Options**

  "meta": {

    "module": "domain",- Brute-force ذكي للنطاقات الفرعية

    "target": "example.com",

    "timestamp_utc": "20251203T120000Z"- معلومات GeoIP للعناوين   For Username Search:

  },

  "result": {   - Concurrent tasks limit

    "whois": {

      "domain_name": "example.com",### 👤 استطلاع أسماء المستخدمين (Username Reconnaissance)

      "registrar": "Example Inc.",

      "creation_date": "1995-08-14",   For Domain Reconnaissance:

      "nameservers": ["ns1.example.com", "ns2.example.com"]

    },#### البحث عبر منصات متعددة ✅   - Subdomain wordlist path

    "dns": {

      "records": {- **80+ منصة مدعومة** بما فيها:   - Port scanning configuration

        "A": ["93.184.216.34"],

        "MX": ["10 mail.example.com"],   - DNS server settings

        "NS": ["ns1.example.com", "ns2.example.com"]

      }**الشبكات الاجتماعية:**   - AXFR zone-transfer options

    },

    "ports": {- Twitter, Facebook, Instagram, TikTok, LinkedIn, Threads, Mastodon, Bluesky

      "93.184.216.34": {

        "80": {"state": "open", "service": "HTTP"},## 🛠️ Available Options

        "443": {"state": "open", "service": "HTTPS"}

      }**منصات التطوير:**

    }

  }- GitHub, GitLab, StackOverflow, Dev.to, CodePen, Medium, Substack, FreeCodeCampThe interactive menu will guide you through configuring:

}

```



### CSV Output Format**منصات الألعاب والترفيه:**Basic Settings:



```csv- Steam, Twitch, Discord, YouTube, Twitch, Dailymotion, Vimeo- Scan Type: Choose between domain or username scanning

type,target,record_type,value

domain,example.com,A,93.184.216.34- Target: Domain name or username to investigate

domain,example.com,MX,10 mail.example.com

domain,example.com,NS,ns1.example.com**منصات الأمان والبحث:**- Output Directory: Where to save results (default: out)

username,johndoe,site,GitHub

username,johndoe,url,https://github.com/johndoe- HackerOne, Bugcrowd, TryHackMe, HackerNews, Academia, Keybase- Output Formats: table,json,csv,md (default: table,json)

```

- Proxy: Optional HTTP proxy URL

---

**منصات أخرى:**- Timeout: Request timeout in seconds (default: 15)

## 🚀 Performance Tips

- Pinterest, Reddit, Telegram, WhatsApp, WeChat, Snapchat, Quora, و أكثر من 50 منصة أخرى...- Retries: Number of retry attempts (default: 2)

1. **Use Concurrent Scanning**: Enable for faster results (default: on)

2. **Adjust Timeout**: Increase for slow networks, decrease for faster responses

3. **Use Wordlists**: For subdomain enumeration, use quality wordlists

4. **Proxy Usage**: Rotate proxies to avoid rate limiting#### خصائص المسح ✅Username Scan Settings:

5. **Batch Operations**: Scan multiple targets in sequence

- كشف متقدم واستجابة ذكية- Concurrency: Number of parallel tasks (default: 50)

---

- دعم Proxy

## 📦 Dependencies

- تدوير User-AgentDomain Scan Settings:

All dependencies are listed in `requirements.txt`:

- إعادة محاولة ذكية عند الفشل- Wordlist: Path to subdomain wordlist

```

aiohttp>=3.8.0- معالجة تجاوز المهلة الزمنية- Top Ports: Ports to scan (includes common web, mail, database services)

beautifulsoup4>=4.9.3

dnspython>=2.2.0- مسح متزامن لتسريع النتائج- Port Scanning: Enable/disable port scanning

requests>=2.26.0

rich>=10.12.0- DNS Settings: Custom DNS server and AXFR options

python-whois>=0.7.3

cryptography>=3.4.7### 📊 تنسيقات الإخراج ✅```

```



Install with:

```bashتدعم الأداة عدة تنسيقات للإخراج:## 📊 Output Example

pip install -r requirements.txt

```- **JSON:** لمعالجة برمجية



---- **CSV:** متوافق مع Excel والجداولWhen scanning a domain, you'll see output like this:



## 🤝 Contributing- **Markdown:** جاهز للتوثيق



Contributions are welcome! To contribute:- **Table:** عرض جميل في Terminal```



1. Fork the repository╭──────────────── DNS Records ────────────────╮

2. Create a feature branch (`git checkout -b feature/AmazingFeature`)

3. Commit your changes (`git commit -m 'Add AmazingFeature'`)---│ Record   Value                              │

4. Push to the branch (`git push origin feature/AmazingFeature`)

5. Open a Pull Request├──────────────────────────────────────────────┤



---## 📋 أمثلة عملية واقعية│ A        93.184.216.34                      │



## 📝 License│ AAAA     2606:2800:220:1:248:1893:25c8:1946│



This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.### مثال 1️⃣: مسح نطاق كامل│ NS       a.iana-servers.net                 │



---│          b.iana-servers.net                 │



## ⭐ Acknowledgments```bash│ MX       0 .                                │



- Built with Python and modern librariesspylo> add google domain google.com╰──────────────────────────────────────────────╯

- Inspired by OSINT best practices

- Community feedback and contributions✓ Added domain 'google.com' with alias 'google'



---╭──────────── Port Scan Results ──────────────╮



## 📞 Support & Contactspylo> scan google│ IP            Port    Service    Details    │



- **GitHub Issues**: [Report bugs or request features](https://github.com/S4ddler/floppa/issues)├──────────────────────────────────────────────┤

- **Discussions**: [Ask questions or share ideas](https://github.com/S4ddler/floppa/discussions)

- **Twitter**: [@S4ddler](https://twitter.com/S4ddler)═══════════════════════════════════════════════════════════│ 93.184.216.34 80      HTTP       nginx      │



---                    WHOIS Information│               443     HTTPS      TLS 1.3    │



## ℹ️ Additional Information═══════════════════════════════════════════════════════════╰──────────────────────────────────────────────╯



| Item | Details |│ Field            │ Value                                │```

|------|---------|

| Version | 0.1.0 |├──────────────────┼──────────────────────────────────────┤

| Status | Active Development |

| Python | 3.9+ |│ Domain Name      │ google.com                           │When scanning a username, you'll see results like this:

| Platform | Windows, Linux, macOS |

| License | MIT |│ Registrar        │ MarkMonitor, Inc.                    │

| Last Updated | December 2025 |

│ Created          │ 1997-09-15                           │```

---

│ Expires          │ 2028-09-14                           │╭───────────── Found Accounts ─────────────╮

<div align="center">

│ Nameservers      │ • ns1.google.com                     ││ Platform    URL                         │

**Made with ❤️ by the SPYLO Team**

│                  │ • ns2.google.com                     │├───────────────────────────────────────────┤

If you find this tool useful, please consider giving it a ⭐ on GitHub!

│                  │ • ns3.google.com                     ││ GitHub      https://github.com/johndoe   │

</div>

│                  │ • ns4.google.com                     ││ Twitter     https://twitter.com/johndoe  │

═══════════════════════════════════════════════════════════│ LinkedIn    https://linkedin.com/in/... │

╰───────────────────────────────────────────╯

═══════════════════════════════════════════════════════════```

                    DNS Records

═══════════════════════════════════════════════════════════## 🛠️ System Requirements

│ Record │ Value                                          │

├────────┼────────────────────────────────────────────────┤- Python 3.9+

│ A      │ 142.250.185.46                                 │- `dig` (bind9-dnsutils) - Will fallback to dnspython if not available

│ AAAA   │ 2607:f8b0:4004:80d::200e                      │

│ MX     │ 10 smtp.google.com                             │## ✨ User Interface Features

│        │ 20 alt1.aspmx.google.com                       │

│ NS     │ ns1.google.com                                 │- Modern, minimal color scheme using:

│        │ ns2.google.com                                 │  - Primary Blue (#0066cc) for main elements

│ TXT    │ v=spf1 include:_spf.google.com ...             │  - Secondary Blue (#4d94ff) for highlights

═══════════════════════════════════════════════════════════  - Clean white for important information

- Interactive command-line interface with:

═══════════════════════════════════════════════════════════  - Organized command groups

                 Port Scan Results  - Shortcuts for common operations

═══════════════════════════════════════════════════════════  - Context-sensitive help

│ IP               │ Port │ Service │ Details           │- Real-time progress indicators:

├──────────────────┼──────┼─────────┼───────────────────┤  - Animated spinners

│ 142.250.185.46   │ 80   │ HTTP    │ nginx             │  - Time elapsed tracking

│                  │ 443  │ HTTPS   │ TLS 1.3 valid     │  - Detailed status updates

│                  │ 443  │ HTTPS   │ Certificate valid │- Clean, organized output:

═══════════════════════════════════════════════════════════  - Modern table layouts

  - Grouped information panels

✓ Scan complete. Results saved to: out/  - Color-coded results

```  - Progress bars for long operations



### مثال 2️⃣: البحث عن اسم مستخدم## 📋 Example Output



```bash<details>

spylo> add john username johndoe<summary>Click to see example username scan output</summary>

✓ Added username 'johndoe' with alias 'john'

![Username Scan](.github/assets/username-scan.png)

spylo> scan john</details>

[Searching for johndoe across 80+ platforms...]

<details>

▶ 15% complete - [████░░░░░░░░░░░░░░░░░░░░░░]<summary>Click to see example domain scan output</summary>



╔════════════════════════════════════════════════════════╗![Domain Scan](.github/assets/domain-scan.png)

║              Found Account                            ║</details>

╟────────────────────────────────────────────────────────╢

║ GitHub                                                ║## 🔒 Security Notes

║ https://github.com/johndoe                            ║

╚════════════════════════════════════════════════════════╝- Only passive techniques are implemented by default except optional lightweight port scanning

- Always ensure you have proper authorization before scanning any targets

╔════════════════════════════════════════════════════════╗- Use proxy options when necessary to avoid rate limiting

║              Found Account                            ║- Be mindful of service terms and conditions when performing username searches

╟────────────────────────────────────────────────────────╢

║ Twitter                                               ║
║ https://twitter.com/johndoe                           ║
╚════════════════════════════════════════════════════════╝

╔════════════════════════════════════════════════════════╗
║              Found Account                            ║
╟────────────────────────────────────────────────────────╢
║ StackOverflow                                         ║
║ https://stackoverflow.com/users/johndoe               ║
╚════════════════════════════════════════════════════════╝

═════════════════════════════════════════════════════════
                 Scan Summary
═════════════════════════════════════════════════════════
• Total Sites: 80
• Found: 3
• Success Rate: 3.8%
• Results saved to: out/
═════════════════════════════════════════════════════════
```

### مثال 3️⃣: المسح المتقدم مع إعدادات مخصصة

```bash
spylo> set timeout 30
✓ Timeout set to 30 seconds

spylo> set retries 5
✓ Retries set to 5

spylo> set proxy http://127.0.0.1:8080
✓ Proxy set to http://127.0.0.1:8080

spylo> add wordpress domain wordpress.com
✓ Added domain 'wordpress.com' with alias 'wordpress'

spylo> scan wordpress dns
[Gathering DNS records...]
✓ Scan complete
```

---

## 🛠️ الإعدادات المتقدمة

### متغيرات الجلسة (Session Variables)

يمكن تعديل الإعدادات باستخدام الأمر `set`:

| الإعداد | الوصف | المثال |
|--------|--------|--------|
| `timeout` | المهلة الزمنية لكل طلب (ثانية) | `set timeout 30` |
| `proxy` | خادم وسيط للطلبات | `set proxy http://localhost:8080` |
| `retries` | عدد المحاولات عند الفشل | `set retries 5` |
| `top_ports` | المنافذ المراد مسحها | `set top_ports 80,443,22,3306` |
| `wordlist` | ملف قائمة الكلمات للنطاقات | `set wordlist /path/to/wordlist.txt` |
| `dns_server` | خادم DNS مخصص | `set dns_server 8.8.8.8` |

### أمثلة الإعدادات:

```bash
# تغيير Timeout
spylo> set timeout 30

# تغيير المنفذ (Proxy)
spylo> set proxy http://localhost:8080

# تغيير عدد المحاولات
spylo> set retries 5

# تغيير أكثر المنافذ استخداماً
spylo> set top_ports 80,443,22,3306,5432,8080,8443

# تغيير wordlist للنطاقات الفرعية
spylo> set wordlist subdomains.txt

# تغيير خادم DNS
spylo> set dns_server 8.8.8.8

# عرض الإعدادات الحالية
spylo> config
```

---

## 📁 هيكل المشروع

```
floppa/
├── main.py                      # البرنامج الرئيسي
├── requirements.txt             # المكتبات المطلوبة
├── README.md                    # هذا الملف
│
├── core/
│   ├── reporting.py            # معالجة التقارير والإخراج
│   │   ├── save_reports()      # حفظ النتائج بصيغ مختلفة
│   │   ├── print_table_summary()  # طباعة ملخص جدول
│   │   ├── render_markdown()   # تحويل لـ Markdown
│   │   └── _save_csv()         # حفظ بصيغة CSV
│   │
│   └── utils.py                # وظائف مساعدة
│       ├── ensure_dir()        # إنشاء مجلدات
│       ├── grab_banner()       # استخراج بيانات الخدمة
│       ├── fetch_tls_cert()    # جلب شهادة SSL
│       └── extract_cert_summary() # ملخص الشهادة
│
├── modules/
│   ├── domain_osint.py         # استطلاع النطاقات
│   │   ├── scan_whois()        # مسح WHOIS
│   │   ├── scan_dns()          # مسح DNS
│   │   ├── scan_ports()        # مسح المنافذ
│   │   └── scan()              # مسح شامل
│   │
│   └── username_osint.py       # البحث عن أسماء المستخدمين
│       ├── scan()              # البحث عبر المنصات
│       └── _probe_site()       # الفحص الفردي للمنصة
│
└── data/
    └── sites.json              # قائمة المنصات المدعومة (80+ منصة)
```

---

## 🔒 ملاحظات أمنية مهمة ⚠️

**قبل الاستخدام، تأكد من:**

1. ✅ لديك إذن صريح للمسح على الأهداف
2. ✅ تتبع سياسات الاستخدام لكل منصة
3. ✅ استخدام Proxy عند الحاجة لتجنب التقييد
4. ✅ المسح يستخدم تقنيات سلبية (Passive) بشكل أساسي
5. ✅ عدم استخدام الأداة بأغراض غير قانونية

---

## 🚀 الميزات المتقدمة

### المسح المتزامن (Concurrent Scanning) ⚡
- البحث السريع عبر منصات متعددة بالتوازي
- تحسين الأداء بشكل كبير
- إدارة ذكية للموارد

### معالجة الأخطاء الحذرة 🛡️
- إعادة محاولة تلقائية عند الفشل
- معالجة تجاوز المهلة الزمنية
- تجنب الحظر من قبل المنصات

### تدوير User-Agent 🔄
- محاكاة متصفحات مختلفة
- تجنب الكشف والحظر
- توازن محاكاة واقعي

### واجهة مستخدم حديثة 🎨
- ألوان جميلة ومنظمة
- رسائل واضحة وسهلة الفهم
- شرح تفصيلي لكل خطوة

---

## 🐛 استكشاف الأخطاء والمشاكل

### المشكلة: "ModuleNotFoundError"
**الحل:**
```bash
pip install -r requirements.txt
```

### المشكلة: "Connection timeout"
**الحل:**
```bash
spylo> set timeout 30  # زيادة المهلة الزمنية
spylo> set proxy http://your-proxy:port  # استخدام proxy
```

### المشكلة: "Rate limited"
**الحل:**
```bash
spylo> set retries 3  # تقليل المحاولات
# استخدم proxy مختلف أو انتظر قليلاً قبل المسح التالي
```

### المشكلة: البرنامج يغلق بعد المسح
**الحل:**
- استخدم الأمر `exit` أو `q` للخروج
- البرنامج مصمم للبقاء مفتوحاً للمسح المتعدد

---

## 📞 الدعم والمساهمة

- 🐛 لإبلاغ عن أخطاء: [فتح Issue](https://github.com/S4ddler/floppa/issues)
- 💡 لاقتراحات جديدة: [ناقش الفكرة](https://github.com/S4ddler/floppa/discussions)
- 🤝 للمساهمة: [فتح Pull Request](https://github.com/S4ddler/floppa/pulls)

---

## 📊 تقارير النتائج

تُحفظ نتائج المسح بشكل آلي في مجلد `out/`:

```
out/
├── username_johndoe.json       # نتائج JSON
├── username_johndoe.csv        # نتائج CSV
├── username_johndoe.md         # نتائج Markdown
├── domain_example.json         # نتائج JSON
├── domain_example.csv          # نتائج CSV
└── domain_example.md           # نتائج Markdown
```

---

## 📄 الترخيص

هذا المشروع مرخص تحت رخصة MIT - انظر ملف [LICENSE](LICENSE) للتفاصيل.

---

## ℹ️ معلومات إضافية

- **الإصدار:** 0.1.0
- **الحالة:** في التطوير النشط ✅
- **آخر تحديث:** ديسمبر 2025
- **اللغات المدعومة:** العربية 🇸🇦 | English 🇬🇧

---

**صُنع بـ ❤️ بواسطة فريق SPYLO**

**Follow us:** [@S4ddler](https://twitter.com/S4ddler) on Twitter
