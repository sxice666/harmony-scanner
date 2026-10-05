# Harmony Scanner 🕵️

An interactive Python-based OSINT tool designed to analyze domain infrastructure. 
It resolves DNS records, scans standard web ports, and extracts detailed information from SSL/TLS certificates.

## Features
- ✅ **DNS Resolution:** Finds all IP addresses associated with a target domain.
- ✅ **Port Scanning:** Checks connectivity on common web ports (80, 443, 8080, 8443).
- ✅ **SSL Analysis:** Fetches and parses X.509 certificates (CN, Issuer, SANs, Validity dates).
- ✅ **JSON Reporting:** Saves structured data reports for further analysis or archiving.
- ✅ **Interactive CLI:** Simple menu-driven interface (`scan`, `help`, `exit`).

## Installation & Usage

Requires Python 3.8+.

1. Clone the repository:
   ```bash
   git clone https://github.com/sxice666/harmony-scanner.git
   cd harmony-scanner
