# Recon Automation Script

## Description
This Python-based script automates reconnaissance tasks for bug bounty hunting and penetration testing. It integrates tools like Subfinder, Assetfinder, httpx, Subzy, and Katana to perform subdomain enumeration, HTTP probing, takeover checks, and endpoint discovery.

## Features
- Subdomain enumeration using:
  - Subfinder
  - Assetfinder
  - crt.sh
  - AlienVault OTX
- HTTP probing with httpx to identify live subdomains.
- Subdomain takeover checks using Subzy.
- Endpoint discovery using Katana.
- Organized output with cleaned and deduplicated results.

## Prerequisites
Ensure the following tools are installed on your system:
1. Python 3.6+
2. Required tools:
   - [Subfinder](https://github.com/projectdiscovery/subfinder)
   - [Assetfinder](https://github.com/tomnomnom/assetfinder)
   - [httpx](https://github.com/projectdiscovery/httpx)
   - [Subzy](https://github.com/LukaSikic/subzy)
   - [Katana](https://github.com/projectdiscovery/katana)
3. Install Python dependencies:
