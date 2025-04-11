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


## Installation
1. Clone this repository:
2. Install required tools (see Prerequisites).
3. Run the script:

## Usage
Run the script by providing a target domain as input:


### Example Workflow:
1. Enter the target domain when prompted (e.g., `example.com`).
2. The script performs subdomain enumeration, HTTP probing, takeover checks, and endpoint discovery.
3. Results are saved in an organized folder structure.

## Output Structure:
<target_domain>/ 
└── recon/ 
├── mainsubdomains.txt                # Combined list of all discovered subdomains (unique) 
├── alive_subdomains_httpx.txt        # Alive subdomains confirmed by httpx (cleaned) 
├── subzy_results.txt                 # Results from Subzy checks 
├── alive_domains_with_status_codes.txt # Alive domains with HTTP status codes 
└── katana_output.txt                 # Combined Katana endpoint discovery results (unique)
   
