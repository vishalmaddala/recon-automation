import os
import subprocess

def create_recon_folder_structure(domain_name):
    """
    Creates a folder structure for recon results and initializes file paths.
    
    :param domain_name: Target domain name (e.g., netflix.com)
    :return: Dictionary of file paths for easy reference.
    """
    # Define folder structure
    base_folder = domain_name.replace(".", "_")  # Replace dots to avoid filesystem issues
    recon_folder = os.path.join(base_folder, "recon")

    # Create folders
    os.makedirs(recon_folder, exist_ok=True)

    # Define file paths for outputs
    files = {
        "mainsubdomains": os.path.join(recon_folder, "mainsubdomains.txt"),
        "httpx_alive": os.path.join(recon_folder, "alive_subdomains_httpx.txt"),
        "subzy_results": os.path.join(recon_folder, "subzy_results.txt"),
        "alive_domains_with_status_codes": os.path.join(recon_folder, "alive_domains_with_status_codes.txt"),
        "all_urls_combined": os.path.join(recon_folder, "all_urls_combined.txt")
    }

    return files

def run_command(command):
    """
    Executes a bash command and returns its output.
    
    :param command: Bash command to execute.
    :return: Command output.
    """
    try:
        result = subprocess.run(command, shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode != 0:
            print(f"[!] Error executing command: {command}\n{result.stderr}")
        return result.stdout.strip()
    except Exception as e:
        print(f"[!] Exception while executing command: {command}\n{e}")
        return ""

def clean_urls(input_file):
    """
    Cleans URLs by removing double protocols (e.g., http://http://).
    
    :param input_file: Path to the file containing URLs.
    """
    cleaned_urls = set()
    
    with open(input_file, "r") as infile:
        for url in infile.readlines():
            url = url.strip()
            # Remove double protocols
            url = url.replace("http://http://", "http://").replace("http://https://", "https://")
            cleaned_urls.add(url)
    
    with open(input_file, "w") as outfile:
        outfile.write("\n".join(cleaned_urls))

def perform_recon(domain_name):
    """
    Performs the entire recon workflow and saves results into organized files.
    
    :param domain_name: Target domain name (e.g., netflix.com)
    """
    print(f"[+] Starting recon for domain: {domain_name}")
    
    # Create folder structure
    files = create_recon_folder_structure(domain_name)
    
    # Subdomain Enumeration
    print("[+] Enumerating subdomains using Subfinder...")
    run_command(f"sudo subfinder -d {domain_name} -all > {files['mainsubdomains']}")
    
    print("[+] Enumerating subdomains using Assetfinder...")
    run_command(f"sudo assetfinder --subs-only {domain_name} >> {files['mainsubdomains']}")
    
    print("[+] Enumerating subdomains using crt.sh...")
    crtsh_command = f"""curl -s "https://crt.sh/?q=%.{domain_name}&output=json" | jq -r '.[].name_value' | sed 's/\\*\\.//g' | sort -u >> {files['mainsubdomains']}"""
    run_command(crtsh_command)
    
    print("[+] Enumerating subdomains using AlienVault...")
    alienvault_command = f"""curl -s "https://otx.alienvault.com/api/v1/indicators/hostname/{domain_name}/passive_dns" | jq -r '.passive_dns[].hostname' | grep -E "^[a-zA-Z0-9.-]+\\.{domain_name}$" | sort -u >> {files['mainsubdomains']}"""
    run_command(alienvault_command)
    
    # Remove duplicates from mainsubdomains.txt
    print("[+] Removing duplicate subdomains...")
    run_command(f"sort -u {files['mainsubdomains']} -o {files['mainsubdomains']}")
    
    # HTTP Probing with httpx
    print("[+] Probing alive subdomains using httpx...")
    run_command(f"cat {files['mainsubdomains']} | httpx -silent > {files['httpx_alive']}")
    
    # Clean URLs in alive_subdomains_httpx.txt
    print("[+] Cleaning URLs in alive_subdomains_httpx.txt...")
    clean_urls(files["httpx_alive"])
    
    # Subzy Checks
    print("[+] Running Subzy to check for takeover vulnerabilities...")
    run_command(f"sudo subzy run --targets {files['mainsubdomains']} > {files['subzy_results']}")
    
    # HTTP Status Codes with httpx
    print("[+] Checking status codes of alive subdomains...")
    run_command(f"cat {files['httpx_alive']} | httpx -sc > {files['alive_domains_with_status_codes']}")
    
    # Further Enumeration with Katana
    choice = input("Do you want to perform further enumeration on alive subdomains? (yes/no): ").strip().lower()
    
    if choice == "yes":
        print("[+] Crawling endpoints using Katana...")
        
        katana_input_file = files["httpx_alive"]
        katana_output_file = files["all_urls_combined"]
        
        katana_command_1 = f"sudo katana -u {katana_input_file} -jc >> {katana_output_file}"
        katana_command_2 = f"sudo katana -u {katana_input_file} -d 5 -ef woff,css,png,svg,jpg,woff2,jpeg,gif >> {katana_output_file}"
        
        run_command(katana_command_1)
        run_command(katana_command_2)

        # Remove duplicates from Katana output
        print("[+] Removing duplicate URLs from Katana output...")
        run_command(f"sort -u {katana_output_file} -o {katana_output_file}")
        
        print(f"[+] Katana results saved to: {katana_output_file}")
    
    print("\n[+] Recon completed! Results saved in:")
    
    for name, path in files.items():
        print(f"- {name}: {path}")

# Main Execution
if __name__ == "__main__":
    domain_name = input("Enter the target domain (e.g., netflix.com): ").strip()
    
    if not domain_name:
        print("[!] Domain name is required.")
        exit(1)
    
    perform_recon(domain_name)
