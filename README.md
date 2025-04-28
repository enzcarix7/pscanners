# Nmap Port and Vulnerability Scanner

This script is a Python-based tool that utilizes the `nmap` library to perform port scanning and vulnerability scanning on a target IP or domain. It allows you to specify customizable arguments for both port scanning and vulnerability scanning.

## Features
- Resolves the target domain to an IP address.
- Scans the target IP for open ports within a specified range.
- Displays the services running on open ports.
- Scans the open ports for vulnerabilities using Nmap scripts.

## Prerequisites

To use this script, you will need:
- Python 3.x
- Nmap installed on your system
- `python-nmap` library for Python

You can install the necessary Python library by running:

pip install python-nmap (first run: 'python -m pip install --upgrade pip')

Ensure that the `nmap` tool is installed on your system. If it's not, you can install it from the official Nmap website: https://nmap.org/download.html

## Usage

1. Clone the repository or download the script to your local machine.

2. Run the script using Python:
    ```bash
    python nmap_script.py
    ```

3. The script will prompt you to enter a target IP or domain:
    - Example input: `target_ip_or_domain.com`

4. After entering the target, you'll be asked to provide arguments for port scanning and vulnerability scanning. 
   - Default port scan argument: `-p1-1024 -sV -O`
   - Default vulnerability scan argument: `--script=vuln`

5. The script will display:
   - The list of open ports on the target.
   - The service information for each open port.
   - Any vulnerabilities found on the open ports.

## Example Output
Enter target IP or domain: target_ip_or_domain.com
Scanning…

Host: target_ip_or_domain.com
Protocol: tcp
Port: 80
Service: http
State: open
…

Vulnerability scanner…

Scanning port 80 for vulnerabilities…
Script: http-vuln-cve2017-5638
Output: Vulnerability found: …

## Customization

- You can customize the port range and other scan arguments directly when prompted.
- Modify the script to suit your scanning needs by changing the default arguments in the script.
