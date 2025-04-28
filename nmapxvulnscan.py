from socket import gethostbyname, gaierror
from nmap import PortScanner

# Function to resolve the target hostname into an IP address.
def get_ip(target: str):
    try:
        return gethostbyname(target)  # Resolves the domain to an IP address
    except gaierror as e:
        print(f"Error resolving target: {e}")
        return None

# Function to perform a port scan on the given target with customizable arguments.
def port_scanner(target: str, scan_args: str = '-p1-1024 -sV -O'):
    open_ports = []  # List to hold open ports
    target_ip = get_ip(target)  # Get the IP address from the hostname
    if not target_ip:
        return []  # Return empty list if the IP could not be resolved
    
    nm = PortScanner()  # Initialize Nmap scanner
    print(f"Scanning target {target_ip} with arguments: {scan_args}...")
    print('-' * 50)
    try:
        nm.scan(target_ip, arguments=scan_args)  # Use custom arguments for scan
    except Exception as e:
        print(f"Error during scan: {e}")
        return []
    
    # Loop through all hosts detected by Nmap
    for host in nm.all_hosts():
        if nm[host]['status']['state'] == 'up':  # Check if the host is active
            print(f"Host {host} is up, checking open ports...")
            for protocol in nm[host].all_protocols():  # Check each protocol (TCP/UDP)
                print(f"Protocol: {protocol}")
                ports = nm[host][protocol].keys()  # Get the list of ports for the current protocol
                for port in ports:
                    port_info = nm[host][protocol][port]
                    if port_info['state'] == 'open':  # Check if the port is open
                        print(f"Port {port} is open.")
                        open_ports.append(port)  # Add open port to the list
                        for key, value in port_info.items():
                            print(f"{key}: {value}")
                        print('-' * 50)
    return open_ports

# Function to scan for vulnerabilities on open ports of the target IP.
def vuln_scanner(target: str, open_ports: list, vuln_args: str = '--script=vuln'):
    if not open_ports:
        print("No open ports to scan for vulnerabilities.")
        return
    
    print(f"Scanning open ports for vulnerabilities with arguments: {vuln_args}...")
    print('-' * 50)
    for port in open_ports:  # Iterate over each open port
        try:
            print(f"Scanning port {port} for vulnerabilities...")
            nm = PortScanner()
            nm.scan(target, arguments=f"-p{port} {vuln_args}")  # Run Nmap vulnerability script on the port
            for host in nm.all_hosts():
                for protocol in nm[host].all_protocols():
                    ports = nm[host][protocol].keys()
                    for port in ports:
                        port_info = nm[host][protocol][port]
                        if 'script' in port_info:  # Check if vulnerability scripts are found
                            for script, output in port_info['script'].items():
                                print(f"Script: {script}")
                                print(f"Output: {output}")
                                print('-' * 50)
        except Exception as e:
            print(f"Error scanning port {port}: {e}")

if __name__ == '__main__':
    target = input('Enter target IP or domain: ')  # Input target IP or domain from the user
    scan_args = input('Enter custom scan arguments (default: "-p1-1024 -sV -O"): ') or '-p1-1024 -sV -O'  # Custom scan arguments
    open_ports = port_scanner(target, scan_args)  # Perform port scanning with custom arguments
    if open_ports:
        vuln_args = input('Enter custom vulnerability scan arguments (default: "--script=vuln"): ') or '--script=vuln'  # Custom vulnerability scan arguments
        vuln_scanner(target, open_ports, vuln_args)  # Perform vulnerability scan on the open ports
    else:
        print("No open ports found.")
