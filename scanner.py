#!/usr/bin/env python3
"""
Network Port Scanner
A comprehensive tool to scan network devices and detect open/closed ports
"""

import socket
import threading
import subprocess
import sys
import time
import argparse
from concurrent.futures import ThreadPoolExecutor
import ipaddress
from datetime import datetime
import json

class NetworkPortScanner:
    def __init__(self, timeout=1, max_threads=100):
        self.timeout = timeout
        self.max_threads = max_threads
        self.results = {}
        self.lock = threading.Lock()
        
    def get_local_network(self):
        """Get the local network range"""
        try:
            # Get default gateway and local IP
            result = subprocess.run(['ip', 'route', 'show', 'default'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                gateway = result.stdout.split()[2]
                # Get local IP
                result = subprocess.run(['hostname', '-I'], 
                                      capture_output=True, text=True)
                local_ip = result.stdout.strip().split()[0]
                
                # Determine network range (assuming /24)
                network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
                return str(network)
        except Exception as e:
            print(f"Error detecting network: {e}")
            return "192.168.1.0/24"  # Default fallback
    
    def ping_host(self, ip):
        """Check if host is alive using ping"""
        try:
            result = subprocess.run(['ping', '-c', '1', '-W', '1', ip], 
                                  capture_output=True, text=True)
            return result.returncode == 0
        except:
            return False
    
    def scan_port(self, ip, port):
        """Scan a single port on a host"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def get_service_name(self, port):
        """Get service name for a port"""
        try:
            return socket.getservbyport(port)
        except:
            return "unknown"
    
    def scan_host_ports(self, ip, ports):
        """Scan all specified ports for a single host"""
        open_ports = []
        closed_ports = []
        
        print(f"Scanning ports on {ip}...")
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            port_results = {port: executor.submit(self.scan_port, ip, port) 
                          for port in ports}
            
            for port, future in port_results.items():
                try:
                    if future.result():
                        service = self.get_service_name(port)
                        open_ports.append((port, service))
                    else:
                        closed_ports.append(port)
                except Exception as e:
                    closed_ports.append(port)
        
        with self.lock:
            self.results[ip] = {
                'open_ports': open_ports,
                'closed_ports': closed_ports,
                'total_open': len(open_ports),
                'total_closed': len(closed_ports)
            }
        
        if open_ports:
            print(f"✓ {ip}: Found {len(open_ports)} open port(s)")
        else:
            print(f"- {ip}: No open ports found")
    
    def discover_hosts(self, network_range):
        """Discover live hosts in the network"""
        print(f"Discovering hosts in {network_range}...")
        live_hosts = []
        
        try:
            network = ipaddress.IPv4Network(network_range)
            hosts = list(network.hosts())
            print(f"Checking {len(hosts)} potential hosts...")
            
            with ThreadPoolExecutor(max_workers=50) as executor:
                ping_results = {str(ip): executor.submit(self.ping_host, str(ip)) 
                              for ip in hosts}
                
                completed = 0
                for ip, future in ping_results.items():
                    try:
                        if future.result():
                            live_hosts.append(ip)
                            print(f"✓ Found live host: {ip}")
                        completed += 1
                        if completed % 50 == 0:
                            print(f"Progress: {completed}/{len(hosts)} checked")
                    except Exception as e:
                        print(f"Error checking {ip}: {e}")
                        
        except Exception as e:
            print(f"Error in host discovery: {e}")
        
        print(f"Host discovery complete: {len(live_hosts)} live hosts found")
        return live_hosts
    
    def scan_network(self, network_range=None, ports=None, host_discovery=True):
        """Scan the entire network"""
        if network_range is None:
            network_range = self.get_local_network()
        
        if ports is None:
            # Common ports to scan
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 
                    1433, 3306, 3389, 5432, 5900, 8080, 8443]
        
        print(f"Starting network scan on {network_range}")
        print(f"Scanning ports: {ports}")
        print(f"Timeout: {self.timeout}s, Max threads: {self.max_threads}")
        print("-" * 60)
        
        start_time = datetime.now()
        
        if host_discovery:
            live_hosts = self.discover_hosts(network_range)
            if not live_hosts:
                print("No live hosts found! Try using --no-ping to scan all IPs")
                return
        else:
            # Scan all IPs in range without ping check
            print("Skipping host discovery, scanning all IPs in range...")
            network = ipaddress.IPv4Network(network_range)
            live_hosts = [str(ip) for ip in network.hosts()]
            print(f"Will scan {len(live_hosts)} IP addresses")
        
        print(f"\nStarting port scan on {len(live_hosts)} host(s)...")
        print("-" * 60)
        
        # Scan ports on live hosts
        with ThreadPoolExecutor(max_workers=min(self.max_threads, len(live_hosts))) as executor:
            futures = []
            for host in live_hosts:
                future = executor.submit(self.scan_host_ports, host, ports)
                futures.append(future)
            
            # Wait for all scans to complete
            completed = 0
            for future in futures:
                try:
                    future.result()
                    completed += 1
                    if completed % 10 == 0:
                        print(f"Progress: {completed}/{len(live_hosts)} hosts scanned")
                except Exception as e:
                    print(f"Error in scan: {e}")
                    completed += 1
        
        end_time = datetime.now()
        print(f"\nScan completed in {end_time - start_time}")
        print(f"Results collected for {len(self.results)} hosts")
        
    def print_results(self, show_closed=False, output_format='table'):
        """Print scan results"""
        if not self.results:
            print("No results to display")
            return
        
        if output_format == 'json':
            print(json.dumps(self.results, indent=2))
            return
        
        print("\n" + "="*80)
        print("NETWORK PORT SCAN RESULTS")
        print("="*80)
        
        total_devices = len(self.results)
        total_open_ports = sum(result['total_open'] for result in self.results.values())
        devices_with_open_ports = sum(1 for result in self.results.values() if result['total_open'] > 0)
        
        print(f"Total devices scanned: {total_devices}")
        print(f"Devices with open ports: {devices_with_open_ports}")
        print(f"Total open ports found: {total_open_ports}")
        print("-" * 80)
        
        # Sort by IP address
        sorted_results = sorted(self.results.items(), key=lambda x: ipaddress.IPv4Address(x[0]))
        
        for ip, result in sorted_results:
            # Show all hosts if show_closed is True, otherwise only show hosts with open ports
            if result['total_open'] > 0 or show_closed:
                print(f"\n📍 Host: {ip}")
                print(f"   Open ports: {result['total_open']}")
                print(f"   Closed ports: {result['total_closed']}")
                
                if result['open_ports']:
                    print("   🔓 OPEN PORTS:")
                    for port, service in sorted(result['open_ports']):
                        print(f"      {port:>5}/tcp  {service}")
                
                if show_closed and result['closed_ports']:
                    print("   🔒 CLOSED PORTS:")
                    closed_ports = sorted(result['closed_ports'])
                    # Show first 20 closed ports, then summarize
                    if len(closed_ports) <= 20:
                        closed_summary = ', '.join(map(str, closed_ports))
                    else:
                        closed_summary = ', '.join(map(str, closed_ports[:20]))
                        closed_summary += f" ... and {len(closed_ports) - 20} more"
                    print(f"      {closed_summary}")
                
                print("-" * 40)
        
        # Summary of devices without open ports
        if not show_closed:
            devices_no_ports = total_devices - devices_with_open_ports
            if devices_no_ports > 0:
                print(f"\n📋 {devices_no_ports} device(s) had no open ports")
                print("   Use --show-closed to see all devices and closed ports")
    
    def save_results(self, filename):
        """Save results to file"""
        try:
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=2)
            print(f"Results saved to {filename}")
        except Exception as e:
            print(f"Error saving results: {e}")

def main():
    parser = argparse.ArgumentParser(description='Network Port Scanner')
    parser.add_argument('-n', '--network', help='Network range (e.g., 192.168.1.0/24)')
    parser.add_argument('-p', '--ports', help='Ports to scan (comma-separated or range)')
    parser.add_argument('-t', '--timeout', type=float, default=1, help='Timeout in seconds')
    parser.add_argument('--threads', type=int, default=100, help='Max concurrent threads')
    parser.add_argument('--show-closed', action='store_true', help='Show closed ports')
    parser.add_argument('--no-ping', action='store_true', help='Skip host discovery')
    parser.add_argument('--output', choices=['table', 'json'], default='table', help='Output format')
    parser.add_argument('--save', help='Save results to file')
    parser.add_argument('--common-ports', action='store_true', help='Scan only common ports')
    parser.add_argument('--all-ports', action='store_true', help='Scan all 65535 ports (very slow)')
    
    args = parser.parse_args()
    
    # Parse ports
    ports = None
    if args.ports:
        try:
            if '-' in args.ports:
                # Range like 1-1024
                start, end = map(int, args.ports.split('-'))
                ports = list(range(start, end + 1))
            else:
                # Comma-separated like 80,443,22
                ports = [int(p.strip()) for p in args.ports.split(',')]
        except ValueError:
            print("Invalid port format. Use comma-separated (80,443,22) or range (1-1024)")
            sys.exit(1)
    elif args.all_ports:
        ports = list(range(1, 65536))
        print("WARNING: Scanning all 65535 ports will take a very long time!")
        response = input("Continue? (y/N): ")
        if response.lower() != 'y':
            sys.exit(0)
    elif args.common_ports:
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 
                1433, 3306, 3389, 5432, 5900, 8080, 8443]
    
    # Create scanner
    scanner = NetworkPortScanner(timeout=args.timeout, max_threads=args.threads)
    
    try:
        # Run scan
        scanner.scan_network(
            network_range=args.network,
            ports=ports,
            host_discovery=not args.no_ping
        )
        
        # Print results
        scanner.print_results(show_closed=args.show_closed, output_format=args.output)
        
        # Save results if requested
        if args.save:
            scanner.save_results(args.save)
            
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()