import threading
import socket
import scapy.all as scapy
from collections import defaultdict
import datetime
import random
import subprocess
import requests
import time
import csv
import os
import netifaces
import ipaddress
import networkx as nx
from ReportGenerator import Report_Generator
import pandas as pd
from rich.live import Live
from rich.table import Table
from rich.console import Console
from plyer import notification
from twilio.rest import Client
import smtplib
from dotenv import load_dotenv
import json

class MenuHandler:
    def display_menu(self, menu_dict, use_color=False):
        print("==============================")
        for index, key in enumerate(menu_dict):
            if use_color:
                print(f"\033[34m{index+1}\u001b[0m) {key}")
            else:
                print(f"{index+1}) {key}")
        print("==============================")

    def handle_menu_selection(self, menu_dict, selection, use_color=False):
        try:
            if selection.isdigit():
                option = int(selection)
                if 1 <= option <= len(menu_dict):
                    key = list(menu_dict.keys())[option - 1]
                    submenu = menu_dict[key]
                    # Check if it's a function and call it
                    if callable(submenu):
                        submenu = submenu()
                    # If submenu is a dict, treat it like another menu
                    if isinstance(submenu, dict):
                        self.display_menu(submenu, use_color)
                        sub_selection = input("[>] Select to run: ")
                        self.handle_menu_selection(submenu, sub_selection, use_color)
                    # If submenu is a string or something else, just print it
                    else:
                        print(f"[+] You selected: {submenu}")
                else:
                    print("[!] Please choose a valid menu number.")
            else:
                print("[!] Invalid option.")
        except Exception as e:
            print(f"[!] Error: {e}")


# === Load Notification Config from JSON ===
try:
    with open("config.json", "r") as f:
        NOTIFICATION_CONFIG = json.load(f)
except Exception as e:
    print(f"[!] Failed to load config.json: {e}")
    NOTIFICATION_CONFIG = {}



def notify_desktop(title, message):
    notification.notify(
        title=title,
        message=message,
        app_name='Network Analyzer',
        timeout=5
    )

def send_email_alert(subject, body, config):
    try:
        message = f"Subject: {subject}\n\n{body}"
        with smtplib.SMTP_SSL(config["smtp_server"], config["smtp_port"]) as server:
            server.login(config["from_email"], config["smtp_password"])
            server.sendmail(config["from_email"], config["to_email"], message)
    except Exception as e:
        print(f"[!] Email failed: {e}")

def send_sms_alert(body, config):
    try:
        client = Client(config["account_sid"], config["auth_token"])
        client.messages.create(
            body=body,
            from_=config["from_number"],
            to=config["to_number"]
        )
    except Exception as e:
        print(f"[!] SMS failed: {e}")


class Discover:
    def __init__(self, NetworkIP_CiderIPv4: str = None, NetworkIP: str = None, 
                SubnetCiderNotation: int = None, subnet_mask: str = None, 
                NetworkInterface: str = None, WaitingTimeDelay: int = 3,
                Orginal_MAC: str = None, MOCK_MAC: list = None,
                MACsite: str = None):
        
        self.Reporter = Report_Generator()
        self.NetworkIP_CiderIPv4 = NetworkIP_CiderIPv4
        self.NetworkIP = NetworkIP
        self.SubnetCiderNotation = SubnetCiderNotation
        self.subnet_mask = subnet_mask
        self.WaitingTime = WaitingTimeDelay
        self.Orginal_MAC = Orginal_MAC
        self.MOCK_MAC = MOCK_MAC
        self.NetworkInterface = NetworkInterface
        self.MACsite = MACsite or "https://macvendorlookup.com/api/v2/"
        self.private_IPv4 = None
        self.mac_vendor_data = self.read_mac_vendor_csv("MAC.CSV") # Specify path of MAC.CSV
        self.network_graph = nx.Graph()
             
        self.DiscoveredData = []
        self.HostData = {
            "No.": None,
            "IP": None,
            "MAC": None,
            "Vendor": None,
            "Network IP": None,
            "Network Subnet": None,
            "Protocol": None,
            "Time & Date" : None
        }
    
    
    def read_mac_vendor_csv(self, csv_file):
        """
        Reads the MAC vendor data using pandas.
        """
        try:
            df = pd.read_csv(csv_file, encoding="utf-8", on_bad_lines="skip")

            # Assuming 'Assignment' is the MAC prefix and 'Organization Name' is the vendor
            df['MAC_Prefix'] = df['Assignment'].str[:4].str.upper()
            mac_vendor_data = dict(zip(df['MAC_Prefix'], df['Organization Name']))
            return mac_vendor_data
        except Exception as e:
            print(f"[!] Error reading MAC vendor CSV with pandas: {e}")
            return {}


    def get_vendor_info(self, macaddress):
        """
        This function retrieves the vendor information for a given MAC address.
        """
        try:
            test = macaddress
            mac_prefix = test[:8].replace(':', '').upper()[:4]
            vendor = self.mac_vendor_data.get(mac_prefix)
            if vendor is not None:
                return vendor + " from MAC.csv"
            else:
                if self.MACsite != None:
                    macsend = self.MACsite + macaddress
                    response = requests.get(macsend, timeout=5)
                    if response.status_code == 200:
                        data = response.json()
                        if data:
                            company_info = data[0]
                            company_name = company_info.get('company', 'Unknown')
                            return company_name + " from MacVendorLookup API"
                        elif response.status_code == 204:
                            return "No vendor information available - 204"
                        else:
                            return f"Error: {response.status_code}"
                    else:
                        return f"Error: {response.status_code}"
                else:
                    return "Unknown"
        except requests.exceptions.RequestException as e:
            return f"Error while getting vendor from URL"


    def GetNetworkData(self, PrintDetails=False, save_to_file=False):
        """
        This function retrieves the network data, including the private IP address, 
        network interface, subnet mask, network address, and other details.
        """
        try:
            interfaces = netifaces.interfaces()
            for iface in interfaces:
                if iface == 'lo':
                    continue
                addresses = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addresses:
                    ipv4_info = addresses[netifaces.AF_INET][0]
                    ip_address = ipv4_info['addr']
                    if ipaddress.IPv4Address(ip_address).is_private:
                        private_IPv4 = ip_address
                        public_IPv4 = requests.get("https://api.ipify.org").text
                        network_interface = iface
                        subnet_mask_str = ipv4_info['netmask']
                        subnet_cidr = sum(bin(int(x)).count('1') for x in subnet_mask_str.split('.'))
                        subnet_mask = ipaddress.IPv4Address(subnet_mask_str)
                        Network_AddressCiderIPv4 = ipaddress.IPv4Network(ip_address + '/' + str(subnet_cidr), strict=False)
                        broadcast_address = Network_AddressCiderIPv4.broadcast_address
                        usable_hosts = list(Network_AddressCiderIPv4.hosts())
                        total_hosts = len(usable_hosts) + 2  # +1 for network address, +1 for broadcast address
                        usable_host_ip_range = f"{usable_hosts[0]} - {usable_hosts[-1]}"
                        network_IPv4 = Network_AddressCiderIPv4.network_address
                        mac_address = addresses[netifaces.AF_LINK][0]['addr']
                        break
            if PrintDetails == True:
                print(f"[>] Current network data of {Network_AddressCiderIPv4}")
                print(f"[-] Network address: {network_IPv4}")
                print(f"[-] Subnet CIDR: {subnet_cidr}")
                print(f"[-] Current Subnet: {subnet_mask}")
                print(f"[-] Broadcast Address: {broadcast_address}")
                print(f"[-] Your private IPv4: {private_IPv4}")
                print(f"[-] Your public IPv4: {public_IPv4.strip()}")
                print(f"[-] Your public IPv4: {public_IPv4.strip()}")
                print(f"[-] Total Number of Hosts: {total_hosts}")
                print(f"[-] Number of Usable Hosts: {len(usable_hosts)}")
                print(f"[-] Usable Host IPv4 Range: {usable_host_ip_range}")
                print(f"[-] Network Interface: {network_interface}")
                print(f"[-] MAC Address: {mac_address}")

            if save_to_file == True:
                NetworkData = {
                    "Network": str(Network_AddressCiderIPv4),
                    "Subnet": str(subnet_mask),
                    "Broadcast": str(broadcast_address),
                    "Private_IPv4": private_IPv4,
                    "Public_IPv4": public_IPv4.strip(),
                    "Total_Hosts": total_hosts,
                    "Usable_Hosts": len(usable_hosts),
                    "Usable_Hosts_Range": usable_host_ip_range,
                    "Network_Interface": network_interface,
                    "MAC_Address": mac_address
                }
                NetworkList = [NetworkData]
            
                self.Reporter.CSV_GenerateReport(Data=NetworkList)
                self.Reporter.TXT_GenerateReport(Data=NetworkList)
            
            self.NetworkIP_CiderIPv4 = Network_AddressCiderIPv4 
            self.NetworkIP = network_IPv4 
            self.SubnetCiderNotation = subnet_cidr
            self.subnet_mask = subnet_mask
            self.private_IPv4 = private_IPv4
            self.NetworkInterface = network_interface
            if self.Orginal_MAC == None:
                self.Orginal_MAC = mac_address 
            
            return (
                Network_AddressCiderIPv4,
                network_IPv4,
                subnet_cidr,
                subnet_mask,
                broadcast_address,
                private_IPv4,
                public_IPv4.strip(),
                total_hosts,
                len(usable_hosts),
                usable_host_ip_range,
                network_interface,
                mac_address
            )

        except Exception as e:
            print(f"[!] An error occurred: {e}")
            return None, None, None, None, None, None, None, None, None, None


    def ARP_DiscoverHosts(self, maxHostgroup=5, verbose=False, mapping=False, save_to_file=False):
        try:
            # Get current network data
            self.GetNetworkData(PrintDetails=verbose)
            print(f"[*] Using interface: {self.NetworkInterface}")
            print(f"[*] Sending ARP request on: {self.NetworkIP_CiderIPv4}")
            print("[>] ARP - Scanning network for active hosts...\n")
            # Prepare ARP request
            arp_request = scapy.ARP(pdst=str(self.NetworkIP_CiderIPv4))
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            request_broadcast = broadcast / arp_request
            IPorder = 1
            # Setup live table
            table = Table(title="Live Discovered Hosts")
            table.add_column("No.", justify="right", style="cyan")
            table.add_column("IP", style="green")
            table.add_column("MAC", style="magenta")
            table.add_column("Vendor", style="yellow")
            table.add_column("Time", style="white")
            with Live(table, refresh_per_second=2) as live:
                while IPorder <= maxHostgroup:
                    answered_packets, _ = scapy.srp(request_broadcast, timeout=1, verbose=False, iface=self.NetworkInterface)
                    for _, received_packet in answered_packets:
                        # Skip duplicates
                        if any(d.get("IP") == received_packet.psrc for d in self.DiscoveredData):
                            continue
                        vendor_info = self.get_vendor_info(received_packet.hwsrc)
                        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                        host_data = {
                            "No.": IPorder,
                            "IP": received_packet.psrc,
                            "MAC": received_packet.hwsrc,
                            "Vendor": vendor_info,
                            "Network IP": self.NetworkIP,
                            "Network Subnet": self.SubnetCiderNotation,
                            "Protocol": "ARP",
                            "Time & Date": timestamp
                        }
                        self.DiscoveredData.append(host_data)

                        print(f"[+] Received response from {received_packet.psrc} ({received_packet.hwsrc})")

                        # Update table
                        table = self.render_live_table(table, host_data)
                        live.update(table)
                        IPorder += 1
                    if IPorder > maxHostgroup:
                        break
                    time.sleep(self.WaitingTime)
            print("[$] Done! Scanning using ARP method complete.")
            # Save to file if requested
            if save_to_file:
                self.Reporter.CSV_GenerateReport(Data=self.DiscoveredData)
                self.Reporter.TXT_GenerateReport(Data=self.DiscoveredData)
            # Optional: Generate network graph
            if mapping:
                self.NetworkMapper()
        except Exception as e:
            print(f"[!] Error during ARP host discovery: {e}")


                  

            print("[$] Done!, scanning using ARP method")
            if save_to_file:
                self.Reporter.CSV_GenerateReport(Data=self.DiscoveredData)
                self.Reporter.TXT_GenerateReport(Data=self.DiscoveredData)
            if mapping:
                self.NetworkMapper()

        except Exception as e:
            print(f"[!] Error during ARP host discovery: {e}")


            while IPorder <= maxHostgroup:
                request_broadcast = broadcast / arp_request
                answered_packets, _ = scapy.srp(request_broadcast, timeout=1, verbose=False)

                for sent_packet, received_packet in answered_packets:
                    if received_packet:
                        duplicate_found = False
                        for data in self.DiscoveredData:
                            if data.get("IP") == received_packet.psrc:
                                duplicate_found = True
                                break
                        if not duplicate_found:
                            vendor_info = self.get_vendor_info(received_packet.hwsrc)
                            timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                            self.HostData = {
                                "No.": IPorder,
                                "IP": received_packet.psrc,
                                "MAC": received_packet.hwsrc,
                                "Vendor": vendor_info,
                                "Network IP": self.NetworkIP,
                                "Network Subnet": self.SubnetCiderNotation,
                                "Protocol": "ARP",
                                "Time & Date": timestamp
                            }
                            self.DiscoveredData.append(self.HostData)
                            if verbose == True:
                                print(f"[{IPorder}] {timestamp}\n[-] {received_packet.psrc}\n[-] {received_packet.hwsrc}\n[-] {vendor_info}\n")
                            
                            IPorder += 1
                            if IPorder > maxHostgroup:
                                break
                            
                time.sleep(self.WaitingTime)
            
            print("[$] Done!, scanning using ARP method")
            
            if save_to_file:
                if save_csv:
                    self.Reporter.CSV_GenerateReport(...)
                if save_txt:
                    self.Reporter.TXT_GenerateReport(...)
            if mapping == True:
                self.NetworkMapper()
                              
        except Exception as e:
            print(f"[!] Error during ARP host discovery: {e}")
        if not self.DiscoveredData:
            print("[!] No hosts discovered. Please check your network connection or permissions.")
        else:
            print(f"[+] Total hosts discovered: {len(self.DiscoveredData)}")
            for host in self.DiscoveredData:
                print(f"    - IP: {host['IP']} | MAC: {host['MAC']}")

            

            
    def render_live_table(self, table, new_data):
        table.add_row(
            str(new_data["No."]),
            new_data["IP"],
            new_data["MAC"],
            new_data["Vendor"],
            new_data["Time & Date"]
        )
        return table
        
            

class Analyzer:
    def __init__(self):
        self.PrivateScanner = Discover()
        

    def identify_devices_by_traffic(self, duration=60, verbose=False):
        """
        Identifies devices on the network by analyzing their traffic patterns.
        """
        try:
            traffic_patterns = defaultdict(set)
            device_profiles = {}
            def packet_callback(packet):
                if packet.haslayer(scapy.IP):
                    src_ip = packet[scapy.IP].src
                    dst_ip = packet[scapy.IP].dst
                    traffic_patterns[src_ip].add(dst_ip)                    
                    # Check if the device's traffic profile has changed
                    prev_profile = device_profiles.get(src_ip)
                    new_profile = f"Communicates with {len(traffic_patterns[src_ip])} unique destinations"
                    if prev_profile != new_profile:
                        device_profiles[src_ip] = new_profile
                        
                        # Print the updated profile
                        if verbose:
                            print(f"[+] Device {src_ip}: {new_profile}")

            print(f"[*] Starting to sniff network traffic for {duration} seconds...")
            scapy.sniff(timeout=duration, prn=packet_callback, store=0)

            print("[$] Done! Device identification by traffic patterns complete.")
            return device_profiles
        except Exception as e:
            print(f"[!] Error during device identification by traffic: {e}")
            return {}
    
    
    def monitor_network_traffic(self, interface=None, duration=60, verbose=False, save_to_file=False, file_path='captured_packets.pcap', protocol_filter=None):
        """
        Monitors network traffic on a specified interface for a given duration.
        """
        try:
            if interface is None:
                self.PrivateScanner.GetNetworkData(PrintDetails=verbose)
                interface = self.PrivateScanner.NetworkInterface
                if interface is None or not interface:
                    raise ValueError("Network interface could not be determined. Please specify an interface.")

            def protocol_filter_function(packet):
                if protocol_filter is None:
                    return True
                if 'TCP' in protocol_filter and packet.haslayer(scapy.TCP):
                    return True
                if 'UDP' in protocol_filter and packet.haslayer(scapy.UDP):
                    return True
                return False

            packets = scapy.sniff(iface=interface, timeout=duration, lfilter=protocol_filter_function)

            print(f"[$] Total packets captured: {len(packets)}")

            if verbose:
                for packet in packets:
                    if packet.haslayer(scapy.Ether):
                        print(f"Source: {packet[scapy.Ether].src}, Destination: {packet[scapy.Ether].dst}")
                    if packet.haslayer(scapy.IP):
                        print(f"IP Src: {packet[scapy.IP].src}, IP Dst: {packet[scapy.IP].dst}")

            print(f"[$] Packet summary:")
            packets.summary()

            if save_to_file:
                if not file_path.endswith('.pcap'):
                    file_path += '.pcap'
                scapy.wrpcap(file_path, packets)
                print(f"[$] Packets saved to {file_path}")

            protocol_count = {'TCP': 0, 'UDP': 0, 'Other': 0}
            for packet in packets:
                if packet.haslayer(scapy.TCP):
                    protocol_count['TCP'] += 1
                elif packet.haslayer(scapy.UDP):
                    protocol_count['UDP'] += 1
                else:
                    protocol_count['Other'] += 1
            print(f"[$] Traffic statistics: {protocol_count}")

            return packets
        except Exception as e:
            print(f"[!] Error during network traffic monitoring: {e}")
            return []


    def detect_rogue_access_points(self, known_ap_list, verbose=False):
        """
        Detects rogue access points by comparing discovered APs against a list of known APs.
        """
        try:
            def packet_callback(packet):
                if packet.haslayer(scapy.Dot11):
                    ssid = packet[scapy.Dot11].info.decode()
                    bssid = packet[scapy.Dot11].addr2
                    if bssid and (ssid, bssid) not in known_ap_list:
                        print(f"[!] Rogue AP detected: SSID={ssid}, BSSID={bssid}")
                        if verbose:
                            print(packet.summary())
    
            scapy.sniff(prn=packet_callback, store=0, timeout=60)
            print(f"[$] Done! Rogue access point detection complete.")
            
        except Exception as e:
            print(f"[!] Error during rogue access point detection: {e}")
    

    def detect_rogue_devices(self, known_devices, verbose=False):
        """
        Detects rogue devices by comparing discovered devices with a list of known devices.
        Saves discovered MACs to known_devices.json.
        """
        try:
            rogue_devices = []
            self.PrivateScanner.ARP_DiscoverHosts(verbose=True, mapping=False, save_to_file=False)
            known_macs = []
            for host in self.PrivateScanner.DiscoveredData:
                mac = host["MAC"]
                known_macs.append(mac)
            # === Save to known_devices.json ===
            with open("known_devices.json", "w") as json_file:
                json.dump(known_macs, json_file, indent=4)
            print(f"\n[+] Saved {len(known_macs)} MAC addresses to 'known_devices.json'.")

            print("\n[+] Known MAC addresses on the network:")

            for mac in known_macs:
                print(f'"{mac}",')
            print("\n[*] You can copy the above MAC list or load it from 'known_devices.json' for future scans.")

            for host in self.PrivateScanner.DiscoveredData:
                if host["MAC"] not in known_devices:
                    rogue_devices.append(host)
                    msg = f"Rogue device detected: {host['IP']} ({host['MAC']})"
                    notify_desktop("Rogue Device Alert", msg)
                    send_email_alert("Rogue Device Alert", msg, NOTIFICATION_CONFIG)
                    send_sms_alert(msg, NOTIFICATION_CONFIG)
                    if verbose:
                        print(msg)
                if verbose and not rogue_devices:
                    print("[+] No rogue devices detected.")
                print(f"[$] Done! Rogue device detection completed.")
                return rogue_devices
        except Exception as e:
            print(f"[!] Error during rogue device detection: {e}")
            return []





    def query_dns(domain, dns_server, timeout=2):
        try:
            pkt = scapy.IP(dst=dns_server) / scapy.UDP(dport=53) / scapy.DNS(rd=1, qd=scapy.DNSQR(qname=domain))
            response = scapy.sr1(pkt, timeout=timeout, verbose=0)
            if response and response.haslayer(scapy.DNS):
                return response[scapy.DNS].an.rdata
        except Exception as e:
            return None
    
    
    def detect_dns_spoofing(self, target_domains, verbose=False):
        """
        Detects DNS spoofing by comparing DNS query results with known legitimate IP addresses.
        """
        try:
            spoofed_domains = []
            dns_servers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]  # Google DNS, Cloudflare DNS, Quad9 DNS
            results_lock = threading.Lock()
    
            def check_domain(domain, legit_ips):
                nonlocal spoofed_domains
                resolved_ips = []
    
                threads = []
                for dns_server in dns_servers:
                    thread = threading.Thread(target=lambda: resolved_ips.append(self.query_dns(domain, dns_server)))
                    thread.start()
                    threads.append(thread)
    
                for thread in threads:
                    thread.join()
    
                unique_ips = set(resolved_ips) - {None}
                if not unique_ips.issubset(legit_ips):
                    with results_lock:
                        spoofed_domains.append((domain, list(unique_ips)))
                    if verbose:
                        for ip in unique_ips:
                            if ip not in legit_ips:
                                print(f"[!] DNS spoofing detected for {domain}: resolved IP {ip}")
    
            threads = []
            for domain, legit_ips in target_domains.items():
                thread = threading.Thread(target=check_domain, args=(domain, legit_ips))
                thread.start()
                threads.append(thread)
    
            for thread in threads:
                thread.join()
    
            print(f"[$] Done! DNS spoofing detection complete. Spoofed domains: {spoofed_domains}")
            return spoofed_domains
    
        except Exception as e:
            print(f"[!] Error during DNS spoofing detection: {e}")
            return []


    def check_dns_poisoning(self, domain, known_ip, verbose=False):
        """
        Checks for DNS poisoning by comparing the resolved IP address of a domain with a known IP address.
        """
        try:
            resolved_ip = socket.gethostbyname(domain)
            if resolved_ip != known_ip:
                print(f"[!] Potential DNS poisoning detected! {domain} resolved to {resolved_ip} instead of {known_ip}")
                if verbose:
                    print(f"[>] Expected IP: {known_ip}\n[>] Resolved IP: {resolved_ip}")
                return False
            else:
                print(f"[+] No DNS poisoning detected. {domain} resolved correctly to {known_ip}")
                return True
        except socket.error as e:
            print(f"[!] Error during DNS poisoning check: {e}")
            return False
    

    def detect_syn_flood(self, duration=60, threshold=1000, verbose=False):
        """
        Detects SYN flood attacks by monitoring the network for a specified duration and counting SYN packets.
        Sends real-time desktop, email, and SMS alerts if a threshold is exceeded.
        """
        try:
            # === CONFIG ===
            smtp_server = "smtp.gmail.com"
            smtp_port = 465
            from_email = "your_email@gmail.com"
            smtp_password = "your_app_password"
            to_email = "recipient@example.com"


            account_sid = "your_twilio_sid"
            auth_token = "your_twilio_token"
            from_number = "+123456789"  # Twilio number
            to_number = "+198765432"    # Your number

            syn_packets = []
            def packet_callback(packet):
                if packet.haslayer(scapy.TCP) and packet[scapy.TCP].flags == 'S':
                    syn_packets.append(packet)

            print(f"[*] Monitoring for SYN flood attacks for {duration} seconds...")
            scapy.sniff(timeout=duration, prn=packet_callback, store=0)

            syn_count = len(syn_packets)
            if verbose:
                print(f"[+] SYN packets detected: {syn_count}")

            if syn_count > threshold:
                msg = f"Potential SYN flood attack detected! SYN packet count: {syn_count}"
                # === Notify ===
                notify_desktop("SYN Flood Alert", msg)
                send_email_alert("SYN Flood Alert", msg, to_email, from_email, smtp_server, smtp_port, smtp_password)
                send_sms_alert(msg, to_number, from_number, account_sid, auth_token)
                print(f"[!] {msg}")

            else:
                print(f"[+] No SYN flood attack detected. SYN packet count: {syn_count}")
        except Exception as e:
            print(f"[!] Error during SYN flood detection: {e}")

    
    
    def monitor_network_for_suspicious_activity(self, duration=60, verbose=False):
        """
        Monitors the network for suspicious activity by analyzing packet patterns.
        """
        try:
            self.PrivateScanner.GetNetworkData(PrintDetails=verbose)
            suspicious_sources = defaultdict(int)
    
            def packet_callback(packet):
                if packet.haslayer(scapy.IP) and packet[scapy.IP].dst == self.PrivateScanner.private_IPv4 and packet[scapy.IP].flags == "DF":
                    suspicious_sources[packet[scapy.IP].src] += 1
                    if verbose:
                        print(f"[!] Suspicious activity detected from {packet[scapy.IP].src}")
                        print(packet.summary())
    
            scapy.sniff(prn=packet_callback, store=0, timeout=duration, filter=f"dst {self.PrivateScanner.private_IPv4}")
            
            threshold = 5
            suspicious_sources = {source: count for source, count in suspicious_sources.items() if count >= threshold}
            
            print(f"[$] Done! Network monitoring for suspicious activity complete.")
            print(f"[-] Detected suspicious sources with {threshold} or more occurrences: {suspicious_sources}")
            
            return suspicious_sources
        except Exception as e:
            print(f"[!] Error during network monitoring for suspicious activity: {e}")
            return {}
    
def main():
    engine = EngineAnalyzer()
    while True:
        engine.ViewFunc("all", use_color=True)  # or False for no color
        try:
            option = input("\n[>] Enter your choice (or 'exit' to quit): ").strip().lower()
            if option == 'exit':
                engine.MainMenu["Exit"]()
                break
            elif option.isdigit():
                engine.ViewFunc(int(option), use_color=True)
            else:
                engine.ViewFunc(option.capitalize(), use_color=True)
        except Exception as e:
            print(f"[!] Error: {e}")



class EngineAnalyzer(Analyzer,MenuHandler):
    def __init__(self):
        super().__init__()
        self.MainMenu = {
            "Analyzer": lambda: self.AnalyzerOptions(FunctionKey="menu"),
            "Help": self.HelpOptions,
            "Exit": lambda: os.abort()
        }
    def prompt_input(self, prompt, default=None):
        """
        Prompts the user for input with an optional default value.
        Converts to the type of the default if provided.
        """
        try:
            user_input = input(f"[>] Enter value for '{prompt}' (default: {default}): ").strip()
            if user_input == "":
                return default
            if default is not None:
                return type(default)(user_input)  # convert to type of default
            return user_input
        except Exception as e:
            print(f"[!] Invalid input: {e}")
            return default    


    def ViewFunc(self, option):
        if isinstance(option, str) and option.lower() == "all":
            print("==============================")
            for index, view in enumerate(self.MainMenu):
                print(f"{index+1}) {view}")
            print("==============================")

        elif isinstance(option, int):
            if 1 <= option <= len(self.MainMenu):
                key = list(self.MainMenu.keys())[option - 1]
                submenu = self.MainMenu[key]()
                if submenu:
                    self.print_submenu(submenu)
                    sub_option = input("[>] Select to run: ")
                    self.handle_submenu(submenu, sub_option)
                else:
                    print(f"{option}. {key}")
            else:
                print(f"[!] Please choose an option within the range 1 - {len(self.MainMenu)}")

        elif isinstance(option, str):
            option = option.capitalize()
            if option in self.MainMenu:
                submenu = self.MainMenu[option]()
                if submenu:
                    self.print_submenu(submenu)
                    sub_option = input("[>] Select to run: ")
                    self.handle_submenu(submenu, sub_option)
                else:
                    print(f"{option}. {submenu}")
            else:
                print(f"[!] Invalid option: {option}")

    def print_submenu(self, submenu):
        print("==============================")
        for idx, sub_key in enumerate(submenu):
            print(f"{idx+1}) {sub_key}")
        print("==============================")

    def handle_submenu(self, submenu, sub_option):
        if sub_option.isdigit():
            sub_option = int(sub_option)
            if 1 <= sub_option <= len(submenu):
                sub_key = list(submenu.keys())[sub_option - 1]
                submenu[sub_key]()
            else:
                print(f"[!] Please choose an option within the range 1 - {len(submenu)}")
        else:
            print(f"[!] Invalid option: {sub_option}")


    
    def AnalyzerOptions(self, FunctionKey='menu', **kwargs):
        if FunctionKey is None:
            FunctionKey = input("Enter Analyzer option: ")
        def run_detect_dns_spoofing():
            try:
                load_from_file = self.prompt_input("Load target domains from file? (y/n)", "y").lower()
                if load_from_file == "y":
                    with open("target_domains.json", "r") as f:
                        target_domains = json.load(f)
                        print(f"[+] Loaded target domains from 'target_domains.json'")
                else:
                    target_input = self.prompt_input("target (JSON format like {\"example.com\": [\"1.1.1.1\"]})")
                    target_domains = json.loads(target_input)
                    # Save for future use
                    with open("target_domains.json", "w") as f:
                        json.dump(target_domains, f, indent=4)
                        print("[+] Saved new target domains to 'target_domains.json'")
                verbose = self.prompt_input("verbose", False)
                self.detect_dns_spoofing(target_domains=target_domains, verbose=verbose)
            except json.JSONDecodeError:
                print("[!] Invalid JSON format. Example: {\"example.com\": [\"1.1.1.1\"]}")
            except Exception as e:
                print(f"[!] Error: {e}")

        def run_detect_rogue_devices():
            try:
                load_from_file = self.prompt_input("Load known devices from file? (y/n)", "y").lower()
                if load_from_file == "y":
                    try:
                        with open("known_devices.json", "r") as f:
                            known_devices = json.load(f)
                        print(f"[+] Loaded {len(known_devices)} known MACs from known_devices.json.")
                    except Exception as e:
                        print(f"[!] Failed to load known_devices.json: {e}")
                        known_devices = []
                else:
                    try:
                        known_input = self.prompt_input("Enter MAC list as JSON (e.g., [\"00:11:22:33:44:55\"])", "[]")
                        known_devices = json.loads(known_input)
                    except json.JSONDecodeError:
                        print("[!] Invalid JSON format. Example: [\"00:11:22:33:44:55\"]")
                        known_devices = []


            except json.JSONDecodeError:
                print("[!] Invalid JSON format. Example: [\"00:11:22:33:44:55\"]")
                return
            verbose = kwargs.get("verbose", self.prompt_input("verbose", False))
            self.detect_rogue_devices(known_devices=known_devices, verbose=verbose)
        self.AnalyzerDic = {
            "Identifies devices on the network by analyzing their traffic patterns": lambda: self.identify_devices_by_traffic(
                duration=kwargs.get("duration", self.prompt_input("duration", 60)),
                verbose=kwargs.get("verbose", self.prompt_input("verbose", False))
            ),
            "Monitors network traffic on a specified interface for a given duration": lambda: self.monitor_network_traffic(
                interface=kwargs.get("network interface", self.prompt_input("network interface")),
                duration=kwargs.get("duration", self.prompt_input("duration", 60)),
                verbose=kwargs.get("verbose", self.prompt_input("verbose", False)),
                save_to_file=kwargs.get("save_to_file", self.prompt_input("save_to_file", False)),
                file_path=kwargs.get("file path", self.prompt_input("file path", 'captured_packets.pcap')),
                protocol_filter=kwargs.get("protocol filter", self.prompt_input("protocol filter"))
            ),
            "Detects rogue access points by comparing discovered APs against a list of known APs": lambda: self.detect_rogue_access_points(
                known_ap_list=kwargs.get("target", self.prompt_input("target")),
                verbose=kwargs.get("verbose", self.prompt_input("verbose", False))
            ),
            "Detects rogue devices by comparing discovered devices with a list of known devices": run_detect_rogue_devices,
            "Detects DNS spoofing by comparing DNS query results with known legitimate IP addresses": run_detect_dns_spoofing,
            "Checks for DNS poisoning by comparing the resolved IP address of a domain with a known IP address": lambda: self.check_dns_poisoning(
                domain=kwargs.get("domain_name", self.prompt_input("domain_name")),
                known_ip=kwargs.get("destination", self.prompt_input("destination")),
                verbose=kwargs.get("verbose", self.prompt_input("verbose", False))
            ),
            "Detects SYN flood attacks by monitoring the network for a specified duration and counting SYN packets": lambda: self.detect_syn_flood(
                duration=kwargs.get("duration", self.prompt_input("duration", 60)),
                threshold=kwargs.get("timeout", self.prompt_input("timeout", 2)),
                verbose=kwargs.get("verbose", self.prompt_user("verbose", False))
            ),
            "Monitors the network for suspicious activity by analyzing packet patterns": lambda: self.monitor_network_for_suspicious_activity(
                duration=kwargs.get("duration", self.prompt_user("duration", 60)),
                verbose=kwargs.get("verbose", self.prompt_user("verbose", False))
            )
        }

        if FunctionKey in self.AnalyzerDic:
            self.AnalyzerDic[FunctionKey]()
        elif FunctionKey == "menu":
            return self.AnalyzerDic
        else:
            print(f"[!] Invalid FunctionKey: {FunctionKey}")



    def HelpOptions(self):
        with open("Analyzer.txt", "r") as HelpRead:
            print(HelpRead.read())
            
    def ViewFunc(self, option, use_color=True):
        if isinstance(option, str) and option.lower() == "all":
            self.display_menu(self.MainMenu, use_color)
        elif isinstance(option, int):
            if 1 <= option <= len(self.MainMenu):
                key = list(self.MainMenu.keys())[option - 1]
                submenu = self.MainMenu[key]()
                if submenu:
                    self.display_menu(submenu, use_color)
                    sub_option = input("[>] Select to run: ")
                    self.handle_menu_selection(submenu, sub_option, use_color)
                else:
                    print(f"{option}. {key}")
            else:
                print("[!] Invalid option range.")
        elif isinstance(option, str):
            key = option.capitalize()
            if key in self.MainMenu:
                submenu = self.MainMenu[key]()
                if submenu:
                    self.display_menu(submenu, use_color)
                    sub_option = input("[>] Select to run: ")
                    self.handle_menu_selection(submenu, sub_option, use_color)
                else:
                    print(f"{key}. {submenu}")
            else:
                print("[!] Invalid option name.")
        else:
            print("[!] Invalid input type.")


                

    def print_submenu(self, submenu):
        print("==============================")
        for idx, sub_key in enumerate(submenu):
            print(f"\033[34m{idx+1}\u001b[0m) {sub_key}")
        print("==============================")


    def handle_submenu(self, submenu, sub_option):
        if sub_option.isdigit():
            sub_option = int(sub_option)
            if 1 <= sub_option <= len(submenu):
                sub_key = list(submenu.keys())[sub_option - 1]
                submenu[sub_key]()
            else:
                print(f"[\033[31m!\u001b[0m] Please choose an option within the range 1 - {len(submenu)}")

        else:
            print(f"[\033[31m!\u001b[0m] Invalid option: {sub_option}")











def main():
    engine = EngineAnalyzer()
    
    while True:
        engine.ViewFunc("all")
        try:
            option = input("\n[\033[36m>\u001b[0m] Enter your choice (or '\033[31mexit\u001b[0m' to quit): ").strip().lower()
            if option == 'exit':
                engine.MainMenu["Exit"]()
                break
            elif option.isdigit():
                engine.ViewFunc(int(option))
            else:
                engine.ViewFunc(option.capitalize())

        except ValueError:
            print("[\033[31m!\u001b[0m] Invalid input. Please enter a number or '\033[31mexit\u001b[0m' to quit.")
        except KeyError:
            print("[\033[31m!\u001b[0m] Invalid option. Please choose a valid option number or name.")
        except Exception as e:
            print(f"[\033[31m!\u001b[0m] An unexpected error occurred: {e}")

def generate_known_devices_file(scanner=None, filename="known_devices.json"):
    """
    Scans the local network and saves discovered MAC addresses to known_devices.json
    """
    if scanner is None:
        from Analyzer_cleaned import Discover
        scanner = Discover()

    print("[*] Running safe discovery to build trusted device list...")
    scanner.ARP_DiscoverHosts(verbose=True, mapping=False, save_to_file=False)

    mac_list = [host["MAC"] for host in scanner.DiscoveredData]

    if not mac_list:
        print("[!] No devices found. Make sure devices are online and retry.")
        return

    if mac_list:
        with open("known_devices.json", "w") as f:
            json.dump(mac_list, f, indent=4)
        print(f"[+] Saved {len(mac_list)} MAC addresses to 'known_devices.json'")
    else:
        print("[!] No MAC addresses to save. Discovery may have failed.")
        print(f"[DEBUG] MAC list: {mac_list}")


            

if __name__ == "__main__":
     main()
