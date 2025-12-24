from scapy.all import *
import requests
import time

class AnalyzeNetwork:
    def __init__(self, pcap_path):
        """
        pcap_path (string): path to a pcap file
        """
        self.pcap_path = pcap_path
        self.packets = rdpcap(pcap_path)
        self.devices = self.get_info()

    def get_ips(self):
        """returns a list of ip addresses (strings) that appear in
        the pcap"""
        IP_addresses = set()
        for packet in self.packets:
            if IP in packet:
                IP_addresses.add(packet[IP].src)
                IP_addresses.add(packet[IP].dst)
            if ARP in packet:
                IP_addresses.add(packet[ARP].psrc)
                IP_addresses.add(packet[ARP].pdst)
        return list(IP_addresses)

    def get_macs(self):
        """returns a list of MAC addresses (strings) that appear in
        the pcap"""
        MAC_addresses = set()
        for packet in self.packets:
            if Ether in packet:
                MAC_addresses.add(packet[Ether].src)
                MAC_addresses.add(packet[Ether].dst)
        return list(MAC_addresses)

    def get_info_by_mac(self, mac):
        """returns a dict with all information about the device with
        given MAC address"""
        for device in self.devices.values():
            if device["MAC"] == mac:
                return device
        return {"MAC": mac, "IP": "Unknown", "VENDOR": "Unknown"}

    def get_info_by_ip(self, ip):
        """returns a dict with all information about the device with
        given IP address"""
        for device in self.devices.values():
            if device["IP"] == ip:
                return device
        return {"MAC": "Unknown", "IP": ip, "VENDOR": "Unknown"}

    def get_info(self):
        """returns a list of dicts with information about every
        device in the pcap"""
        seen_macs = {}
        devices = []
        for packet in self.packets:
            mac = None
            ip = None
            if Ether in packet:
                mac = packet[Ether].src
                if IP in packet:
                    ip = packet[IP].src
            if ARP in packet:
                mac = packet[ARP].hwsrc
                ip = packet[ARP].psrc
            if mac:
                if mac not in seen_macs:
                    device = {
                        "MAC": mac,
                        "IP": "Unknown",
                        "VENDOR": self.get_vendor(mac),
                        "OS": "Unknown"
                    }
                    devices.append(device)
                    seen_macs[mac] = device
                if ip:
                    seen_macs[mac]["IP"] = ip
        for device in devices:
            device["OS"] = self.guess_os(device)
        return devices


    def get_vendor(self, mac):
        """
        Get vendor name from MAC address
        """
        try:
            url = f"https://api.macvendors.com/{mac}"
            response = requests.get(url, timeout=2)
            if response.status_code == 200:
                time.sleep(1)
                # if we go too quickly the API might return unknown for a known vendor
                return response.text.strip()
        except Exception:
            pass
        return "Unknown"
    
    def guess_os(self, device_info):
        """
        returns assumed operating system of a device
        """
        windows_default_payload = b"abcdefghijklmnopqrstuvwabcdefghi"
        unix_default_payload = bytes(range(0x10, 0x50))  # 0x10 to 0x4F = 64 bytes
        mac = device_info.get("MAC")
        if not mac:
            return "Unknown"
        ttl_signs = []
        payload_signs = []
        for packet in self.packets:
            if Ether in packet and packet[Ether].src == mac:
                if IP in packet:
                    ttl = packet[IP].ttl
                    if ttl <= 128:
                        ttl_signs.append("Windows")
                        if ttl <= 64:
                            ttl_signs.append("Unix")
                    else:
                        ttl_signs.append("Network Device")
                if ICMP in packet and packet[ICMP].type == 8:
                    if Raw in packet:
                        payload = bytes(packet[Raw].load)
                        if windows_default_payload in payload:
                            payload_signs.append("Windows")
                        elif unix_default_payload in payload:
                            payload_signs.append("Unix")
        all_signs = ttl_signs + payload_signs
        if not all_signs:
            return "Unknown"
        return list(set(all_signs))
    
    def __repr__(self):
        return f"AnalyzeNetwork('{self.pcap_path}')"

    def __str__(self):
        return f"Network analysis of {self.pcap_path}"
