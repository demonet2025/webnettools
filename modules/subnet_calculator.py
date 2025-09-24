"""
IP Subnet Calculator Module
Handles IPv4 and IPv6 subnet calculations
"""

import ipaddress
import math
from typing import Dict, List, Tuple, Union


class SubnetCalculator:
    """IP Subnet Calculator for IPv4 and IPv6"""

    @staticmethod
    def calculate_ipv4_subnet(ip_address: str, subnet_mask: str = None, cidr: int = None) -> Dict:
        """Calculate IPv4 subnet information"""
        try:
            # Parse IP address
            ip = ipaddress.IPv4Address(ip_address)
            
            # Determine subnet mask
            if cidr is not None:
                network = ipaddress.IPv4Network(f"{ip_address}/{cidr}", strict=False)
            elif subnet_mask:
                # Convert subnet mask to CIDR
                mask = ipaddress.IPv4Address(subnet_mask)
                cidr = SubnetCalculator._subnet_mask_to_cidr(mask)
                network = ipaddress.IPv4Network(f"{ip_address}/{cidr}", strict=False)
            else:
                return {
                    'success': False,
                    'error': 'Either subnet mask or CIDR notation is required'
                }
            
            # Calculate network information
            network_address = str(network.network_address)
            broadcast_address = str(network.broadcast_address)
            subnet_mask = str(network.netmask)
            wildcard_mask = str(network.hostmask)
            cidr_notation = f"/{network.prefixlen}"
            
            # Calculate usable hosts
            total_hosts = network.num_addresses
            usable_hosts = total_hosts - 2 if total_hosts > 2 else total_hosts
            
            # Calculate host range
            if total_hosts > 2:
                first_host = str(network.network_address + 1)
                last_host = str(network.broadcast_address - 1)
            else:
                first_host = str(network.network_address)
                last_host = str(network.broadcast_address)
            
            # Determine IP class
            ip_class = SubnetCalculator._get_ip_class(ip)
            
            # Calculate binary representations
            ip_binary = SubnetCalculator._ip_to_binary(ip_address)
            subnet_binary = SubnetCalculator._ip_to_binary(subnet_mask)
            network_binary = SubnetCalculator._ip_to_binary(network_address)
            
            return {
                'success': True,
                'input': {
                    'ip_address': ip_address,
                    'subnet_mask': subnet_mask,
                    'cidr': network.prefixlen
                },
                'network_info': {
                    'network_address': network_address,
                    'broadcast_address': broadcast_address,
                    'subnet_mask': subnet_mask,
                    'wildcard_mask': wildcard_mask,
                    'cidr_notation': cidr_notation,
                    'ip_class': ip_class
                },
                'host_info': {
                    'total_hosts': total_hosts,
                    'usable_hosts': usable_hosts,
                    'first_host': first_host,
                    'last_host': last_host
                },
                'binary_info': {
                    'ip_binary': ip_binary,
                    'subnet_binary': subnet_binary,
                    'network_binary': network_binary
                },
                'raw_output': SubnetCalculator._format_ipv4_output(ip_address, network, ip_class)
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'IPv4 subnet calculation failed: {str(e)}'
            }

    @staticmethod
    def calculate_ipv6_subnet(ip_address: str, prefix_length: int) -> Dict:
        """Calculate IPv6 subnet information"""
        try:
            # Parse IP address
            ip = ipaddress.IPv6Address(ip_address)
            network = ipaddress.IPv6Network(f"{ip_address}/{prefix_length}", strict=False)
            
            # Calculate network information
            network_address = str(network.network_address)
            broadcast_address = str(network.broadcast_address)
            cidr_notation = f"/{network.prefixlen}"
            
            # Calculate usable hosts
            total_hosts = network.num_addresses
            usable_hosts = total_hosts - 2 if total_hosts > 2 else total_hosts
            
            # Calculate host range
            if total_hosts > 2:
                first_host = str(network.network_address + 1)
                last_host = str(network.broadcast_address - 1)
            else:
                first_host = str(network.network_address)
                last_host = str(network.broadcast_address)
            
            # Calculate binary representations
            ip_binary = SubnetCalculator._ipv6_to_binary(ip_address)
            network_binary = SubnetCalculator._ipv6_to_binary(network_address)
            
            return {
                'success': True,
                'input': {
                    'ip_address': ip_address,
                    'prefix_length': prefix_length
                },
                'network_info': {
                    'network_address': network_address,
                    'broadcast_address': broadcast_address,
                    'cidr_notation': cidr_notation,
                    'prefix_length': prefix_length
                },
                'host_info': {
                    'total_hosts': total_hosts,
                    'usable_hosts': usable_hosts,
                    'first_host': first_host,
                    'last_host': last_host
                },
                'binary_info': {
                    'ip_binary': ip_binary,
                    'network_binary': network_binary
                },
                'raw_output': SubnetCalculator._format_ipv6_output(ip_address, network)
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'IPv6 subnet calculation failed: {str(e)}'
            }

    @staticmethod
    def _subnet_mask_to_cidr(subnet_mask: ipaddress.IPv4Address) -> int:
        """Convert subnet mask to CIDR notation"""
        mask_int = int(subnet_mask)
        cidr = 0
        while mask_int & 0x80000000:
            cidr += 1
            mask_int <<= 1
        return cidr

    @staticmethod
    def _get_ip_class(ip: ipaddress.IPv4Address) -> str:
        """Determine IP class"""
        first_octet = int(ip) >> 24
        if 1 <= first_octet <= 126:
            return 'A'
        elif 128 <= first_octet <= 191:
            return 'B'
        elif 192 <= first_octet <= 223:
            return 'C'
        elif 224 <= first_octet <= 239:
            return 'D (Multicast)'
        elif 240 <= first_octet <= 255:
            return 'E (Reserved)'
        else:
            return 'Unknown'

    @staticmethod
    def _ip_to_binary(ip_address: str) -> str:
        """Convert IP address to binary representation"""
        octets = ip_address.split('.')
        binary_octets = [format(int(octet), '08b') for octet in octets]
        return '.'.join(binary_octets)

    @staticmethod
    def _ipv6_to_binary(ip_address: str) -> str:
        """Convert IPv6 address to binary representation"""
        ip = ipaddress.IPv6Address(ip_address)
        binary = format(int(ip), '0128b')
        # Group into 16-bit chunks
        chunks = [binary[i:i+16] for i in range(0, 128, 16)]
        return ':'.join(chunks)

    @staticmethod
    def _format_ipv4_output(ip_address: str, network: ipaddress.IPv4Network, ip_class: str) -> str:
        """Format IPv4 calculation output"""
        output = []
        output.append("IPv4 Subnet Calculator Results")
        output.append("=" * 40)
        output.append("")
        
        output.append(f"Input IP Address: {ip_address}")
        output.append(f"Subnet Mask: {network.netmask}")
        output.append(f"CIDR Notation: /{network.prefixlen}")
        output.append(f"IP Class: {ip_class}")
        output.append("")
        
        output.append("Network Information:")
        output.append(f"  Network Address: {network.network_address}")
        output.append(f"  Broadcast Address: {network.broadcast_address}")
        output.append(f"  Wildcard Mask: {network.hostmask}")
        output.append("")
        
        output.append("Host Information:")
        output.append(f"  Total Hosts: {network.num_addresses}")
        if network.num_addresses > 2:
            output.append(f"  Usable Hosts: {network.num_addresses - 2}")
            output.append(f"  First Host: {network.network_address + 1}")
            output.append(f"  Last Host: {network.broadcast_address - 1}")
        else:
            output.append(f"  Usable Hosts: {network.num_addresses}")
            output.append(f"  Host Range: {network.network_address} - {network.broadcast_address}")
        output.append("")
        
        output.append("Binary Representations:")
        output.append(f"  IP Address: {SubnetCalculator._ip_to_binary(ip_address)}")
        output.append(f"  Subnet Mask: {SubnetCalculator._ip_to_binary(str(network.netmask))}")
        output.append(f"  Network: {SubnetCalculator._ip_to_binary(str(network.network_address))}")
        
        return "\n".join(output)

    @staticmethod
    def _format_ipv6_output(ip_address: str, network: ipaddress.IPv6Network) -> str:
        """Format IPv6 calculation output"""
        output = []
        output.append("IPv6 Subnet Calculator Results")
        output.append("=" * 40)
        output.append("")
        
        output.append(f"Input IP Address: {ip_address}")
        output.append(f"Prefix Length: /{network.prefixlen}")
        output.append("")
        
        output.append("Network Information:")
        output.append(f"  Network Address: {network.network_address}")
        output.append(f"  Broadcast Address: {network.broadcast_address}")
        output.append("")
        
        output.append("Host Information:")
        output.append(f"  Total Hosts: {network.num_addresses}")
        if network.num_addresses > 2:
            output.append(f"  Usable Hosts: {network.num_addresses - 2}")
            output.append(f"  First Host: {network.network_address + 1}")
            output.append(f"  Last Host: {network.broadcast_address - 1}")
        else:
            output.append(f"  Usable Hosts: {network.num_addresses}")
            output.append(f"  Host Range: {network.network_address} - {network.broadcast_address}")
        output.append("")
        
        output.append("Binary Representations:")
        output.append(f"  IP Address: {SubnetCalculator._ipv6_to_binary(ip_address)}")
        output.append(f"  Network: {SubnetCalculator._ipv6_to_binary(str(network.network_address))}")
        
        return "\n".join(output)

    @staticmethod
    def get_common_subnets() -> List[Dict]:
        """Get list of common subnet masks"""
        return [
            {'name': '/8 (255.0.0.0)', 'cidr': 8, 'mask': '255.0.0.0', 'hosts': 16777214},
            {'name': '/16 (255.255.0.0)', 'cidr': 16, 'mask': '255.255.0.0', 'hosts': 65534},
            {'name': '/24 (255.255.255.0)', 'cidr': 24, 'mask': '255.255.255.0', 'hosts': 254},
            {'name': '/25 (255.255.255.128)', 'cidr': 25, 'mask': '255.255.255.128', 'hosts': 126},
            {'name': '/26 (255.255.255.192)', 'cidr': 26, 'mask': '255.255.255.192', 'hosts': 62},
            {'name': '/27 (255.255.255.224)', 'cidr': 27, 'mask': '255.255.255.224', 'hosts': 30},
            {'name': '/28 (255.255.255.240)', 'cidr': 28, 'mask': '255.255.255.240', 'hosts': 14},
            {'name': '/29 (255.255.255.248)', 'cidr': 29, 'mask': '255.255.255.248', 'hosts': 6},
            {'name': '/30 (255.255.255.252)', 'cidr': 30, 'mask': '255.255.255.252', 'hosts': 2},
            {'name': '/31 (255.255.255.254)', 'cidr': 31, 'mask': '255.255.255.254', 'hosts': 0},
            {'name': '/32 (255.255.255.255)', 'cidr': 32, 'mask': '255.255.255.255', 'hosts': 1}
        ]

    @staticmethod
    def get_common_ipv6_prefixes() -> List[Dict]:
        """Get list of common IPv6 prefix lengths"""
        return [
            {'name': '/64', 'prefix': 64, 'description': 'Standard subnet size'},
            {'name': '/56', 'prefix': 56, 'description': 'Large subnet'},
            {'name': '/48', 'prefix': 48, 'description': 'Site prefix'},
            {'name': '/32', 'prefix': 32, 'description': 'ISP allocation'},
            {'name': '/128', 'prefix': 128, 'description': 'Single host'}
        ]
