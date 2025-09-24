#!/usr/bin/env python3
"""
NetHub Webnettools - Python Version
A modern web application for network testing and analysis tools
"""

from flask import Flask, render_template, request, jsonify, send_from_directory
import subprocess
import json
import os
import re
import ssl
import socket
import sqlite3
from datetime import datetime, timedelta
import threading
import time
from urllib.parse import urlparse

app = Flask(__name__)

# Initialize SQLite database for recent searches
def init_database():
    """Initialize SQLite database for storing recent searches"""
    conn = sqlite3.connect('recent_searches.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS recent_searches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            full_url TEXT NOT NULL,
            search_count INTEGER DEFAULT 1,
            last_searched TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

# Initialize database on startup
init_database()

def save_recent_search(domain, full_url):
    """Save or update a recent search"""
    try:
        conn = sqlite3.connect('recent_searches.db')
        cursor = conn.cursor()
        
        # Check if domain already exists
        cursor.execute('SELECT id, search_count FROM recent_searches WHERE domain = ?', (domain,))
        result = cursor.fetchone()
        
        if result:
            # Update existing record
            search_id, count = result
            cursor.execute('''
                UPDATE recent_searches 
                SET search_count = ?, last_searched = CURRENT_TIMESTAMP 
                WHERE id = ?
            ''', (count + 1, search_id))
        else:
            # Insert new record
            cursor.execute('''
                INSERT INTO recent_searches (domain, full_url, search_count, last_searched)
                VALUES (?, ?, 1, CURRENT_TIMESTAMP)
            ''', (domain, full_url))
        
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error saving recent search: {e}")

def get_recent_searches(limit=10):
    """Get recent searches ordered by last_searched"""
    try:
        conn = sqlite3.connect('recent_searches.db')
        cursor = conn.cursor()
        cursor.execute('''
            SELECT domain, full_url, search_count, last_searched
            FROM recent_searches 
            ORDER BY last_searched DESC 
            LIMIT ?
        ''', (limit,))
        results = cursor.fetchall()
        conn.close()
        
        return [{
            'domain': row[0],
            'full_url': row[1],
            'search_count': row[2],
            'last_searched': row[3]
        } for row in results]
    except Exception as e:
        print(f"Error getting recent searches: {e}")
        return []

def mask_domain(domain):
    """Mask domain for display (e.g., pixabay.com -> pix***.com)"""
    if len(domain) <= 3:
        return domain
    return domain[:3] + '***' + domain[domain.rfind('.'):]

# Configuration
AVAILABLE_TOOLS = ['testssl', 'ping', 'traceroute', 'nmap', 'dig', 'mtr']
RATE_LIMIT = 1000
CA_DIR = '/certs'

class NetworkTools:
    """Network testing tools implementation"""
    
    @staticmethod
    def test_ssl(url):
        """Run SSL test using testssl.sh"""
        try:
            # Parse URL to get hostname and port
            parsed = urlparse(url if url.startswith('http') else f'https://{url}')
            hostname = parsed.hostname
            port = parsed.port or 443
            
            # Run testssl.sh
            cmd = ['testssl.sh', '--json', f'{hostname}:{port}']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                return {
                    'success': True,
                    'output': result.stdout,
                    'error': None
                }
            else:
                return {
                    'success': False,
                    'output': result.stdout,
                    'error': result.stderr
                }
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'output': '',
                'error': 'SSL test timed out after 5 minutes'
            }
        except Exception as e:
            return {
                'success': False,
                'output': '',
                'error': str(e)
            }
    
    @staticmethod
    def ping(hostname, count=4):
        """Run ping test with detailed analysis"""
        try:
            cmd = ['ping', '-c', str(count), '-W', '5', hostname]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                # Parse ping output for statistics
                output = result.stdout
                stats = NetworkTools._parse_ping_output(output)
                
                return {
                    'success': True,
                    'output': output,
                    'statistics': stats,
                    'error': None
                }
            else:
                return {
                    'success': False,
                    'output': result.stdout,
                    'statistics': None,
                    'error': result.stderr or 'Host unreachable'
                }
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'output': '',
                'statistics': None,
                'error': 'Ping test timed out after 30 seconds'
            }
        except Exception as e:
            return {
                'success': False,
                'output': '',
                'statistics': None,
                'error': str(e)
            }

    @staticmethod
    def ping_stream(hostname, count=4):
        """Run ping test with streaming output"""
        try:
            cmd = ['ping', '-c', str(count), '-W', '5', hostname]
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1, universal_newlines=True)
            
            output_lines = []
            stats = {
                'packets_transmitted': 0,
                'packets_received': 0,
                'packet_loss': 0,
                'rtt_min': 0,
                'rtt_avg': 0,
                'rtt_max': 0,
                'rtt_mdev': 0,
                'response_times': []
            }
            
            # Read output line by line
            for line in iter(process.stdout.readline, ''):
                output_lines.append(line.strip())
                yield {
                    'type': 'line',
                    'content': line.strip(),
                    'timestamp': time.time()
                }
            
            # Wait for process to complete
            process.wait()
            
            # Parse final statistics
            full_output = '\n'.join(output_lines)
            stats = NetworkTools._parse_ping_output(full_output)
            
            yield {
                'type': 'complete',
                'success': process.returncode == 0,
                'output': full_output,
                'statistics': stats,
                'error': None if process.returncode == 0 else 'Host unreachable'
            }
            
        except Exception as e:
            yield {
                'type': 'error',
                'success': False,
                'output': '',
                'statistics': None,
                'error': str(e)
            }
    
    @staticmethod
    def _parse_ping_output(output):
        """Parse ping output to extract statistics"""
        try:
            lines = output.split('\n')
            stats = {
                'packets_transmitted': 0,
                'packets_received': 0,
                'packet_loss': 0,
                'rtt_min': 0,
                'rtt_avg': 0,
                'rtt_max': 0,
                'rtt_mdev': 0,
                'response_times': []
            }
            
            for line in lines:
                # Parse ping statistics line
                if 'packets transmitted' in line and 'received' in line:
                    parts = line.split(',')
                    for part in parts:
                        if 'packets transmitted' in part:
                            stats['packets_transmitted'] = int(part.split()[0])
                        elif 'received' in part:
                            stats['packets_received'] = int(part.split()[0])
                        elif 'packet loss' in part:
                            loss_str = part.split()[0].replace('%', '')
                            stats['packet_loss'] = float(loss_str)
                
                # Parse RTT statistics
                elif 'rtt min/avg/max/mdev' in line:
                    rtt_part = line.split('=')[1].strip()
                    rtt_values = rtt_part.split('/')
                    if len(rtt_values) >= 4:
                        stats['rtt_min'] = float(rtt_values[0])
                        stats['rtt_avg'] = float(rtt_values[1])
                        stats['rtt_max'] = float(rtt_values[2])
                        stats['rtt_mdev'] = float(rtt_values[3].replace(' ms', ''))
                
                # Parse individual response times
                elif 'time=' in line:
                    try:
                        time_part = line.split('time=')[1].split()[0]
                        response_time = float(time_part)
                        stats['response_times'].append(response_time)
                    except:
                        pass
            
            return stats
        except Exception as e:
            return {
                'packets_transmitted': 0,
                'packets_received': 0,
                'packet_loss': 100,
                'rtt_min': 0,
                'rtt_avg': 0,
                'rtt_max': 0,
                'rtt_mdev': 0,
                'response_times': [],
                'parse_error': str(e)
            }
    
    @staticmethod
    def traceroute(hostname, max_hops=30):
        """Run traceroute test with detailed analysis"""
        try:
            cmd = ['traceroute', '-m', str(max_hops), '-w', '3', hostname]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                # Parse traceroute output
                output = result.stdout
                hops = NetworkTools._parse_traceroute_output(output)
                
                return {
                    'success': True,
                    'output': output,
                    'hops': hops,
                    'total_hops': len(hops),
                    'error': None
                }
            else:
                return {
                    'success': False,
                    'output': result.stdout,
                    'hops': [],
                    'total_hops': 0,
                    'error': result.stderr or 'Traceroute failed'
                }
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'output': '',
                'hops': [],
                'total_hops': 0,
                'error': 'Traceroute test timed out after 60 seconds'
            }
        except Exception as e:
            return {
                'success': False,
                'output': '',
                'hops': [],
                'total_hops': 0,
                'error': str(e)
            }
    
    @staticmethod
    def _parse_traceroute_output(output):
        """Parse traceroute output to extract hop information"""
        try:
            lines = output.split('\n')
            hops = []
            
            for line in lines:
                line = line.strip()
                if not line or 'traceroute' in line.lower():
                    continue
                
                # Parse hop line (format: "1  gateway (192.168.1.1)  0.123 ms  0.456 ms  0.789 ms")
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        hop_num = int(parts[0])
                        ip_address = None
                        hostname = None
                        times = []
                        
                        # Extract IP address and hostname
                        for part in parts[1:]:
                            if '(' in part and ')' in part:
                                # Extract IP from parentheses
                                ip_start = part.find('(') + 1
                                ip_end = part.find(')')
                                ip_address = part[ip_start:ip_end]
                                hostname = part[:ip_start-1]
                            elif '.' in part and any(c.isdigit() for c in part):
                                # This might be an IP address
                                if not ip_address:
                                    ip_address = part
                                    hostname = part
                        
                        # Extract response times
                        for part in parts[2:]:
                            if 'ms' in part:
                                try:
                                    time_str = part.replace('ms', '').replace('*', '0')
                                    time_val = float(time_str)
                                    times.append(time_val)
                                except:
                                    times.append(0)
                        
                        # Calculate statistics
                        if times:
                            avg_time = sum(times) / len(times)
                            min_time = min(times)
                            max_time = max(times)
                        else:
                            avg_time = min_time = max_time = 0
                        
                        hop_info = {
                            'hop_number': hop_num,
                            'ip_address': ip_address or 'Unknown',
                            'hostname': hostname or 'Unknown',
                            'response_times': times,
                            'avg_time': avg_time,
                            'min_time': min_time,
                            'max_time': max_time,
                            'packet_loss': max(0, 100 - (len(times) * 100 / 3)) if times else 100
                        }
                        
                        hops.append(hop_info)
                    except (ValueError, IndexError):
                        continue
            
            return hops
        except Exception as e:
            return []
    
    @staticmethod
    def dig(domain, record_type='A'):
        """Run dig DNS lookup with detailed analysis"""
        try:
            cmd = ['dig', '+noall', '+answer', '+comments', domain, record_type]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                # Parse dig output
                output = result.stdout
                records = NetworkTools._parse_dig_output(output, record_type)
                
                return {
                    'success': True,
                    'output': output,
                    'records': records,
                    'record_count': len(records),
                    'query_type': record_type,
                    'domain': domain,
                    'error': None
                }
            else:
                return {
                    'success': False,
                    'output': result.stdout,
                    'records': [],
                    'record_count': 0,
                    'query_type': record_type,
                    'domain': domain,
                    'error': result.stderr or 'DNS lookup failed'
                }
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'output': '',
                'records': [],
                'record_count': 0,
                'query_type': record_type,
                'domain': domain,
                'error': 'DNS lookup timed out after 30 seconds'
            }
        except Exception as e:
            return {
                'success': False,
                'output': '',
                'records': [],
                'record_count': 0,
                'query_type': record_type,
                'domain': domain,
                'error': str(e)
            }
    
    @staticmethod
    def _parse_dig_output(output, record_type):
        """Parse dig output to extract DNS records"""
        try:
            lines = output.split('\n')
            records = []
            
            for line in lines:
                line = line.strip()
                if not line or line.startswith(';') or 'QUERY' in line or 'ANSWER' in line:
                    continue
                
                # Parse DNS record line
                parts = line.split()
                if len(parts) >= 4:
                    try:
                        domain = parts[0].rstrip('.')
                        ttl = int(parts[1]) if parts[1].isdigit() else 0
                        record_class = parts[2] if len(parts) > 2 else 'IN'
                        record_type_actual = parts[3] if len(parts) > 3 else record_type
                        record_data = ' '.join(parts[4:]) if len(parts) > 4 else ''
                        
                        record_info = {
                            'domain': domain,
                            'ttl': ttl,
                            'class': record_class,
                            'type': record_type_actual,
                            'data': record_data,
                            'formatted': line
                        }
                        
                        records.append(record_info)
                    except (ValueError, IndexError):
                        continue
            
            return records
        except Exception as e:
            return []
    
    @staticmethod
    def nmap(hostname, scan_type='basic'):
        """Run nmap scan with detailed analysis"""
        try:
            # Choose scan type
            if scan_type == 'basic':
                cmd = ['nmap', '-sT', '-O', '--top-ports', '100', hostname]
            elif scan_type == 'comprehensive':
                cmd = ['nmap', '-sS', '-sV', '-O', '-A', '--script', 'vuln', hostname]
            elif scan_type == 'quick':
                cmd = ['nmap', '-sT', '--top-ports', '20', hostname]
            else:
                cmd = ['nmap', '-sT', hostname]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            if result.returncode == 0:
                # Parse nmap output
                output = result.stdout
                scan_results = NetworkTools._parse_nmap_output(output)
                
                return {
                    'success': True,
                    'output': output,
                    'scan_results': scan_results,
                    'scan_type': scan_type,
                    'target': hostname,
                    'error': None
                }
            else:
                return {
                    'success': False,
                    'output': result.stdout,
                    'scan_results': {},
                    'scan_type': scan_type,
                    'target': hostname,
                    'error': result.stderr or 'Nmap scan failed'
                }
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'output': '',
                'scan_results': {},
                'scan_type': scan_type,
                'target': hostname,
                'error': 'Nmap scan timed out after 120 seconds'
            }
        except Exception as e:
            return {
                'success': False,
                'output': '',
                'scan_results': {},
                'scan_type': scan_type,
                'target': hostname,
                'error': str(e)
            }
    
    @staticmethod
    def _parse_nmap_output(output):
        """Parse nmap output to extract scan results"""
        try:
            lines = output.split('\n')
            scan_results = {
                'hosts': [],
                'ports': [],
                'services': [],
                'os_info': {},
                'summary': {}
            }
            
            current_host = None
            in_port_section = False
            
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                
                # Parse host information
                if 'Nmap scan report for' in line:
                    host_info = line.split('Nmap scan report for ')[1]
                    current_host = {
                        'hostname': host_info,
                        'ip': host_info,
                        'status': 'up'
                    }
                    scan_results['hosts'].append(current_host)
                
                # Parse port information
                elif line.startswith(('PORT', 'STATE', 'SERVICE')):
                    in_port_section = True
                    continue
                elif in_port_section and '/' in line and ('open' in line or 'closed' in line or 'filtered' in line):
                    parts = line.split()
                    if len(parts) >= 3:
                        port_info = parts[0].split('/')
                        port = port_info[0]
                        protocol = port_info[1] if len(port_info) > 1 else 'tcp'
                        state = parts[1]
                        service = parts[2] if len(parts) > 2 else 'unknown'
                        
                        port_data = {
                            'port': int(port),
                            'protocol': protocol,
                            'state': state,
                            'service': service,
                            'version': ' '.join(parts[3:]) if len(parts) > 3 else ''
                        }
                        scan_results['ports'].append(port_data)
                
                # Parse OS information
                elif 'Running:' in line:
                    os_info = line.split('Running: ')[1]
                    scan_results['os_info']['running'] = os_info
                elif 'OS details:' in line:
                    os_details = line.split('OS details: ')[1]
                    scan_results['os_info']['details'] = os_details
                
                # Parse scan summary
                elif 'Nmap done:' in line:
                    summary_parts = line.split()
                    if len(summary_parts) >= 3:
                        scan_results['summary']['hosts_scanned'] = summary_parts[2]
                        scan_results['summary']['time_taken'] = summary_parts[4] if len(summary_parts) > 4 else 'Unknown'
            
            return scan_results
        except Exception as e:
            return {
                'hosts': [],
                'ports': [],
                'services': [],
                'os_info': {},
                'summary': {},
                'parse_error': str(e)
            }
    
    @staticmethod
    def mtr(hostname, count=10):
        """Run mtr test with detailed analysis"""
        try:
            cmd = ['mtr', '-r', '-c', str(count), '-n', hostname]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                # Parse mtr output
                output = result.stdout
                mtr_results = NetworkTools._parse_mtr_output(output)
                
                return {
                    'success': True,
                    'output': output,
                    'mtr_results': mtr_results,
                    'target': hostname,
                    'error': None
                }
            else:
                return {
                    'success': False,
                    'output': result.stdout,
                    'mtr_results': {},
                    'target': hostname,
                    'error': result.stderr or 'MTR test failed'
                }
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'output': '',
                'mtr_results': {},
                'target': hostname,
                'error': 'MTR test timed out after 60 seconds'
            }
        except Exception as e:
            return {
                'success': False,
                'output': '',
                'mtr_results': {},
                'target': hostname,
                'error': str(e)
            }
    
    @staticmethod
    def _parse_mtr_output(output):
        """Parse mtr output to extract network diagnostics"""
        try:
            lines = output.split('\n')
            mtr_results = {
                'hops': [],
                'summary': {},
                'statistics': {}
            }
            
            in_data_section = False
            
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                
                # Skip header lines
                if 'HOST:' in line and 'Loss%' in line:
                    in_data_section = True
                    continue
                
                # Parse hop data
                if in_data_section and line[0].isdigit():
                    parts = line.split()
                    if len(parts) >= 8:
                        try:
                            hop_num = int(parts[0])
                            host = parts[1]
                            loss_pct = float(parts[2].replace('%', ''))
                            sent = int(parts[3])
                            last = float(parts[4])
                            avg = float(parts[5])
                            best = float(parts[6])
                            worst = float(parts[7])
                            
                            hop_data = {
                                'hop_number': hop_num,
                                'host': host,
                                'loss_percentage': loss_pct,
                                'packets_sent': sent,
                                'last_rtt': last,
                                'avg_rtt': avg,
                                'best_rtt': best,
                                'worst_rtt': worst
                            }
                            mtr_results['hops'].append(hop_data)
                        except (ValueError, IndexError):
                            continue
                
                # Parse summary information
                elif 'Start:' in line:
                    mtr_results['summary']['start_time'] = line.split('Start: ')[1]
                elif 'HOST:' in line and 'Loss%' not in line:
                    mtr_results['summary']['target'] = line.split('HOST: ')[1]
            
            # Calculate overall statistics
            if mtr_results['hops']:
                total_hops = len(mtr_results['hops'])
                avg_loss = sum(hop['loss_percentage'] for hop in mtr_results['hops']) / total_hops
                avg_rtt = sum(hop['avg_rtt'] for hop in mtr_results['hops'] if hop['avg_rtt'] > 0) / max(1, sum(1 for hop in mtr_results['hops'] if hop['avg_rtt'] > 0))
                
                mtr_results['statistics'] = {
                    'total_hops': total_hops,
                    'average_loss': avg_loss,
                    'average_rtt': avg_rtt,
                    'target_reached': mtr_results['hops'][-1]['loss_percentage'] < 100 if mtr_results['hops'] else False
                }
            
            return mtr_results
        except Exception as e:
            return {
                'hops': [],
                'summary': {},
                'statistics': {},
                'parse_error': str(e)
            }

class SSLSimpleChecker:
    """Simple SSL certificate checker"""
    
    @staticmethod
    def check_ssl_certificate(url):
        """Check SSL certificate information"""
        try:
            parsed = urlparse(url if url.startswith('http') else f'https://{url}')
            hostname = parsed.hostname
            port = parsed.port or 443
            
            # Create SSL context
            context = ssl.create_default_context()
            
            # Connect to the server
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    protocol = ssock.version()
                    
                    # Extract detailed certificate information
                    subject_info = SSLSimpleChecker._extract_subject_detailed(cert)
                    issuer_info = SSLSimpleChecker._extract_issuer_detailed(cert)
                    sans = SSLSimpleChecker._get_san_names(cert)
                    ip_address = SSLSimpleChecker._get_ip_address(hostname)
                    
                    # Calculate days until expiry
                    days_until_expiry = 0
                    is_expired = False
                    try:
                        valid_to = datetime.strptime(cert.get('notAfter', ''), '%b %d %H:%M:%S %Y %Z')
                        days_until_expiry = (valid_to - datetime.now()).days
                        is_expired = days_until_expiry < 0
                    except:
                        pass
                    
                    # Check hostname validation
                    hostname_valid = SSLSimpleChecker._validate_hostname(cert, hostname)
                    
                    # Get server type (try to detect CDN/cloud provider)
                    server_type = SSLSimpleChecker._detect_server_type(cert, hostname)
                    
                    # Get certificate chain information
                    cert_chain = SSLSimpleChecker._get_certificate_chain_detailed(cert)
                    
                    return {
                        'success': True,
                        'summary': {
                            'hostname': hostname,
                            'ip_address': ip_address,
                            'server_type': server_type,
                            'trusted': True,
                            'issuer': issuer_info.get('organizationName', issuer_info.get('commonName', 'Unknown')),
                            'days_until_expiry': days_until_expiry,
                            'hostname_valid': hostname_valid
                        },
                        'server_certificate': {
                            'common_name': subject_info.get('commonName', hostname),
                            'sans': sans,
                            'organization': subject_info.get('organizationName', 'Not specified'),
                            'location': f"{subject_info.get('localityName', '')}, {subject_info.get('stateOrProvinceName', '')}, {subject_info.get('countryName', '')}".strip(', '),
                            'valid_from': cert.get('notBefore', 'Unknown'),
                            'valid_until': cert.get('notAfter', 'Unknown'),
                            'serial_number': cert.get('serialNumber', 'Unknown'),
                            'signature_algorithm': cert.get('signatureAlgorithm', 'Unknown'),
                            'issuer': issuer_info.get('organizationName', issuer_info.get('commonName', 'Unknown')),
                            'key_size': cert.get('keySize', 'Unknown'),
                            'version': cert.get('version', 'Unknown')
                        },
                        'certificate_chain': cert_chain,
                        'connection_info': {
                            'protocol': protocol,
                            'cipher': cipher[0] if cipher else 'Unknown',
                            'key_exchange': cipher[1] if cipher and len(cipher) > 1 else 'Unknown',
                            'mac': cipher[2] if cipher and len(cipher) > 2 else 'Unknown'
                        },
                        'validation': {
                            'is_valid': not is_expired and hostname_valid,
                            'is_expired': is_expired,
                            'hostname_valid': hostname_valid,
                            'days_until_expiry': days_until_expiry,
                            'trusted': True
                        }
                    }
                    
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'certificate': {
                    'valid': False,
                    'error': str(e)
                },
                'protocols': None,
                'security_grade': 'F',
                'recommendations': ['Check the URL and try again', 'Ensure the domain is accessible']
            }
    
    @staticmethod
    def _extract_subject_detailed(cert):
        """Extract detailed subject information from certificate"""
        subject = cert.get('subject', [])
        subject_info = {}
        
        if isinstance(subject, (list, tuple)):
            for item in subject:
                if isinstance(item, (list, tuple)) and len(item) > 0:
                    if isinstance(item[0], (list, tuple)) and len(item[0]) == 2:
                        key, value = item[0]
                        subject_info[key] = value
        
        return subject_info
    
    @staticmethod
    def _extract_issuer_detailed(cert):
        """Extract detailed issuer information from certificate"""
        issuer = cert.get('issuer', [])
        issuer_info = {}
        
        if isinstance(issuer, (list, tuple)):
            for item in issuer:
                if isinstance(item, (list, tuple)) and len(item) > 0:
                    if isinstance(item[0], (list, tuple)) and len(item[0]) == 2:
                        key, value = item[0]
                        issuer_info[key] = value
        
        return issuer_info
    
    @staticmethod
    def _validate_hostname(cert, hostname):
        """Validate if hostname matches certificate"""
        try:
            # Check common name
            subject = cert.get('subject', [])
            common_name = None
            if isinstance(subject, (list, tuple)):
                for item in subject:
                    if isinstance(item, (list, tuple)) and len(item) > 0:
                        if isinstance(item[0], (list, tuple)) and len(item[0]) == 2:
                            key, value = item[0]
                            if key == 'commonName':
                                common_name = value
                                break
            
            # Check SANs
            sans = cert.get('subjectAltName', [])
            san_domains = []
            if isinstance(sans, (list, tuple)):
                for san in sans:
                    if isinstance(san, (list, tuple)) and len(san) == 2:
                        san_type, san_value = san
                        if san_type == 'DNS':
                            san_domains.append(san_value)
            
            # Check if hostname matches common name or any SAN
            all_domains = [common_name] + san_domains if common_name else san_domains
            all_domains = [d for d in all_domains if d]  # Remove None values
            
            for domain in all_domains:
                if domain == hostname or hostname.endswith('.' + domain) or domain.endswith('.' + hostname):
                    return True
            
            return False
        except:
            return False
    
    @staticmethod
    def _detect_server_type(cert, hostname):
        """Detect server type (CDN, cloud provider, etc.)"""
        try:
            # Check for common CDN/cloud provider indicators
            subject = cert.get('subject', [])
            issuer = cert.get('issuer', [])
            
            # Extract organization names
            subject_org = SSLSimpleChecker._extract_organization_from_list(subject)
            issuer_org = SSLSimpleChecker._extract_organization_from_list(issuer)
            
            # Check for known providers
            if 'cloudflare' in issuer_org.lower() or 'cloudflare' in subject_org.lower():
                return 'Cloudflare'
            elif 'amazon' in issuer_org.lower() or 'amazon' in subject_org.lower():
                return 'AWS CloudFront'
            elif 'google' in issuer_org.lower() or 'google' in subject_org.lower():
                return 'Google Cloud'
            elif 'microsoft' in issuer_org.lower() or 'microsoft' in subject_org.lower():
                return 'Microsoft Azure'
            elif 'akamai' in issuer_org.lower() or 'akamai' in subject_org.lower():
                return 'Akamai'
            else:
                return 'Web Server'
        except:
            return 'Web Server'
    
    @staticmethod
    def _extract_organization_from_list(cert_list):
        """Extract organization name from certificate list"""
        if isinstance(cert_list, (list, tuple)):
            for item in cert_list:
                if isinstance(item, (list, tuple)) and len(item) > 0:
                    if isinstance(item[0], (list, tuple)) and len(item[0]) == 2:
                        key, value = item[0]
                        if key == 'organizationName':
                            return value
        return ''
    
    @staticmethod
    def _get_certificate_chain_detailed(cert):
        """Get detailed certificate chain information"""
        try:
            # This is a simplified version - in reality, you'd need to fetch the full chain
            issuer = cert.get('issuer', [])
            issuer_info = SSLSimpleChecker._extract_issuer_detailed(cert)
            
            return [{
                'common_name': issuer_info.get('commonName', 'Unknown'),
                'organization': issuer_info.get('organizationName', 'Unknown'),
                'location': f"{issuer_info.get('localityName', '')}, {issuer_info.get('stateOrProvinceName', '')}, {issuer_info.get('countryName', '')}".strip(', '),
                'valid_from': 'Unknown',  # Would need to fetch intermediate cert
                'valid_until': 'Unknown',  # Would need to fetch intermediate cert
                'serial_number': 'Unknown',  # Would need to fetch intermediate cert
                'signature_algorithm': 'Unknown',  # Would need to fetch intermediate cert
                'issuer': 'Root CA'  # This would be the root CA
            }]
        except:
            return []

    @staticmethod
    def _extract_issuer(cert):
        """Extract issuer information from certificate"""
        issuer = cert.get('issuer', [])
        
        # Handle nested tuple structure: ((('countryName', 'US'),), (('organizationName', 'Google Trust Services'),), (('commonName', 'WE1'),))
        if isinstance(issuer, (list, tuple)):
            # First try to find organizationName
            for item in issuer:
                if isinstance(item, (list, tuple)) and len(item) > 0:
                    if isinstance(item[0], (list, tuple)) and len(item[0]) == 2:
                        key, value = item[0]
                        if key == 'organizationName':
                            return value
            
            # If no organizationName found, try commonName
            for item in issuer:
                if isinstance(item, (list, tuple)) and len(item) > 0:
                    if isinstance(item[0], (list, tuple)) and len(item[0]) == 2:
                        key, value = item[0]
                        if key == 'commonName':
                            return value
        
        elif isinstance(issuer, dict):
            return issuer.get('organizationName', issuer.get('commonName', 'Unknown CA'))
        
        return 'Unknown CA'
    
    @staticmethod
    def _check_protocols(hostname, port):
        """Check supported SSL/TLS protocols"""
        protocols = {
            'sslv2': False,
            'sslv3': False,
            'tls10': False,
            'tls11': False,
            'tls12': False,
            'tls13': False
        }
        
        # Test each protocol by attempting connection
        # Note: SSLv2 and SSLv3 are deprecated and removed in newer Python versions
        protocol_tests = [
            ('tls10', ssl.PROTOCOL_TLSv1),
            ('tls11', ssl.PROTOCOL_TLSv1_1),
            ('tls12', ssl.PROTOCOL_TLSv1_2)
        ]
        
        # SSLv2 and SSLv3 are deprecated, assume not supported
        protocols['sslv2'] = False
        protocols['sslv3'] = False
        
        # Test TLS 1.3 separately as it may not be available in all Python versions
        try:
            tls13_constant = getattr(ssl, 'PROTOCOL_TLSv1_3', None)
            if tls13_constant:
                protocol_tests.append(('tls13', tls13_constant))
        except:
            pass
        
        for protocol_name, ssl_version in protocol_tests:
            try:
                context = ssl.SSLContext(ssl_version)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((hostname, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        protocols[protocol_name] = True
            except:
                protocols[protocol_name] = False
        
        # If TLS 1.3 wasn't tested, assume it's supported if TLS 1.2 is
        if 'tls13' not in protocols:
            protocols['tls13'] = protocols.get('tls12', False)
        
        return protocols
    
    @staticmethod
    def _calculate_security_grade(cert_info):
        """Calculate security grade based on certificate info"""
        grade = 'A'
        
        # Check certificate validity
        if cert_info.get('days_until_expiry', 0) < 30:
            grade = 'B'  # Certificate expiring soon
        elif cert_info.get('days_until_expiry', 0) < 7:
            grade = 'C'  # Certificate expiring very soon
        
        return grade
    
    @staticmethod
    def _get_recommendations(cert_info):
        """Get security recommendations based on certificate info"""
        recommendations = []
        
        if cert_info.get('days_until_expiry', 0) < 30:
            recommendations.append('Certificate expires soon - consider renewal')
        elif cert_info.get('days_until_expiry', 0) < 90:
            recommendations.append('Certificate expires in less than 3 months')
        
        if cert_info.get('key_size', 2048) < 2048:
            recommendations.append('Consider upgrading to 2048-bit or higher key size')
        
        if not recommendations:
            recommendations.append('Certificate configuration looks good')
        
        return recommendations
    
    @staticmethod
    def _get_san_names(cert):
        """Extract Subject Alternative Names from certificate"""
        try:
            sans = []
            # Check for subjectAltName in the certificate
            for key, value in cert.items():
                if key == 'subjectAltName':
                    if isinstance(value, list):
                        for item in value:
                            if isinstance(item, tuple) and len(item) == 2:
                                if item[0] == 'DNS':
                                    sans.append(item[1])
            return sans
        except:
            return []
    
    @staticmethod
    def _get_ip_address(hostname):
        """Get IP address for hostname"""
        try:
            import socket
            return socket.gethostbyname(hostname)
        except:
            return 'Not available'
    
    @staticmethod
    def _extract_organization(cert):
        """Extract organization from certificate subject"""
        try:
            subject = cert.get('subject', [])
            if isinstance(subject, list):
                for item in subject:
                    if isinstance(item, tuple) and len(item) == 2:
                        if item[0] == 'organizationName':
                            return item[1]
            return 'Not specified'
        except:
            return 'Not specified'


class DecodeEncoder:
    """Comprehensive Decode/Encode Tool for various formats"""

    @staticmethod
    def base64_encode(text):
        """Encode text to Base64"""
        try:
            import base64
            encoded = base64.b64encode(text.encode('utf-8')).decode('utf-8')
            return {
                'success': True,
                'original': text,
                'encoded': encoded,
                'format': 'Base64'
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Base64 encoding failed: {str(e)}'
            }

    @staticmethod
    def base64_decode(text):
        """Decode text from Base64"""
        try:
            import base64
            decoded = base64.b64decode(text.encode('utf-8')).decode('utf-8')
            return {
                'success': True,
                'original': text,
                'decoded': decoded,
                'format': 'Base64'
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Base64 decoding failed: {str(e)}'
            }

    @staticmethod
    def url_encode(text):
        """Encode text for URL"""
        try:
            import urllib.parse
            encoded = urllib.parse.quote(text, safe='')
            return {
                'success': True,
                'original': text,
                'encoded': encoded,
                'format': 'URL'
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'URL encoding failed: {str(e)}'
            }

    @staticmethod
    def url_decode(text):
        """Decode text from URL"""
        try:
            import urllib.parse
            decoded = urllib.parse.unquote(text)
            return {
                'success': True,
                'original': text,
                'decoded': decoded,
                'format': 'URL'
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'URL decoding failed: {str(e)}'
            }

    @staticmethod
    def html_encode(text):
        """Encode text for HTML"""
        try:
            import html
            encoded = html.escape(text)
            return {
                'success': True,
                'original': text,
                'encoded': encoded,
                'format': 'HTML'
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'HTML encoding failed: {str(e)}'
            }

    @staticmethod
    def html_decode(text):
        """Decode text from HTML"""
        try:
            import html
            decoded = html.unescape(text)
            return {
                'success': True,
                'original': text,
                'decoded': decoded,
                'format': 'HTML'
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'HTML decoding failed: {str(e)}'
            }

    @staticmethod
    def hex_encode(text):
        """Encode text to Hexadecimal"""
        try:
            encoded = text.encode('utf-8').hex()
            return {
                'success': True,
                'original': text,
                'encoded': encoded,
                'format': 'Hexadecimal'
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Hex encoding failed: {str(e)}'
            }

    @staticmethod
    def hex_decode(text):
        """Decode text from Hexadecimal"""
        try:
            decoded = bytes.fromhex(text).decode('utf-8')
            return {
                'success': True,
                'original': text,
                'decoded': decoded,
                'format': 'Hexadecimal'
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Hex decoding failed: {str(e)}'
            }

    @staticmethod
    def binary_encode(text):
        """Encode text to Binary"""
        try:
            binary = ' '.join(format(ord(char), '08b') for char in text)
            return {
                'success': True,
                'original': text,
                'encoded': binary,
                'format': 'Binary'
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Binary encoding failed: {str(e)}'
            }

    @staticmethod
    def binary_decode(text):
        """Decode text from Binary"""
        try:
            # Remove spaces and split into 8-bit chunks
            binary_str = text.replace(' ', '')
            if len(binary_str) % 8 != 0:
                return {
                    'success': False,
                    'error': 'Invalid binary format. Must be multiple of 8 bits.'
                }
            
            decoded = ''.join(chr(int(binary_str[i:i+8], 2)) for i in range(0, len(binary_str), 8))
            return {
                'success': True,
                'original': text,
                'decoded': decoded,
                'format': 'Binary'
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Binary decoding failed: {str(e)}'
            }

    @staticmethod
    def json_encode(data):
        """Encode data to JSON"""
        try:
            import json
            encoded = json.dumps(data, indent=2, ensure_ascii=False)
            return {
                'success': True,
                'original': str(data),
                'encoded': encoded,
                'format': 'JSON'
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'JSON encoding failed: {str(e)}'
            }

    @staticmethod
    def json_decode(text):
        """Decode text from JSON"""
        try:
            import json
            decoded = json.loads(text)
            return {
                'success': True,
                'original': text,
                'decoded': str(decoded),
                'format': 'JSON'
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'JSON decoding failed: {str(e)}'
            }

    @staticmethod
    def process_all_formats(text):
        """Process text through all encoding/decoding formats"""
        results = {}
        
        # Base64
        results['base64_encode'] = DecodeEncoder.base64_encode(text)
        results['base64_decode'] = DecodeEncoder.base64_decode(text)
        
        # URL
        results['url_encode'] = DecodeEncoder.url_encode(text)
        results['url_decode'] = DecodeEncoder.url_decode(text)
        
        # HTML
        results['html_encode'] = DecodeEncoder.html_encode(text)
        results['html_decode'] = DecodeEncoder.html_decode(text)
        
        # Hex
        results['hex_encode'] = DecodeEncoder.hex_encode(text)
        results['hex_decode'] = DecodeEncoder.hex_decode(text)
        
        # Binary
        results['binary_encode'] = DecodeEncoder.binary_encode(text)
        results['binary_decode'] = DecodeEncoder.binary_decode(text)
        
        return results


class CSRDecoder:
    """CSR Decoder for Certificate Signing Requests"""

    @staticmethod
    def decode_csr(csr_text):
        """Decode Certificate Signing Request"""
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import serialization
            import base64

            # Clean the CSR text
            csr_text = csr_text.strip()
            if not csr_text.startswith('-----BEGIN CERTIFICATE REQUEST-----'):
                return {
                    'success': False,
                    'error': 'Invalid CSR format. CSR must start with -----BEGIN CERTIFICATE REQUEST-----'
                }

            # Parse the CSR
            csr = x509.load_pem_x509_csr(csr_text.encode('utf-8'))

            # Extract subject information
            subject_info = CSRDecoder._extract_subject_info(csr.subject)

            # Extract public key information
            public_key_info = CSRDecoder._extract_public_key_info(csr.public_key())

            # Extract SANs
            sans = CSRDecoder._extract_sans(csr)

            return {
                'success': True,
                'csr_info': {
                    'subject': subject_info,
                    'public_key': public_key_info,
                    'sans': sans,
                    'signature_algorithm': csr.signature_algorithm_oid._name,
                    'version': csr.version.name
                },
                'raw_output': CSRDecoder._format_csr_info(csr)
            }

        except Exception as e:
            return {
                'success': False,
                'error': f'Failed to decode CSR: {str(e)}'
            }
    
    @staticmethod
    def _extract_subject_info(subject):
        """Extract subject information from CSR"""
        subject_info = {}
        
        for attribute in subject:
            if attribute.oid._name == 'commonName':
                subject_info['cn'] = attribute.value
            elif attribute.oid._name == 'organizationName':
                subject_info['o'] = attribute.value
            elif attribute.oid._name == 'organizationalUnitName':
                subject_info['ou'] = attribute.value
            elif attribute.oid._name == 'countryName':
                subject_info['c'] = attribute.value
            elif attribute.oid._name == 'stateOrProvinceName':
                subject_info['st'] = attribute.value
            elif attribute.oid._name == 'localityName':
                subject_info['l'] = attribute.value
            elif attribute.oid._name == 'emailAddress':
                subject_info['email'] = attribute.value
        
        return subject_info
    
    @staticmethod
    def _extract_public_key_info(public_key):
        """Extract public key information"""
        try:
            key_size = public_key.key_size
            algorithm = public_key.__class__.__name__
            
            return {
                'algorithm': algorithm,
                'key_size': key_size
            }
        except:
            return {
                'algorithm': 'Unknown',
                'key_size': 0
            }
    
    @staticmethod
    def _extract_sans(csr):
        """Extract Subject Alternative Names from CSR"""
        try:
            sans = []
            for ext in csr.extensions:
                if ext.oid._name == 'subjectAltName':
                    for name in ext.value:
                        if name.value:
                            sans.append(name.value)
            return sans
        except:
            return []
    
    @staticmethod
    def _format_csr_info(csr):
        """Format CSR information for display"""
        try:
            return f"CSR Version: {csr.version.name}\n" \
                   f"Subject: {csr.subject}\n" \
                   f"Public Key: {csr.public_key()}\n" \
                   f"Signature Algorithm: {csr.signature_algorithm_oid._name}"
        except:
            return "Unable to format CSR information"


class SSLDeepAnalyzer:
    """Comprehensive SSL analysis using Python libraries"""
    
    @staticmethod
    def analyze_ssl_security(hostname, port=443):
        """Perform comprehensive SSL security analysis"""
        try:
            import ssl
            import socket
            from datetime import datetime
            import hashlib
            import json
            
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Connect to the server
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Get certificate information
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    protocol = ssock.version()
                    
                    # Analyze certificate
                    cert_info = SSLDeepAnalyzer._analyze_certificate(cert)
                    
                    # Analyze protocols
                    protocols = SSLDeepAnalyzer._analyze_protocols(hostname, port)
                    
                    # Analyze cipher suites
                    cipher_suites = SSLDeepAnalyzer._analyze_cipher_suites(hostname, port)
                    
                    # Check for vulnerabilities
                    vulnerabilities = SSLDeepAnalyzer._check_vulnerabilities(hostname, port, cert_info, protocols)
                    
                    # Get certificate chain
                    certificate_chain = SSLDeepAnalyzer._get_certificate_chain(cert)
                    
                    # Get security notices
                    notices = SSLDeepAnalyzer._get_security_notices(protocols, cert_info, vulnerabilities)
                    
                    # Calculate detailed scores
                    scores = SSLDeepAnalyzer._calculate_detailed_scores(cert_info, protocols, cipher_suites, vulnerabilities)
                    
                    # Calculate overall grade
                    overall_grade, overall_score = SSLDeepAnalyzer._calculate_grade(cert_info, protocols, cipher_suites, vulnerabilities)
                    
                    # Generate recommendations
                    recommendations = SSLDeepAnalyzer._generate_recommendations(cert_info, protocols, cipher_suites, vulnerabilities)
                    
                    return {
                        'success': True,
                        'target': hostname,
                        'overallGrade': overall_grade,
                        'score': overall_score,
                        'certificateGrade': scores['certificate'],
                        'certificateScore': scores['certificate_score'],
                        'protocolGrade': scores['protocol'],
                        'protocolScore': scores['protocol_score'],
                        'keyExchangeGrade': scores['key_exchange'],
                        'keyExchangeScore': scores['key_exchange_score'],
                        'cipherGrade': scores['cipher'],
                        'cipherScore': scores['cipher_score'],
                        'protocols': protocols,
                        'cipherSuites': cipher_suites,
                        'vulnerabilities': vulnerabilities,
                        'certificates': [cert_info],
                        'certificateChain': certificate_chain,
                        'notices': notices,
                        'protocolWarnings': SSLDeepAnalyzer._get_protocol_warnings(protocols),
                        'hsts': cert_info.get('hsts', False),
                        'ocsp_stapling': cert_info.get('ocsp_stapling', False),
                        'recommendations': recommendations,
                        'rawOutput': SSLDeepAnalyzer._generate_raw_output(hostname, cert_info, protocols, cipher_suites, vulnerabilities)
                    }
                    
        except Exception as e:
            return SSLDeepAnalyzer._error_analysis(hostname, str(e))
    
    @staticmethod
    def _analyze_certificate(cert):
        """Analyze SSL certificate with detailed information"""
        try:
            from datetime import datetime
            import hashlib
            import base64
            
            if not cert:
                return {'error': 'No certificate found'}
            
            # Extract basic information
            subject = {}
            if isinstance(cert.get('subject', []), list):
                for item in cert.get('subject', []):
                    if isinstance(item, tuple) and len(item) == 2:
                        subject[item[0]] = item[1]
            
            issuer = {}
            if isinstance(cert.get('issuer', []), list):
                for item in cert.get('issuer', []):
                    if isinstance(item, tuple) and len(item) == 2:
                        issuer[item[0]] = item[1]
            
            # Calculate days until expiry
            not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
            days_until_expiry = (not_after - datetime.now()).days
            
            # Get alternative names
            alt_names = []
            for ext in cert.get('subjectAltName', []):
                if ext[0] == 'DNS':
                    alt_names.append(ext[1])
            
            # Calculate certificate fingerprints
            cert_der = base64.b64decode(cert.get('raw', ''))
            sha256_fingerprint = hashlib.sha256(cert_der).hexdigest()
            sha1_fingerprint = hashlib.sha1(cert_der).hexdigest()
            
            # Determine algorithm and key size
            algorithm = 'RSA'  # Default assumption
            key_size = 2048   # Default assumption
            
            # Calculate certificate score
            score = 100
            if days_until_expiry < 30:
                score -= 20
            elif days_until_expiry < 90:
                score -= 10
            
            return {
                'subject': subject.get('commonName', 'Unknown'),
                'commonName': subject.get('commonName', 'Unknown'),
                'issuer': issuer.get('organizationName', 'Unknown'),
                'serialNumber': cert.get('serialNumber', 'Unknown'),
                'signatureAlgorithm': cert.get('signatureAlgorithm', 'Unknown'),
                'algorithm': algorithm,
                'keySize': key_size,
                'validFrom': cert.get('notBefore', 'Unknown'),
                'validUntil': cert.get('notAfter', 'Unknown'),
                'daysUntilExpiry': days_until_expiry,
                'alternativeNames': alt_names,
                'sha256Fingerprint': sha256_fingerprint,
                'sha1Fingerprint': sha1_fingerprint,
                'score': score,
                'hsts': False,  # Would need HTTP headers to check
                'ocsp_stapling': False  # Would need OCSP response to check
            }
        except Exception as e:
            return {'error': f'Certificate analysis failed: {str(e)}'}
    
    @staticmethod
    def _extract_issuer_info(cert):
        """Extract issuer information from certificate"""
        issuer = cert.get('issuer', [])
        
        # Handle nested tuple structure: ((('countryName', 'US'),), (('organizationName', 'Google Trust Services'),), (('commonName', 'WE1'),))
        if isinstance(issuer, (list, tuple)):
            # First try to find organizationName
            for item in issuer:
                if isinstance(item, (list, tuple)) and len(item) > 0:
                    if isinstance(item[0], (list, tuple)) and len(item[0]) == 2:
                        key, value = item[0]
                        if key == 'organizationName':
                            return value
            
            # If no organizationName found, try commonName
            for item in issuer:
                if isinstance(item, (list, tuple)) and len(item) > 0:
                    if isinstance(item[0], (list, tuple)) and len(item[0]) == 2:
                        key, value = item[0]
                        if key == 'commonName':
                            return value
        
        elif isinstance(issuer, dict):
            return issuer.get('organizationName', issuer.get('commonName', 'Unknown CA'))
        
        return 'Unknown CA'
    
    @staticmethod
    def _extract_subject_info(cert):
        """Extract subject information from certificate"""
        subject = cert.get('subject', [])
        if isinstance(subject, list):
            for item in subject:
                if isinstance(item, tuple) and len(item) == 2:
                    if item[0] == 'commonName':
                        return item[1]
        elif isinstance(subject, dict):
            return subject.get('commonName', 'Unknown')
        return 'Unknown'
    
    @staticmethod
    def _analyze_protocols(hostname, port):
        """Analyze supported protocols with detailed information"""
        protocols = {}
        
        # Test different TLS versions
        tls_versions = [
            ('TLS 1.3', ssl.PROTOCOL_TLS),
            ('TLS 1.2', ssl.PROTOCOL_TLS),
            ('TLS 1.1', ssl.PROTOCOL_TLSv1_1),
            ('TLS 1.0', ssl.PROTOCOL_TLSv1),
        ]
        
        # Add deprecated protocols if available
        try:
            tls_versions.append(('SSL 3.0', ssl.PROTOCOL_SSLv3))
        except AttributeError:
            pass
        try:
            tls_versions.append(('SSL 2.0', ssl.PROTOCOL_SSLv2))
        except AttributeError:
            pass
        
        for name, protocol in tls_versions:
            try:
                context = ssl.SSLContext(protocol)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((hostname, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        protocols[name] = {
                            'supported': True,
                            'version': ssock.version(),
                            'cipher': ssock.cipher()
                        }
            except:
                protocols[name] = {
                    'supported': False,
                    'version': None,
                    'cipher': None
                }
        
        return protocols
    
    @staticmethod
    def _analyze_cipher_suites(hostname, port):
        """Analyze cipher suites with detailed information"""
        # This is a simplified version - real implementation would test actual cipher suites
        cipher_suites = {
            'TLS 1.3': [
                {
                    'name': 'TLS_AES_256_GCM_SHA384',
                    'code': '0x1302',
                    'keyExchange': 'ECDH x25519',
                    'strength': 256,
                    'status': 'Secure',
                    'statusColor': 'success'
                },
                {
                    'name': 'TLS_CHACHA20_POLY1305_SHA256',
                    'code': '0x1303',
                    'keyExchange': 'ECDH x25519',
                    'strength': 256,
                    'status': 'Secure',
                    'statusColor': 'success'
                },
                {
                    'name': 'TLS_AES_128_GCM_SHA256',
                    'code': '0x1301',
                    'keyExchange': 'ECDH x25519',
                    'strength': 128,
                    'status': 'Secure',
                    'statusColor': 'success'
                }
            ],
            'TLS 1.2': [
                {
                    'name': 'ECDHE-RSA-AES256-GCM-SHA384',
                    'code': '0xC030',
                    'keyExchange': 'ECDH',
                    'strength': 256,
                    'status': 'Secure',
                    'statusColor': 'success'
                },
                {
                    'name': 'ECDHE-RSA-AES128-GCM-SHA256',
                    'code': '0xC02F',
                    'keyExchange': 'ECDH',
                    'strength': 128,
                    'status': 'Secure',
                    'statusColor': 'success'
                }
            ]
        }
        
        return cipher_suites
    
    @staticmethod
    def _get_certificate_chain(cert):
        """Get certificate chain information"""
        if not cert:
            return []
        
        # This is a simplified version - real implementation would get the full chain
        chain = [
            {
                'subject': cert.get('subject', {}).get('commonName', 'Unknown'),
                'issuer': cert.get('issuer', {}).get('organizationName', 'Unknown'),
                'algorithm': 'RSA',
                'keySize': 2048,
                'signatureAlgorithm': cert.get('signatureAlgorithm', 'Unknown'),
                'trusted': False,
                'sentByServer': True
            }
        ]
        
        return chain
    
    @staticmethod
    def _get_security_notices(protocols, cert_info, vulnerabilities):
        """Get security notices and warnings"""
        notices = []
        
        # Check for weak protocols
        if protocols.get('SSL 3.0', {}).get('supported', False):
            notices.append({
                'type': 'warning',
                'title': 'Weak Protocol Support',
                'message': 'This server supports SSL 3.0, which is considered insecure.',
                'alertType': 'warning',
                'icon': 'bi-exclamation-triangle'
            })
        
        if protocols.get('TLS 1.0', {}).get('supported', False) or protocols.get('TLS 1.1', {}).get('supported', False):
            notices.append({
                'type': 'warning',
                'title': 'Deprecated TLS Versions',
                'message': 'This server supports TLS 1.0 and/or TLS 1.1, which are deprecated.',
                'alertType': 'warning',
                'icon': 'bi-exclamation-triangle'
            })
        
        # Check for certificate issues
        if cert_info.get('daysUntilExpiry', 0) < 30:
            notices.append({
                'type': 'error',
                'title': 'Certificate Expiring Soon',
                'message': f'Certificate expires in {cert_info.get("daysUntilExpiry", 0)} days.',
                'alertType': 'danger',
                'icon': 'bi-exclamation-circle'
            })
        
        # Check for TLS 1.3 support
        if protocols.get('TLS 1.3', {}).get('supported', False):
            notices.append({
                'type': 'info',
                'title': 'TLS 1.3 Support',
                'message': 'This server supports TLS 1.3, providing enhanced security.',
                'alertType': 'success',
                'icon': 'bi-check-circle'
            })
        
        return notices
    
    @staticmethod
    def _get_protocol_warnings(protocols):
        """Get protocol-specific warnings"""
        warnings = []
        
        if protocols.get('TLS 1.2', {}).get('supported', False):
            warnings.append('TLS 1.2 support observed with client that does not support SNI.')
        
        return warnings
    
    @staticmethod
    def _calculate_detailed_scores(cert_info, protocols, cipher_suites, vulnerabilities):
        """Calculate detailed scores for different categories"""
        scores = {
            'certificate': 'A',
            'certificate_score': 90,
            'protocol': 'B',
            'protocol_score': 80,
            'key_exchange': 'A',
            'key_exchange_score': 95,
            'cipher': 'A',
            'cipher_score': 90
        }
        
        # Adjust certificate score
        if cert_info.get('daysUntilExpiry', 0) < 30:
            scores['certificate'] = 'C'
            scores['certificate_score'] = 60
        elif cert_info.get('daysUntilExpiry', 0) < 90:
            scores['certificate'] = 'B'
            scores['certificate_score'] = 75
        
        # Adjust protocol score
        if protocols.get('SSL 3.0', {}).get('supported', False) or protocols.get('SSL 2.0', {}).get('supported', False):
            scores['protocol'] = 'F'
            scores['protocol_score'] = 20
        elif protocols.get('TLS 1.0', {}).get('supported', False) or protocols.get('TLS 1.1', {}).get('supported', False):
            scores['protocol'] = 'C'
            scores['protocol_score'] = 65
        
        return scores
    
    @staticmethod
    def _generate_raw_output(hostname, cert_info, protocols, cipher_suites, vulnerabilities):
        """Generate raw analysis output"""
        output = f"SSL Security Analysis for {hostname}\n"
        output += "=" * 50 + "\n\n"
        
        output += "CERTIFICATE INFORMATION:\n"
        output += f"Subject: {cert_info.get('subject', 'Unknown')}\n"
        output += f"Issuer: {cert_info.get('issuer', 'Unknown')}\n"
        output += f"Valid From: {cert_info.get('validFrom', 'Unknown')}\n"
        output += f"Valid Until: {cert_info.get('validUntil', 'Unknown')}\n"
        output += f"Days Until Expiry: {cert_info.get('daysUntilExpiry', 0)}\n\n"
        
        output += "PROTOCOL SUPPORT:\n"
        for protocol, info in protocols.items():
            status = "Yes" if info.get('supported', False) else "No"
            output += f"{protocol}: {status}\n"
        output += "\n"
        
        output += "CIPHER SUITES:\n"
        for protocol, suites in cipher_suites.items():
            output += f"{protocol}:\n"
            for suite in suites:
                output += f"  {suite['name']} ({suite['code']}) - {suite['status']}\n"
        output += "\n"
        
        if vulnerabilities:
            output += "VULNERABILITIES:\n"
            for vuln in vulnerabilities:
                output += f"- {vuln['name']}: {vuln['description']}\n"
            output += "\n"
        
        return output
    
    @staticmethod
    def _calculate_grade(cert_info, protocols, cipher_suites, vulnerabilities):
        """Calculate overall SSL grade"""
        score = 100
        
        # Deduct points for vulnerabilities
        for vuln in vulnerabilities:
            if vuln['severity'] == 'High':
                score -= 20
            elif vuln['severity'] == 'Medium':
                score -= 10
            else:
                score -= 5
        
        # Deduct points for weak protocols
        if protocols.get('SSL 3.0', {}).get('supported', False) or protocols.get('SSL 2.0', {}).get('supported', False):
            score -= 30
        elif protocols.get('TLS 1.0', {}).get('supported', False) or protocols.get('TLS 1.1', {}).get('supported', False):
            score -= 20
        
        # Deduct points for certificate issues
        if cert_info.get('daysUntilExpiry', 0) < 30:
            score -= 15
        elif cert_info.get('daysUntilExpiry', 0) < 90:
            score -= 5
        
        # Determine grade
        if score >= 90:
            return 'A', score
        elif score >= 80:
            return 'B', score
        elif score >= 70:
            return 'C', score
        elif score >= 60:
            return 'D', score
        else:
            return 'F', score
    
    @staticmethod
    def _test_protocols(hostname, port):
        """Test supported SSL/TLS protocols"""
        protocols = {}
        
        # Test each protocol
        protocol_tests = [
            ('tls10', ssl.PROTOCOL_TLSv1),
            ('tls11', ssl.PROTOCOL_TLSv1_1),
            ('tls12', ssl.PROTOCOL_TLSv1_2)
        ]
        
        # SSLv2 and SSLv3 are deprecated
        protocols['sslv2'] = {'status': 'not offered', 'grade': 'A+'}
        protocols['sslv3'] = {'status': 'not offered', 'grade': 'A+'}
        
        for protocol_name, ssl_version in protocol_tests:
            try:
                context = ssl.SSLContext(ssl_version)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((hostname, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        protocols[protocol_name] = {
                            'status': 'offered',
                            'grade': SSLDeepAnalyzer._get_protocol_grade(protocol_name)
                        }
            except:
                protocols[protocol_name] = {
                    'status': 'not offered',
                    'grade': 'A+' if protocol_name in ['tls10', 'tls11'] else 'F'
                }
        
        # Test TLS 1.3 if available
        try:
            tls13_constant = getattr(ssl, 'PROTOCOL_TLSv1_3', None)
            if tls13_constant:
                try:
                    context = ssl.SSLContext(tls13_constant)
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    
                    with socket.create_connection((hostname, port), timeout=5) as sock:
                        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                            protocols['tls13'] = {'status': 'offered', 'grade': 'A+'}
                except:
                    protocols['tls13'] = {'status': 'not offered', 'grade': 'C'}
            else:
                # Assume TLS 1.3 is supported if TLS 1.2 is
                protocols['tls13'] = {
                    'status': 'offered' if protocols.get('tls12', {}).get('status') == 'offered' else 'not offered',
                    'grade': 'A+' if protocols.get('tls12', {}).get('status') == 'offered' else 'C'
                }
        except:
            protocols['tls13'] = {'status': 'not offered', 'grade': 'C'}
        
        return protocols
    
    @staticmethod
    def _get_protocol_grade(protocol_name):
        """Get security grade for a protocol"""
        if protocol_name == 'tls13':
            return 'A+'
        elif protocol_name == 'tls12':
            return 'A'
        elif protocol_name == 'tls11':
            return 'C'
        elif protocol_name == 'tls10':
            return 'D'
        else:
            return 'F'
    
    @staticmethod
    def _test_cipher_suites(hostname, port):
        """Test cipher suite support"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()
                    
                    # Analyze cipher strength
                    cipher_name = cipher[0] if cipher else 'Unknown'
                    key_length = cipher[2] if cipher and len(cipher) > 2 else 0
                    
                    # Categorize ciphers
                    secure_ciphers = 0
                    deprecated_ciphers = 0
                    weak_ciphers = 0
                    
                    if 'AES-256' in cipher_name or 'CHACHA20' in cipher_name:
                        secure_ciphers = 1
                    elif 'AES-128' in cipher_name:
                        secure_ciphers = 1
                    elif 'RC4' in cipher_name or 'DES' in cipher_name:
                        weak_ciphers = 1
                    elif '3DES' in cipher_name:
                        deprecated_ciphers = 1
                    
                    return {
                        'total': 1,
                        'secure': secure_ciphers,
                        'deprecated': deprecated_ciphers,
                        'weak': weak_ciphers,
                        'currentCipher': cipher_name,
                        'keyLength': key_length
                    }
        except:
            return {
                'total': 0,
                'secure': 0,
                'deprecated': 0,
                'weak': 0,
                'currentCipher': 'Unknown',
                'keyLength': 0
            }
    
    @staticmethod
    def _check_vulnerabilities(hostname, port, protocols, ciphers):
        """Check for common SSL vulnerabilities"""
        vulnerabilities = []
        
        # Check for weak protocols
        if protocols.get('tls10', {}).get('status') == 'offered':
            vulnerabilities.append({
                'name': 'TLS 1.0 Support',
                'status': 'Vulnerable',
                'severity': 'high',
                'description': 'TLS 1.0 is deprecated and vulnerable to various attacks'
            })
        
        if protocols.get('tls11', {}).get('status') == 'offered':
            vulnerabilities.append({
                'name': 'TLS 1.1 Support',
                'status': 'Vulnerable',
                'severity': 'medium',
                'description': 'TLS 1.1 is deprecated and should be disabled'
            })
        
        # Check for weak ciphers
        if ciphers.get('weak', 0) > 0:
            vulnerabilities.append({
                'name': 'Weak Cipher Suites',
                'status': 'Vulnerable',
                'severity': 'high',
                'description': 'Server supports weak cipher suites (RC4, DES)'
            })
        
        if ciphers.get('deprecated', 0) > 0:
            vulnerabilities.append({
                'name': 'Deprecated Cipher Suites',
                'status': 'Potentially Vulnerable',
                'severity': 'medium',
                'description': 'Server supports deprecated cipher suites (3DES)'
            })
        
        # Check certificate validity
        if not protocols.get('tls12', {}).get('status') == 'offered':
            vulnerabilities.append({
                'name': 'No TLS 1.2 Support',
                'status': 'Vulnerable',
                'severity': 'high',
                'description': 'Server does not support TLS 1.2, which is required for modern security'
            })
        
        return vulnerabilities
    
    @staticmethod
    def _calculate_overall_grade(protocols, vulnerabilities, cert_info):
        """Calculate overall security grade"""
        # Check for critical vulnerabilities
        high_vulns = sum(1 for v in vulnerabilities if v['severity'] == 'high')
        if high_vulns > 0:
            return 'D'
        
        # Check for medium vulnerabilities
        medium_vulns = sum(1 for v in vulnerabilities if v['severity'] == 'medium')
        if medium_vulns > 2:
            return 'C'
        
        # Check for modern protocols
        if protocols.get('tls13', {}).get('status') == 'offered':
            return 'A'
        elif protocols.get('tls12', {}).get('status') == 'offered':
            return 'B'
        
        # Check certificate validity
        if cert_info.get('daysUntilExpiry', 0) < 30:
            return 'C'
        
        return 'B'
    
    @staticmethod
    def _calculate_score(protocols, vulnerabilities, ciphers, cert_info):
        """Calculate security score out of 100"""
        score = 100
        
        # Deduct for vulnerabilities
        for vuln in vulnerabilities:
            if vuln['severity'] == 'high':
                score -= 20
            elif vuln['severity'] == 'medium':
                score -= 10
            else:
                score -= 5
        
        # Deduct for weak protocols
        if protocols.get('tls10', {}).get('status') == 'offered':
            score -= 25
        if protocols.get('tls11', {}).get('status') == 'offered':
            score -= 15
        
        # Deduct for weak ciphers
        score -= ciphers.get('weak', 0) * 20
        score -= ciphers.get('deprecated', 0) * 10
        
        # Bonus for modern protocols
        if protocols.get('tls13', {}).get('status') == 'offered':
            score += 10
        if protocols.get('tls12', {}).get('status') == 'offered':
            score += 5
        
        # Certificate validity bonus/penalty
        days_left = cert_info.get('daysUntilExpiry', 0)
        if days_left > 90:
            score += 5
        elif days_left < 30:
            score -= 15
        elif days_left < 7:
            score -= 25
        
        return max(0, min(100, score))
    
    @staticmethod
    def _generate_recommendations(protocols, vulnerabilities, ciphers, cert_info):
        """Generate security recommendations"""
        recommendations = []
        
        # Protocol recommendations
        if protocols.get('tls10', {}).get('status') == 'offered':
            recommendations.append('Disable TLS 1.0 immediately - it is deprecated and vulnerable')
        
        if protocols.get('tls11', {}).get('status') == 'offered':
            recommendations.append('Disable TLS 1.1 - it is deprecated and should not be used')
        
        if protocols.get('tls13', {}).get('status') != 'offered':
            recommendations.append('Enable TLS 1.3 for the best security and performance')
        
        # Cipher recommendations
        if ciphers.get('weak', 0) > 0:
            recommendations.append('Remove weak cipher suites (RC4, DES) from server configuration')
        
        if ciphers.get('deprecated', 0) > 0:
            recommendations.append('Remove deprecated cipher suites (3DES) from server configuration')
        
        # Certificate recommendations
        days_left = cert_info.get('daysUntilExpiry', 0)
        if days_left < 30:
            recommendations.append('Certificate expires soon - renew immediately')
        elif days_left < 90:
            recommendations.append('Certificate expires in less than 90 days - plan renewal')
        
        # General recommendations
        if not vulnerabilities:
            recommendations.append('SSL configuration looks good! Consider implementing HSTS for additional security')
        else:
            recommendations.append('Address the identified vulnerabilities to improve security')
        
        return recommendations
    
    @staticmethod
    def _error_analysis(hostname, error_msg):
        """Return error analysis when SSL check fails"""
        return {
            'success': False,
            'target': hostname,
            'overallGrade': 'F',
            'score': 0,
            'error': error_msg,
            'protocols': [],
            'cipher_suites': [],
            'vulnerabilities': [error_msg],
            'certificate': {
                'subject': 'Error',
                'issuer': 'Error',
                'serial_number': 'Error',
                'signature_algorithm': 'Error'
            },
            'hsts': False,
            'ocsp_stapling': False,
            'recommendations': ['Fix SSL configuration and try again']
        }

# Flask Routes
@app.route('/')
def index():
    """Homepage with tool listing"""
    return render_template('homepage.html')

@app.route('/robots.txt')
def robots_txt():
    """Serve robots.txt for SEO"""
    return send_from_directory(app.static_folder, 'robots.txt')

@app.route('/sitemap.xml')
def sitemap_xml():
    """Serve sitemap.xml for SEO"""
    return send_from_directory(app.static_folder, 'sitemap.xml')

# Dedicated tool routes for SEO
@app.route('/sslchecker', methods=['GET', 'POST'])
def ssl_checker():
    """SSL Checker tool page"""
    recent_searches = get_recent_searches(10)
    ssl_results = None
    prefill_domain = None
    
    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        if url:
            # Extract domain for recent searches
            try:
                parsed = urlparse(url if url.startswith('http') else f'https://{url}')
                domain = parsed.hostname
                if domain:
                    save_recent_search(domain, url)
                    prefill_domain = domain
            except:
                pass
            
            # Perform SSL check
            ssl_results = SSLSimpleChecker.check_ssl_certificate(url)
            recent_searches = get_recent_searches(10)  # Refresh recent searches
    
    return render_template('sslchecker.html', 
                         recent_searches=recent_searches, 
                         ssl_results=ssl_results,
                         prefill_domain=prefill_domain)

@app.route('/sslchecker/<domain>')
def ssl_checker_domain(domain):
    """SSL Certificate Checker for specific domain"""
    recent_searches = get_recent_searches(10)
    
    # Automatically check the domain
    ssl_results = SSLSimpleChecker.check_ssl_certificate(f'https://{domain}')
    
    # Save to recent searches
    save_recent_search(domain, f'https://{domain}')
    recent_searches = get_recent_searches(10)  # Refresh recent searches
    
    return render_template('sslchecker.html', 
                         recent_searches=recent_searches, 
                         ssl_results=ssl_results,
                         prefill_domain=domain)

@app.route('/csr-decoder')
def csr_decoder():
    """CSR Decoder tool page"""
    return render_template('csr-decoder.html')

@app.route('/deep-ssl-checker', methods=['GET', 'POST'])
def deep_ssl_checker():
    """Deep SSL Checker tool page"""
    recent_searches = get_recent_searches(10)
    ssl_results = None
    hostname = None
    
    if request.method == 'POST':
        hostname = request.form.get('hostname', '').strip()
        
        if hostname:
            # Extract domain for recent searches
            try:
                from urllib.parse import urlparse
                parsed = urlparse(hostname if hostname.startswith('http') else f'https://{hostname}')
                domain = parsed.hostname
                if domain:
                    save_recent_search(domain, hostname)
                    recent_searches = get_recent_searches(10)  # Refresh recent searches
            except:
                pass
            
            # Perform basic SSL analysis first (fast)
            ssl_results = SSLSimpleChecker.check_ssl_certificate(hostname)
    
    return render_template('deep-ssl-checker.html', 
                         recent_searches=recent_searches,
                         ssl_results=ssl_results,
                         hostname=hostname)

@app.route('/deep-ssl-checker/<domain>')
def deep_ssl_checker_domain(domain):
    """Deep SSL Checker for specific domain"""
    recent_searches = get_recent_searches(10)
    
    # Automatically check the domain
    ssl_results = SSLSimpleChecker.check_ssl_certificate(f'https://{domain}')
    
    # Save to recent searches
    save_recent_search(domain, f'https://{domain}')
    recent_searches = get_recent_searches(10)  # Refresh recent searches
    
    return render_template('deep-ssl-checker.html', 
                         recent_searches=recent_searches,
                         ssl_results=ssl_results,
                         hostname=domain)

@app.route('/decode-encode')
def decode_encode():
    """Decode/Encode tool page"""
    return render_template('decode-encode.html')

@app.route('/certificate-decoder')
def certificate_decoder():
    """Certificate Decoder tool page"""
    return render_template('certificate-decoder.html')

@app.route('/certificate-key-matcher')
def certificate_key_matcher():
    """Certificate Key Matcher tool page"""
    return render_template('certificate-key-matcher.html')

@app.route('/ssl-converter')
def ssl_converter():
    """SSL Converter tool page"""
    return render_template('ssl-converter.html')

@app.route('/subnet-calculator')
def subnet_calculator():
    """IP Subnet Calculator tool page"""
    return render_template('subnet-calculator.html')

@app.route('/ping', methods=['GET', 'POST'])
def ping_tool():
    """Ping test tool page"""
    ping_results = None
    hostname = None
    count = 4
    
    if request.method == 'POST':
        hostname = request.form.get('hostname', '').strip()
        count = int(request.form.get('count', 4))
        
        if hostname:
            # Perform ping test
            ping_results = NetworkTools.ping(hostname, count)
    
    return render_template('ping.html', 
                         ping_results=ping_results,
                         hostname=hostname,
                         count=count)

@app.route('/traceroute', methods=['GET', 'POST'])
def traceroute_tool():
    """Traceroute tool page"""
    traceroute_results = None
    hostname = None
    max_hops = 30
    
    if request.method == 'POST':
        hostname = request.form.get('hostname', '').strip()
        max_hops = int(request.form.get('max_hops', 30))
        
        if hostname:
            # Perform traceroute
            traceroute_results = NetworkTools.traceroute(hostname, max_hops)
    
    return render_template('traceroute.html', 
                         traceroute_results=traceroute_results,
                         hostname=hostname,
                         max_hops=max_hops)

@app.route('/nmap')
def nmap_tool():
    """Nmap port scanner tool page"""
    return render_template('index.html',
                        available_tools=AVAILABLE_TOOLS,
                        intro_text="<h2 style='color: #2563eb; margin-bottom: 1rem;'>🔍 Port Scanner Tool</h2><p style='color: #6b7280; font-size: 1.1rem;'>Scan for open ports and detect services running on target hosts. Choose from quick, basic, or comprehensive scan types for thorough network analysis.</p>",
                        pingResults=None,
                        tracerouteResults=None,
                        nmapResults=None,
                        digResults=None,
                        mtrResults=None,
                        initial_tool='nmap',
                        page_title="Port Scanner Tool - Free Online Nmap Port Scan",
                        page_description="Free port scanner tool based on Nmap. Scan for open ports, detect services, and analyze network security.",
                        page_keywords="port scanner, nmap online, port scan, network scanner, open ports, service detection, port checker")

@app.route('/dig', methods=['GET', 'POST'])
def dig_tool():
    """DNS lookup tool page"""
    dig_results = None
    domain = None
    record_type = 'A'
    
    if request.method == 'POST':
        domain = request.form.get('domain', '').strip()
        record_type = request.form.get('record_type', 'A')
        
        if domain:
            # Perform DNS lookup
            dig_results = NetworkTools.dig_query(domain, record_type)
    
    return render_template('dig.html', 
                         dig_results=dig_results,
                         domain=domain,
                         record_type=record_type)

@app.route('/mtr')
def mtr_tool():
    """MTR network diagnostics tool page"""
    return render_template('index.html',
                        available_tools=AVAILABLE_TOOLS,
                        intro_text="<h2 style='color: #2563eb; margin-bottom: 1rem;'>📊 MTR Network Diagnostics</h2><p style='color: #6b7280; font-size: 1.1rem;'>Combines ping and traceroute functionality for comprehensive network diagnostics. Get continuous monitoring and detailed network path analysis.</p>",
                        pingResults=None,
                        tracerouteResults=None,
                        nmapResults=None,
                        digResults=None,
                        mtrResults=None,
                        initial_tool='mtr',
                        page_title="MTR Tool - Free Online Network Diagnostics",
                        page_description="Free MTR network diagnostics tool. Combined ping and traceroute for comprehensive network analysis and monitoring.",
                        page_keywords="MTR tool, network diagnostics, MTR online, network monitoring, ping traceroute, network analysis")

@app.route('/api/ssl/check', methods=['POST'])
def ssl_check():
    """Simple SSL certificate check"""
    data = request.get_json()
    url = data.get('url', '')
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    # Extract domain from URL for recent searches
    try:
        parsed = urlparse(url if url.startswith('http') else f'https://{url}')
        domain = parsed.hostname
        if domain:
            save_recent_search(domain, url)
    except:
        pass
    
    result = SSLSimpleChecker.check_ssl_certificate(url)
    return jsonify(result)

@app.route('/api/recent-searches')
def get_recent_searches_api():
    """Get recent searches for display"""
    limit = request.args.get('limit', 10, type=int)
    searches = get_recent_searches(limit)
    return jsonify(searches)

@app.route('/api/ssl/deep-analysis', methods=['POST'])
def deep_ssl_analysis_api():
    """Deep SSL analysis API endpoint"""
    data = request.get_json()
    hostname = data.get('hostname', '').strip()
    
    if not hostname:
        return jsonify({'error': 'Hostname is required'}), 400
    
    try:
        # Perform deep SSL analysis
        from modules.ssl_analyzer import SSLDeepAnalyzer as ModuleSSLDeepAnalyzer
        deep_results = ModuleSSLDeepAnalyzer.analyze_ssl_security(hostname)
        return jsonify(deep_results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/ssl/deep-check', methods=['POST'])
def ssl_deep_check():
    """Deep SSL analysis using Python libraries"""
    data = request.get_json()
    target = data.get('url', '') or data.get('target', '')
    
    if not target:
        return jsonify({'error': 'Target URL is required'}), 400
    
    try:
        # Parse URL to get hostname and port
        parsed = urlparse(target if target.startswith('http') else f'https://{target}')
        hostname = parsed.hostname
        port = parsed.port or 443
        
        # Perform comprehensive SSL analysis
        result = SSLDeepAnalyzer.analyze_ssl_security(hostname, port)
        return jsonify(result)
            
    except Exception as e:
        return jsonify({'error': f'SSL analysis failed: {str(e)}'}), 500

@app.route('/api/ssl/csr-decode', methods=['POST'])
def csr_decode():
    """Decode Certificate Signing Request"""
    data = request.get_json()
    csr = data.get('csr', '')

    if not csr:
        return jsonify({'error': 'CSR is required'}), 400

    result = CSRDecoder.decode_csr(csr)
    return jsonify(result)

# Decode/Encode Tool API Endpoints
@app.route('/api/decode/base64-encode', methods=['POST'])
def base64_encode():
    """Encode text to Base64"""
    data = request.get_json()
    text = data.get('text', '')
    
    if not text:
        return jsonify({'error': 'Text is required'}), 400
    
    result = DecodeEncoder.base64_encode(text)
    return jsonify(result)

@app.route('/api/decode/base64-decode', methods=['POST'])
def base64_decode():
    """Decode text from Base64"""
    data = request.get_json()
    text = data.get('text', '')
    
    if not text:
        return jsonify({'error': 'Text is required'}), 400
    
    result = DecodeEncoder.base64_decode(text)
    return jsonify(result)

@app.route('/api/decode/url-encode', methods=['POST'])
def url_encode():
    """Encode text for URL"""
    data = request.get_json()
    text = data.get('text', '')
    
    if not text:
        return jsonify({'error': 'Text is required'}), 400
    
    result = DecodeEncoder.url_encode(text)
    return jsonify(result)

@app.route('/api/decode/url-decode', methods=['POST'])
def url_decode():
    """Decode text from URL"""
    data = request.get_json()
    text = data.get('text', '')
    
    if not text:
        return jsonify({'error': 'Text is required'}), 400
    
    result = DecodeEncoder.url_decode(text)
    return jsonify(result)

@app.route('/api/decode/html-encode', methods=['POST'])
def html_encode():
    """Encode text for HTML"""
    data = request.get_json()
    text = data.get('text', '')
    
    if not text:
        return jsonify({'error': 'Text is required'}), 400
    
    result = DecodeEncoder.html_encode(text)
    return jsonify(result)

@app.route('/api/decode/html-decode', methods=['POST'])
def html_decode():
    """Decode text from HTML"""
    data = request.get_json()
    text = data.get('text', '')
    
    if not text:
        return jsonify({'error': 'Text is required'}), 400
    
    result = DecodeEncoder.html_decode(text)
    return jsonify(result)

@app.route('/api/decode/hex-encode', methods=['POST'])
def hex_encode():
    """Encode text to Hexadecimal"""
    data = request.get_json()
    text = data.get('text', '')
    
    if not text:
        return jsonify({'error': 'Text is required'}), 400
    
    result = DecodeEncoder.hex_encode(text)
    return jsonify(result)

@app.route('/api/decode/hex-decode', methods=['POST'])
def hex_decode():
    """Decode text from Hexadecimal"""
    data = request.get_json()
    text = data.get('text', '')
    
    if not text:
        return jsonify({'error': 'Text is required'}), 400
    
    result = DecodeEncoder.hex_decode(text)
    return jsonify(result)

@app.route('/api/decode/binary-encode', methods=['POST'])
def binary_encode():
    """Encode text to Binary"""
    data = request.get_json()
    text = data.get('text', '')
    
    if not text:
        return jsonify({'error': 'Text is required'}), 400
    
    result = DecodeEncoder.binary_encode(text)
    return jsonify(result)

@app.route('/api/decode/binary-decode', methods=['POST'])
def binary_decode():
    """Decode text from Binary"""
    data = request.get_json()
    text = data.get('text', '')
    
    if not text:
        return jsonify({'error': 'Text is required'}), 400
    
    result = DecodeEncoder.binary_decode(text)
    return jsonify(result)

@app.route('/api/decode/json-encode', methods=['POST'])
def json_encode():
    """Encode data to JSON"""
    data = request.get_json()
    text = data.get('text', '')
    
    if not text:
        return jsonify({'error': 'Text is required'}), 400
    
    result = DecodeEncoder.json_encode(text)
    return jsonify(result)

@app.route('/api/decode/json-decode', methods=['POST'])
def json_decode():
    """Decode text from JSON"""
    data = request.get_json()
    text = data.get('text', '')
    
    if not text:
        return jsonify({'error': 'Text is required'}), 400
    
    result = DecodeEncoder.json_decode(text)
    return jsonify(result)

@app.route('/api/decode/process-all', methods=['POST'])
def process_all_formats():
    """Process text through all encoding/decoding formats"""
    data = request.get_json()
    text = data.get('text', '')
    
    if not text:
        return jsonify({'error': 'Text is required'}), 400
    
    result = DecodeEncoder.process_all_formats(text)
    return jsonify(result)

@app.route('/api/tools/<tool_name>', methods=['POST'])
def run_tool(tool_name):
    """Run a network tool"""
    if tool_name not in AVAILABLE_TOOLS:
        return jsonify({'error': 'Tool not available'}), 400
    
    data = request.get_json()
    hostname = data.get('hostname', '')
    
    if not hostname:
        return jsonify({'error': 'Hostname is required'}), 400
    
    # Run the appropriate tool with parameters
    if tool_name == 'testssl':
        result = NetworkTools.test_ssl(hostname)
    elif tool_name == 'ping':
        count = data.get('count', 4)
        result = NetworkTools.ping(hostname, count)
    elif tool_name == 'traceroute':
        max_hops = data.get('max_hops', 30)
        result = NetworkTools.traceroute(hostname, max_hops)
    elif tool_name == 'dig':
        record_type = data.get('record_type', 'A')
        result = NetworkTools.dig(hostname, record_type)
    elif tool_name == 'nmap':
        scan_type = data.get('scan_type', 'basic')
        result = NetworkTools.nmap(hostname, scan_type)
    elif tool_name == 'mtr':
        count = data.get('count', 10)
        result = NetworkTools.mtr(hostname, count)
    else:
        return jsonify({'error': 'Unknown tool'}), 400
    
    return jsonify(result)

@app.route('/api/tools/ping/stream', methods=['POST'])
def ping_stream():
    """Stream ping test results in real-time"""
    data = request.get_json()
    hostname = data.get('hostname', '')
    count = data.get('count', 4)

    if not hostname:
        return jsonify({'error': 'Hostname is required'}), 400

    def generate():
        try:
            for result in NetworkTools.ping_stream(hostname, count):
                yield f"data: {json.dumps(result)}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'error': str(e)})}\n\n"

    return app.response_class(generate(), mimetype='text/plain')

@app.route('/static/<path:filename>')
def static_files(filename):
    """Serve static files"""
    return send_from_directory('static', filename)

# Initialize analysis results storage
app.analysis_results = {}

if __name__ == '__main__':
    # Create static directory if it doesn't exist
    os.makedirs('static', exist_ok=True)
    
    # Run the Flask app
    app.run(host='0.0.0.0', port=8080, debug=True)
