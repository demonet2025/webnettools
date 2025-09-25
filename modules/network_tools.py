"""
Network Tools Module
Handles ping, traceroute, nmap, dig, mtr, and other network diagnostic tools
"""

import subprocess
import threading
import time
import re
import json
from datetime import datetime


class NetworkTools:
    """Network diagnostic tools"""

    @staticmethod
    def ping(host, count=4, timeout=5):
        """Ping a host and return results"""
        try:
            # Determine ping command based on OS
            import platform
            system = platform.system().lower()
            
            if system == "windows":
                cmd = ["ping", "-n", str(count), "-w", str(timeout * 1000), host]
            else:
                cmd = ["ping", "-c", str(count), "-W", str(timeout), host]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 10)
            
            if result.returncode == 0:
                return NetworkTools._parse_ping_output(result.stdout, host)
            else:
                return {
                    'success': False,
                    'host': host,
                    'error': f'Ping failed: {result.stderr}',
                    'raw_output': result.stdout + result.stderr
                }
                
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'host': host,
                'error': 'Ping timeout',
                'raw_output': 'Ping command timed out'
            }
        except Exception as e:
            return {
                'success': False,
                'host': host,
                'error': f'Ping error: {str(e)}',
                'raw_output': str(e)
            }

    @staticmethod
    def _parse_ping_output(output, host):
        """Parse ping command output"""
        try:
            lines = output.strip().split('\n')
            
            # Extract statistics
            stats = {
                'packets_sent': 0,
                'packets_received': 0,
                'packet_loss': 0,
                'min_time': 0,
                'max_time': 0,
                'avg_time': 0
            }
            
            # Parse ping results
            ping_results = []
            for line in lines:
                # Look for ping response lines
                if 'time=' in line or 'time<' in line:
                    # Extract time from response
                    time_match = re.search(r'time[<=](\d+\.?\d*)', line)
                    if time_match:
                        ping_results.append(float(time_match.group(1)))
                
                # Look for statistics
                if 'packets transmitted' in line or 'Packets: Sent' in line:
                    # Extract packet statistics
                    sent_match = re.search(r'(\d+)\s+packets?\s+transmitted', line)
                    if sent_match:
                        stats['packets_sent'] = int(sent_match.group(1))
                    
                    received_match = re.search(r'(\d+)\s+received', line)
                    if received_match:
                        stats['packets_received'] = int(received_match.group(1))
                    
                    loss_match = re.search(r'(\d+\.?\d*)% packet loss', line)
                    if loss_match:
                        stats['packet_loss'] = float(loss_match.group(1))
                
                # Look for timing statistics
                if 'min/avg/max' in line or 'Minimum/Maximum/Average' in line:
                    timing_match = re.search(r'(\d+\.?\d*)/(\d+\.?\d*)/(\d+\.?\d*)', line)
                    if timing_match:
                        stats['min_time'] = float(timing_match.group(1))
                        stats['avg_time'] = float(timing_match.group(2))
                        stats['max_time'] = float(timing_match.group(3))
            
            # Calculate packet loss if not found
            if stats['packets_sent'] > 0 and stats['packet_loss'] == 0:
                stats['packet_loss'] = ((stats['packets_sent'] - stats['packets_received']) / stats['packets_sent']) * 100
            
            return {
                'success': True,
                'host': host,
                'stats': stats,
                'ping_results': ping_results,
                'raw_output': output
            }
            
        except Exception as e:
            return {
                'success': False,
                'host': host,
                'error': f'Failed to parse ping output: {str(e)}',
                'raw_output': output
            }

    @staticmethod
    def traceroute(host, max_hops=30, timeout=5):
        """Traceroute to a host"""
        try:
            # Determine traceroute command based on OS
            import platform
            system = platform.system().lower()
            
            if system == "windows":
                cmd = ["tracert", "-h", str(max_hops), "-w", str(timeout * 1000), host]
            else:
                cmd = ["traceroute", "-m", str(max_hops), "-w", str(timeout), host]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout * max_hops)
            
            if result.returncode == 0:
                return NetworkTools._parse_traceroute_output(result.stdout, host)
            else:
                return {
                    'success': False,
                    'host': host,
                    'error': f'Traceroute failed: {result.stderr}',
                    'raw_output': result.stdout + result.stderr
                }
                
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'host': host,
                'error': 'Traceroute timeout',
                'raw_output': 'Traceroute command timed out'
            }
        except Exception as e:
            return {
                'success': False,
                'host': host,
                'error': f'Traceroute error: {str(e)}',
                'raw_output': str(e)
            }

    @staticmethod
    def _parse_traceroute_output(output, host):
        """Parse traceroute command output"""
        try:
            lines = output.strip().split('\n')
            hops = []
            
            for line in lines:
                # Skip header lines
                if 'traceroute' in line.lower() or 'tracing route' in line.lower():
                    continue
                
                # Parse hop information
                hop_match = re.match(r'\s*(\d+)\s+(.+)', line)
                if hop_match:
                    hop_num = int(hop_match.group(1))
                    hop_info = hop_match.group(2)
                    
                    # Extract IP and timing information
                    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', hop_info)
                    ip = ip_match.group(1) if ip_match else 'Unknown'
                    
                    # Extract timing information
                    times = re.findall(r'(\d+\.?\d*)\s*ms', hop_info)
                    times = [float(t) for t in times] if times else []
                    
                    hops.append({
                        'hop': hop_num,
                        'ip': ip,
                        'times': times,
                        'avg_time': sum(times) / len(times) if times else 0
                    })
            
            return {
                'success': True,
                'host': host,
                'hops': hops,
                'raw_output': output
            }
            
        except Exception as e:
            return {
                'success': False,
                'host': host,
                'error': f'Failed to parse traceroute output: {str(e)}',
                'raw_output': output
            }

    @staticmethod
    def nmap_scan(host, scan_type='basic'):
        """Perform nmap scan on a host"""
        try:
            # Check if nmap is available
            try:
                subprocess.run(['nmap', '--version'], capture_output=True, check=True)
            except (subprocess.CalledProcessError, FileNotFoundError):
                return {
                    'success': False,
                    'host': host,
                    'error': 'nmap is not installed or not available',
                    'raw_output': 'nmap command not found'
                }
            
            # Determine scan command based on type
            if scan_type == 'basic':
                cmd = ['nmap', '-sS', '-O', '-sV', host]
            elif scan_type == 'full':
                cmd = ['nmap', '-sS', '-O', '-sV', '-A', '--script=vuln', host]
            else:
                cmd = ['nmap', host]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                return NetworkTools._parse_nmap_output(result.stdout, host)
            else:
                return {
                    'success': False,
                    'host': host,
                    'error': f'Nmap scan failed: {result.stderr}',
                    'raw_output': result.stdout + result.stderr
                }
                
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'host': host,
                'error': 'Nmap scan timeout',
                'raw_output': 'Nmap scan timed out'
            }
        except Exception as e:
            return {
                'success': False,
                'host': host,
                'error': f'Nmap scan error: {str(e)}',
                'raw_output': str(e)
            }

    @staticmethod
    def _parse_nmap_output(output, host):
        """Parse nmap command output"""
        try:
            lines = output.strip().split('\n')
            ports = []
            os_info = None
            host_info = None
            
            for line in lines:
                # Parse port information
                port_match = re.match(r'(\d+)/(tcp|udp)\s+(\w+)\s+(.+)', line)
                if port_match:
                    port_num = int(port_match.group(1))
                    protocol = port_match.group(2)
                    state = port_match.group(3)
                    service = port_match.group(4)
                    
                    ports.append({
                        'port': port_num,
                        'protocol': protocol,
                        'state': state,
                        'service': service
                    })
                
                # Parse OS information
                if 'OS details:' in line:
                    os_info = line.split('OS details:')[1].strip()
                elif 'Running:' in line:
                    os_info = line.split('Running:')[1].strip()
                
                # Parse host information
                if 'Host is up' in line:
                    host_info = line.strip()
            
            return {
                'success': True,
                'host': host,
                'ports': ports,
                'os_info': os_info,
                'host_info': host_info,
                'raw_output': output
            }
            
        except Exception as e:
            return {
                'success': False,
                'host': host,
                'error': f'Failed to parse nmap output: {str(e)}',
                'raw_output': output
            }

    @staticmethod
    def dig_query(domain, query_type='A'):
        """Perform DNS query using dig"""
        try:
            # Check if dig is available
            try:
                subprocess.run(['dig', '-v'], capture_output=True, check=True)
            except (subprocess.CalledProcessError, FileNotFoundError):
                return {
                    'success': False,
                    'domain': domain,
                    'error': 'dig is not installed or not available',
                    'raw_output': 'dig command not found'
                }
            
            # Use full dig output for better parsing
            cmd = ['dig', '+noall', '+answer', '+comments', query_type, domain]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                return NetworkTools._parse_dig_output(result.stdout, domain, query_type)
            else:
                return {
                    'success': False,
                    'domain': domain,
                    'error': f'Dig query failed: {result.stderr}',
                    'raw_output': result.stdout + result.stderr
                }
                
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'domain': domain,
                'error': 'Dig query timeout',
                'raw_output': 'Dig query timed out'
            }
        except Exception as e:
            return {
                'success': False,
                'domain': domain,
                'error': f'Dig query error: {str(e)}',
                'raw_output': str(e)
            }

    @staticmethod
    def _parse_dig_output(output, domain, query_type):
        """Parse dig command output"""
        try:
            import re
            lines = output.strip().split('\n')
            records = []
            query_time = None
            status = 'Success'
            
            # Parse dig output
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                
                # Parse query time
                if 'Query time:' in line:
                    time_match = re.search(r'Query time: (\d+) msec', line)
                    if time_match:
                        query_time = int(time_match.group(1))
                
                # Parse status
                if 'status:' in line:
                    status_match = re.search(r'status: (\w+)', line)
                    if status_match:
                        status = status_match.group(1)
                
                # Parse DNS records
                # Format: domain. TTL IN TYPE value
                record_match = re.match(r'([^\s]+)\s+(\d+)\s+IN\s+(\w+)\s+(.+)', line)
                if record_match:
                    record_name = record_match.group(1).rstrip('.')
                    ttl = int(record_match.group(2))
                    record_type = record_match.group(3)
                    record_value = record_match.group(4).rstrip('.')
                    
                    # Clean up record value based on type
                    if record_type == 'MX':
                        # MX records: priority value
                        mx_match = re.match(r'(\d+)\s+(.+)', record_value)
                        if mx_match:
                            record_value = f"{mx_match.group(2)} (Priority: {mx_match.group(1)})"
                    elif record_type == 'SOA':
                        # SOA records: keep as is but clean up
                        record_value = record_value.replace(' ', ' ')
                    elif record_type == 'TXT':
                        # TXT records: remove quotes
                        record_value = record_value.strip('"')
                    
                    records.append({
                        'name': record_name,
                        'type': record_type,
                        'value': record_value,
                        'ttl': ttl
                    })
            
            # If no structured records found, try to parse simple output
            if not records:
                simple_lines = [line.strip() for line in lines if line.strip() and not line.startswith(';')]
                for line in simple_lines:
                    if line and not line.startswith(';'):
                        records.append({
                            'name': domain,
                            'type': query_type,
                            'value': line,
                            'ttl': 0
                        })
            
            # Calculate summary
            summary = {
                'query_time': query_time or 0,
                'record_count': len(records),
                'status': status
            }
            
            return {
                'success': True,
                'domain': domain,
                'query_type': query_type,
                'records': records,
                'summary': summary,
                'raw_output': output
            }
            
        except Exception as e:
            return {
                'success': False,
                'domain': domain,
                'error': f'Failed to parse dig output: {str(e)}',
                'raw_output': output
            }

    @staticmethod
    def mtr_trace(host, max_hops=30, count=10):
        """Perform MTR trace to a host"""
        try:
            # Check if mtr is available
            try:
                subprocess.run(['mtr', '--version'], capture_output=True, check=True)
            except (subprocess.CalledProcessError, FileNotFoundError):
                return {
                    'success': False,
                    'host': host,
                    'error': 'mtr is not installed or not available',
                    'raw_output': 'mtr command not found'
                }
            
            cmd = ['mtr', '-r', '-c', str(count), '-m', str(max_hops), host]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=count * 5)
            
            if result.returncode == 0:
                return NetworkTools._parse_mtr_output(result.stdout, host)
            else:
                return {
                    'success': False,
                    'host': host,
                    'error': f'MTR trace failed: {result.stderr}',
                    'raw_output': result.stdout + result.stderr
                }
                
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'host': host,
                'error': 'MTR trace timeout',
                'raw_output': 'MTR trace timed out'
            }
        except Exception as e:
            return {
                'success': False,
                'host': host,
                'error': f'MTR trace error: {str(e)}',
                'raw_output': str(e)
            }

    @staticmethod
    def _parse_mtr_output(output, host):
        """Parse MTR command output"""
        try:
            lines = output.strip().split('\n')
            hops = []
            
            for line in lines:
                # Skip header lines
                if 'HOST:' in line or 'Loss%' in line:
                    continue
                
                # Parse hop information
                parts = line.split()
                if len(parts) >= 8:
                    try:
                        hop_num = int(parts[0])
                        hostname = parts[1]
                        ip = parts[2]
                        loss = float(parts[3].replace('%', ''))
                        sent = int(parts[4])
                        last = float(parts[5])
                        avg = float(parts[6])
                        best = float(parts[7])
                        worst = float(parts[8]) if len(parts) > 8 else 0
                        
                        hops.append({
                            'hop': hop_num,
                            'hostname': hostname,
                            'ip': ip,
                            'loss': loss,
                            'sent': sent,
                            'last': last,
                            'avg': avg,
                            'best': best,
                            'worst': worst
                        })
                    except (ValueError, IndexError):
                        continue
            
            return {
                'success': True,
                'host': host,
                'hops': hops,
                'raw_output': output
            }
            
        except Exception as e:
            return {
                'success': False,
                'host': host,
                'error': f'Failed to parse MTR output: {str(e)}',
                'raw_output': output
            }

    @staticmethod
    def whois_query(domain):
        """Perform WHOIS query for a domain"""
        try:
            # Check if whois is available
            try:
                subprocess.run(['whois', '--version'], capture_output=True, check=True)
            except (subprocess.CalledProcessError, FileNotFoundError):
                return {
                    'success': False,
                    'domain': domain,
                    'error': 'whois is not installed or not available',
                    'raw_output': 'whois command not found'
                }
            
            cmd = ['whois', domain]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                return NetworkTools._parse_whois_output(result.stdout, domain)
            else:
                return {
                    'success': False,
                    'domain': domain,
                    'error': f'WHOIS query failed: {result.stderr}',
                    'raw_output': result.stdout + result.stderr
                }
                
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'domain': domain,
                'error': 'WHOIS query timeout',
                'raw_output': 'WHOIS query timed out'
            }
        except Exception as e:
            return {
                'success': False,
                'domain': domain,
                'error': f'WHOIS query error: {str(e)}',
                'raw_output': str(e)
            }

    @staticmethod
    def _parse_whois_output(output, domain):
        """Parse WHOIS command output"""
        try:
            lines = output.strip().split('\n')
            whois_info = {}
            
            for line in lines:
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip().lower()
                    value = value.strip()
                    
                    if key in whois_info:
                        if isinstance(whois_info[key], list):
                            whois_info[key].append(value)
                        else:
                            whois_info[key] = [whois_info[key], value]
                    else:
                        whois_info[key] = value
            
            return {
                'success': True,
                'domain': domain,
                'whois_info': whois_info,
                'raw_output': output
            }
            
        except Exception as e:
            return {
                'success': False,
                'domain': domain,
                'error': f'Failed to parse WHOIS output: {str(e)}',
                'raw_output': output
            }
