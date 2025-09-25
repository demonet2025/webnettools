"""
Network Tools Routes
Handles ping, traceroute, nmap, dig, mtr and other network diagnostic tools
"""

from flask import Blueprint, render_template, request, jsonify, Response
from modules.network_tools import NetworkTools
import json
import subprocess
import threading
import time

# Create blueprint
network_tools_bp = Blueprint('network_tools', __name__)

@network_tools_bp.route('/ping', methods=['GET', 'POST'])
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

@network_tools_bp.route('/traceroute', methods=['GET', 'POST'])
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

@network_tools_bp.route('/api/traceroute/stream')
def traceroute_stream():
    """Streaming traceroute endpoint"""
    hostname = request.args.get('hostname', '').strip()
    max_hops = int(request.args.get('max_hops', 30))
    
    if not hostname:
        return jsonify({'error': 'Hostname is required'}), 400
    
    def generate():
        try:
            # Determine traceroute command based on OS
            import platform
            system = platform.system().lower()
            
            if system == "windows":
                cmd = ["tracert", "-h", str(max_hops), "-w", "3000", hostname]
            else:
                cmd = ["traceroute", "-m", str(max_hops), "-w", "3", hostname]
            
            # Send initial status immediately
            yield f"data: {json.dumps({'type': 'start', 'hostname': hostname, 'max_hops': max_hops})}\n\n"
            
            # Start traceroute process with optimized settings
            process = subprocess.Popen(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                text=True, 
                bufsize=0,  # Unbuffered for faster streaming
                universal_newlines=True
            )
            
            hop_count = 0
            buffer = ""
            
            # Read output in chunks for better performance
            while True:
                chunk = process.stdout.read(1024)  # Read in 1KB chunks
                if not chunk:
                    break
                    
                buffer += chunk
                lines = buffer.split('\n')
                buffer = lines[-1]  # Keep incomplete line in buffer
                
                for line in lines[:-1]:  # Process complete lines
                    if line.strip():
                        hop_count += 1
                        # Send minimal data for better performance
                        line_data = {
                            'type': 'hop',
                            'hop_number': hop_count,
                        'line': line.strip()
                        }
                        yield f"data: {json.dumps(line_data)}\n\n"
            
            # Process remaining buffer
            if buffer.strip():
                hop_count += 1
                line_data = {
                    'type': 'hop',
                    'hop_number': hop_count,
                    'line': buffer.strip()
                }
                yield f"data: {json.dumps(line_data)}\n\n"
            
            # Wait for process to complete with timeout
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
            
            # Send completion status
            yield f"data: {json.dumps({'type': 'complete', 'total_hops': hop_count})}\n\n"
            
        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"
    
    return Response(generate(), mimetype='text/event-stream')

@network_tools_bp.route('/nmap', methods=['GET', 'POST'])
def nmap_tool():
    """Nmap tool page"""
    nmap_results = None
    hostname = None
    scan_type = 'basic'
    
    if request.method == 'POST':
        hostname = request.form.get('hostname', '').strip()
        scan_type = request.form.get('scan_type', 'basic')
        
        if hostname:
            # Perform Nmap scan
            nmap_results = NetworkTools.nmap_scan(hostname, scan_type)
    
    return render_template('nmap.html', 
                         nmap_results=nmap_results,
                         hostname=hostname,
                         scan_type=scan_type)

@network_tools_bp.route('/dig', methods=['GET', 'POST'])
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

@network_tools_bp.route('/mtr', methods=['GET', 'POST'])
def mtr_tool():
    """MTR tool page"""
    mtr_results = None
    hostname = None
    count = 10
    max_hops = 30
    
    if request.method == 'POST':
        hostname = request.form.get('hostname', '').strip()
        count = int(request.form.get('count', 10))
        max_hops = int(request.form.get('max_hops', 30))
        
        if hostname:
            # Perform MTR trace
            mtr_results = NetworkTools.mtr_trace(hostname, max_hops, count)
    
    return render_template('mtr.html', 
                         mtr_results=mtr_results,
                         hostname=hostname,
                         count=count,
                         max_hops=max_hops)

@network_tools_bp.route('/api/mtr/stream')
def mtr_stream():
    """Streaming MTR endpoint"""
    hostname = request.args.get('hostname', '').strip()
    max_hops = int(request.args.get('max_hops', 30))
    count = int(request.args.get('count', 10))
    
    if not hostname:
        return jsonify({'error': 'Hostname is required'}), 400
    
    def generate():
        try:
            # Send initial status immediately
            yield f"data: {json.dumps({'type': 'start', 'hostname': hostname, 'max_hops': max_hops, 'count': count})}\n\n"
            
            # Start MTR process with optimized settings
            cmd = ['mtr', '-r', '-c', str(count), '-m', str(max_hops), hostname]
            process = subprocess.Popen(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                text=True, 
                bufsize=0,  # Unbuffered for faster streaming
                universal_newlines=True
            )
            
            hop_count = 0
            buffer = ""
            hops_data = []
            
            # Read output in chunks for better performance
            while True:
                chunk = process.stdout.read(1024)  # Read in 1KB chunks
                if not chunk:
                    break
                    
                buffer += chunk
                lines = buffer.split('\n')
                buffer = lines[-1]  # Keep incomplete line in buffer
                
                for line in lines[:-1]:  # Process complete lines
                    if line.strip():
                        hop_count += 1
                        # Parse MTR line and send as JSON
                        hop_data = parse_mtr_line(line.strip(), hop_count)
                        if hop_data:
                            hops_data.append(hop_data)
                            yield f"data: {json.dumps({'type': 'hop', 'hop_data': hop_data, 'hop_number': hop_count})}\n\n"
            
            # Process remaining buffer
            if buffer.strip():
                hop_count += 1
                hop_data = parse_mtr_line(buffer.strip(), hop_count)
                if hop_data:
                    hops_data.append(hop_data)
                    yield f"data: {json.dumps({'type': 'hop', 'hop_data': hop_data, 'hop_number': hop_count})}\n\n"
            
            # Wait for process to complete with timeout
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
            
            # Send completion status with summary
            summary = calculate_mtr_summary(hops_data)
            yield f"data: {json.dumps({'type': 'complete', 'total_hops': hop_count, 'summary': summary})}\n\n"
            
        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"
    
    def parse_mtr_line(line, hop_number):
        """Parse a single MTR line to extract hop data"""
        try:
            # MTR output format: "HOST: hostname Loss% Snt Last Avg Best Wrst StDev"
            # or: "1. 192.168.1.1 0.0% 10 0.5 0.6 0.4 1.2 0.2"
            parts = line.split()
            if len(parts) < 3:
                return None
                
            # Check if it's a header line
            if 'HOST:' in line or 'Loss%' in line:
                return {'type': 'header', 'line': line}
            
            # Parse hop data
            hop_data = {
                'hop_number': hop_number,
                'ip_address': parts[1] if len(parts) > 1 else 'N/A',
                'hostname': None,
                'loss_percentage': 0.0,
                'sent': 0,
                'last_rtt': 0.0,
                'avg_rtt': 0.0,
                'best_rtt': 0.0,
                'worst_rtt': 0.0,
                'stdev_rtt': 0.0,
                'raw_line': line
            }
            
            # Try to parse numeric data
            if len(parts) >= 8:
                try:
                    hop_data['loss_percentage'] = float(parts[2].replace('%', ''))
                    hop_data['sent'] = int(parts[3])
                    hop_data['last_rtt'] = float(parts[4]) if parts[4] != '0.0' else 0.0
                    hop_data['avg_rtt'] = float(parts[5]) if parts[5] != '0.0' else 0.0
                    hop_data['best_rtt'] = float(parts[6]) if parts[6] != '0.0' else 0.0
                    hop_data['worst_rtt'] = float(parts[7]) if parts[7] != '0.0' else 0.0
                    hop_data['stdev_rtt'] = float(parts[8]) if len(parts) > 8 and parts[8] != '0.0' else 0.0
                except (ValueError, IndexError):
                    pass
            
            return hop_data
            
        except Exception:
            return {'type': 'raw', 'line': line, 'hop_number': hop_number}
    
    def calculate_mtr_summary(hops_data):
        """Calculate summary statistics from hops data"""
        if not hops_data:
            return {}
            
        valid_hops = [h for h in hops_data if 'loss_percentage' in h and isinstance(h['loss_percentage'], (int, float))]
        
        if not valid_hops:
            return {}
            
        total_hops = len(valid_hops)
        reachable_hops = len([h for h in valid_hops if h['loss_percentage'] < 100])
        avg_loss = sum(h['loss_percentage'] for h in valid_hops) / total_hops
        
        rtt_hops = [h for h in valid_hops if h['avg_rtt'] > 0]
        avg_rtt = sum(h['avg_rtt'] for h in rtt_hops) / len(rtt_hops) if rtt_hops else 0
        
        return {
            'total_hops': total_hops,
            'reachable_hops': reachable_hops,
            'avg_loss': round(avg_loss, 1),
            'avg_rtt': round(avg_rtt, 1)
        }
    
    return Response(generate(), mimetype='text/event-stream')

# API Routes for Network Tools
@network_tools_bp.route('/api/tools/<tool_name>', methods=['POST'])
def network_tool_api(tool_name):
    """Generic network tool API endpoint"""
    data = request.get_json()
    
    try:
        if tool_name == 'ping':
            hostname = data.get('hostname', '').strip()
            count = data.get('count', 4)
            if not hostname:
                return jsonify({'error': 'Hostname is required'}), 400
            result = NetworkTools.ping(hostname, count)
            
        elif tool_name == 'traceroute':
            hostname = data.get('hostname', '').strip()
            max_hops = data.get('max_hops', 30)
            if not hostname:
                return jsonify({'error': 'Hostname is required'}), 400
            result = NetworkTools.traceroute(hostname, max_hops)
            
        elif tool_name == 'dig':
            domain = data.get('domain', '').strip()
            record_type = data.get('record_type', 'A')
            if not domain:
                return jsonify({'error': 'Domain is required'}), 400
            result = NetworkTools.dig_query(domain, record_type)
            
        elif tool_name == 'nmap':
            hostname = data.get('hostname', '').strip()
            scan_type = data.get('scan_type', 'basic')
            if not hostname:
                return jsonify({'error': 'Hostname is required'}), 400
            result = NetworkTools.nmap_scan(hostname, scan_type)
            
        elif tool_name == 'mtr':
            hostname = data.get('hostname', '').strip()
            if not hostname:
                return jsonify({'error': 'Hostname is required'}), 400
            result = NetworkTools.mtr_trace(hostname)
            
        else:
            return jsonify({'error': f'Unknown tool: {tool_name}'}), 400
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@network_tools_bp.route('/api/tools/ping/stream', methods=['POST'])
def ping_stream_api():
    """Streaming ping API endpoint"""
    data = request.get_json()
    hostname = data.get('hostname', '').strip()
    count = data.get('count', 4)
    
    if not hostname:
        return jsonify({'error': 'Hostname is required'}), 400
    
    def generate():
        try:
            # This would need to be implemented with proper streaming
            # For now, return a simple response
            result = NetworkTools.ping(hostname, count)
            yield f"data: {json.dumps(result)}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"
    
    return Response(generate(), mimetype='text/plain')
