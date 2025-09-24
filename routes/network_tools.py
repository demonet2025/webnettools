"""
Network Tools Routes
Handles ping, traceroute, nmap, dig, mtr and other network diagnostic tools
"""

from flask import Blueprint, render_template, request, jsonify, Response
from modules.network_tools import NetworkTools
import json

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

@network_tools_bp.route('/nmap')
def nmap_tool():
    """Nmap tool page"""
    return render_template('nmap.html')

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

@network_tools_bp.route('/mtr')
def mtr_tool():
    """MTR tool page"""
    return render_template('mtr.html')

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
