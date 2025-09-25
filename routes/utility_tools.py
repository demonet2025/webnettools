"""
Utility Tools Routes
Handles decode/encode tools, subnet calculator, and other utility functions
"""

from flask import Blueprint, render_template, request, jsonify
from modules.decode_encoder import DecodeEncoder
from modules.subnet_calculator import SubnetCalculator

# Create blueprint
utility_tools_bp = Blueprint('utility_tools', __name__)

@utility_tools_bp.route('/utils-decode-encode', methods=['GET', 'POST'])
def decode_encode():
    """Decode/Encode tool page"""
    results = {}
    input_text = ''
    operation = ''
    format_type = ''
    detection = {}
    
    if request.method == 'POST':
        input_text = request.form.get('input_text', '').strip()
        operation = request.form.get('operation', '')
        format_type = request.form.get('format_type', '')
        
        # Auto-detect format and operation if not provided
        if input_text and not operation and not format_type:
            detection = DecodeEncoder.detect_format_and_operation(input_text)
            format_type = detection.get('format_type', '')
            operation = detection.get('operation', '')
        
        if input_text and operation and format_type:
            # Process the encoding/decoding based on format and operation
            if format_type == 'base64':
                if operation == 'encode':
                    results = DecodeEncoder.base64_encode(input_text)
                elif operation == 'decode':
                    results = DecodeEncoder.base64_decode(input_text)
            elif format_type == 'url':
                if operation == 'encode':
                    results = DecodeEncoder.url_encode(input_text)
                elif operation == 'decode':
                    results = DecodeEncoder.url_decode(input_text)
            elif format_type == 'html':
                if operation == 'encode':
                    results = DecodeEncoder.html_encode(input_text)
                elif operation == 'decode':
                    results = DecodeEncoder.html_decode(input_text)
            elif format_type == 'hex':
                if operation == 'encode':
                    results = DecodeEncoder.hex_encode(input_text)
                elif operation == 'decode':
                    results = DecodeEncoder.hex_decode(input_text)
            elif format_type == 'binary':
                if operation == 'encode':
                    results = DecodeEncoder.binary_encode(input_text)
                elif operation == 'decode':
                    results = DecodeEncoder.binary_decode(input_text)
            elif format_type == 'json':
                if operation == 'encode':
                    results = DecodeEncoder.json_encode(input_text)
                elif operation == 'decode':
                    results = DecodeEncoder.json_decode(input_text)
    
    return render_template('utils-decode-encode.html',
                         results=results,
                         input_text=input_text,
                         operation=operation,
                         format_type=format_type,
                         detection=detection)

@utility_tools_bp.route('/utils-subnet-calculator', methods=['GET', 'POST'])
def subnet_calculator():
    """IP Subnet Calculator tool page"""
    ipv4_results = None
    ipv6_results = None
    ipv4_address = None
    ipv4_subnet = None
    ipv4_custom = None
    ipv6_address = None
    ipv6_prefix = None
    
    if request.method == 'POST':
        # Handle IPv4 calculation
        if 'ipv4_address' in request.form:
            ipv4_address = request.form.get('ipv4_address', '').strip()
            ipv4_subnet = request.form.get('ipv4_subnet', '').strip()
            ipv4_custom = request.form.get('ipv4_custom', '').strip()
            
            if ipv4_address:
                cidr = None
                if ipv4_custom:
                    try:
                        cidr = int(ipv4_custom)
                    except ValueError:
                        pass
                elif ipv4_subnet:
                    try:
                        cidr = int(ipv4_subnet.replace('/', ''))
                    except ValueError:
                        pass
                
                if cidr is not None:
                    raw_result = SubnetCalculator.calculate_ipv4_subnet(ipv4_address, cidr=cidr)
                    if raw_result.get('success'):
                        # Flatten the nested structure for template
                        ipv4_results = {
                            'success': True,
                            'network_address': raw_result['network_info']['network_address'],
                            'broadcast_address': raw_result['network_info']['broadcast_address'],
                            'subnet_mask': raw_result['network_info']['subnet_mask'],
                            'wildcard_mask': raw_result['network_info']['wildcard_mask'],
                            'cidr_notation': raw_result['network_info']['cidr_notation'],
                            'ip_class': raw_result['network_info']['ip_class'],
                            'total_hosts': raw_result['host_info']['total_hosts'],
                            'usable_hosts': raw_result['host_info']['usable_hosts'],
                            'first_host': raw_result['host_info']['first_host'],
                            'last_host': raw_result['host_info']['last_host'],
                            'raw_output': raw_result['raw_output']
                        }
                    else:
                        ipv4_results = raw_result
        
        # Handle IPv6 calculation
        elif 'ipv6_address' in request.form:
            ipv6_address = request.form.get('ipv6_address', '').strip()
            ipv6_prefix = request.form.get('ipv6_prefix', '').strip()
            
            if ipv6_address and ipv6_prefix:
                try:
                    prefix_length = int(ipv6_prefix.replace('/', ''))
                    raw_result = SubnetCalculator.calculate_ipv6_subnet(ipv6_address, prefix_length)
                    if raw_result.get('success'):
                        # Flatten the nested structure for template
                        ipv6_results = {
                            'success': True,
                            'network_address': raw_result['network_info']['network_address'],
                            'first_address': raw_result['host_info']['first_host'],
                            'last_address': raw_result['host_info']['last_host'],
                            'compressed_network': raw_result['network_info']['network_address'],
                            'expanded_network': raw_result['network_info']['network_address'],
                            'prefix_length': f"/{raw_result['network_info']['prefix_length']}",
                            'total_addresses': raw_result['host_info']['total_hosts'],
                            'address_type': 'Global Unicast' if raw_result['network_info']['network_address'].startswith('2001:') else 'Other',
                            'raw_output': raw_result['raw_output']
                        }
                    else:
                        ipv6_results = raw_result
                except ValueError:
                    pass
    
    return render_template('utils-subnet-calculator.html',
                         ipv4_results=ipv4_results,
                         ipv6_results=ipv6_results,
                         ipv4_address=ipv4_address,
                         ipv4_subnet=ipv4_subnet,
                         ipv4_custom=ipv4_custom,
                         ipv6_address=ipv6_address,
                         ipv6_prefix=ipv6_prefix)

# API Routes for Utility Tools
@utility_tools_bp.route('/api/decode/base64-encode', methods=['POST'])
def base64_encode_api():
    """Base64 encode API endpoint"""
    data = request.get_json()
    text = data.get('text', '').strip()
    
    if not text:
        return jsonify({'error': 'Text is required'}), 400
    
    try:
        result = DecodeEncoder.base64_encode(text)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@utility_tools_bp.route('/api/decode/base64-decode', methods=['POST'])
def base64_decode_api():
    """Base64 decode API endpoint"""
    data = request.get_json()
    text = data.get('text', '').strip()
    
    if not text:
        return jsonify({'error': 'Text is required'}), 400
    
    try:
        result = DecodeEncoder.base64_decode(text)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@utility_tools_bp.route('/api/decode/url-encode', methods=['POST'])
def url_encode_api():
    """URL encode API endpoint"""
    data = request.get_json()
    text = data.get('text', '').strip()
    
    if not text:
        return jsonify({'error': 'Text is required'}), 400
    
    try:
        result = DecodeEncoder.url_encode(text)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@utility_tools_bp.route('/api/decode/url-decode', methods=['POST'])
def url_decode_api():
    """URL decode API endpoint"""
    data = request.get_json()
    text = data.get('text', '').strip()
    
    if not text:
        return jsonify({'error': 'Text is required'}), 400
    
    try:
        result = DecodeEncoder.url_decode(text)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@utility_tools_bp.route('/api/decode/html-encode', methods=['POST'])
def html_encode_api():
    """HTML encode API endpoint"""
    data = request.get_json()
    text = data.get('text', '').strip()
    
    if not text:
        return jsonify({'error': 'Text is required'}), 400
    
    try:
        result = DecodeEncoder.html_encode(text)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@utility_tools_bp.route('/api/decode/html-decode', methods=['POST'])
def html_decode_api():
    """HTML decode API endpoint"""
    data = request.get_json()
    text = data.get('text', '').strip()
    
    if not text:
        return jsonify({'error': 'Text is required'}), 400
    
    try:
        result = DecodeEncoder.html_decode(text)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@utility_tools_bp.route('/api/decode/hex-encode', methods=['POST'])
def hex_encode_api():
    """Hex encode API endpoint"""
    data = request.get_json()
    text = data.get('text', '').strip()
    
    if not text:
        return jsonify({'error': 'Text is required'}), 400
    
    try:
        result = DecodeEncoder.hex_encode(text)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@utility_tools_bp.route('/api/decode/hex-decode', methods=['POST'])
def hex_decode_api():
    """Hex decode API endpoint"""
    data = request.get_json()
    text = data.get('text', '').strip()
    
    if not text:
        return jsonify({'error': 'Text is required'}), 400
    
    try:
        result = DecodeEncoder.hex_decode(text)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@utility_tools_bp.route('/api/decode/binary-encode', methods=['POST'])
def binary_encode_api():
    """Binary encode API endpoint"""
    data = request.get_json()
    text = data.get('text', '').strip()
    
    if not text:
        return jsonify({'error': 'Text is required'}), 400
    
    try:
        result = DecodeEncoder.binary_encode(text)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@utility_tools_bp.route('/api/decode/binary-decode', methods=['POST'])
def binary_decode_api():
    """Binary decode API endpoint"""
    data = request.get_json()
    text = data.get('text', '').strip()
    
    if not text:
        return jsonify({'error': 'Text is required'}), 400
    
    try:
        result = DecodeEncoder.binary_decode(text)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@utility_tools_bp.route('/api/decode/json-encode', methods=['POST'])
def json_encode_api():
    """JSON encode API endpoint"""
    data = request.get_json()
    text = data.get('text', '').strip()
    
    if not text:
        return jsonify({'error': 'Text is required'}), 400
    
    try:
        result = DecodeEncoder.json_encode(text)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@utility_tools_bp.route('/api/decode/json-decode', methods=['POST'])
def json_decode_api():
    """JSON decode API endpoint"""
    data = request.get_json()
    text = data.get('text', '').strip()
    
    if not text:
        return jsonify({'error': 'Text is required'}), 400
    
    try:
        result = DecodeEncoder.json_decode(text)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@utility_tools_bp.route('/api/decode/process-all', methods=['POST'])
def process_all_api():
    """Process all encoding/decoding API endpoint"""
    data = request.get_json()
    text = data.get('text', '').strip()
    
    if not text:
        return jsonify({'error': 'Text is required'}), 400
    
    try:
        result = DecodeEncoder.process_all(text)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Subnet Calculator API Routes
@utility_tools_bp.route('/api/subnet/ipv4', methods=['POST'])
def calculate_ipv4_subnet():
    """Calculate IPv4 subnet information"""
    data = request.get_json()
    ip_address = data.get('ip_address', '').strip()
    cidr = data.get('cidr')
    
    if not ip_address:
        return jsonify({'error': 'IP address is required'}), 400
    
    if cidr is None:
        return jsonify({'error': 'CIDR notation is required'}), 400
    
    result = SubnetCalculator.calculate_ipv4_subnet(ip_address, cidr=cidr)
    return jsonify(result)

@utility_tools_bp.route('/api/subnet/ipv6', methods=['POST'])
def calculate_ipv6_subnet():
    """Calculate IPv6 subnet information"""
    data = request.get_json()
    ip_address = data.get('ip_address', '').strip()
    prefix_length = data.get('prefix_length')
    
    if not ip_address:
        return jsonify({'error': 'IPv6 address is required'}), 400
    
    if prefix_length is None:
        return jsonify({'error': 'Prefix length is required'}), 400
    
    result = SubnetCalculator.calculate_ipv6_subnet(ip_address, prefix_length)
    return jsonify(result)

@utility_tools_bp.route('/api/subnet/common-subnets', methods=['GET'])
def get_common_subnets():
    """Get list of common subnet masks"""
    subnets = SubnetCalculator.get_common_subnets()
    return jsonify(subnets)

@utility_tools_bp.route('/api/subnet/common-ipv6-prefixes', methods=['GET'])
def get_common_ipv6_prefixes():
    """Get list of common IPv6 prefix lengths"""
    prefixes = SubnetCalculator.get_common_ipv6_prefixes()
    return jsonify(prefixes)
