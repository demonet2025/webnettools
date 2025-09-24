"""
Utility Tools Routes
Handles decode/encode tools, subnet calculator, and other utility functions
"""

from flask import Blueprint, render_template, request, jsonify
from modules.decode_encoder import DecodeEncoder
from modules.subnet_calculator import SubnetCalculator

# Create blueprint
utility_tools_bp = Blueprint('utility_tools', __name__)

@utility_tools_bp.route('/decode-encode')
def decode_encode():
    """Decode/Encode tool page"""
    return render_template('decode-encode.html')

@utility_tools_bp.route('/subnet-calculator')
def subnet_calculator():
    """IP Subnet Calculator tool page"""
    return render_template('subnet-calculator.html')

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
