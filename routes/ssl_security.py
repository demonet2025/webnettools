"""
SSL & Security Routes
Handles SSL checker, deep SSL checker, CSR decoder, and certificate tools
"""

from flask import Blueprint, render_template, request, jsonify
from modules.ssl_analyzer import SSLAnalyzer, SSLDeepAnalyzer, CSRDecoder
from .utils import get_recent_searches, save_recent_search

# Create blueprint
ssl_security_bp = Blueprint('ssl_security', __name__)

@ssl_security_bp.route('/sslchecker', methods=['GET', 'POST'])
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
                from urllib.parse import urlparse
                parsed = urlparse(url if url.startswith('http') else f'https://{url}')
                domain = parsed.hostname
                if domain:
                    save_recent_search(domain, url)
                    prefill_domain = domain
                    # Perform SSL check with just the domain
                    ssl_results = SSLAnalyzer.check_ssl_certificate(domain)
                else:
                    # If no hostname found, try the original URL
                    ssl_results = SSLAnalyzer.check_ssl_certificate(url)
            except:
                # Fallback: try the original URL
                ssl_results = SSLAnalyzer.check_ssl_certificate(url)
            
            recent_searches = get_recent_searches(10)  # Refresh recent searches
    
    return render_template('sslchecker.html', 
                         recent_searches=recent_searches, 
                         ssl_results=ssl_results,
                         prefill_domain=prefill_domain)

@ssl_security_bp.route('/sslchecker/<domain>')
def ssl_checker_domain(domain):
    """SSL Certificate Checker for specific domain"""
    recent_searches = get_recent_searches(10)
    
    # Automatically check the domain (pass just the domain, not the full URL)
    ssl_results = SSLAnalyzer.check_ssl_certificate(domain)
    
    # Save to recent searches
    save_recent_search(domain, f'https://{domain}')
    recent_searches = get_recent_searches(10)  # Refresh recent searches
    
    return render_template('sslchecker.html', 
                         recent_searches=recent_searches, 
                         ssl_results=ssl_results,
                         prefill_domain=domain)

@ssl_security_bp.route('/deep-ssl-checker', methods=['GET', 'POST'])
def deep_ssl_checker():
    """Deep SSL Checker tool page"""
    from datetime import datetime
    
    recent_searches = get_recent_searches(10)
    ssl_results = None
    hostname = None
    assessment_time = None
    
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
                    # Perform basic SSL analysis with just the domain
                    ssl_results = SSLAnalyzer.check_ssl_certificate(domain)
                else:
                    # If no hostname found, try the original hostname
                    ssl_results = SSLAnalyzer.check_ssl_certificate(hostname)
            except:
                # Fallback: try the original hostname
                ssl_results = SSLAnalyzer.check_ssl_certificate(hostname)
            
            # Get current time for assessment
            assessment_time = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S')
    
    return render_template('deep-ssl-checker.html', 
                         recent_searches=recent_searches,
                         ssl_results=ssl_results,
                         hostname=hostname,
                         assessment_time=assessment_time)

@ssl_security_bp.route('/deep-ssl-checker/<domain>')
def deep_ssl_checker_domain(domain):
    """Deep SSL Checker for specific domain"""
    from datetime import datetime
    
    recent_searches = get_recent_searches(10)
    
    # Automatically check the domain (pass just the domain, not the full URL)
    ssl_results = SSLAnalyzer.check_ssl_certificate(domain)
    
    # Save to recent searches
    save_recent_search(domain, f'https://{domain}')
    recent_searches = get_recent_searches(10)  # Refresh recent searches
    
    # Get current time for assessment
    assessment_time = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S')
    
    return render_template('deep-ssl-checker.html', 
                         recent_searches=recent_searches,
                         ssl_results=ssl_results,
                         hostname=domain,
                         assessment_time=assessment_time)

@ssl_security_bp.route('/csr-decoder')
def csr_decoder():
    """CSR Decoder tool page"""
    return render_template('csr-decoder.html')

@ssl_security_bp.route('/certificate-decoder')
def certificate_decoder():
    """Certificate Decoder tool page"""
    return render_template('certificate-decoder.html')

@ssl_security_bp.route('/certificate-key-matcher')
def certificate_key_matcher():
    """Certificate Key Matcher tool page"""
    return render_template('certificate-key-matcher.html')

@ssl_security_bp.route('/ssl-converter')
def ssl_converter():
    """SSL Converter tool page"""
    return render_template('ssl-converter.html')

# API Routes for SSL & Security
@ssl_security_bp.route('/api/ssl/check', methods=['POST'])
def ssl_check_api():
    """SSL check API endpoint"""
    data = request.get_json()
    url = data.get('url', '').strip()
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    try:
        # Add protocol if missing
        if not url.startswith(('http://', 'https://')):
            url = f'https://{url}'
        
        result = SSLAnalyzer.check_ssl_certificate(url)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@ssl_security_bp.route('/api/ssl/deep-analysis', methods=['POST'])
def deep_ssl_analysis_api():
    """Deep SSL analysis API endpoint"""
    data = request.get_json()
    hostname = data.get('hostname', '').strip()
    
    if not hostname:
        return jsonify({'error': 'Hostname is required'}), 400
    
    try:
        # Perform deep SSL analysis
        deep_results = SSLDeepAnalyzer.analyze_ssl_security(hostname)
        return jsonify(deep_results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@ssl_security_bp.route('/api/ssl/csr-decode', methods=['POST'])
def csr_decode_api():
    """CSR decode API endpoint"""
    data = request.get_json()
    csr_text = data.get('csr', '').strip()
    
    if not csr_text:
        return jsonify({'error': 'CSR is required'}), 400
    
    try:
        result = CSRDecoder.decode_csr(csr_text)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
