"""
SSL & Security Routes
Handles SSL checker, deep SSL checker, CSR decoder, and certificate tools
"""

from flask import Blueprint, render_template, request, jsonify
from datetime import datetime
from modules.ssl_analyzer import SSLAnalyzer, SSLDeepAnalyzer, CSRDecoder, CertificateDecoder, CertificateKeyMatcher, SSLConverter
from modules.ssl_bulk_checker import SSLBulkChecker
from modules.ocsp_checker import OCSPChecker
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
    
    # Fetch domain description
    domain_info = SSLAnalyzer.fetch_domain_description(prefill_domain) if prefill_domain else None
    
    return render_template('sslchecker.html', 
                         recent_searches=recent_searches, 
                         ssl_results=ssl_results,
                         prefill_domain=prefill_domain,
                         domain_info=domain_info)

@ssl_security_bp.route('/sslchecker/<domain>')
def ssl_checker_domain(domain):
    """SSL Certificate Checker for specific domain"""
    recent_searches = get_recent_searches(10)
    
    # Automatically check the domain (pass just the domain, not the full URL)
    ssl_results = SSLAnalyzer.check_ssl_certificate(domain)
    
    # Save to recent searches
    save_recent_search(domain, f'https://{domain}')
    recent_searches = get_recent_searches(10)  # Refresh recent searches
    
    # Fetch domain description
    domain_info = SSLAnalyzer.fetch_domain_description(domain)
    
    return render_template('sslchecker.html', 
                         recent_searches=recent_searches, 
                         ssl_results=ssl_results,
                         prefill_domain=domain,
                         domain_info=domain_info)

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
    
    # Fetch domain description
    domain_info = SSLAnalyzer.fetch_domain_description(hostname) if hostname else None
    
    return render_template('deep-ssl-checker.html', 
                         recent_searches=recent_searches,
                         ssl_results=ssl_results,
                         hostname=hostname,
                         assessment_time=assessment_time,
                         domain_info=domain_info)

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
    
    # Fetch domain description
    domain_info = SSLAnalyzer.fetch_domain_description(domain)
    
    return render_template('deep-ssl-checker.html', 
                         recent_searches=recent_searches,
                         ssl_results=ssl_results,
                         hostname=domain,
                         assessment_time=assessment_time,
                         domain_info=domain_info)

@ssl_security_bp.route('/csr-decoder', methods=['GET', 'POST'])
def csr_decoder():
    """CSR Decoder tool page"""
    if request.method == 'POST':
        csr = request.form.get('csr', '').strip()
        
        if not csr:
            return render_template('csr-decoder.html', 
                                 csr=csr,
                                 csr_result={'success': False, 'error': 'CSR is required'})
        
        try:
            # Decode the CSR
            result = CSRDecoder.decode_csr(csr)
            return render_template('csr-decoder.html', 
                                 csr=csr,
                                 csr_result=result)
        except Exception as e:
            return render_template('csr-decoder.html', 
                                 csr=csr,
                                 csr_result={'success': False, 'error': str(e)})
    
    return render_template('csr-decoder.html')

@ssl_security_bp.route('/certificate-decoder', methods=['GET', 'POST'])
def certificate_decoder():
    """Certificate Decoder tool page"""
    if request.method == 'POST':
        certificate = request.form.get('certificate', '').strip()
        
        if not certificate:
            return render_template('certificate-decoder.html', 
                                 certificate=certificate,
                                 certificate_result={'success': False, 'error': 'Certificate is required'})
        
        try:
            # Decode the certificate
            result = CertificateDecoder.decode_certificate(certificate)
            return render_template('certificate-decoder.html', 
                                 certificate=certificate,
                                 certificate_result=result)
        except Exception as e:
            return render_template('certificate-decoder.html', 
                                 certificate=certificate,
                                 certificate_result={'success': False, 'error': str(e)})
    
    return render_template('certificate-decoder.html')

@ssl_security_bp.route('/certificate-key-matcher', methods=['GET', 'POST'])
def certificate_key_matcher():
    """Certificate Key Matcher tool page"""
    if request.method == 'POST':
        certificate = request.form.get('certificate', '').strip()
        private_key = request.form.get('private_key', '').strip()
        
        if not certificate or not private_key:
            return render_template('certificate-key-matcher.html', 
                                 certificate=certificate,
                                 private_key=private_key,
                                 match_result={'success': False, 'error': 'Both certificate and private key are required'})
        
        try:
            # Match the certificate and key
            result = CertificateKeyMatcher.match_certificate_key(certificate, private_key)
            return render_template('certificate-key-matcher.html', 
                                 certificate=certificate,
                                 private_key=private_key,
                                 match_result=result)
        except Exception as e:
            return render_template('certificate-key-matcher.html', 
                                 certificate=certificate,
                                 private_key=private_key,
                                 match_result={'success': False, 'error': str(e)})
    
    return render_template('certificate-key-matcher.html')

@ssl_security_bp.route('/api/ssl/certificate-key-match', methods=['POST'])
def certificate_key_match_api():
    """API endpoint for certificate key matching"""
    try:
        data = request.get_json()
        certificate = data.get('certificate', '').strip()
        private_key = data.get('private_key', '').strip()
        
        if not certificate or not private_key:
            return jsonify({
                'success': False,
                'error': 'Both certificate and private key are required'
            }), 400
        
        # Match the certificate and key
        result = CertificateKeyMatcher.match_certificate_key(certificate, private_key)
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@ssl_security_bp.route('/ssl-converter', methods=['GET', 'POST'])
def ssl_converter():
    """SSL Converter tool page"""
    if request.method == 'POST':
        input_format = request.form.get('input_format', '').strip()
        output_format = request.form.get('output_format', '').strip()
        input_data = request.form.get('input_data', '').strip()
        password = request.form.get('password', '').strip() or None
        conversion_type = request.form.get('conversion_type', 'certificate')
        
        if not input_format or not output_format or not input_data:
            return render_template('ssl-converter.html', 
                                 input_format=input_format,
                                 output_format=output_format,
                                 input_data=input_data,
                                 password=password,
                                 conversion_type=conversion_type,
                                 conversion_result={'success': False, 'error': 'All fields are required'})
        
        try:
            if conversion_type == 'certificate':
                result = SSLConverter.convert_certificate(input_data, input_format, output_format, password)
            elif conversion_type == 'private_key':
                result = SSLConverter.convert_private_key(input_data, input_format, output_format, password)
            elif conversion_type == 'both':
                key_data = request.form.get('key_data', '').strip()
                if not key_data:
                    return render_template('ssl-converter.html', 
                                         input_format=input_format,
                                         output_format=output_format,
                                         input_data=input_data,
                                         key_data=key_data,
                                         password=password,
                                         conversion_type=conversion_type,
                                         conversion_result={'success': False, 'error': 'Both certificate and private key are required for combined conversion'})
                result = SSLConverter.convert_certificate_and_key(input_data, key_data, input_format, output_format, password)
            else:
                result = {'success': False, 'error': 'Invalid conversion type'}
            
            return render_template('ssl-converter.html', 
                                 input_format=input_format,
                                 output_format=output_format,
                                 input_data=input_data,
                                 key_data=request.form.get('key_data', ''),
                                 password=password,
                                 conversion_type=conversion_type,
                                 conversion_result=result)
        except Exception as e:
            return render_template('ssl-converter.html', 
                                 input_format=input_format,
                                 output_format=output_format,
                                 input_data=input_data,
                                 key_data=request.form.get('key_data', ''),
                                 password=password,
                                 conversion_type=conversion_type,
                                 conversion_result={'success': False, 'error': str(e)})
    
    return render_template('ssl-converter.html', 
                         input_format='',
                         output_format='',
                         input_data='',
                         key_data='',
                         password='',
                         conversion_type='certificate',
                         conversion_result=None)

@ssl_security_bp.route('/api/ssl/convert', methods=['POST'])
def ssl_convert_api():
    """SSL converter API endpoint"""
    try:
        data = request.get_json()
        input_format = data.get('input_format', '').strip()
        output_format = data.get('output_format', '').strip()
        input_data = data.get('input_data', '').strip()
        password = data.get('password', '').strip() or None
        conversion_type = data.get('conversion_type', 'certificate')
        
        if not input_format or not output_format or not input_data:
            return jsonify({
                'success': False,
                'error': 'All fields are required'
            }), 400
        
        if conversion_type == 'certificate':
            result = SSLConverter.convert_certificate(input_data, input_format, output_format, password)
        elif conversion_type == 'private_key':
            result = SSLConverter.convert_private_key(input_data, input_format, output_format, password)
        elif conversion_type == 'both':
            key_data = data.get('key_data', '').strip()
            if not key_data:
                return jsonify({
                    'success': False,
                    'error': 'Both certificate and private key are required for combined conversion'
                }), 400
            result = SSLConverter.convert_certificate_and_key(input_data, key_data, input_format, output_format, password)
        else:
            result = {'success': False, 'error': 'Invalid conversion type'}
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

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

@ssl_security_bp.route('/api/ssl/certificate-decode', methods=['POST'])
def certificate_decode_api():
    """Certificate decoder API endpoint"""
    data = request.get_json()
    certificate = data.get('certificate', '').strip()
    
    if not certificate:
        return jsonify({'error': 'Certificate is required'}), 400
    
    try:
        # Decode the certificate
        result = CertificateDecoder.decode_certificate(certificate)
        
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@ssl_security_bp.route('/ssl-bulk-checker', methods=['GET', 'POST'])
def ssl_bulk_checker():
    """SSL Bulk Checker tool page"""
    bulk_results = None
    hostnames_input = ""
    
    if request.method == 'POST':
        hostnames_input = request.form.get('hostnames', '').strip()
        if hostnames_input:
            # Parse hostnames from input
            hostnames = SSLBulkChecker.parse_hostnames_input(hostnames_input)
            
            if hostnames:
                # Perform bulk SSL check
                bulk_checker = SSLBulkChecker()
                bulk_results = bulk_checker.check_bulk_ssl(hostnames)
            else:
                bulk_results = {
                    'success': False,
                    'error': 'No valid hostnames found in input',
                    'results': [],
                    'summary': {
                        'total': 0,
                        'valid': 0,
                        'errors': 0,
                        'checked_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
                    }
                }
    
    return render_template('ssl-bulk-checker.html', 
                         bulk_results=bulk_results,
                         hostnames_input=hostnames_input)

@ssl_security_bp.route('/api/ssl-bulk-checker', methods=['POST'])
def api_ssl_bulk_checker():
    """API endpoint for SSL bulk checker"""
    try:
        data = request.get_json()
        hostnames_input = data.get('hostnames', '')
        
        if not hostnames_input:
            return jsonify({'error': 'No hostnames provided'}), 400
        
        # Parse hostnames from input
        hostnames = SSLBulkChecker.parse_hostnames_input(hostnames_input)
        
        if not hostnames:
            return jsonify({'error': 'No valid hostnames found'}), 400
        
        # Perform bulk SSL check
        bulk_checker = SSLBulkChecker()
        result = bulk_checker.check_bulk_ssl(hostnames)
        
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@ssl_security_bp.route('/ocsp-checker', methods=['GET', 'POST'])
def ocsp_checker():
    """OCSP Status Checker tool page"""
    ocsp_results = None
    certificate_input = ""
    
    if request.method == 'POST':
        certificate_input = request.form.get('certificate', '').strip()
        if certificate_input:
            # Validate certificate input
            validation = OCSPChecker.validate_certificate_input(certificate_input)
            if not validation['valid']:
                ocsp_results = {
                    'success': False,
                    'error': validation['error'],
                    'certificate_info': None,
                    'ocsp_url': None,
                    'ocsp_status': None,
                    'checked_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
                }
            else:
                # Perform OCSP check
                ocsp_checker = OCSPChecker()
                ocsp_results = ocsp_checker.check_ocsp_status(certificate_input)
    
    return render_template('ocsp-checker.html', 
                         ocsp_results=ocsp_results,
                         certificate_input=certificate_input)

@ssl_security_bp.route('/api/ocsp-checker', methods=['POST'])
def api_ocsp_checker():
    """API endpoint for OCSP checker"""
    try:
        data = request.get_json()
        certificate = data.get('certificate', '')
        
        if not certificate:
            return jsonify({'error': 'Certificate is required'}), 400
        
        # Validate certificate input
        validation = OCSPChecker.validate_certificate_input(certificate)
        if not validation['valid']:
            return jsonify({'error': validation['error']}), 400
        
        # Perform OCSP check
        ocsp_checker = OCSPChecker()
        result = ocsp_checker.check_ocsp_status(certificate)
        
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

