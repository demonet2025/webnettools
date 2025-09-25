"""
Decode/Encode Module
Handles various text encoding and decoding operations
"""

import base64
import urllib.parse
import html
import json
import re


class DecodeEncoder:
    """Comprehensive Decode/Encode Tool for various formats"""

    @staticmethod
    def detect_format_and_operation(text):
        """Detect the most likely format type and operation based on input text"""
        if not text or not text.strip():
            return {'format_type': '', 'operation': '', 'confidence': 0}
        
        text = text.strip()
        confidence = 0
        detected_format = ''
        detected_operation = ''
        
        # Base64 detection
        if re.match(r'^[A-Za-z0-9+/]*={0,2}$', text) and len(text) % 4 == 0:
            try:
                # Try to decode to see if it's valid Base64
                base64.b64decode(text + '==')  # Add padding if needed
                detected_format = 'base64'
                detected_operation = 'decode'
                confidence = 90
            except:
                pass
        
        # URL encoding detection
        if '%' in text and re.search(r'%[0-9A-Fa-f]{2}', text):
            detected_format = 'url'
            detected_operation = 'decode'
            confidence = 85
        
        # HTML entities detection
        if '&' in text and (';' in text or re.search(r'&[a-zA-Z]+;', text) or re.search(r'&#\d+;', text)):
            detected_format = 'html'
            detected_operation = 'decode'
            confidence = 80
        
        # Hexadecimal detection
        if re.match(r'^[0-9A-Fa-f\s]+$', text.replace(' ', '')) and len(text.replace(' ', '')) % 2 == 0:
            detected_format = 'hex'
            detected_operation = 'decode'
            confidence = 75
        
        # Binary detection
        if re.match(r'^[01\s]+$', text) and len(text.replace(' ', '')) % 8 == 0:
            detected_format = 'binary'
            detected_operation = 'decode'
            confidence = 70
        
        # JSON detection
        if (text.startswith('{') and text.endswith('}')) or (text.startswith('[') and text.endswith(']')):
            try:
                json.loads(text)
                detected_format = 'json'
                detected_operation = 'encode'  # Format JSON
                confidence = 95
            except:
                pass
        
        # If no specific format detected, check if it looks like plain text
        if not detected_format and re.match(r'^[a-zA-Z0-9\s.,!?@#$%^&*()_+\-=\[\]{}|;:"\'<>?/~`]+$', text):
            # Plain text - suggest encoding
            detected_format = 'base64'  # Default to Base64 for plain text
            detected_operation = 'encode'
            confidence = 60
        
        return {
            'format_type': detected_format,
            'operation': detected_operation,
            'confidence': confidence
        }

    @staticmethod
    def base64_encode(text):
        """Encode text to Base64"""
        try:
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
