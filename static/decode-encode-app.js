// Decode/Encode Tool Vue.js Application
const { createApp } = Vue;

createApp({
    data() {
        return {
            // Base64
            base64Input: '',
            base64EncodeResult: null,
            base64DecodeResult: null,
            isLoadingBase64: false,
            
            // URL
            urlInput: '',
            urlEncodeResult: null,
            urlDecodeResult: null,
            isLoadingUrl: false,
            
            // HTML
            htmlInput: '',
            htmlEncodeResult: null,
            htmlDecodeResult: null,
            isLoadingHtml: false,
            
            // Hex
            hexInput: '',
            hexEncodeResult: null,
            hexDecodeResult: null,
            isLoadingHex: false,
            
            // Binary
            binaryInput: '',
            binaryEncodeResult: null,
            binaryDecodeResult: null,
            isLoadingBinary: false,
            
            // All formats
            allFormatsText: '',
            allResults: null,
            isProcessingAll: false
        }
    },
    
    methods: {
        // Base64 methods
        async encodeBase64() {
            if (!this.base64Input.trim()) {
                alert('Please enter text to encode');
                return;
            }
            
            this.isLoadingBase64 = true;
            try {
                const response = await fetch('/api/decode/base64-encode', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ text: this.base64Input })
                });
                
                this.base64EncodeResult = await response.json();
            } catch (error) {
                this.base64EncodeResult = {
                    success: false,
                    error: 'Network error: ' + error.message
                };
            } finally {
                this.isLoadingBase64 = false;
            }
        },
        
        async decodeBase64() {
            if (!this.base64Input.trim()) {
                alert('Please enter Base64 text to decode');
                return;
            }
            
            this.isLoadingBase64 = true;
            try {
                const response = await fetch('/api/decode/base64-decode', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ text: this.base64Input })
                });
                
                this.base64DecodeResult = await response.json();
            } catch (error) {
                this.base64DecodeResult = {
                    success: false,
                    error: 'Network error: ' + error.message
                };
            } finally {
                this.isLoadingBase64 = false;
            }
        },
        
        // URL methods
        async encodeUrl() {
            if (!this.urlInput.trim()) {
                alert('Please enter text to encode');
                return;
            }
            
            this.isLoadingUrl = true;
            try {
                const response = await fetch('/api/decode/url-encode', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ text: this.urlInput })
                });
                
                this.urlEncodeResult = await response.json();
            } catch (error) {
                this.urlEncodeResult = {
                    success: false,
                    error: 'Network error: ' + error.message
                };
            } finally {
                this.isLoadingUrl = false;
            }
        },
        
        async decodeUrl() {
            if (!this.urlInput.trim()) {
                alert('Please enter URL encoded text to decode');
                return;
            }
            
            this.isLoadingUrl = true;
            try {
                const response = await fetch('/api/decode/url-decode', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ text: this.urlInput })
                });
                
                this.urlDecodeResult = await response.json();
            } catch (error) {
                this.urlDecodeResult = {
                    success: false,
                    error: 'Network error: ' + error.message
                };
            } finally {
                this.isLoadingUrl = false;
            }
        },
        
        // HTML methods
        async encodeHtml() {
            if (!this.htmlInput.trim()) {
                alert('Please enter text to encode');
                return;
            }
            
            this.isLoadingHtml = true;
            try {
                const response = await fetch('/api/decode/html-encode', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ text: this.htmlInput })
                });
                
                this.htmlEncodeResult = await response.json();
            } catch (error) {
                this.htmlEncodeResult = {
                    success: false,
                    error: 'Network error: ' + error.message
                };
            } finally {
                this.isLoadingHtml = false;
            }
        },
        
        async decodeHtml() {
            if (!this.htmlInput.trim()) {
                alert('Please enter HTML encoded text to decode');
                return;
            }
            
            this.isLoadingHtml = true;
            try {
                const response = await fetch('/api/decode/html-decode', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ text: this.htmlInput })
                });
                
                this.htmlDecodeResult = await response.json();
            } catch (error) {
                this.htmlDecodeResult = {
                    success: false,
                    error: 'Network error: ' + error.message
                };
            } finally {
                this.isLoadingHtml = false;
            }
        },
        
        // Hex methods
        async encodeHex() {
            if (!this.hexInput.trim()) {
                alert('Please enter text to encode');
                return;
            }
            
            this.isLoadingHex = true;
            try {
                const response = await fetch('/api/decode/hex-encode', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ text: this.hexInput })
                });
                
                this.hexEncodeResult = await response.json();
            } catch (error) {
                this.hexEncodeResult = {
                    success: false,
                    error: 'Network error: ' + error.message
                };
            } finally {
                this.isLoadingHex = false;
            }
        },
        
        async decodeHex() {
            if (!this.hexInput.trim()) {
                alert('Please enter hexadecimal text to decode');
                return;
            }
            
            this.isLoadingHex = true;
            try {
                const response = await fetch('/api/decode/hex-decode', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ text: this.hexInput })
                });
                
                this.hexDecodeResult = await response.json();
            } catch (error) {
                this.hexDecodeResult = {
                    success: false,
                    error: 'Network error: ' + error.message
                };
            } finally {
                this.isLoadingHex = false;
            }
        },
        
        // Binary methods
        async encodeBinary() {
            if (!this.binaryInput.trim()) {
                alert('Please enter text to encode');
                return;
            }
            
            this.isLoadingBinary = true;
            try {
                const response = await fetch('/api/decode/binary-encode', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ text: this.binaryInput })
                });
                
                this.binaryEncodeResult = await response.json();
            } catch (error) {
                this.binaryEncodeResult = {
                    success: false,
                    error: 'Network error: ' + error.message
                };
            } finally {
                this.isLoadingBinary = false;
            }
        },
        
        async decodeBinary() {
            if (!this.binaryInput.trim()) {
                alert('Please enter binary text to decode');
                return;
            }
            
            this.isLoadingBinary = true;
            try {
                const response = await fetch('/api/decode/binary-decode', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ text: this.binaryInput })
                });
                
                this.binaryDecodeResult = await response.json();
            } catch (error) {
                this.binaryDecodeResult = {
                    success: false,
                    error: 'Network error: ' + error.message
                };
            } finally {
                this.isLoadingBinary = false;
            }
        },
        
        // Process all formats
        async processAllFormats() {
            if (!this.allFormatsText.trim()) {
                alert('Please enter text to process');
                return;
            }
            
            this.isProcessingAll = true;
            this.allResults = null;
            
            try {
                const response = await fetch('/api/decode/process-all', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ text: this.allFormatsText })
                });
                
                this.allResults = await response.json();
            } catch (error) {
                this.allResults = {
                    error: 'Network error: ' + error.message
                };
            } finally {
                this.isProcessingAll = false;
            }
        },
        
        // Clear all results
        clearAllResults() {
            this.base64EncodeResult = null;
            this.base64DecodeResult = null;
            this.urlEncodeResult = null;
            this.urlDecodeResult = null;
            this.htmlEncodeResult = null;
            this.htmlDecodeResult = null;
            this.hexEncodeResult = null;
            this.hexDecodeResult = null;
            this.binaryEncodeResult = null;
            this.binaryDecodeResult = null;
            this.allResults = null;
        }
    },
    
    mounted() {
        console.log('Decode/Encode Tool Vue app mounted');
    }
}).mount('#decode-encode-app');
