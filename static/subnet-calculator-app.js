// IP Subnet Calculator Vue.js Application
const { createApp } = Vue;

createApp({
    data() {
        return {
            // IPv4 Calculator
            ipv4Address: '',
            ipv4Subnet: '',
            ipv4Custom: '',
            ipv4Results: null,
            isLoadingIPv4: false,
            
            // IPv6 Calculator
            ipv6Address: '',
            ipv6Prefix: '',
            ipv6Results: null,
            isLoadingIPv6: false,
            
            // Error handling
            error: null
        }
    },
    
    methods: {
        // IPv4 Calculator
        async calculateIPv4() {
            if (!this.ipv4Address.trim()) {
                this.showError('Please enter an IPv4 address');
                return;
            }
            
            let cidr = null;
            if (this.ipv4Custom) {
                cidr = parseInt(this.ipv4Custom);
                if (cidr < 0 || cidr > 32) {
                    this.showError('CIDR must be between 0 and 32');
                    return;
                }
            } else if (this.ipv4Subnet) {
                cidr = parseInt(this.ipv4Subnet.replace('/', ''));
            } else {
                this.showError('Please select a subnet mask or enter a custom CIDR');
                return;
            }
            
            this.isLoadingIPv4 = true;
            this.hideError();
            
            try {
                const response = await fetch('/api/subnet/ipv4', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        ip_address: this.ipv4Address,
                        cidr: cidr
                    })
                });
                
                this.ipv4Results = await response.json();
                
                if (this.ipv4Results.success) {
                    this.showIPv4Results();
                } else {
                    this.showError(this.ipv4Results.error);
                }
            } catch (error) {
                this.showError('Network error: ' + error.message);
            } finally {
                this.isLoadingIPv4 = false;
            }
        },
        
        // IPv6 Calculator
        async calculateIPv6() {
            if (!this.ipv6Address.trim()) {
                this.showError('Please enter an IPv6 address');
                return;
            }
            
            if (!this.ipv6Prefix) {
                this.showError('Please select a prefix length');
                return;
            }
            
            const prefixLength = parseInt(this.ipv6Prefix.replace('/', ''));
            
            this.isLoadingIPv6 = true;
            this.hideError();
            
            try {
                const response = await fetch('/api/subnet/ipv6', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        ip_address: this.ipv6Address,
                        prefix_length: prefixLength
                    })
                });
                
                this.ipv6Results = await response.json();
                
                if (this.ipv6Results.success) {
                    this.showIPv6Results();
                } else {
                    this.showError(this.ipv6Results.error);
                }
            } catch (error) {
                this.showError('Network error: ' + error.message);
            } finally {
                this.isLoadingIPv6 = false;
            }
        },
        
        // Show IPv4 Results
        showIPv4Results() {
            document.getElementById('ipv4-results-section').classList.remove('d-none');
            document.getElementById('ipv6-results-section').classList.add('d-none');
            document.getElementById('error-section').classList.add('d-none');
            
            // Populate results
            const resultsDiv = document.getElementById('ipv4-results');
            const data = this.ipv4Results;
            
            resultsDiv.innerHTML = `
                <div class="row">
                    <div class="col-md-6">
                        <h6 class="text-primary">Input Information</h6>
                        <table class="table table-sm">
                            <tr><td><strong>IP Address:</strong></td><td>${data.input.ip_address}</td></tr>
                            <tr><td><strong>Subnet Mask:</strong></td><td>${data.network_info.subnet_mask}</td></tr>
                            <tr><td><strong>CIDR Notation:</strong></td><td>${data.network_info.cidr_notation}</td></tr>
                            <tr><td><strong>IP Class:</strong></td><td>${data.network_info.ip_class}</td></tr>
                        </table>
                    </div>
                    <div class="col-md-6">
                        <h6 class="text-primary">Network Information</h6>
                        <table class="table table-sm">
                            <tr><td><strong>Network Address:</strong></td><td>${data.network_info.network_address}</td></tr>
                            <tr><td><strong>Broadcast Address:</strong></td><td>${data.network_info.broadcast_address}</td></tr>
                            <tr><td><strong>Wildcard Mask:</strong></td><td>${data.network_info.wildcard_mask}</td></tr>
                        </table>
                    </div>
                </div>
                
                <div class="row mt-3">
                    <div class="col-md-6">
                        <h6 class="text-primary">Host Information</h6>
                        <table class="table table-sm">
                            <tr><td><strong>Total Hosts:</strong></td><td>${data.host_info.total_hosts.toLocaleString()}</td></tr>
                            <tr><td><strong>Usable Hosts:</strong></td><td>${data.host_info.usable_hosts.toLocaleString()}</td></tr>
                            <tr><td><strong>First Host:</strong></td><td>${data.host_info.first_host}</td></tr>
                            <tr><td><strong>Last Host:</strong></td><td>${data.host_info.last_host}</td></tr>
                        </table>
                    </div>
                    <div class="col-md-6">
                        <h6 class="text-primary">Binary Representations</h6>
                        <table class="table table-sm">
                            <tr><td><strong>IP Address:</strong></td><td><code>${data.binary_info.ip_binary}</code></td></tr>
                            <tr><td><strong>Subnet Mask:</strong></td><td><code>${data.binary_info.subnet_binary}</code></td></tr>
                            <tr><td><strong>Network:</strong></td><td><code>${data.binary_info.network_binary}</code></td></tr>
                        </table>
                    </div>
                </div>
            `;
        },
        
        // Show IPv6 Results
        showIPv6Results() {
            document.getElementById('ipv6-results-section').classList.remove('d-none');
            document.getElementById('ipv4-results-section').classList.add('d-none');
            document.getElementById('error-section').classList.add('d-none');
            
            // Populate results
            const resultsDiv = document.getElementById('ipv6-results');
            const data = this.ipv6Results;
            
            resultsDiv.innerHTML = `
                <div class="row">
                    <div class="col-md-6">
                        <h6 class="text-primary">Input Information</h6>
                        <table class="table table-sm">
                            <tr><td><strong>IPv6 Address:</strong></td><td>${data.input.ip_address}</td></tr>
                            <tr><td><strong>Prefix Length:</strong></td><td>${data.network_info.prefix_length}</td></tr>
                            <tr><td><strong>CIDR Notation:</strong></td><td>${data.network_info.cidr_notation}</td></tr>
                        </table>
                    </div>
                    <div class="col-md-6">
                        <h6 class="text-primary">Network Information</h6>
                        <table class="table table-sm">
                            <tr><td><strong>Network Address:</strong></td><td>${data.network_info.network_address}</td></tr>
                            <tr><td><strong>Broadcast Address:</strong></td><td>${data.network_info.broadcast_address}</td></tr>
                        </table>
                    </div>
                </div>
                
                <div class="row mt-3">
                    <div class="col-md-6">
                        <h6 class="text-primary">Host Information</h6>
                        <table class="table table-sm">
                            <tr><td><strong>Total Hosts:</strong></td><td>${data.host_info.total_hosts.toLocaleString()}</td></tr>
                            <tr><td><strong>Usable Hosts:</strong></td><td>${data.host_info.usable_hosts.toLocaleString()}</td></tr>
                            <tr><td><strong>First Host:</strong></td><td>${data.host_info.first_host}</td></tr>
                            <tr><td><strong>Last Host:</strong></td><td>${data.host_info.last_host}</td></tr>
                        </table>
                    </div>
                    <div class="col-md-6">
                        <h6 class="text-primary">Binary Representations</h6>
                        <table class="table table-sm">
                            <tr><td><strong>IPv6 Address:</strong></td><td><code>${data.binary_info.ip_binary}</code></td></tr>
                            <tr><td><strong>Network:</strong></td><td><code>${data.binary_info.network_binary}</code></td></tr>
                        </table>
                    </div>
                </div>
            `;
        },
        
        // Error handling
        showError(message) {
            this.error = message;
            document.getElementById('error-message').textContent = message;
            document.getElementById('error-section').classList.remove('d-none');
            document.getElementById('ipv4-results-section').classList.add('d-none');
            document.getElementById('ipv6-results-section').classList.add('d-none');
        },
        
        hideError() {
            this.error = null;
            document.getElementById('error-section').classList.add('d-none');
        },
        
        // Clear forms
        clearIPv4() {
            this.ipv4Address = '';
            this.ipv4Subnet = '';
            this.ipv4Custom = '';
            this.ipv4Results = null;
            document.getElementById('ipv4-results-section').classList.add('d-none');
        },
        
        clearIPv6() {
            this.ipv6Address = '';
            this.ipv6Prefix = '';
            this.ipv6Results = null;
            document.getElementById('ipv6-results-section').classList.add('d-none');
        }
    },
    
    mounted() {
        console.log('IP Subnet Calculator Vue app mounted');
        
        // Set up form event listeners
        document.getElementById('ipv4-calculator-form').addEventListener('submit', (e) => {
            e.preventDefault();
            this.calculateIPv4();
        });
        
        document.getElementById('ipv6-calculator-form').addEventListener('submit', (e) => {
            e.preventDefault();
            this.calculateIPv6();
        });
    }
}).mount('#subnet-calculator-app');
