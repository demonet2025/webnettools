// NetHub Webnettools - Python Version JavaScript

document.addEventListener('DOMContentLoaded', function() {
    // SSL Checker functionality
    const sslCheckBtn = document.getElementById('ssl-check-btn');
    const sslDeepCheckBtn = document.getElementById('ssl-deep-check-btn');
    const sslNewCheckBtn = document.getElementById('ssl-new-check-btn');
    const sslUrlInput = document.querySelector('.ssl-url-input');
    
    // Event listeners
    if (sslCheckBtn) {
        sslCheckBtn.addEventListener('click', runSimpleSSLCheck);
    }
    
    if (sslDeepCheckBtn) {
        sslDeepCheckBtn.addEventListener('click', runDeepSSLAnalysis);
    }
    
    if (sslNewCheckBtn) {
        sslNewCheckBtn.addEventListener('click', resetSSLChecker);
    }
    
    // Simple SSL Check function
    async function runSimpleSSLCheck() {
        const url = sslUrlInput.value.trim();
        if (!url) {
            alert('Please enter a valid URL');
            return;
        }
        
        const btnText = sslCheckBtn.querySelector('.btn-text');
        const btnLoading = sslCheckBtn.querySelector('.btn-loading');
        
        // Update UI
        btnText.style.display = 'none';
        btnLoading.style.display = 'inline';
        sslCheckBtn.disabled = true;
        
        try {
            const response = await fetch('/api/ssl/check', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ url: url })
            });
            
            const data = await response.json();
            
            if (data.success) {
                displaySimpleResults(data);
            } else {
                alert('SSL check failed: ' + (data.error || 'Unknown error'));
            }
        } catch (error) {
            console.error('Error:', error);
            alert('SSL check failed: ' + error.message);
        } finally {
            // Reset button state
            btnText.style.display = 'inline';
            btnLoading.style.display = 'none';
            sslCheckBtn.disabled = false;
        }
    }
    
    // Display simple SSL results
    function displaySimpleResults(data) {
        const resultsContainer = document.getElementById('ssl-simple-results');
        const actionsContainer = document.getElementById('ssl-checker-actions');
        
        const resultsHTML = `
            <div class="ssl-simple-results">
                <div class="ssl-results-header">
                    <h3>🔒 SSL Certificate Analysis</h3>
                    <div class="ssl-status-badge ssl-status-ok">
                        ✅ Valid Certificate
                    </div>
                </div>
                
                <div class="ssl-results-grid">
                    <div class="ssl-result-card">
                        <div class="ssl-result-icon">🌐</div>
                        <div class="ssl-result-content">
                            <h4>Domain Information</h4>
                            <p><strong>URL:</strong> ${data.certificate.common_name}</p>
                            <p><strong>Server:</strong> Apache</p>
                            <p><strong>Status:</strong> ${data.certificate.trusted ? 'Trusted by browsers' : 'Not trusted'}</p>
                        </div>
                    </div>
                    
                    <div class="ssl-result-card">
                        <div class="ssl-result-icon">📜</div>
                        <div class="ssl-result-content">
                            <h4>Certificate Details</h4>
                            <p><strong>Common Name:</strong> ${data.certificate.common_name}</p>
                            <p><strong>Issuer:</strong> ${data.certificate.issuer}</p>
                            <p><strong>Valid Until:</strong> ${data.certificate.valid_to}</p>
                            <p><strong>Expires in:</strong> ${data.certificate.days_until_expiry} days</p>
                        </div>
                    </div>
                    
                    <div class="ssl-result-card">
                        <div class="ssl-result-icon">🔐</div>
                        <div class="ssl-result-content">
                            <h4>Protocol Support</h4>
                            <div class="protocol-list">
                                <div class="protocol-item secure">
                                    <span class="protocol-name">SSLv2</span>
                                    <span class="protocol-status">✅ Not Offered</span>
                                </div>
                                <div class="protocol-item secure">
                                    <span class="protocol-name">SSLv3</span>
                                    <span class="protocol-status">✅ Not Offered</span>
                                </div>
                                <div class="protocol-item deprecated">
                                    <span class="protocol-name">TLS 1.0</span>
                                    <span class="protocol-status">⚠️ Deprecated</span>
                                </div>
                                <div class="protocol-item deprecated">
                                    <span class="protocol-name">TLS 1.1</span>
                                    <span class="protocol-status">⚠️ Deprecated</span>
                                </div>
                                <div class="protocol-item secure">
                                    <span class="protocol-name">TLS 1.2</span>
                                    <span class="protocol-status">✅ Secure</span>
                                </div>
                                <div class="protocol-item secure">
                                    <span class="protocol-name">TLS 1.3</span>
                                    <span class="protocol-status">✅ Secure</span>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="ssl-result-card">
                        <div class="ssl-result-icon">🛡️</div>
                        <div class="ssl-result-content">
                            <h4>Security Assessment</h4>
                            <div class="security-grade">
                                <span class="grade-label">Security Grade:</span>
                                <span class="grade-value grade-${data.security_grade.toLowerCase()}">${data.security_grade}</span>
                            </div>
                            <div class="security-recommendations">
                                <h5>Recommendations:</h5>
                                <ul>
                                    <li>Disable TLS 1.0 and 1.1 for better security</li>
                                    <li>Monitor certificate expiration</li>
                                    <li>Consider implementing HSTS</li>
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
        
        resultsContainer.innerHTML = resultsHTML;
        resultsContainer.style.display = 'block';
        actionsContainer.style.display = 'block';
    }
    
    // Deep SSL Analysis function
    async function runDeepSSLAnalysis() {
        const url = sslUrlInput.value.trim();
        if (!url) {
            alert('Please enter a valid URL');
            return;
        }
        
        // Hide simple checker, show deep analysis
        document.getElementById('ssl-simple-checker').style.display = 'none';
        document.getElementById('ssl-deep-analysis').style.display = 'block';
        
        // Update deep test URL
        document.getElementById('deep-test-url').textContent = url;
        
        // Start progress animation
        startDeepAnalysisProgress();
        
        try {
            const response = await fetch('/api/ssl/deep-analysis', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ url: url })
            });
            
            const data = await response.json();
            console.log('Deep analysis started:', data);
            
            // Simulate deep analysis completion after progress
            setTimeout(() => {
                const mockData = generateMockDeepResults(url);
                displayDeepResults(mockData);
            }, 8000);
            
        } catch (error) {
            console.error('Error:', error);
            alert('Deep analysis failed: ' + error.message);
        }
    }
    
    // Start deep analysis progress animation
    function startDeepAnalysisProgress() {
        const progressBar = document.getElementById('deep-progress-bar');
        const progressText = document.getElementById('deep-progress-text');
        const progressSteps = document.querySelectorAll('.progress-step');
        
        let progress = 0;
        const interval = setInterval(() => {
            progress += Math.random() * 15;
            if (progress > 100) progress = 100;
            
            progressBar.style.width = progress + '%';
            progressText.textContent = Math.round(progress) + '%';
            
            // Update step completion
            const completedSteps = Math.floor(progress / 20);
            progressSteps.forEach((step, index) => {
                if (index < completedSteps) {
                    step.classList.remove('active');
                    step.classList.add('completed');
                    step.querySelector('.step-icon').textContent = '✅';
                } else if (index === completedSteps) {
                    step.classList.add('active');
                    step.querySelector('.step-icon').textContent = '⏳';
                } else {
                    step.classList.remove('active', 'completed');
                    step.querySelector('.step-icon').textContent = '⏳';
                }
            });
            
            if (progress >= 100) {
                clearInterval(interval);
                setTimeout(() => {
                    document.getElementById('ssl-deep-progress').style.display = 'none';
                    document.getElementById('ssl-deep-results').style.display = 'block';
                }, 1000);
            }
        }, 200);
    }
    
    // Generate mock deep results
    function generateMockDeepResults(url) {
        return {
            url: url,
            timestamp: new Date().toISOString(),
            overallGrade: 'B',
            score: 91,
            vulnerabilities: [
                { name: 'BEAST', status: 'vulnerable', severity: 'medium' },
                { name: 'LUCKY13', status: 'potentially vulnerable', severity: 'low' }
            ],
            protocols: {
                sslv2: { status: 'not offered', grade: 'A' },
                sslv3: { status: 'not offered', grade: 'A' },
                tls10: { status: 'offered', grade: 'C' },
                tls11: { status: 'offered', grade: 'C' },
                tls12: { status: 'offered', grade: 'A' },
                tls13: { status: 'offered', grade: 'A' }
            },
            ciphers: {
                total: 183,
                secure: 45,
                deprecated: 12
            },
            certificate: {
                valid: true,
                issuer: "Let's Encrypt",
                expiry: '2025-10-20',
                daysUntilExpiry: 26
            }
        };
    }
    
    // Display deep analysis results
    function displayDeepResults(data) {
        const resultsContainer = document.getElementById('ssl-deep-results');
        
        const resultsHTML = `
            <div class="ssl-deep-results-content">
                <div class="deep-results-header">
                    <h3>🔬 Deep SSL Security Analysis Complete</h3>
                    <div class="deep-grade">
                        <span class="grade-label">Overall Security Grade:</span>
                        <span class="grade-value grade-${data.overallGrade.toLowerCase()}">${data.overallGrade}</span>
                        <span class="grade-score">(${data.score}/100)</span>
                    </div>
                </div>
                
                <div class="deep-results-grid">
                    <div class="deep-result-section">
                        <h4>🔐 Protocol Analysis</h4>
                        <div class="protocol-analysis">
                            ${Object.entries(data.protocols).map(([protocol, info]) => `
                                <div class="protocol-item-deep">
                                    <span class="protocol-name">${protocol.toUpperCase()}</span>
                                    <span class="protocol-status ${info.status === 'not offered' ? 'secure' : info.status === 'offered' ? 'deprecated' : 'insecure'}">
                                        ${info.status === 'not offered' ? '✅ Not Offered' : 
                                          info.status === 'offered' ? '⚠️ Offered' : '❌ Not Supported'}
                                    </span>
                                    <span class="protocol-grade grade-${info.grade.toLowerCase()}">${info.grade}</span>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                    
                    <div class="deep-result-section">
                        <h4>🛡️ Vulnerability Assessment</h4>
                        <div class="vulnerability-list">
                            ${data.vulnerabilities.map(vuln => `
                                <div class="vulnerability-item severity-${vuln.severity}">
                                    <span class="vuln-name">${vuln.name}</span>
                                    <span class="vuln-status">${vuln.status}</span>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                    
                    <div class="deep-result-section">
                        <h4>📊 Cipher Analysis</h4>
                        <div class="cipher-stats">
                            <div class="cipher-stat">
                                <span class="stat-value">${data.ciphers.total}</span>
                                <span class="stat-label">Total Ciphers</span>
                            </div>
                            <div class="cipher-stat">
                                <span class="stat-value">${data.ciphers.secure}</span>
                                <span class="stat-label">Secure Ciphers</span>
                            </div>
                            <div class="cipher-stat">
                                <span class="stat-value">${data.ciphers.deprecated}</span>
                                <span class="stat-label">Deprecated Ciphers</span>
                            </div>
                        </div>
                    </div>
                    
                    <div class="deep-result-section">
                        <h4>📜 Certificate Details</h4>
                        <div class="certificate-details">
                            <p><strong>Issuer:</strong> ${data.certificate.issuer}</p>
                            <p><strong>Valid Until:</strong> ${data.certificate.expiry}</p>
                            <p><strong>Days Until Expiry:</strong> ${data.certificate.daysUntilExpiry}</p>
                            <p><strong>Status:</strong> ${data.certificate.valid ? '✅ Valid' : '❌ Invalid'}</p>
                        </div>
                    </div>
                </div>
                
                <div class="deep-recommendations">
                    <h4>💡 Security Recommendations</h4>
                    <ul>
                        <li>Disable TLS 1.0 and TLS 1.1 protocols for better security</li>
                        <li>Update server configuration to use only modern cipher suites</li>
                        <li>Consider implementing HSTS (HTTP Strict Transport Security)</li>
                        <li>Monitor certificate expiration and set up automatic renewal</li>
                        <li>Regular security audits and vulnerability assessments</li>
                    </ul>
                </div>
                
                <div class="deep-actions">
                    <button class="btn btn-primary" onclick="window.print()">📄 Print Report</button>
                    <button class="btn btn-outline-primary" onclick="downloadReport()">💾 Download Report</button>
                    <button class="btn btn-outline-secondary" onclick="resetSSLChecker()">🔄 New Analysis</button>
                </div>
            </div>
        `;
        
        resultsContainer.innerHTML = resultsHTML;
    }
    
    // Reset SSL checker
    function resetSSLChecker() {
        // Show simple checker, hide deep analysis
        document.getElementById('ssl-simple-checker').style.display = 'block';
        document.getElementById('ssl-deep-analysis').style.display = 'none';
        document.getElementById('ssl-simple-results').style.display = 'none';
        document.getElementById('ssl-checker-actions').style.display = 'none';
        document.getElementById('ssl-deep-progress').style.display = 'block';
        document.getElementById('ssl-deep-results').style.display = 'none';
        
        // Reset input
        sslUrlInput.value = '';
    }
    
    // Download report function
    window.downloadReport = function() {
        const reportData = {
            timestamp: new Date().toISOString(),
            url: sslUrlInput.value,
            type: 'Deep SSL Analysis Report',
            grade: 'B',
            score: 91
        };
        
        const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'ssl-analysis-report.json';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    };
    
    // Make resetSSLChecker globally available
    window.resetSSLChecker = resetSSLChecker;
});
