// NetHub Webnettools - Vue 3 Application
const { createApp, ref, reactive, computed, onMounted } = Vue;

createApp({
    setup() {
        // Reactive state
        console.log('Vue app initializing with initialTool:', window.initialTool);
        
        // Get initial tool from URL or window variable
        const getInitialTool = () => {
            if (window.initialTool) {
                console.log('Using window.initialTool:', window.initialTool);
                return window.initialTool;
            }
            
            // Fallback: try to get from URL path
            const path = window.location.pathname;
            if (path === '/ping') return 'ping';
            if (path === '/traceroute') return 'traceroute';
            if (path === '/nmap') return 'nmap';
            if (path === '/dig') return 'dig';
            if (path === '/mtr') return 'mtr';
            if (path === '/sslchecker') return 'ssl-checker';
            
            return 'ssl-checker';
        };
        
        const currentView = ref(getInitialTool());
        console.log('Current view set to:', currentView.value);
        
        // Force update if needed
        onMounted(() => {
            console.log('Vue app mounted, currentView:', currentView.value);
            const newTool = getInitialTool();
            if (newTool !== currentView.value) {
                console.log('Updating currentView to:', newTool);
                currentView.value = newTool;
            }
        });
        const sslUrl = ref('https://testssl.sh/');
        const isLoading = ref(false);
        const currentMode = ref('simple'); // 'simple' or 'deep'
        const simpleResults = ref(null);
        const deepResults = ref(null);
        const showProgress = ref(false);
        
        // Individual tool form data
        const pingHostname = ref('');
        const pingCount = ref(4);
        const pingResults = ref(null);
        const pingStreaming = ref(false);
        const pingStreamLines = ref([]);
        
        const tracerouteHostname = ref('');
        const tracerouteMaxHops = ref(30);
        const tracerouteResults = ref(null);
        
        const nmapHostname = ref('');
        const nmapScanType = ref('quick');
        const nmapResults = ref(null);
        
        const digHostname = ref('');
        const digRecordType = ref('A');
        const digResults = ref(null);
        
        const mtrHostname = ref('');
        const mtrCount = ref(10);
        const mtrResults = ref(null);
        const progress = ref(0);
        const completedSteps = ref(0);
        
        // Progress steps
        const progressSteps = ref([
            'Analyzing remote server',
            'Testing SSL/TLS for PCI DSS compliance',
            'Testing SSL/TLS for HIPAA guidance',
            'Testing SSL/TLS for NIST guidelines',
            'Testing SSL/TLS for industry best practices',
            'Preparing your report'
        ]);
        
        // CDN features
        const cdnFeatures = ref([
            {
                id: 1,
                icon: '🌍',
                title: 'Global CDN Network',
                description: '195+ countries, 6 continents'
            },
            {
                id: 2,
                icon: '⚡',
                title: 'Smart Routing',
                description: 'Intelligent traffic distribution'
            },
            {
                id: 3,
                icon: '🔒',
                title: 'SSL Management',
                description: 'Automated certificate deployment'
            },
            {
                id: 4,
                icon: '📊',
                title: 'Real-time Analytics',
                description: 'Performance monitoring & insights'
            },
            {
                id: 5,
                icon: '🛡️',
                title: 'DDoS Protection',
                description: 'Advanced security features'
            },
            {
                id: 6,
                icon: '💰',
                title: 'Cost Optimization',
                description: 'Reduce bandwidth costs by 40%'
            }
        ]);
        
        // Individual tool functions
        const runPing = async () => {
            if (!pingHostname.value.trim()) return;
            
            isLoading.value = true;
            pingStreaming.value = true;
            pingResults.value = null;
            pingStreamLines.value = [];
            
            try {
                const response = await fetch('/api/tools/ping/stream', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ 
                        hostname: pingHostname.value,
                        count: pingCount.value 
                    })
                });
                
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                
                const reader = response.body.getReader();
                const decoder = new TextDecoder();
                
                while (true) {
                    const { done, value } = await reader.read();
                    if (done) break;
                    
                    const chunk = decoder.decode(value);
                    const lines = chunk.split('\n');
                    
                    for (const line of lines) {
                        if (line.startsWith('data: ')) {
                            try {
                                const data = JSON.parse(line.slice(6));
                                
                                if (data.type === 'line') {
                                    pingStreamLines.value.push({
                                        content: data.content,
                                        timestamp: data.timestamp
                                    });
                                } else if (data.type === 'complete') {
                                    console.log('Ping complete data:', data);
                                    pingResults.value = {
                                        success: data.success,
                                        output: data.output,
                                        statistics: data.statistics,
                                        error: data.error
                                    };
                                    console.log('Ping results set:', pingResults.value);
                                    pingStreaming.value = false;
                                } else if (data.type === 'error') {
                                    pingResults.value = {
                                        success: false,
                                        error: data.error
                                    };
                                    pingStreaming.value = false;
                                }
                            } catch (e) {
                                console.error('Error parsing stream data:', e);
                            }
                        }
                    }
                }
            } catch (error) {
                pingResults.value = { success: false, error: error.message };
                pingStreaming.value = false;
            } finally {
                isLoading.value = false;
            }
        };

        const runTraceroute = async () => {
            if (!tracerouteHostname.value.trim()) return;
            
            isLoading.value = true;
            tracerouteResults.value = null;
            
            try {
                const response = await fetch('/api/tools/traceroute', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ 
                        hostname: tracerouteHostname.value,
                        max_hops: tracerouteMaxHops.value 
                    })
                });
                
                const data = await response.json();
                tracerouteResults.value = data;
            } catch (error) {
                tracerouteResults.value = { success: false, error: error.message };
            } finally {
                isLoading.value = false;
            }
        };

        const runNmap = async () => {
            if (!nmapHostname.value.trim()) return;
            
            isLoading.value = true;
            nmapResults.value = null;
            
            try {
                const response = await fetch('/api/tools/nmap', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ 
                        hostname: nmapHostname.value,
                        scan_type: nmapScanType.value 
                    })
                });
                
                const data = await response.json();
                nmapResults.value = data;
            } catch (error) {
                nmapResults.value = { success: false, error: error.message };
            } finally {
                isLoading.value = false;
            }
        };

        const runDig = async () => {
            if (!digHostname.value.trim()) return;
            
            isLoading.value = true;
            digResults.value = null;
            
            try {
                const response = await fetch('/api/tools/dig', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ 
                        hostname: digHostname.value,
                        record_type: digRecordType.value 
                    })
                });
                
                const data = await response.json();
                digResults.value = data;
            } catch (error) {
                digResults.value = { success: false, error: error.message };
            } finally {
                isLoading.value = false;
            }
        };

        const runMtr = async () => {
            if (!mtrHostname.value.trim()) return;
            
            isLoading.value = true;
            mtrResults.value = null;
            
            try {
                const response = await fetch('/api/tools/mtr', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ 
                        hostname: mtrHostname.value,
                        count: mtrCount.value 
                    })
                });
                
                const data = await response.json();
                mtrResults.value = data;
            } catch (error) {
                mtrResults.value = { success: false, error: error.message };
            } finally {
                isLoading.value = false;
            }
        };
        
        // Intro text
        const introText = ref('<h2 style="color: #2563eb; margin-bottom: 1rem;">🔧 NetHub Network Tools</h2><p style="color: #6b7280; font-size: 1.1rem;">Test and analyze network connectivity, SSL certificates, and DNS resolution for your domains. These tools are integrated into your NetHub platform for seamless domain management.</p>');
        
        // Methods
        const runSimpleSSLCheck = async () => {
            if (!sslUrl.value.trim()) {
                alert('Please enter a valid URL');
                return;
            }
            
            isLoading.value = true;
            simpleResults.value = null;
            
            try {
                const response = await fetch('/api/ssl/check', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ url: sslUrl.value })
                });
                
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                
                const data = await response.json();
                simpleResults.value = data;
                
            } catch (error) {
                console.error('Error:', error);
                simpleResults.value = { 
                    success: false, 
                    error: error.message || 'Network error or invalid response.',
                    certificate: null,
                    protocols: null,
                    security_grade: 'F'
                };
            } finally {
                isLoading.value = false;
            }
        };
        
        const runDeepSSLAnalysis = async () => {
            if (!sslUrl.value.trim()) {
                alert('Please enter a valid URL');
                return;
            }
            
            currentMode.value = 'deep';
            showProgress.value = true;
            progress.value = 0;
            completedSteps.value = 0;
            deepResults.value = null;
            
            // Start progress animation
            const progressInterval = setInterval(() => {
                progress.value += Math.random() * 15;
                if (progress.value > 90) progress.value = 90; // Don't complete until real data arrives
                
                completedSteps.value = Math.floor(progress.value / 20);
            }, 1000);
            
            try {
                const response = await fetch('/api/ssl/deep-check', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ target: sslUrl.value })
                });
                
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                
                const data = await response.json();
                console.log('Deep analysis result:', data);
                
                // Complete progress
                clearInterval(progressInterval);
                progress.value = 100;
                completedSteps.value = progressSteps.value.length;
                
                deepResults.value = data;
                
            } catch (error) {
                console.error('Error:', error);
                clearInterval(progressInterval);
                deepResults.value = { 
                    success: false, 
                    error: error.message || 'Network error or invalid response.',
                    overallGrade: 'F',
                    score: 0,
                    protocols: {},
                    vulnerabilities: [],
                    ciphers: { total: 0, secure: 0, deprecated: 0, weak: 0 },
                    certificate: { valid: false },
                    recommendations: ['SSL analysis failed. Please try again.']
                };
            } finally {
                showProgress.value = false;
            }
        };
        
        const startDeepAnalysisProgress = () => {
            const interval = setInterval(() => {
                progress.value += Math.random() * 15;
                if (progress.value > 100) progress.value = 100;
                
                completedSteps.value = Math.floor(progress.value / 20);
                
                if (progress.value >= 100) {
                    clearInterval(interval);
                }
            }, 200);
        };
        
        
        const resetSSLChecker = () => {
            currentMode.value = 'simple';
            simpleResults.value = null;
            deepResults.value = null;
            showProgress.value = false;
            progress.value = 0;
            completedSteps.value = 0;
            sslUrl.value = '';
        };
        
        const printReport = () => {
            window.print();
        };
        
        const downloadReport = () => {
            const reportData = {
                timestamp: new Date().toISOString(),
                url: sslUrl.value,
                type: 'Deep SSL Analysis Report',
                grade: deepResults.value?.overallGrade || 'F',
                score: deepResults.value?.score || 0
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
        
        const learnMoreCDN = () => {
            alert('Learn more about NetHub CDN features! This would typically redirect to your CDN marketing page.');
        };
        
        
        // Helper methods
        const getProtocolClass = (protocol, status) => {
            if (!protocol || status === undefined) return 'insecure';
            if (protocol === 'sslv2' || protocol === 'sslv3') {
                return status ? 'deprecated' : 'secure';
            } else if (protocol === 'tls10' || protocol === 'tls11') {
                return status ? 'deprecated' : 'secure';
            } else {
                return status ? 'secure' : 'insecure';
            }
        };
        
        const getProtocolStatus = (protocol, status) => {
            if (!protocol || status === undefined) return '❌ Not Available';
            if (protocol === 'sslv2' || protocol === 'sslv3') {
                return status ? '⚠️ Offered' : '✅ Not Offered';
            } else if (protocol === 'tls10' || protocol === 'tls11') {
                return status ? '⚠️ Deprecated' : '✅ Not Offered';
            } else {
                return status ? '✅ Secure' : '❌ Not Offered';
            }
        };
        
        const getProtocolStatusClass = (status) => {
            if (!status) return 'insecure';
            if (status === 'not offered') return 'secure';
            if (status === 'offered') return 'deprecated';
            return 'insecure';
        };
        
        const getProtocolStatusText = (status) => {
            if (!status) return '❌ Not Available';
            if (status === 'not offered') return '✅ Not Offered';
            if (status === 'offered') return '⚠️ Offered';
            return '❌ Not Supported';
        };
        
        // Lifecycle
        onMounted(() => {
            console.log('NetHub Webnettools Vue 3 app mounted');
        });
        
        // Return reactive data and methods
        return {
            currentView,
            sslUrl,
            isLoading,
            currentMode,
            simpleResults,
            deepResults,
            showProgress,
            progress,
            completedSteps,
            progressSteps,
            cdnFeatures,
            introText,
            // Individual tool form data
            pingHostname,
            pingCount,
            pingResults,
            pingStreaming,
            pingStreamLines,
            tracerouteHostname,
            tracerouteMaxHops,
            tracerouteResults,
            nmapHostname,
            nmapScanType,
            nmapResults,
            digHostname,
            digRecordType,
            digResults,
            mtrHostname,
            mtrCount,
            mtrResults,
            // Methods
            runSimpleSSLCheck,
            runDeepSSLAnalysis,
            resetSSLChecker,
            printReport,
            downloadReport,
            learnMoreCDN,
            runPing,
            runTraceroute,
            runNmap,
            runDig,
            runMtr,
            getProtocolClass,
            getProtocolStatus,
            getProtocolStatusClass,
            getProtocolStatusText
        };
    }
}).mount('#app');
