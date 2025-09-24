// SSL Checker Vue 3 Application
const { createApp, ref } = Vue;

createApp({
    setup() {
        // Reactive state
        const sslUrl = ref('');
        const isLoading = ref(false);
        const isLoadingDeep = ref(false);
        const currentMode = ref('simple'); // 'simple' or 'deep'
        const simpleResults = ref(null);
        const deepResults = ref(null);
        const hasQueried = ref(false);
        const recentSearches = ref([]);

        // Process URL to ensure it has proper scheme and port
        const processUrl = (url) => {
            if (!url.trim()) return null;
            
            let processedUrl = url.trim();
            
            // If it doesn't start with http:// or https://, add https://
            if (!processedUrl.startsWith('http://') && !processedUrl.startsWith('https://')) {
                processedUrl = 'https://' + processedUrl;
            }
            
            // If it's http://, change to https://
            if (processedUrl.startsWith('http://')) {
                processedUrl = processedUrl.replace('http://', 'https://');
            }
            
            return processedUrl;
        };

        // Simple SSL check
        const runSimpleSSL = async () => {
            if (!sslUrl.value.trim()) return;
            
            const processedUrl = processUrl(sslUrl.value);
            if (!processedUrl) return;
            
            isLoading.value = true;
            hasQueried.value = true;
            simpleResults.value = null;
            deepResults.value = null;
            
            try {
                const response = await fetch('/api/ssl/check', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url: processedUrl })
                });
                
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                
                const data = await response.json();
                simpleResults.value = data;
            } catch (error) {
                simpleResults.value = { 
                    certificate: { valid: false, error: error.message },
                    recommendations: ['Check the URL and try again']
                };
            } finally {
                isLoading.value = false;
            }
        };

        // Deep SSL analysis
        const runDeepSSL = async () => {
            if (!sslUrl.value.trim()) return;
            
            const processedUrl = processUrl(sslUrl.value);
            if (!processedUrl) return;
            
            isLoadingDeep.value = true;
            simpleResults.value = null;
            deepResults.value = null;
            
            try {
                const response = await fetch('/api/ssl/deep-check', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url: processedUrl })
                });
                
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                
                const data = await response.json();
                deepResults.value = data;
            } catch (error) {
                deepResults.value = { 
                    certificate: { subject: 'Error', issuer: 'Error' },
                    protocols: [],
                    cipher_suites: [],
                    hsts: false,
                    ocsp_stapling: false,
                    vulnerabilities: [error.message]
                };
            } finally {
                isLoadingDeep.value = false;
            }
        };

        // Check SSL function (alias for runSimpleSSL)
        const checkSSL = runSimpleSSL;

        // Mask domain for display (e.g., pixabay.com -> pix***.com)
        const maskDomain = (domain) => {
            if (!domain || domain.length <= 3) return domain;
            const lastDot = domain.lastIndexOf('.');
            if (lastDot === -1) return domain;
            return domain.substring(0, 3) + '***' + domain.substring(lastDot);
        };

        // Load recent searches
        const loadRecentSearches = async () => {
            try {
                const response = await fetch('/api/recent-searches?limit=10');
                if (response.ok) {
                    const searches = await response.json();
                    recentSearches.value = searches;
                }
            } catch (error) {
                console.error('Error loading recent searches:', error);
            }
        };

        // Initialize with data from backend
        if (window.recentSearchesData) {
            recentSearches.value = window.recentSearchesData;
        }
        
        // Prefill domain if provided
        if (window.prefillDomain) {
            sslUrl.value = window.prefillDomain;
        }

        // Load recent searches on mount (fallback)
        loadRecentSearches();

        return {
            sslUrl,
            isLoading,
            isLoadingDeep,
            currentMode,
            simpleResults,
            deepResults,
            hasQueried,
            recentSearches,
            checkSSL,
            runSimpleSSL,
            runDeepSSL,
            maskDomain
        };
    }
}).mount('#app');
