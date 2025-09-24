// Deep SSL Checker Vue 3 Application
const { createApp, ref } = Vue;

createApp({
    setup() {
        // Reactive state
        const sslUrl = ref('');
        const sslPort = ref('443');
        const deepResults = ref(null);
        const isLoading = ref(false);

        // Deep SSL analysis function
        const runDeepAnalysis = async () => {
            if (!sslUrl.value.trim()) return;
            
            isLoading.value = true;
            deepResults.value = null;
            
            try {
                const response = await fetch('/api/ssl/deep-check', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ 
                        url: sslUrl.value,
                        port: parseInt(sslPort.value)
                    })
                });
                
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                
                const data = await response.json();
                deepResults.value = data;
            } catch (error) {
                deepResults.value = { 
                    success: false, 
                    error: error.message,
                    overallGrade: 'F',
                    score: 0
                };
            } finally {
                isLoading.value = false;
            }
        };

        return {
            sslUrl,
            sslPort,
            deepResults,
            isLoading,
            runDeepAnalysis
        };
    }
}).mount('#app');
