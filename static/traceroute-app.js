// Traceroute Vue 3 Application
const { createApp, ref } = Vue;

createApp({
    setup() {
        // Reactive state
        const tracerouteHostname = ref('');
        const tracerouteMaxHops = ref(30);
        const tracerouteResults = ref(null);
        const isLoading = ref(false);

        // Traceroute function
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
                
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                
                const data = await response.json();
                tracerouteResults.value = data;
            } catch (error) {
                tracerouteResults.value = { 
                    success: false, 
                    error: error.message 
                };
            } finally {
                isLoading.value = false;
            }
        };

        return {
            tracerouteHostname,
            tracerouteMaxHops,
            tracerouteResults,
            isLoading,
            runTraceroute
        };
    }
}).mount('#app');
