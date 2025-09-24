// DNS Lookup Vue 3 Application
const { createApp, ref } = Vue;

createApp({
    setup() {
        // Reactive state
        const digHostname = ref('');
        const digRecordType = ref('A');
        const digResults = ref(null);
        const isLoading = ref(false);

        // DNS lookup function
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
                
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                
                const data = await response.json();
                digResults.value = data;
            } catch (error) {
                digResults.value = { 
                    success: false, 
                    error: error.message 
                };
            } finally {
                isLoading.value = false;
            }
        };

        return {
            digHostname,
            digRecordType,
            digResults,
            isLoading,
            runDig
        };
    }
}).mount('#app');
