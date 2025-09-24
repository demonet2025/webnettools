// CSR Decoder Vue 3 Application
const { createApp, ref } = Vue;

createApp({
    setup() {
        // Reactive state
        const csrInput = ref('');
        const csrResults = ref(null);
        const isLoading = ref(false);

        // CSR decode function
        const decodeCSR = async () => {
            if (!csrInput.value.trim()) return;
            
            isLoading.value = true;
            csrResults.value = null;
            
            try {
                const response = await fetch('/api/ssl/csr-decode', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ 
                        csr: csrInput.value
                    })
                });
                
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                
                const data = await response.json();
                csrResults.value = data;
            } catch (error) {
                csrResults.value = { 
                    success: false, 
                    error: error.message 
                };
            } finally {
                isLoading.value = false;
            }
        };

        return {
            csrInput,
            csrResults,
            isLoading,
            decodeCSR
        };
    }
}).mount('#app');
