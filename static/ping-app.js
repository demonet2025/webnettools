// Ping Tool Vue 3 Application
const { createApp, ref, onMounted } = Vue;

createApp({
    setup() {
        // Reactive state
        const pingHostname = ref('');
        const pingCount = ref(4);
        const pingResults = ref(null);
        const pingStreaming = ref(false);
        const pingStreamLines = ref([]);
        const isLoading = ref(false);

        // Ping streaming function
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

        return {
            pingHostname,
            pingCount,
            pingResults,
            pingStreaming,
            pingStreamLines,
            isLoading,
            runPing
        };
    }
}).mount('#app');
