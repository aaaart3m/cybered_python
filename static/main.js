document.addEventListener('DOMContentLoaded', function() {
    const scanTypeSelect = document.getElementById('scanType');
    const methodRadios = document.querySelectorAll('input[name="method"]');

    updateScanTypes();

    methodRadios.forEach(radio => {
        radio.addEventListener('change', updateScanTypes);
    });

    function updateScanTypes() {
        const scanTypesPython = [
            { value: 'availability', text: 'CHECK AVAILABILITY' },
            { value: 'directories', text: 'DIRECTORY BRUTEFORCE' },
            { value: 'subdomains', text: 'SUBDOMAIN BRUTEFORCE' },
        ];

        const scanTypesExternal = [
            { value: 'availability', text: 'CHECK AVAILABILITY (httpx)' },
            { value: 'version', text: 'VERSION DETECTION (nmap)' },
            { value: 'subdomains', text: 'SUBDOMAIN BRUTEFORCE (ffuf)' },
            { value: 'directories', text: 'DIRECTORY BRUTEFORCE (ffuf)' },
            { value: 'screenshot', text: 'GET SCREENSHOT (gowitness)' },
            { value: 'nuclei', text: 'VULNERABILITY SCAN (nuclei)' },
            { value: 'sqlmap', text: 'SQL INJECTION SCAN (sqlmap)' }
        ];

        scanTypeSelect.innerHTML = '';

        const selectedMethod = document.querySelector('input[name="method"]:checked').value;

        let optionsToAdd = [];
        if (selectedMethod === 'python') {
            optionsToAdd = scanTypesPython;
        } else if (selectedMethod === 'external') {
            optionsToAdd = scanTypesExternal;
        }

        optionsToAdd.forEach(option => {
            const newOption = document.createElement('option');
            newOption.value = option.value;
            newOption.text = option.text;
            scanTypeSelect.appendChild(newOption);
        });
    }

    document.getElementById('scanForm').addEventListener('submit', async function(event) {
        event.preventDefault();

        const url = document.getElementById('url').value;
        const method = document.querySelector('input[name="method"]:checked').value;
        const scanType = document.getElementById('scanType').value;
        const resultBox = document.getElementById('result');

        resultBox.textContent = 'Scanning...';

        const socket = new WebSocket(`ws://${window.location.host}/ws`);
        socket.onopen = function() {
            const data = JSON.stringify({ url: url, method: method, scanType: scanType });
            socket.send(data);
        };

        socket.onmessage = function(event) {
            const parsedData = JSON.parse(event.data);
            const type = parsedData.type;
            const result = parsedData.data;
            const duration = parsedData.duration;

            if (type === 'error') {
                resultBox.textContent = 'Except error: ' + result;
            } else if (scanType === 'screenshot') {
                const imageUrl = `/static/screenshots/${result}`;
                resultBox.innerHTML = `<img src="${imageUrl}" alt="Screenshot" style="max-width: 100%;">`;
            } else if (method === 'external') {
                    const ansi_up = new AnsiUp();
                    const htmlResult = ansi_up.ansi_to_html(result);
                    resultBox.innerHTML = `<pre>${htmlResult}</pre><p>Scan duration: ${duration.toFixed(2)} seconds</p>`;
                } else {
                    resultBox.innerHTML = `<pre>${result}</pre><p>Scan duration: ${duration.toFixed(2)} seconds</p>`;
                }
        };

        socket.onerror = function(error) {
            resultBox.textContent = 'Error during scan: ' + error.message;
        };

        socket.onclose = function() {
            console.log('WebSocket connection closed');
        };
    });
});
