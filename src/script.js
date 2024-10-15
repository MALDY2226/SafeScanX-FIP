document.getElementById('scan-form').addEventListener('submit', async function(e) { 
    e.preventDefault();  // Prevent page reload

    const url = document.getElementById('url-input').value.trim();
    const file = document.getElementById('file-input').files[0];

    try {
        let data;
        if (url) {
            // Scan URL
            const response = await fetch('/scan-url', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url })
            });
            if (!response.ok) throw new Error(`Server error: ${response.status}`);
            data = await response.json();
        } else if (file) {
            // Scan file
            const formData = new FormData();
            formData.append('file', file);

            const response = await fetch('/scan-file', {
                method: 'POST',
                body: formData
            });
            if (!response.ok) throw new Error(`Server error: ${response.status}`);
            data = await response.json();
        } else {
            alert('Please enter a URL or select a file.');
            return;
        }

        displayResults(data);
    } catch (error) {
        console.error('Error during scan:', error);
        alert('An error occurred during the scan. Check the console for details.');
    }
});

function displayResults(data) {
    const chartData = {
        labels: ['Malware Detected', 'Clean'],
        datasets: [{
            data: [data.combinedResult, 100 - data.combinedResult],
            backgroundColor: ['#FF6384', '#36A2EB']
        }]
    };

    const chartOptions = {
        plugins: {
            title: {
                display: true,
                text: 'Malware Detection Results'
            }
        }
    };

    // Clear previous chart before creating a new one
    if (window.currentChart) {
        window.currentChart.destroy();
    }

    window.currentChart = new Chart(document.getElementById('pie-chart').getContext('2d'), {
        type: 'pie',
        data: chartData,
        options: chartOptions
    });
}
// Get references to the URL and File input fields
const urlInput = document.getElementById('url-input');
const fileInput = document.getElementById('file-input');

// Disable file input when the user enters a URL
urlInput.addEventListener('input', function() {
    if (urlInput.value.trim() !== "") {
        fileInput.disabled = true;  // Disable file input
    } else {
        fileInput.disabled = false;  // Enable file input if URL is cleared
    }
});

// Disable URL input when the user selects a file
fileInput.addEventListener('change', function() {
    if (fileInput.files.length > 0) {
        urlInput.disabled = true;  // Disable URL input
    } else {
        urlInput.disabled = false;  // Enable URL input if file is cleared
    }
});
