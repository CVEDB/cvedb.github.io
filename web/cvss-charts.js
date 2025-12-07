/**
 * CVSS Preview Chart Functions
 */

// Global variables for CVSS preview chart
let cvssPreviewChart = null;
let cvssPreviewData = null;
let currentCvssVersion = 'v3.1';

function initializeCvssPreview() {
    const ctx = document.getElementById('homepageScoreChart');
    if (!ctx) return;

    fetch('data/cvss_analysis.json')
        .then(response => response.json())
        .then(data => {
            cvssPreviewData = data;

            // Initialize chart with default version (v3.1)
            updateCvssPreviewChart('v3.1');

            // Add event listeners for version buttons
            const versionButtons = document.querySelectorAll('.cvss-version-btn');
            versionButtons.forEach(button => {
                button.addEventListener('click', function () {
                    const version = this.getAttribute('data-version');
                    updateCvssPreviewChart(version);

                    // Update button states
                    versionButtons.forEach(btn => {
                        btn.classList.remove('active');
                    });
                    this.classList.add('active');

                    // Update version label
                    const versionLabel = document.getElementById('homepageCvssVersionLabel');
                    if (versionLabel) {
                        versionLabel.textContent = `CVSS ${version}`;
                    }
                });
            });
        })
        .catch(error => {
            console.error('CVSS preview error:', error);
            ctx.parentElement.innerHTML = '<div class="text-center text-muted py-4"><small>Preview unavailable</small></div>';
        });
}

function updateCvssPreviewChart(version) {
    const ctx = document.getElementById('homepageScoreChart');
    if (!ctx || !cvssPreviewData) return;

    currentCvssVersion = version;

    // Get score data for the selected version
    const versionScores = cvssPreviewData.score_distribution[version] || {};
    const scoreBins = {};

    // Create 1-point score bins for the selected version
    Object.entries(versionScores).forEach(([score, count]) => {
        const scoreFloat = parseFloat(score);
        let bin;

        // Create 1-point score bins (0-0.99, 1.0-1.99, etc.)
        if (scoreFloat >= 10.0) bin = '10.0';
        else if (scoreFloat >= 9.0) bin = '9.0-9.9';
        else if (scoreFloat >= 8.0) bin = '8.0-8.9';
        else if (scoreFloat >= 7.0) bin = '7.0-7.9';
        else if (scoreFloat >= 6.0) bin = '6.0-6.9';
        else if (scoreFloat >= 5.0) bin = '5.0-5.9';
        else if (scoreFloat >= 4.0) bin = '4.0-4.9';
        else if (scoreFloat >= 3.0) bin = '3.0-3.9';
        else if (scoreFloat >= 2.0) bin = '2.0-2.9';
        else if (scoreFloat >= 1.0) bin = '1.0-1.9';
        else bin = '0.0-0.9';

        scoreBins[bin] = (scoreBins[bin] || 0) + count;
    });

    // Display all bins in sequential order from 0-10
    const orderedBins = ['0.0-0.9', '1.0-1.9', '2.0-2.9', '3.0-3.9', '4.0-4.9',
        '5.0-5.9', '6.0-6.9', '7.0-7.9', '8.0-8.9', '9.0-9.9', '10.0'];

    const labels = orderedBins;
    const values = orderedBins.map(bin => scoreBins[bin] || 0);

    // Light blue/gray color palette matching CVEDB design (11 bins)
    const colors = [
        '#d6e7f5', // Lightest blue (0.0-0.9)
        '#c8dff0', // Very light blue (1.0-1.9)
        '#b9d7eb', // Light blue (2.0-2.9)
        '#aacfe6', // Light-medium blue (3.0-3.9)
        '#9bc7e1', // Medium blue (4.0-4.9)
        '#8cbfdc', // Medium-dark blue (5.0-5.9)
        '#7db7d7', // Dark blue (6.0-6.9)
        '#6eafd2', // Darker blue (7.0-7.9)
        '#5fa7cd', // Very dark blue (8.0-8.9)
        '#509fc8', // Darkest blue (9.0-9.9)
        '#4197c3'  // Deepest blue (10.0)
    ];

    // Destroy existing chart if it exists
    if (cvssPreviewChart) {
        cvssPreviewChart.destroy();
    }

    // Create new chart
    cvssPreviewChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                data: values,
                backgroundColor: colors,
                borderColor: colors,
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false }
            },
            scales: {
                y: {
                    display: true,
                    grid: { color: 'rgba(0,0,0,0.1)' },
                    title: {
                        display: true,
                        text: 'CVE Count',
                        font: { size: 10 }
                    }
                },
                x: {
                    display: true,
                    grid: { color: 'rgba(0,0,0,0.1)' },
                    title: {
                        display: true,
                        text: 'CVSS Score Range',
                        font: { size: 10 }
                    }
                }
            }
        }
    });
}

function initializeCwePreview() {
    const ctx = document.getElementById('cwePreviewChart');
    if (!ctx) return;

    fetch('data/cwe_analysis.json')
        .then(response => response.json())
        .then(data => {
            const cweData = data.top_cwes || [];
            const topCWEs = cweData.slice(0, 5);
            const labels = topCWEs.map(item => `CWE-${item.id}`);
            const values = topCWEs.map(item => item.count);

            new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: labels,
                    datasets: [{
                        data: values,
                        backgroundColor: ['#a8c8ec', '#9bc7e1', '#8cbfdc', '#7db7d7', '#6eafd2'],
                        borderColor: ['#9bc7e1', '#8cbfdc', '#7db7d7', '#6eafd2', '#5fa7cd'],
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { display: false } },
                    scales: {
                        y: { display: true, grid: { color: 'rgba(0,0,0,0.1)' } },
                        x: { display: true, grid: { color: 'rgba(0,0,0,0.1)' } }
                    }
                }
            });
        })
        .catch(error => {
            console.error('CWE preview error:', error);
            ctx.parentElement.innerHTML = '<div class="text-center text-muted py-4"><small>Preview unavailable</small></div>';
        });
}

function initializeCnaPreview() {
    const ctx = document.getElementById('cnaPreviewChart');
    if (!ctx) return;

    fetch('data/cna_analysis.json')
        .then(response => response.json())
        .then(data => {
            const cnaData = data.cna_assigners || [];
            const topCNAs = cnaData.slice(0, 5);
            const labels = topCNAs.map(item => item.name.length > 15 ? item.name.substring(0, 15) + '...' : item.name);
            const values = topCNAs.map(item => item.count);

            new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: labels,
                    datasets: [{
                        data: values,
                        backgroundColor: ['#a8c8ec', '#9bc7e1', '#8cbfdc', '#7db7d7', '#6eafd2'],
                        borderColor: ['#9bc7e1', '#8cbfdc', '#7db7d7', '#6eafd2', '#5fa7cd'],
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    indexAxis: 'y',
                    plugins: { legend: { display: false } },
                    scales: {
                        y: { display: true, grid: { color: 'rgba(0,0,0,0.1)' } },
                        x: { display: true, grid: { color: 'rgba(0,0,0,0.1)' } }
                    }
                }
            });
        })
        .catch(error => {
            console.error('CNA preview error:', error);
            ctx.parentElement.innerHTML = '<div class="text-center text-muted py-4"><small>Preview unavailable</small></div>';
        });
}

function initializeCpePreview() {
    const ctx = document.getElementById('cpePreviewChart');
    if (!ctx) return;

    fetch('data/cpe_analysis.json')
        .then(response => response.json())
        .then(data => {
            const cpeData = data.top_cpes || [];
            const topCPEs = cpeData.slice(0, 5);
            const labels = topCPEs.map(item => item.vendor.length > 12 ? item.vendor.substring(0, 12) + '...' : item.vendor);
            const values = topCPEs.map(item => item.count);

            new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: labels,
                    datasets: [{
                        data: values,
                        backgroundColor: ['#a8c8ec', '#9bc7e1', '#8cbfdc', '#7db7d7', '#6eafd2'],
                        borderColor: ['#9bc7e1', '#8cbfdc', '#7db7d7', '#6eafd2', '#5fa7cd'],
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { display: false } },
                    scales: {
                        y: { display: true, grid: { color: 'rgba(0,0,0,0.1)' } },
                        x: { display: true, grid: { color: 'rgba(0,0,0,0.1)' } }
                    }
                }
            });
        })
        .catch(error => {
            console.error('CPE preview error:', error);
            ctx.parentElement.innerHTML = '<div class="text-center text-muted py-4"><small>Preview unavailable</small></div>';
        });
}
