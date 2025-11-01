/**
 * Chart initialization and configuration for CVE Database Dashboard
 */

// Wait for Chart.js to load before configuring
document.addEventListener('DOMContentLoaded', function () {
    if (typeof Chart !== 'undefined') {
        // Global configuration for Chart.js with design system
        Chart.defaults.responsive = true;
        Chart.defaults.maintainAspectRatio = false;
        Chart.defaults.plugins.legend.position = 'top';
        Chart.defaults.plugins.legend.labels.usePointStyle = true;
        Chart.defaults.plugins.legend.labels.padding = 20;
        Chart.defaults.plugins.legend.labels.font = {
            family: 'Inter, sans-serif',
            size: 12,
            weight: '500'
        };
        Chart.defaults.plugins.title.display = true;
        Chart.defaults.plugins.title.font = {
            family: 'Inter, sans-serif',
            size: 16,
            weight: '600'
        };
        Chart.defaults.plugins.title.color = '#212529';
        Chart.defaults.plugins.tooltip.backgroundColor = 'rgba(255, 255, 255, 0.95)';
        Chart.defaults.plugins.tooltip.titleColor = '#212529';
        Chart.defaults.plugins.tooltip.bodyColor = '#6c757d';
        Chart.defaults.plugins.tooltip.borderColor = '#dee2e6';
        Chart.defaults.plugins.tooltip.borderWidth = 1;
        Chart.defaults.plugins.tooltip.cornerRadius = 8;
        Chart.defaults.plugins.tooltip.titleFont = {
            family: 'Inter, sans-serif',
            size: 13,
            weight: '600'
        };
        Chart.defaults.plugins.tooltip.bodyFont = {
            family: 'Inter, sans-serif',
            size: 12,
            weight: '400'
        };
        // Chart.js v4 scale configuration
        Chart.defaults.elements.point.backgroundColor = '#2196f3';
        Chart.defaults.elements.point.borderColor = '#2196f3';
        Chart.defaults.elements.line.borderColor = '#2196f3';
        Chart.defaults.elements.bar.backgroundColor = '#2196f3';

        // Note: Scale-specific defaults are set per chart type in Chart.js v4
        // Global scale defaults are handled differently
    }

    // Add active class to current page navigation link
    const currentPage = window.location.pathname.split('/').pop() || 'index.html';
    const navLinks = document.querySelectorAll('.nav-menu a');

    navLinks.forEach(link => {
        const href = link.getAttribute('href');
        if (href === currentPage || (currentPage === '' && href === 'index.html')) {
            link.classList.add('active');
        }
    });
});

// Initialize CVEs by Year Chart
function initializeCveChart() {
    const ctx = document.getElementById('cvesByYearChart');
    if (!ctx) return;

    // Sample data - this would be populated by the Python backend
    const yearlyData = {
        labels: [],
        datasets: [{
            label: 'CVEs Published',
            data: [],
            borderColor: window.CVE_COLORS.primary,
            backgroundColor: window.CVE_COLORS.primaryLight,
            fill: false,
            tension: 0.1
        }]
    };

    // Load actual CVE data from JSON files
    const currentYear = new Date().getFullYear();
    const loadPromises = [];

    // Generate years from 1999 to current year and load data
    for (let year = 1999; year <= currentYear; year++) {
        yearlyData.labels.push(year.toString());

        // Load actual CVE data for each year
        const promise = fetch(`data/cve_${year}.json`)
            .then(response => {
                if (!response.ok) {
                    console.warn(`No data found for year ${year}`);
                    return { total_cves: 0 };
                }
                return response.json();
            })
            .then(data => {
                return { year: year, count: data.total_cves || 0 };
            })
            .catch(error => {
                console.warn(`Error loading data for year ${year}:`, error);
                return { year: year, count: 0 };
            });

        loadPromises.push(promise);
    }

    // Wait for all data to load, then create the chart and update stats
    Promise.all(loadPromises).then(results => {
        // Sort results by year to ensure correct order
        results.sort((a, b) => a.year - b.year);

        // Extract the CVE counts in the correct order
        yearlyData.datasets[0].data = results.map(result => result.count);

        // Calculate and update statistics
        updateStatistics(results);

        // Create the chart with real data
        createChart();
    }).catch(error => {
        console.error('Error loading CVE data:', error);
        // Fallback: create chart with empty data and show error in stats
        updateStatisticsError();
        createChart();
    });

    function updateStatistics(results) {
        try {
            // Calculate total CVEs
            const totalCves = results.reduce((sum, result) => sum + result.count, 0);
            document.getElementById('total-cves').textContent = totalCves.toLocaleString();

            // Calculate CVEs this year (current year)
            const currentYear = new Date().getFullYear();
            const currentYearData = results.find(r => r.year === currentYear);
            const cvesThisYear = currentYearData ? currentYearData.count : 0;
            document.getElementById('cves-this-year').textContent = cvesThisYear.toLocaleString();

            // Calculate average CVEs per day (based on current year)
            const dayOfYear = Math.floor((new Date() - new Date(currentYear, 0, 0)) / (1000 * 60 * 60 * 24));
            const avgCvesPerDay = cvesThisYear > 0 && dayOfYear > 0 ? (cvesThisYear / dayOfYear).toFixed(1) : '0';
            document.getElementById('avg-cves-per-day').textContent = avgCvesPerDay;

            // Calculate YTD growth rate (current year YTD vs same period last year)
            const prevYearData = results.find(r => r.year === currentYear - 1);
            const prevYearCount = prevYearData ? prevYearData.count : 0;

            if (prevYearCount > 0) {
                // Calculate same period last year (YTD comparison)
                const dayOfYear = Math.floor((new Date() - new Date(currentYear, 0, 0)) / (1000 * 60 * 60 * 24));
                const yearProgress = dayOfYear / 365; // Approximate year progress
                const prevYearYtdEstimate = Math.round(prevYearCount * yearProgress);

                const growthRate = prevYearYtdEstimate > 0 ? ((cvesThisYear - prevYearYtdEstimate) / prevYearYtdEstimate) * 100 : 0;
                const growthText = growthRate >= 0 ? `+${growthRate.toFixed(1)}%` : `${growthRate.toFixed(1)}%`;
                document.getElementById('growth-rate').textContent = growthText;
                document.getElementById('growth-detail').textContent = `${cvesThisYear.toLocaleString()} vs ${prevYearYtdEstimate.toLocaleString()} (YTD vs Same Period ${currentYear - 1})`;
            } else {
                document.getElementById('growth-rate').textContent = 'N/A';
                document.getElementById('growth-detail').textContent = 'No previous year data';
            }
        } catch (error) {
            console.error('Error updating statistics:', error);
            updateStatisticsError();
        }
    }

    function updateStatisticsError() {
        document.getElementById('total-cves').textContent = 'Error';
        document.getElementById('cves-this-year').textContent = 'Error';
        document.getElementById('avg-cves-per-day').textContent = 'Error';
        document.getElementById('growth-rate').textContent = 'Error';
        document.getElementById('growth-detail').textContent = 'Error loading data';
    }

    function createChart() {
        new Chart(ctx, {
            type: 'line',
            data: yearlyData,
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    title: {
                        display: true,
                        text: 'CVE Publications by Year',
                        font: {
                            size: 16,
                            weight: 'bold'
                        }
                    },
                    legend: {
                        display: false
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Number of CVEs'
                        },
                        grid: {
                            color: 'rgba(0, 0, 0, 0.1)'
                        }
                    },
                    x: {
                        title: {
                            display: true,
                            text: 'Year'
                        },
                        grid: {
                            color: 'rgba(0, 0, 0, 0.1)'
                        }
                    }
                },
                elements: {
                    point: {
                        radius: 4,
                        hoverRadius: 6
                    }
                }
            }
        });
    }
}

// Initialize preview charts with simplified, error-free approach
function initializeSimplePreviewCharts() {
    // Growth Preview Chart
    initializeGrowthPreview();

    // CVSS Preview Chart (temporarily disabled)
    initializeCvssPreview();

    // CWE Preview Chart
    initializeCwePreview();

    // CNA Preview Chart
    initializeCnaPreview();

    // CPE Preview Chart
    initializeCpePreview();

    // Forecast Preview Chart
    initializeForecastPreview();

    // CNA Scorecard Preview Chart
    initializeCnaScorecardPreview();
}

function initializeGrowthPreview() {
    const ctx = document.getElementById('growthPreviewChart');
    if (!ctx) return;

    fetch('data/growth_analysis.json')
        .then(response => response.json())
        .then(data => {
            const growthData = data.growth_data || [];
            const currentYear = new Date().getFullYear();
            const filteredData = growthData.filter(item => item.year !== currentYear);

            const labels = filteredData.map(item => item.year.toString());
            const values = filteredData.map(item => item.growth_rate || 0);

            new Chart(ctx, {
                type: 'line',
                data: {
                    labels: labels,
                    datasets: [{
                        data: values,
                        borderColor: '#5a9bd4',
                        backgroundColor: 'rgba(90, 155, 212, 0.1)',
                        fill: true,
                        tension: 0.4
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
            console.error('Growth preview error:', error);
            ctx.parentElement.innerHTML = '<div class="text-center text-muted py-4"><small>Preview unavailable</small></div>';
        });
}

function initializeCnaScorecardPreview() {
    const ctx = document.getElementById('cnaScorecardPreviewChart');
    if (!ctx) return;

    // Sample CNA Scorecard data
    const scorecardData = {
        labels: ['Microsoft', 'Google', 'Apple', 'Adobe', 'Oracle'],
        datasets: [{
            label: 'Scorecard Score',
            data: [95, 88, 92, 85, 90],
            backgroundColor: [
                window.CVE_COLORS.chartColors[0],
                window.CVE_COLORS.chartColors[1],
                window.CVE_COLORS.chartColors[2],
                window.CVE_COLORS.chartColors[3],
                window.CVE_COLORS.chartColors[4]
            ],
            borderColor: [
                window.CVE_COLORS.chartColors[0],
                window.CVE_COLORS.chartColors[1],
                window.CVE_COLORS.chartColors[2],
                window.CVE_COLORS.chartColors[3],
                window.CVE_COLORS.chartColors[4]
            ],
            borderWidth: 1
        }]
    };

    new Chart(ctx, {
        type: 'bar',
        data: scorecardData,
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                title: {
                    display: true,
                    text: 'Top CNA Scorecard Rankings',
                    font: { size: 14 }
                },
                legend: {
                    display: false
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    max: 100,
                    title: {
                        display: true,
                        text: 'Scorecard Score'
                    },
                    grid: {
                        color: 'rgba(0,0,0,0.1)'
                    }
                },
                x: {
                    title: {
                        display: true,
                        text: 'CNA Organization'
                    },
                    grid: {
                        color: 'rgba(0,0,0,0.1)'
                    }
                }
            }
        }
    });
}
