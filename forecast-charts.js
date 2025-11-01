/**
 * CVE Forecast Charts and Data Visualization
 */

// Initialize forecast dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', function () {
    if (typeof Chart === 'undefined') {
        console.error('Chart.js not loaded');
        return;
    }

    // Initialize main forecast chart
    initializeMainForecastChart();

    // Initialize model performance chart
    initializeModelPerformanceChart();

    // Initialize trend analysis chart
    initializeTrendAnalysisChart();
});

function initializeMainForecastChart() {
    const ctx = document.getElementById('mainForecastChart');
    if (!ctx) return;

    // Sample historical and forecast data
    const forecastData = {
        labels: ['Jan 2024', 'Feb 2024', 'Mar 2024', 'Apr 2024', 'May 2024', 'Jun 2024',
                 'Jul 2024', 'Aug 2024', 'Sep 2024', 'Oct 2024', 'Nov 2024', 'Dec 2024',
                 'Jan 2025', 'Feb 2025', 'Mar 2025'],
        datasets: [{
            label: 'Historical CVEs',
            data: [2200, 2100, 2400, 2300, 2500, 2600, 2700, 2800, 2900, 3000, 3100, 3200, null, null, null],
            borderColor: window.CVE_COLORS.primary,
            backgroundColor: 'rgba(33, 150, 243, 0.1)',
            fill: false,
            tension: 0.1,
            pointRadius: 4
        }, {
            label: 'Forecast CVEs',
            data: [null, null, null, null, null, null, null, null, null, null, null, null, 3300, 3400, 3500],
            borderColor: window.CVE_COLORS.warning,
            backgroundColor: 'rgba(255, 193, 7, 0.1)',
            fill: false,
            tension: 0.1,
            pointRadius: 4,
            borderDash: [5, 5]
        }]
    };

    new Chart(ctx, {
        type: 'line',
        data: forecastData,
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                title: {
                    display: true,
                    text: 'CVE Publication Forecast (12-Month Horizon)',
                    font: { size: 16, weight: 'bold' }
                },
                legend: {
                    display: true,
                    position: 'top'
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
                        text: 'Month'
                    },
                    grid: {
                        color: 'rgba(0, 0, 0, 0.1)'
                    }
                }
            },
            elements: {
                point: {
                    hoverRadius: 6
                }
            }
        }
    });
}

function initializeModelPerformanceChart() {
    const ctx = document.getElementById('modelPerformanceChart');
    if (!ctx) return;

    const performanceData = {
        labels: ['ARIMA', 'SARIMA', 'Prophet', 'LSTM', 'XGBoost'],
        datasets: [{
            label: 'MAE (Mean Absolute Error)',
            data: [150, 120, 180, 90, 110],
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
        data: performanceData,
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                title: {
                    display: true,
                    text: 'Model Performance Comparison',
                    font: { size: 16, weight: 'bold' }
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
                        text: 'Mean Absolute Error'
                    },
                    grid: {
                        color: 'rgba(0, 0, 0, 0.1)'
                    }
                },
                x: {
                    title: {
                        display: true,
                        text: 'Model'
                    },
                    grid: {
                        color: 'rgba(0, 0, 0, 0.1)'
                    }
                }
            }
        }
    });
}

function initializeTrendAnalysisChart() {
    const ctx = document.getElementById('trendAnalysisChart');
    if (!ctx) return;

    const trendData = {
        labels: ['2019', '2020', '2021', '2022', '2023', '2024'],
        datasets: [{
            label: 'Yearly Growth Rate (%)',
            data: [8.5, 12.3, 15.7, 18.2, 22.1, 25.8],
            borderColor: window.CVE_COLORS.success,
            backgroundColor: 'rgba(129, 199, 132, 0.1)',
            fill: true,
            tension: 0.4
        }]
    };

    new Chart(ctx, {
        type: 'line',
        data: trendData,
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                title: {
                    display: true,
                    text: 'CVE Publication Growth Trends',
                    font: { size: 16, weight: 'bold' }
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
                        text: 'Growth Rate (%)'
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
                    radius: 5,
                    hoverRadius: 7
                }
            }
        }
    });
}
