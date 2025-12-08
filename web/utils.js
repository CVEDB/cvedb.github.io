/**
 * Utility functions and color definitions for CVE Database Dashboard
 */

// Enhanced Color palette for consistent styling (Light Blue to Grey)
window.CVE_COLORS = window.CVE_COLORS || {
    primary: '#2196f3',
    secondary: '#64b5f6',
    success: '#81c784',
    warning: '#ffb74d',
    danger: '#f06292',
    light: '#f8f9fa',
    dark: '#212529',

    // Light Blue to Grey Visualization Palette
    vizColors: [
        '#e3f2fd', // Very light blue
        '#bbdefb', // Light blue
        '#90caf9', // Medium light blue
        '#64b5f6', // Medium blue
        '#42a5f5', // Blue
        '#2196f3', // Primary blue
        '#1e88e5', // Darker blue
        '#1976d2', // Dark blue
        '#9e9e9e', // Medium grey
        '#757575'  // Dark grey
    ],

    // Chart-specific colors
    chartColors: [
        '#2196f3', // Primary blue
        '#64b5f6', // Secondary blue
        '#90caf9', // Tertiary blue
        '#bbdefb', // Quaternary blue
        '#81c784', // Accent green
        '#ffb74d', // Accent orange
        '#f06292', // Accent pink
        '#e0e0e0', // Light grey
        '#9e9e9e', // Medium grey
        '#616161'  // Dark grey
    ],

    // Gradient colors for backgrounds
    gradients: {
        primary: 'linear-gradient(135deg, #e3f2fd, #bbdefb)',
        secondary: 'linear-gradient(135deg, #bbdefb, #90caf9)',
        tertiary: 'linear-gradient(135deg, #90caf9, #64b5f6)'
    }
};

// Enhanced utility function to generate colors for charts
function getChartColors(count, type = 'chart') {
    const colors = [];
    const palette = type === 'viz' ? CVE_COLORS.vizColors : CVE_COLORS.chartColors;

    for (let i = 0; i < count; i++) {
        colors.push(palette[i % palette.length]);
    }
    return colors;
}

// Generate light blue to grey gradient colors
function getGradientColors(count) {
    const colors = [];
    for (let i = 0; i < count; i++) {
        const ratio = i / Math.max(count - 1, 1);
        // Interpolate between light blue and grey
        const r = Math.round(227 + (158 - 227) * ratio); // e3 to 9e
        const g = Math.round(242 + (158 - 242) * ratio); // f2 to 9e
        const b = Math.round(253 + (158 - 253) * ratio); // fd to 9e
        colors.push(`rgb(${r}, ${g}, ${b})`);
    }
    return colors;
}

// Get color with opacity
function getColorWithOpacity(color, opacity = 0.8) {
    if (color.startsWith('#')) {
        const r = parseInt(color.slice(1, 3), 16);
        const g = parseInt(color.slice(3, 5), 16);
        const b = parseInt(color.slice(5, 7), 16);
        return `rgba(${r}, ${g}, ${b}, ${opacity})`;
    }
    return color;
}

// Utility function to format numbers
function formatNumber(num) {
    if (num >= 1000000) {
        return (num / 1000000).toFixed(1) + 'M';
    } else if (num >= 1000) {
        return (num / 1000).toFixed(1) + 'K';
    }
    return num.toString();
}

// Utility function to show loading state
function showLoading(containerId) {
    const container = document.getElementById(containerId);
    if (container) {
        container.innerHTML = '<div class="loading"><div class="spinner"></div>Loading data...</div>';
    }
}

// Utility function to hide loading state
function hideLoading(containerId) {
    const container = document.getElementById(containerId);
    if (container) {
        const loading = container.querySelector('.loading');
        if (loading) {
            loading.remove();
        }
    }
}

// Get current year for dynamic functionality
const CURRENT_YEAR = new Date().getFullYear();
const AVAILABLE_YEARS = [];
for (let year = 1999; year <= CURRENT_YEAR; year++) {
    AVAILABLE_YEARS.push(year);
}
