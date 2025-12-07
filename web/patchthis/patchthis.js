/**
 * PatchThis Website JavaScript
 * Handles interactive features and animations
 */

// Initialize the application when DOM is loaded
document.addEventListener('DOMContentLoaded', function () {
    initializeStatistics();
    initializeAnimations();
    initializeNavigation();
});

/**
 * Animate statistics counters
 */
function initializeStatistics() {
    const statsElements = [
        { id: 'patches-applied', target: 15420 },
        { id: 'vulnerabilities-fixed', target: 8934 },
        { id: 'uptime-percent', target: 99.9 },
        { id: 'compliance-score', target: 100 }
    ];

    statsElements.forEach(stat => {
        const element = document.getElementById(stat.id);
        if (element) {
            animateCounter(element, 0, stat.target, 2000);
        }
    });
}

/**
 * Animate counter from start to end value
 */
function animateCounter(element, start, end, duration) {
    let startTime = null;

    function animation(currentTime) {
        if (startTime === null) startTime = currentTime;
        const timeElapsed = currentTime - startTime;
        const progress = Math.min(timeElapsed / duration, 1);

        // Easing function for smooth animation
        const easeOutQuart = 1 - Math.pow(1 - progress, 4);

        let currentValue;
        if (typeof end === 'number' && end % 1 === 0) {
            // Integer value
            currentValue = Math.floor(start + (end - start) * easeOutQuart);
        } else {
            // Float value
            currentValue = (start + (end - start) * easeOutQuart).toFixed(1);
        }

        element.textContent = currentValue;

        if (progress < 1) {
            requestAnimationFrame(animation);
        } else {
            element.textContent = end;
        }
    }

    requestAnimationFrame(animation);
}

/**
 * Initialize scroll animations and interactions
 */
function initializeAnimations() {
    // Intersection Observer for fade-in animations
    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    };

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('animate-in');
            }
        });
    }, observerOptions);

    // Observe elements for animation
    const animateElements = document.querySelectorAll('.feature-card, .stat-item, .hero');
    animateElements.forEach(el => {
        el.style.opacity = '0';
        el.style.transform = 'translateY(20px)';
        el.style.transition = 'opacity 0.6s ease, transform 0.6s ease';
        observer.observe(el);
    });

    // Add animate-in styles
    const style = document.createElement('style');
    style.textContent = `
        .animate-in {
            opacity: 1 !important;
            transform: translateY(0) !important;
        }
    `;
    document.head.appendChild(style);
}

/**
 * Initialize navigation interactions
 */
function initializeNavigation() {
    // Add smooth scrolling for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });

    // Add active state management for navigation
    const currentPage = window.location.pathname.split('/').pop() || 'index.html';
    const navLinks = document.querySelectorAll('.nav a');

    navLinks.forEach(link => {
        const href = link.getAttribute('href');
        if (href === currentPage || (currentPage === '' && href === 'index.html')) {
            link.classList.add('active');
        }
    });
}

/**
 * Utility function to format numbers
 */
function formatNumber(num) {
    if (num >= 1000000) {
        return (num / 1000000).toFixed(1) + 'M';
    } else if (num >= 1000) {
        return (num / 1000).toFixed(1) + 'K';
    }
    return num.toString();
}

/**
 * Show loading state for dynamic content
 */
function showLoading(containerId) {
    const container = document.getElementById(containerId);
    if (container) {
        container.innerHTML = '<div class="loading"><div class="spinner"></div>Loading...</div>';
    }
}

/**
 * Hide loading state
 */
function hideLoading(containerId) {
    const container = document.getElementById(containerId);
    if (container) {
        const loading = container.querySelector('.loading');
        if (loading) {
            loading.remove();
        }
    }
}
