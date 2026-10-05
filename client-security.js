(function (root) {
    function escapeHTML(value) {
        return String(value ?? '').replace(/[&<>"']/g, character => ({
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#39;'
        })[character]);
    }

    function safeHttpUrl(value) {
        try {
            const url = new URL(String(value ?? ''));
            return url.protocol === 'http:' || url.protocol === 'https:' ? url.href : '';
        } catch {
            return '';
        }
    }

    function parseJSON(value, fallback = null) {
        try {
            return JSON.parse(value);
        } catch {
            return fallback;
        }
    }

    const security = { escapeHTML, safeHttpUrl, parseJSON };
    if (root) root.CyberPaySecurity = security;
    if (typeof module !== 'undefined' && module.exports) module.exports = security;
})(typeof window === 'undefined' ? globalThis : window);