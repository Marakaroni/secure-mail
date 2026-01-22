// api.js - Common API Module
const API_BASE = 'https://localhost';

class SecureMailAPI {
    constructor() {
        this.token = localStorage.getItem('auth_token');
        this.csrfToken = localStorage.getItem('csrf_token');
        this.mfaToken = localStorage.getItem('mfa_token');
    }

    // Initialize CSRF token at startup
    async initCSRF() {
        try {
            const response = await fetch(`${API_BASE}/auth/csrf-token`);
            const data = await response.json();
            if (data.csrf_token) {
                this.csrfToken = data.csrf_token;
                localStorage.setItem('csrf_token', this.csrfToken);
            }
        } catch (error) {
            console.warn('Failed to fetch CSRF token:', error);
        }
    }

    // Helper for API requests
    async request(method, endpoint, data = null) {
        const url = `${API_BASE}${endpoint}`;
        const options = {
            method,
            headers: {
                'Content-Type': 'application/json',
            },
        };

        // Add auth token if available
        if (this.token) {
            options.headers['Authorization'] = `Bearer ${this.token}`;
        }

        // Add CSRF token for state-changing operations
        if (this.csrfToken && ['POST', 'PUT', 'DELETE', 'PATCH'].includes(method)) {
            options.headers['X-CSRF-Token'] = this.csrfToken;
        }

        if (data) {
            options.body = JSON.stringify(data);
        }

        const response = await fetch(url, options);
        const contentType = response.headers.get('content-type');
        
        let responseData;
        if (contentType && contentType.includes('application/json')) {
            responseData = await response.json();
        } else {
            responseData = await response.text();
        }

        if (!response.ok) {
            throw new Error(responseData.detail || `HTTP ${response.status}`);
        }

        // Store CSRF token from response if available
        if (responseData.csrf_token) {
            this.csrfToken = responseData.csrf_token;
            localStorage.setItem('csrf_token', this.csrfToken);
        }

        return responseData;
    }

    // Auth endpoints
    async register(username, email, password) {
        return this.request('POST', '/auth/register', { username, email, password });
    }

    async login(email, password) {
        const response = await this.request('POST', '/auth/login', { email, password });
        
        if (response.access_token) {
            this.token = response.access_token;
            localStorage.setItem('auth_token', this.token);
        }
        if (response.csrf_token) {
            this.csrfToken = response.csrf_token;
            localStorage.setItem('csrf_token', this.csrfToken);
        }
        if (response.mfa_token) {
            this.mfaToken = response.mfa_token;
            localStorage.setItem('mfa_token', this.mfaToken);
        }
        
        return response;
    }

    async setup2FA(email, password) {
        return this.request('POST', '/auth/2fa/setup', { email, password });
    }

    async enable2FA(email, password, code) {
        return this.request('POST', '/auth/2fa/enable', { email, password, code });
    }

    async verify2FA(mfaToken, code) {
        const response = await this.request('POST', '/auth/2fa/verify', {
            mfa_token: mfaToken,
            code
        });
        
        if (response.access_token) {
            this.token = response.access_token;
            localStorage.setItem('auth_token', this.token);
        }
        
        return response;
    }

    async logout() {
        try {
            await this.request('POST', '/auth/logout');
        } finally {
            localStorage.removeItem('auth_token');
            localStorage.removeItem('csrf_token');
            localStorage.removeItem('mfa_token');
            this.token = null;
            this.csrfToken = null;
            this.mfaToken = null;
        }
    }

    // Message endpoints
    async getInbox() {
        return this.request('GET', '/messages/inbox');
    }

    async getMessage(messageId) {
        return this.request('GET', `/messages/inbox/${messageId}`);
    }

    async sendMessage(toUsername, subject, body) {
        // Backend expects recipients as list of usernames/emails
        return this.request('POST', '/messages/send', {
            recipients: [toUsername],
            subject: subject,
            body: body
        });
    }

    async uploadAttachment(messageId, file) {
        // This endpoint requires special handling (FormData, not JSON)
        const url = `${API_BASE}/messages/attachments/upload?message_id=${messageId}`;
        const formData = new FormData();
        formData.append('file', file);

        const options = {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${this.token}`,
                'X-CSRF-Token': this.csrfToken,
            },
            body: formData,
        };

        const response = await fetch(url, options);
        const responseData = await response.json();

        if (!response.ok) {
            throw new Error(responseData.detail || `HTTP ${response.status}`);
        }

        return responseData;
    }

    async downloadAttachment(attachmentId) {
        return this.request('GET', `/messages/attachments/${attachmentId}/download`);
    }

    async markAsRead(messageId) {
        return this.request('PUT', `/messages/inbox/${messageId}/read`);
    }

    async deleteMessage(messageId) {
        return this.request('DELETE', `/messages/inbox/${messageId}`);
    }

    async getCurrentUser() {
        try {
            return await this.request('GET', '/auth/me');
        } catch (error) {
            return null;
        }
    }

    async getAvailableRecipients() {
        try {
            return await this.request('GET', '/auth/users');
        } catch (error) {
            return [];
        }
    }

    isLoggedIn() {
        return !!localStorage.getItem('auth_token');
    }

    hasMFAPending() {
        return !!localStorage.getItem('mfa_token');
    }
}

// Global API instance
const api = new SecureMailAPI();
