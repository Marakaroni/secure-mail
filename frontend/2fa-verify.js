// 2fa-verify.js
document.getElementById('verify2FAForm').addEventListener('submit', async (e) => {
    e.preventDefault();

    const totp = document.getElementById('totp').value;
    const mfaToken = sessionStorage.getItem('login_mfa_token');

    if (!mfaToken) {
        window.location.href = 'login.html';
        return;
    }

    const errorDiv = document.getElementById('errorMessage');
    errorDiv.classList.remove('show');

    try {
        const btn = e.target.querySelector('button[type="submit"]');
        btn.classList.add('loading');
        btn.disabled = true;

        await api.verify2FA(mfaToken, totp);

        // Clear session storage
        sessionStorage.removeItem('login_email');
        sessionStorage.removeItem('login_mfa_token');

        // Redirect to inbox
        setTimeout(() => {
            window.location.href = 'inbox.html';
        }, 500);
    } catch (error) {
        errorDiv.textContent = `✗ Błąd: ${error.message}`;
        errorDiv.classList.add('show');
        
        const btn = e.target.querySelector('button[type="submit"]');
        btn.classList.remove('loading');
        btn.disabled = false;
    }
});
