// login.js
document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();

    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;

    const errorDiv = document.getElementById('errorMessage');
    errorDiv.classList.remove('show');

    try {
        const btn = e.target.querySelector('button[type="submit"]');
        btn.classList.add('loading');
        btn.disabled = true;

        const response = await api.login(email, password);

        if (response.requires_2fa) {
            // Store email and mfa_token for 2FA verification
            sessionStorage.setItem('login_email', email);
            sessionStorage.setItem('login_mfa_token', response.mfa_token);
            
            // Redirect to 2FA verification
            setTimeout(() => {
                window.location.href = '2fa-verify.html';
            }, 500);
        } else {
            // No 2FA, logged in successfully
            setTimeout(() => {
                window.location.href = 'inbox.html';
            }, 500);
        }
    } catch (error) {
        errorDiv.textContent = `✗ Błąd: ${error.message}`;
        errorDiv.classList.add('show');
        
        const btn = e.target.querySelector('button[type="submit"]');
        btn.classList.remove('loading');
        btn.disabled = false;
    }
});
