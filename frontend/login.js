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
            sessionStorage.setItem('login_email', email);
            sessionStorage.setItem('login_mfa_token', response.mfa_token);
            
            setTimeout(() => {
                window.location.href = '2fa-verify.html';
            }, 500);
        } else {
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
