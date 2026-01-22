document.getElementById('registerForm').addEventListener('submit', async (e) => {
    e.preventDefault();

    const username = document.getElementById('username').value;
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;

    const errorDiv = document.getElementById('errorMessage');
    const successDiv = document.getElementById('successMessage');
    
    errorDiv.classList.remove('show');
    successDiv.classList.remove('show');

    try {
        const btn = e.target.querySelector('button[type="submit"]');
        btn.classList.add('loading');
        btn.disabled = true;

        await api.register(username, email, password);

        successDiv.textContent = '✓ Konto utworzone! Przechodzę do setup 2FA...';
        successDiv.classList.add('show');

        sessionStorage.setItem('register_email', email);
        sessionStorage.setItem('register_password', password);

        setTimeout(() => {
            window.location.href = '2fa-setup.html';
        }, 2000);
    } catch (error) {
        errorDiv.textContent = `✗ Błąd: ${error.message}`;
        errorDiv.classList.add('show');
        
        const btn = e.target.querySelector('button[type="submit"]');
        btn.classList.remove('loading');
        btn.disabled = false;
    }
});
