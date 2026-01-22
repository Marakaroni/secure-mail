// 2fa-setup.js
let setupData = null;

async function initSetup() {
    const email = sessionStorage.getItem('register_email');
    const password = sessionStorage.getItem('register_password');

    if (!email || !password) {
        document.getElementById('errorMessage').textContent = '✗ Brak danych rejestracji. Wróć do rejestracji.';
        document.getElementById('errorMessage').classList.add('show');
        return;
    }

    try {
        setupData = await api.setup2FA(email, password);
        
        // Display secret
        document.getElementById('secretCode').textContent = setupData.secret;

        // Generate QR code
        if (typeof QRCode !== 'undefined' && QRCode.toCanvas) {
            const canvas = document.getElementById('qrCode');
            await QRCode.toCanvas(canvas, setupData.provisioning_uri, {
                errorCorrectionLevel: 'H',
                type: 'image/png',
                quality: 0.95,
                margin: 1,
                width: 200,
                color: {
                    dark: '#000000',
                    light: '#ffffff'
                }
            });
        }
    } catch (error) {
        document.getElementById('errorMessage').textContent = `✗ Błąd: ${error.message}`;
        document.getElementById('errorMessage').classList.add('show');
    }
}

document.getElementById('setup2FAForm').addEventListener('submit', async (e) => {
    e.preventDefault();

    const totp = document.getElementById('totp').value;
    const email = sessionStorage.getItem('register_email');
    const password = sessionStorage.getItem('register_password');

    const errorDiv = document.getElementById('errorMessage');
    errorDiv.classList.remove('show');

    try {
        const btn = e.target.querySelector('button[type="submit"]');
        btn.classList.add('loading');
        btn.disabled = true;

        await api.enable2FA(email, password, totp);

        // Store credentials for login
        sessionStorage.removeItem('register_email');
        sessionStorage.removeItem('register_password');

        alert('✓ 2FA aktywowana! Teraz możesz się zalogować.');
        window.location.href = 'login.html';
    } catch (error) {
        errorDiv.textContent = `✗ Błąd: ${error.message}`;
        errorDiv.classList.add('show');
        
        const btn = e.target.querySelector('button[type="submit"]');
        btn.classList.remove('loading');
        btn.disabled = false;
    }
});

// Initialize on page load
window.addEventListener('load', initSetup);
