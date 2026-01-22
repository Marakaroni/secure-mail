// inbox.js
let currentView = 'inbox';

// Check if user is logged in
if (!api.isLoggedIn()) {
    window.location.href = 'login.html';
}

// Navigation
document.querySelectorAll('.sidebar-item').forEach(btn => {
    btn.addEventListener('click', (e) => {
        const page = e.target.dataset.page;
        
        if (page === 'logout') {
            logout();
            return;
        }

        // Update active button
        document.querySelectorAll('.sidebar-item').forEach(b => b.classList.remove('active'));
        e.target.classList.add('active');

        // Show view
        showView(page);
    });
});

function showView(view) {
    currentView = view;

    document.getElementById('inboxView').style.display = 'none';
    document.getElementById('composeView').style.display = 'none';
    document.getElementById('messageView').style.display = 'none';

    if (view === 'inbox') {
        document.getElementById('inboxView').style.display = 'block';
        loadMessages();
    } else if (view === 'compose') {
        document.getElementById('composeView').style.display = 'block';
    }
}

async function loadUserInfo() {
    try {
        const user = await api.getCurrentUser();
        if (user) {
            document.getElementById('userInfo').textContent = `Zalogowany jako: ${user.email}`;
        }
    } catch (error) {
        console.error('Error loading user info:', error);
    }
}

async function loadMessages() {
    const messageList = document.getElementById('messageList');
    
    try {
        const messages = await api.getInbox();
        
        if (!messages || messages.length === 0) {
            messageList.innerHTML = '<li style="padding: 20px; text-align: center; color: var(--gray-500);">Brak wiadomości</li>';
            return;
        }

        messageList.innerHTML = messages.map(msg => `
            <li class="message-item ${msg.read ? '' : 'unread'}" onclick="viewMessage(${msg.id})">
                <div class="message-from">📨 ${msg.sender_username || 'Nieznany'}</div>
                <div class="message-subject">${msg.subject}</div>
                <div class="message-date">${new Date(msg.created_at).toLocaleString('pl-PL')}</div>
            </li>
        `).join('');
    } catch (error) {
        messageList.innerHTML = `<li style="padding: 20px; color: var(--danger);">Błąd: ${error.message}</li>`;
    }
}

async function viewMessage(messageId) {
    try {
        const message = await api.getMessage(messageId);
        
        // Mark as read
        if (!message.read) {
            await api.markAsRead(messageId);
        }

        const messageView = document.getElementById('messageView');
        const messageDetail = document.getElementById('messageDetail');

        // Build attachments HTML
        let attachmentsHTML = '';
        if (message.attachments && message.attachments.length > 0) {
            attachmentsHTML = `
                <div style="margin-top: 20px; padding: 15px; background: var(--gray-100); border-radius: 6px;">
                    <h3 style="margin-top: 0; margin-bottom: 10px;">📎 Załączniki (${message.attachments.length}):</h3>
                    <ul style="list-style: none; padding: 0; margin: 0;">
                        ${message.attachments.map(att => `
                            <li style="padding: 8px 0; border-bottom: 1px solid var(--gray-300); display: flex; justify-content: space-between; align-items: center;">
                                <span>📄 ${att.filename} (${(att.size_bytes / 1024).toFixed(1)} KB)</span>
                                <button class="btn-secondary" onclick="downloadAttachment(${att.id}, '${att.filename}')">Pobierz</button>
                            </li>
                        `).join('')}
                    </ul>
                </div>
            `;
        }

        messageDetail.innerHTML = `
            <div class="detail-header">
                <div class="detail-from">Nadawca: ${message.sender_username || 'Nieznany'}</div>
                <div class="detail-subject">${message.subject}</div>
                <div class="detail-date">${new Date(message.created_at).toLocaleString('pl-PL')}</div>
            </div>
            <div class="detail-body">${message.body || '(Zaszyfrowana wiadomość)'}</div>
            ${attachmentsHTML}
            <div style="margin-top: 20px; display: flex; gap: 10px;">
                <button class="btn-danger" onclick="deleteMessage(${messageId})">Usuń</button>
                <button class="btn-secondary" onclick="backToInbox()">Wróć</button>
            </div>
        `;

        messageView.style.display = 'block';
        document.getElementById('inboxView').style.display = 'none';
        document.getElementById('composeView').style.display = 'none';
    } catch (error) {
        alert(`Błąd: ${error.message}`);
    }
}

async function deleteMessage(messageId) {
    if (!confirm('Czy na pewno chcesz usunąć tę wiadomość?')) return;

    try {
        await api.deleteMessage(messageId);
        backToInbox();
        loadMessages();
    } catch (error) {
        alert(`Błąd: ${error.message}`);
    }
}

function backToInbox() {
    document.getElementById('messageView').style.display = 'none';
    document.getElementById('inboxView').style.display = 'block';
    loadMessages();
}

async function downloadAttachment(attachmentId, filename) {
    try {
        const response = await api.downloadAttachment(attachmentId);
        // Create blob from base64
        const byteCharacters = atob(response.data_base64);
        const byteNumbers = new Array(byteCharacters.length);
        for (let i = 0; i < byteCharacters.length; i++) {
            byteNumbers[i] = byteCharacters.charCodeAt(i);
        }
        const byteArray = new Uint8Array(byteNumbers);
        const blob = new Blob([byteArray], { type: response.mime_type });
        
        // Create download link
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = response.filename || filename;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
    } catch (error) {
        alert(`Błąd przy pobraniu: ${error.message}`);
    }
}

// Attachments preview
document.getElementById('attachments').addEventListener('change', (e) => {
    const files = e.target.files;
    const attachmentsList = document.getElementById('attachmentsList');
    
    if (files.length === 0) {
        attachmentsList.innerHTML = '';
        return;
    }

    attachmentsList.innerHTML = Array.from(files).map((file, idx) => `
        <div style="padding: 8px; background: var(--gray-200); border-radius: 4px; margin-bottom: 5px; display: flex; justify-content: space-between; align-items: center;">
            <span>📎 ${file.name} (${(file.size / 1024).toFixed(1)} KB)</span>
            <button type="button" class="btn-small" onclick="removeAttachment(${idx})">✕</button>
        </div>
    `).join('');
});

function removeAttachment(index) {
    const input = document.getElementById('attachments');
    const dataTransfer = new DataTransfer();
    Array.from(input.files).forEach((file, idx) => {
        if (idx !== index) dataTransfer.items.add(file);
    });
    input.files = dataTransfer.files;
    input.dispatchEvent(new Event('change', { bubbles: true }));
}

// Recipients autocomplete
let recipients = [];
document.getElementById('toEmail').addEventListener('focus', async () => {
    if (recipients.length === 0) {
        recipients = await api.getAvailableRecipients();
    }
    showRecipientsList('');
});

document.getElementById('toEmail').addEventListener('input', (e) => {
    showRecipientsList(e.target.value.toLowerCase());
});

function showRecipientsList(filter) {
    const list = document.getElementById('recipientsList');
    if (recipients.length === 0) {
        list.style.display = 'none';
        return;
    }

    const filtered = recipients.filter(r => 
        r.email.toLowerCase().includes(filter) || 
        r.username.toLowerCase().includes(filter)
    );

    if (filtered.length === 0) {
        list.innerHTML = '<div style="padding: 10px; color: var(--gray-500);">Brak wyników</div>';
    } else {
        list.innerHTML = filtered.map(r => `
            <div style="padding: 10px; border-bottom: 1px solid var(--gray-200); cursor: pointer; hover: background-color: var(--gray-100);" onclick="selectRecipient('${r.email}')">
                <strong>${r.username}</strong><br>
                <small style="color: var(--gray-500);">${r.email}</small>
            </div>
        `).join('');
    }
    list.style.display = filtered.length > 0 ? 'block' : 'none';
}

function selectRecipient(email) {
    document.getElementById('toEmail').value = email;
    document.getElementById('recipientsList').style.display = 'none';
}

// Compose form
document.getElementById('composeForm').addEventListener('submit', async (e) => {
    e.preventDefault();

    const toEmail = document.getElementById('toEmail').value;
    const subject = document.getElementById('subject').value;
    const body = document.getElementById('body').value;
    const files = document.getElementById('attachments').files;

    console.log('DEBUG: Form data:', { toEmail, subject, body, fileCount: files.length });

    const errorDiv = document.getElementById('composeError');
    const successDiv = document.getElementById('composeSuccess');
    
    errorDiv.classList.remove('show');
    successDiv.classList.remove('show');

    try {
        const btn = e.target.querySelector('button[type="submit"]');
        btn.classList.add('loading');
        btn.disabled = true;

        // 1. Send message first
        const messageResult = await api.sendMessage(toEmail, subject, body);
        const messageId = messageResult.message_id;

        // 2. Upload attachments if any
        if (files.length > 0) {
            for (let file of files) {
                try {
                    await api.uploadAttachment(messageId, file);
                } catch (error) {
                    console.warn(`Failed to upload ${file.name}:`, error);
                }
            }
        }

        successDiv.textContent = `✓ Wiadomość wysłana${files.length > 0 ? ` z ${files.length} załącznikami` : ''}!`;
        successDiv.classList.add('show');

        // Reset form
        e.target.reset();
        document.getElementById('attachmentsList').innerHTML = '';

        // Return to inbox after 2 seconds
        setTimeout(() => {
            showView('inbox');
        }, 2000);
    } catch (error) {
        errorDiv.textContent = `✗ Błąd: ${error.message}`;
        errorDiv.classList.add('show');
        
        const btn = e.target.querySelector('button[type="submit"]');
        btn.classList.remove('loading');
        btn.disabled = false;
    }
});

async function logout() {
    try {
        await api.logout();
        window.location.href = 'login.html';
    } catch (error) {
        console.error('Logout error:', error);
        // Force logout anyway
        localStorage.clear();
        sessionStorage.clear();
        window.location.href = 'login.html';
    }
}

// Initialize
window.addEventListener('load', () => {
    loadUserInfo();
    showView('inbox');
});
