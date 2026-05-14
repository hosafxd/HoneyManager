
// API Configuration
const API_BASE = '/api';

// State
let refreshInterval = null;
let alertFilter = 'all';
let currentUserRole = 'viewer'; // default lowest auth
let currentUsername = '';

// Chart instances
let timelineChart = null;
let honeypotChart = null;

function formatTimestamp(timestamp) {
    if (!timestamp) return 'N/A';
    const date = new Date(timestamp);
    return date.toLocaleTimeString('en-US', {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    });
}

function formatDate(timestamp) {
    if (!timestamp) return 'N/A';
    const date = new Date(timestamp);
    return date.toLocaleDateString('en-US', {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;

    const icons = {
        success: '✅',
        error: '❌',
        info: 'ℹ️',
        warning: '⚠️'
    };

    toast.innerHTML = `
        <span class="toast-icon">${icons[type] || icons.info}</span>
        <span class="toast-message">${message}</span>
    `;

    container.appendChild(toast);

    setTimeout(() => {
        toast.style.animation = 'toastIn 0.3s ease reverse';
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

async function apiCall(endpoint, options = {}) {
    try {
        const response = await fetch(`${API_BASE}${endpoint}`, {
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            },
            ...options
        });

        if (response.status === 401) {
            // shows overlay if the user isn't logged in and stops the process
            document.getElementById('login-overlay').style.display = 'flex';
            return null; 
        }

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'API request failed');
        }

        return data;
    } catch (error) {
        console.error('API Error:', error);
        throw error;
    }
}

// ============================================
// Dashboard Stats
// ============================================

async function loadStats() {
    try {
        const data = await apiCall('/stats');

        if (data.success) {
            const alerts = data.alerts;

            document.getElementById('stat-critical').textContent = alerts.critical || 0;
            document.getElementById('stat-high').textContent = alerts.high || 0;
            document.getElementById('stat-medium').textContent = alerts.medium || 0;
            document.getElementById('stat-low').textContent = alerts.low || 0;
            document.getElementById('stat-total').textContent = alerts.total_24h || 0;
            document.getElementById('stat-ips').textContent = alerts.unique_ips_24h || 0;

            // Update honeypot chart with by_honeypot data
            if (honeypotChart && alerts.by_honeypot) {
                const labels = Object.keys(alerts.by_honeypot);
                const values = Object.values(alerts.by_honeypot);
                const bgPalette     = ['rgba(0,255,65,0.3)', 'rgba(0,212,255,0.3)', 'rgba(191,0,255,0.3)', 'rgba(255,102,0,0.3)'];
                const borderPalette = ['#00ff41', '#00d4ff', '#bf00ff', '#ff6600'];
                honeypotChart.data.labels = labels;
                honeypotChart.data.datasets[0].data = values;
                honeypotChart.data.datasets[0].backgroundColor = labels.map((_, i) => bgPalette[i % bgPalette.length]);
                honeypotChart.data.datasets[0].borderColor = labels.map((_, i) => borderPalette[i % borderPalette.length]);
                honeypotChart.update();
            }

            // Add animation effect for non-zero values
            document.querySelectorAll('.stat-card').forEach(card => {
                const value = parseInt(card.querySelector('.stat-value').textContent);
                if (value > 0) {
                    card.style.animation = 'none';
                    card.offsetHeight; // Trigger reflow
                    card.style.animation = 'pulse 0.5s ease';
                }
            });
        }
    } catch (error) {
        console.error('Failed to load stats:', error);
    }
}

// ============================================
// Charts
// ============================================

function initCharts() {
    if (typeof Chart === 'undefined') return;

    const gridColor = 'rgba(0, 212, 255, 0.06)';
    const tickColor = '#555';
    const monoFont = "'JetBrains Mono', monospace";
    const tooltipDefaults = {
        backgroundColor: 'rgba(5, 5, 8, 0.95)',
        borderColor: 'rgba(0, 212, 255, 0.3)',
        borderWidth: 1,
        titleColor: '#00d4ff',
        bodyColor: '#e0e0e0',
        titleFont: { family: monoFont, size: 11 },
        bodyFont: { family: monoFont, size: 11 }
    };

    const timelineCtx = document.getElementById('timeline-chart');
    if (timelineCtx) {
        timelineChart = new Chart(timelineCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [
                    { label: 'Critical', data: [], borderColor: '#ff0040', backgroundColor: 'rgba(255,0,64,0.12)',  borderWidth: 1.5, tension: 0.3, fill: true, pointRadius: 0, pointHoverRadius: 4 },
                    { label: 'High',     data: [], borderColor: '#ff6600', backgroundColor: 'rgba(255,102,0,0.08)', borderWidth: 1.5, tension: 0.3, fill: true, pointRadius: 0, pointHoverRadius: 4 },
                    { label: 'Medium',   data: [], borderColor: '#ffff00', backgroundColor: 'rgba(255,255,0,0.05)', borderWidth: 1.5, tension: 0.3, fill: true, pointRadius: 0, pointHoverRadius: 4 },
                    { label: 'Low',      data: [], borderColor: '#00d4ff', backgroundColor: 'rgba(0,212,255,0.05)', borderWidth: 1.5, tension: 0.3, fill: true, pointRadius: 0, pointHoverRadius: 4 }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: false,
                interaction: { mode: 'index', intersect: false },
                plugins: {
                    legend: {
                        position: 'top',
                        labels: { color: '#888', font: { family: monoFont, size: 10 }, boxWidth: 10, padding: 12 }
                    },
                    tooltip: tooltipDefaults
                },
                scales: {
                    x: { ticks: { color: tickColor, maxTicksLimit: 8, maxRotation: 0, font: { size: 10 } }, grid: { color: gridColor } },
                    y: { ticks: { color: tickColor, font: { size: 10 } }, grid: { color: gridColor }, beginAtZero: true }
                }
            }
        });
    }

    const honeypotCtx = document.getElementById('honeypot-chart');
    if (honeypotCtx) {
        const barBg     = ['rgba(0,255,65,0.3)', 'rgba(0,212,255,0.3)', 'rgba(191,0,255,0.3)', 'rgba(255,102,0,0.3)'];
        const barBorder = ['#00ff41', '#00d4ff', '#bf00ff', '#ff6600'];
        honeypotChart = new Chart(honeypotCtx, {
            type: 'bar',
            data: {
                labels: [],
                datasets: [{ label: 'Alerts', data: [], backgroundColor: barBg, borderColor: barBorder, borderWidth: 1 }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: false,
                animation: false,
                plugins: {
                    legend: { display: false },
                    tooltip: tooltipDefaults
                },
                scales: {
                    x: { ticks: { color: tickColor, font: { size: 10 } }, grid: { color: gridColor }, beginAtZero: true },
                    y: { ticks: { color: '#00d4ff', font: { family: monoFont, size: 10 } }, grid: { color: gridColor } }
                }
            }
        });
    }
}

async function loadCharts() {
    if (!timelineChart) return;
    try {
        const data = await apiCall('/stats/timeline');
        if (data && data.success) {
            const { labels, datasets } = data.timeline;
            timelineChart.data.labels = labels;
            timelineChart.data.datasets[0].data = datasets.critical;
            timelineChart.data.datasets[1].data = datasets.high;
            timelineChart.data.datasets[2].data = datasets.medium;
            timelineChart.data.datasets[3].data = datasets.low;
            timelineChart.update();
        }
    } catch (error) {
        console.error('Failed to load timeline chart:', error);
    }
}

// ============================================
// Honeypot Nodes
// ============================================

async function loadNodes() {
    const container = document.getElementById('nodes-grid');

    try {
        const data = await apiCall('/nodes');

        if (data.success && data.nodes.length > 0) {
            container.innerHTML = data.nodes.map(node => createNodeCard(node)).join('');

            // Attach event listeners
            container.querySelectorAll('.btn-stop').forEach(btn => {
                btn.addEventListener('click', () => stopNode(btn.dataset.id));
            });

            container.querySelectorAll('.btn-start').forEach(btn => {
                btn.addEventListener('click', () => startNode(btn.dataset.id));
            });

            container.querySelectorAll('.btn-delete').forEach(btn => {
                btn.addEventListener('click', () => deleteNode(btn.dataset.id, btn.dataset.name));
            });
        } else {
            container.innerHTML = `
                <div class="empty-state">
                    <p>🍯 No honeypots deployed yet</p>
                    <p>Click "Deploy New" to create your first honeypot</p>
                </div>
            `;
        }
    } catch (error) {
        container.innerHTML = `<div class="loading">Failed to load honeypots</div>`;
        showToast('Failed to load honeypots', 'error');
    }
}

function createNodeCard(node) {
    const isRunning = node.status === 'running';

    const typeIcons = {
        'cowrie': '🔒',
        'web-camera': '📷',
        'dionaea': '🖨️',
        'custom-iot': '📡'
    };

    const icon = typeIcons[node.type] || '🍯';

    // create button HTML's according to the role
    let actionsHtml = '';
    
    if (currentUserRole === 'admin' || currentUserRole === 'operator') {
        const toggleBtn = isRunning
            ? `<button class="btn btn-secondary btn-stop" data-id="${node.container_id}">⏹ Stop</button>`
            : `<button class="btn btn-primary btn-start" data-id="${node.container_id}">▶ Start</button>`;
            
        // only admin can see the delete button
        const deleteBtn = currentUserRole === 'admin'
            ? `<button class="btn btn-danger btn-delete" data-id="${node.container_id}" data-name="${node.name}">🗑 Delete</button>`
            : '';

        actionsHtml = `
            <div class="node-actions">
                ${toggleBtn}
                ${deleteBtn}
            </div>
        `;
    }

    return `
        <div class="node-card ${isRunning ? '' : 'stopped'}">
            <div class="node-header">
                <div class="node-info">
                    <h3>${icon} ${node.name}</h3>
                    <div class="node-type">${node.type} / ${node.role}</div>
                </div>
                <div class="node-status ${isRunning ? '' : 'stopped'}">
                    <span class="dot"></span>
                    ${node.status}
                </div>
            </div>
            <div class="node-details">
                <span class="label">IP:</span>
                <span class="value">${node.ip_address}</span>
                <span class="label">Ports:</span>
                <span class="value">${node.ports || 'N/A'}</span>
                <span class="label">ID:</span>
                <span class="value">${node.id}</span>
            </div>
            ${actionsHtml}
        </div>
    `;
}

async function stopNode(containerId) {
    try {
        const data = await apiCall(`/nodes/${containerId}/stop`, { method: 'POST' });
        if (data.success) {
            showToast('Honeypot stopped', 'success');
            loadNodes();
        }
    } catch (error) {
        showToast('Failed to stop honeypot', 'error');
    }
}

async function startNode(containerId) {
    try {
        const data = await apiCall(`/nodes/${containerId}/start`, { method: 'POST' });
        if (data.success) {
            showToast('Honeypot started', 'success');
            loadNodes();
        }
    } catch (error) {
        showToast('Failed to start honeypot', 'error');
    }
}

async function deleteNode(containerId, name) {
    if (!confirm(`Delete honeypot "${name}"? This action cannot be undone.`)) {
        return;
    }

    try {
        const data = await apiCall(`/nodes/${containerId}`, { method: 'DELETE' });
        if (data.success) {
            showToast('Honeypot deleted', 'success');
            loadNodes();
        }
    } catch (error) {
        showToast('Failed to delete honeypot', 'error');
    }
}

// ============================================
// Alerts
// ============================================

async function loadAlerts() {
    const container = document.getElementById('alerts-terminal');

    try {
        let url = '/logs?hours=24&limit=200';
        if (alertFilter === 'critical') url += '&severity=critical';
        else if (alertFilter === 'high') url += '&severity=high';

        const data = await apiCall(url);

        if (data.success && data.alerts.length > 0) {
            container.innerHTML = data.alerts.map(alert => createAlertEntry(alert)).join('');
        } else {
            container.innerHTML = `
                <div class="empty-state" style="text-align: center; padding: 2rem; color: var(--text-muted);">
                    <p>🔍 No alerts in the last 24 hours</p>
                    <p>Your honeypots are waiting for intruders...</p>
                </div>
            `;
        }
    } catch (error) {
        container.innerHTML = `<div class="loading">Failed to load alerts</div>`;
    }
}

function createAlertEntry(alert) {
    // Create the red badge if the MITRE code exists, otherwise leave it blank.
    const mitreHtml = alert.mitre_id 
        ? `<span class="mitre-tag">${alert.mitre_id}</span>` 
        : '';

    return `
        <div class="alert-entry">
            <div class="alert-header">
                <span class="alert-severity ${alert.severity}">${alert.severity}</span>
                <span class="alert-time">${formatDate(alert.timestamp)}</span>
                <span class="alert-honeypot">${alert.honeypot_name}</span>
            </div>
            <div class="alert-content">
                <span class="alert-ip">${alert.source_ip}</span> → ${mitreHtml} ${alert.event_type}
                ${alert.description ? `<br><small>${alert.description}</small>` : ''}
            </div>
        </div>
    `;
}

// ============================================
// Deploy Modal
// ============================================

function openDeployModal() {
    document.getElementById('deploy-modal').classList.add('active');
    document.getElementById('node-name').focus();
}

function closeDeployModal() {
    document.getElementById('deploy-modal').classList.remove('active');
    document.getElementById('deploy-form').reset();
}

async function handleDeploy(e) {
    e.preventDefault();

    const form = e.target;
    const formData = new FormData(form);
    const data = Object.fromEntries(formData.entries());
    const submitBtn = form.querySelector('button[type="submit"]');
    const originalText = submitBtn.innerHTML;

    // Disable button
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<span class="spin">↻</span> DEPLOYING...';

    // Show scanning message if IP is empty
    if (!data.ip_address) {
        showToast('Scanning network for free IP...', 'info');
    }

    try {
        const response = await fetch('/api/nodes', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(data)
        });

        const result = await response.json();

        if (result.success) {
            showToast(`Honeypot deployed successfully! IP: ${result.ip_address || 'Assigned'}`, 'success');
            closeDeployModal();
            loadNodes(); // Refresh list
        } else {
            showToast(`Deployment failed: ${result.error}`, 'error');
        }
    } catch (error) {
        console.error('Deploy error:', error);
        showToast('Failed to deploy honeypot. See console.', 'error');
    } finally {
        submitBtn.disabled = false;
        submitBtn.innerHTML = originalText;
    }
}

// Verify IP Handler
const verifyBtn = document.getElementById('btn-verify-ip');
const ipInput = document.getElementById('node-ip');
const ipFeedback = document.getElementById('ip-feedback');

if (verifyBtn && ipInput) {
    verifyBtn.addEventListener('click', async () => {
        const ip = ipInput.value.trim();
        if (!ip) {
            // If empty, just show info
            ipFeedback.textContent = 'Leave empty for automatic assignment';
            ipFeedback.className = 'feedback-text info';
            return;
        }

        // Validate format roughly
        if (!/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(ip)) {
            ipFeedback.textContent = 'Invalid IP format';
            ipFeedback.className = 'feedback-text error';
            return;
        }

        verifyBtn.disabled = true;
        verifyBtn.innerHTML = '⏳';
        ipFeedback.textContent = 'Checking availability...';
        ipFeedback.className = 'feedback-text';

        try {
            const response = await fetch(`/api/verify-ip/${ip}`);
            const result = await response.json();

            if (result.available) {
                ipFeedback.innerHTML = `✅ ${result.message}`;
                ipFeedback.className = 'feedback-text success';
            } else {
                ipFeedback.innerHTML = `❌ ${result.message}`;
                ipFeedback.className = 'feedback-text error';
            }
        } catch (error) {
            ipFeedback.textContent = 'Error verifying IP';
            ipFeedback.className = 'feedback-text error';
        } finally {
            verifyBtn.disabled = false;
            verifyBtn.innerHTML = '🔍 Verify';
        }
    });
}

// ============================================
// Settings & Users Modal
// ============================================

function openSettingsModal() {
    document.getElementById('settings-modal').classList.add('active');
    loadUsers(); // Modal açıldığında kullanıcıları yükle
    loadTelegramConfig(); // Modal açıldığında mevcut Telegram ayarlarını yükle
}

function closeSettingsModal() {
    document.getElementById('settings-modal').classList.remove('active');
    document.getElementById('add-user-form').reset();
}

// Telegram Ayarlarını Getir
async function loadTelegramConfig() {
    try {
        const data = await apiCall('/settings/telegram');
        if (data.success && data.config) {
            document.getElementById('telegram-bot-token').value = data.config.bot_token || '';
            document.getElementById('telegram-chat-id').value = data.config.chat_id || '';
        }
    } catch (error) {
        console.error('Failed to load Telegram config:', error);
    }
}

// Telegram Ayarlarını Kaydet
async function handleTelegramSettingsUpdate(e) {
    e.preventDefault();
    const botToken = document.getElementById('telegram-bot-token').value;
    const chatId = document.getElementById('telegram-chat-id').value;

    try {
        const data = await apiCall('/settings/telegram', {
            method: 'POST',
            body: JSON.stringify({ bot_token: botToken, chat_id: chatId })
        });

        if (data.success) {
            showToast('Telegram configuration updated!', 'success');
        } else {
            showToast(`Update failed: ${data.error}`, 'error');
        }
    } catch (error) {
        showToast('Failed to update Telegram config', 'error');
    }
}

// Kullanıcıları Listele
async function loadUsers() {
    const tbody = document.getElementById('users-table-body');
    tbody.innerHTML = '<tr><td colspan="3" class="loading">Loading users...</td></tr>';

    try {
        const data = await apiCall('/users');
        if (data.success && data.users.length > 0) {
            tbody.innerHTML = data.users.map(user => `
                <tr style="border-bottom: 1px solid rgba(255,255,255,0.05);">
                    <td style="padding: 8px; color: var(--neon-cyan);">${user.username}</td>
                    <td style="padding: 8px;">
                        <span class="alert-severity ${getRoleClass(user.role)}">${user.role.toUpperCase()}</span>
                    </td>
                    <td style="padding: 8px;">
                        <button class="btn btn-danger btn-delete-user" data-id="${user.id}" data-username="${user.username}" style="padding: 2px 8px; font-size: 0.7rem;">Delete</button>
                    </td>
                </tr>
            `).join('');

            // Silme butonlarına event listener ekle
            tbody.querySelectorAll('.btn-delete-user').forEach(btn => {
                btn.addEventListener('click', () => deleteUser(btn.dataset.id, btn.dataset.username));
            });
        } else {
            tbody.innerHTML = '<tr><td colspan="3" style="padding: 8px; color: var(--text-muted);">No users found.</td></tr>';
        }
    } catch (error) {
        tbody.innerHTML = '<tr><td colspan="3" style="padding: 8px; color: var(--neon-red);">Failed to load users.</td></tr>';
    }
}

// Role göre renk sınıfı döndüren yardımcı fonksiyon
function getRoleClass(role) {
    switch (role.toLowerCase()) {
        case 'admin': return 'critical';   // Kırmızı rozet
        case 'operator': return 'medium';  // Sarı rozet
        case 'viewer': return 'low';       // Mavi rozet
        default: return 'high';
    }
}

// add new user
async function handleAddUser(e) {
    e.preventDefault();
    const username = document.getElementById('new-username').value;
    const password = document.getElementById('new-password').value;
    const role = document.getElementById('new-role').value;

    const submitBtn = e.target.querySelector('button[type="submit"]');
    const originalText = submitBtn.textContent;
    submitBtn.textContent = 'ADDING...';
    submitBtn.disabled = true;

    try {
        const data = await apiCall('/users', {
            method: 'POST',
            body: JSON.stringify({ username, password, role })
        });

        if (data.success) {
            showToast(`User ${username} added successfully!`, 'success');
            document.getElementById('add-user-form').reset();
            loadUsers(); // Listeyi yenile
        } else {
            showToast(`Failed to add user: ${data.error}`, 'error');
        }
    } catch (error) {
        showToast('Failed to add user', 'error');
    } finally {
        submitBtn.textContent = originalText;
        submitBtn.disabled = false;
    }
}

// Kullanıcı Sil
async function deleteUser(userId, username) {
    if (!confirm(`Are you sure you want to delete the user "${username}"?`)) {
        return;
    }

    try {
        const data = await apiCall(`/users/${userId}`, { method: 'DELETE' });
        if (data.success) {
            showToast(`User ${username} deleted.`, 'success');
            loadUsers(); // Listeyi yenile
        } else {
            showToast(`Failed to delete user: ${data.error}`, 'error');
        }
    } catch (error) {
        showToast('Failed to delete user', 'error');
    }
}



// ============================================
// Telegram Test
// ============================================

async function testTelegram() {
    try {
        showToast('Sending test notification...', 'info');
        const data = await apiCall('/test-telegram', { method: 'POST' });

        if (data.success) {
            showToast('Telegram test sent!', 'success');
        } else {
            throw new Error(data.message);
        }
    } catch (error) {
        showToast('Telegram test failed', 'error');
    }
}

// ============================================
// Clock
// ============================================

function updateClock() {
    const now = new Date();
    const timeStr = now.toLocaleTimeString('en-US', {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false
    });
    const dateStr = now.toLocaleDateString('en-US', {
        weekday: 'short',
        month: 'short',
        day: 'numeric'
    });

    document.getElementById('datetime').textContent = `${dateStr} ${timeStr}`;
}

// ============================================
// Refresh Data
// ============================================

function refreshAll() {
    loadStats();
    loadNodes();
    loadAlerts();
    loadCharts();
}

function startAutoRefresh(intervalMs = 10000) {
    if (refreshInterval) {
        clearInterval(refreshInterval);
    }
    refreshInterval = setInterval(refreshAll, intervalMs);
}

// ============================================
// Authentication
// ============================================

// Role-based interface:
function applyRolePermissions() {
    const btnSettings = document.getElementById('btn-settings');
    const btnDeploy = document.getElementById('btn-add-node');

    // hide all at the start
    if (btnSettings) btnSettings.style.display = 'none';
    if (btnDeploy) btnDeploy.style.display = 'none';

    // show according to the role
    if (currentUserRole === 'admin') {
        if (btnSettings) btnSettings.style.display = 'inline-flex';
        if (btnDeploy) btnDeploy.style.display = 'inline-flex';
    } 
    else if (currentUserRole === 'operator') {
        if (btnDeploy) btnDeploy.style.display = 'inline-flex';
        // Operator should not see the settings
    }
    // Viewer does not see neither
}

async function checkAuthentication() {
    try {
        const response = await fetch('/api/check-auth');
        
        if (response.ok) {
            // 1. DURUM: OTURUM GEÇERLİ
            // Sadece bu durumda giriş ekranını gizliyoruz
            const data = await response.json();
            currentUserRole = data.user.role; 
            currentUsername = data.user.username;
            
            document.getElementById('login-overlay').style.display = 'none'; // EKRANI KAPAT
            
            applyRolePermissions(); 
            refreshAll(); 
        } else {
            // 2. DURUM: OTURUM SÜRESİ DOLMUŞ VEYA YETKİSİZ
            // Ekranın açık kalmasını garanti altına alıyoruz
            document.getElementById('login-overlay').style.display = 'flex'; // EKRANI AÇIK TUT
        }
    } catch (error) {
        // 3. DURUM: SUNUCUYA BAĞLANILAMIYOR
        // Güvenlik gereği ekranı yine açık tutuyoruz
        console.log("Not authenticated or server unreachable");
        document.getElementById('login-overlay').style.display = 'flex'; // EKRANI AÇIK TUT
    }
}

async function handleAdminLogin(e) {
    e.preventDefault();
    const username = document.getElementById('login-username').value;
    const password = document.getElementById('admin-password').value;
    const errorDiv = document.getElementById('login-error');

    try {
        const response = await fetch('/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        if (response.ok) {
            const data = await response.json(); // Yanıtı oku
            currentUserRole = data.user.role;   // Rolü kaydet
            currentUsername = data.user.username;

            document.getElementById('login-overlay').style.display = 'none';
            showToast(`Welcome back, ${currentUsername}!`, 'success');
            
            applyRolePermissions(); // Yetkileri uygula
            refreshAll();
        } else {
            errorDiv.textContent = 'INVALID CREDENTIALS';
            errorDiv.style.display = 'block';
        }
    } catch (error) {
        showToast('Login failed', 'error');
    }
}

async function handleLogout() {
    try {
        await fetch('/api/logout', { method: 'POST' });
        
        // Frontend state'ini temizle
        currentUserRole = 'viewer';
        currentUsername = '';
        
        window.location.href = '/'; 
    } catch (error) {
        console.error("Logout failed:", error);
        window.location.reload();
    }
}

// ============================================
// Event Listeners
// ============================================

document.addEventListener('DOMContentLoaded', () => {

    checkAuthentication();
    updateClock();
    initCharts();

    // Start auto-refresh
    startAutoRefresh();
    setInterval(updateClock, 1000);

    // Button handlers
    document.getElementById('admin-login-form').addEventListener('submit', handleAdminLogin);
    document.getElementById('btn-logout').addEventListener('click', handleLogout);
    document.getElementById('btn-add-node').addEventListener('click', openDeployModal);
    document.getElementById('modal-close').addEventListener('click', closeDeployModal);
    document.getElementById('btn-cancel').addEventListener('click', closeDeployModal);
    document.getElementById('btn-refresh').addEventListener('click', refreshAll);
    document.getElementById('btn-test-telegram').addEventListener('click', testTelegram);
    
    // Settings Modal
    const btnSettings = document.getElementById('btn-settings');
    if (btnSettings) {
        btnSettings.addEventListener('click', openSettingsModal);
    }
    
    const settingsModalClose = document.getElementById('settings-modal-close');
    if (settingsModalClose) {
        settingsModalClose.addEventListener('click', closeSettingsModal);
    }

    // Settings Forms
    const telegramForm = document.getElementById('telegram-settings-form');
    if (telegramForm) {
        telegramForm.addEventListener('submit', handleTelegramSettingsUpdate);
    }

    const addUserForm = document.getElementById('add-user-form');
    if (addUserForm) {
        addUserForm.addEventListener('submit', handleAddUser);
    }

    // Close Settings if clicked outside the modal
    document.getElementById('settings-modal').addEventListener('click', (e) => {
        if (e.target.classList.contains('modal')) {
            closeSettingsModal();
        }
    });

    // Alert filter
    document.getElementById('alert-filter').addEventListener('change', (e) => {
        alertFilter = e.target.value;
        loadAlerts();
    });

    // Deploy form
    document.getElementById('deploy-form').addEventListener('submit', handleDeploy);

    // Close modal on background click
    document.getElementById('deploy-modal').addEventListener('click', (e) => {
        if (e.target.classList.contains('modal')) {
            closeDeployModal();
        }
    });

    // Keyboard shortcuts
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            closeDeployModal();
        }
        if (e.key === 'r' && e.ctrlKey) {
            e.preventDefault();
            refreshAll();
        }
    });
});
