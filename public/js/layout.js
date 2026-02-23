/* public/js/layout.js */
document.addEventListener("DOMContentLoaded", () => {
    // 1. Theme Check
    const savedTheme = localStorage.getItem('theme') || 'dark';
    document.documentElement.setAttribute('data-theme', savedTheme);

    // 2. Inject Header
    const header = document.getElementById('app-header');
    const path = window.location.pathname;
    
    if(header) {
    const user = JSON.parse(localStorage.getItem('nexus_user'));
    const authLink = user 
        ? `<div style="display:flex; align-items:center; gap:15px;">
             <span style="color:var(--accent); font-weight:bold;"><i class="fas fa-user-circle"></i> ${user.name}</span>
             <button onclick="logout()" style="background:var(--bg-card); color:var(--text-main); border:1px solid var(--border); padding:5px 10px; border-radius:6px; cursor:pointer;">Logout</button>
           </div>`
        : `<a href="/login" class="nav-link" style="color:var(--accent); font-weight:bold;"><i class="fas fa-sign-in-alt"></i> Login</a>`;

    if(header) {
        header.innerHTML = `
            <div class="main-header">
                <div class="brand" onclick="window.location.href='/'">
                    <i class="fas fa-atom"></i> NEXUS
                </div>
                <nav class="nav-links">
                    <a href="/" class="nav-link ${path === '/' ? 'active' : ''}">Home</a>
                    <a href="/jobs" class="nav-link ${path === '/jobs' ? 'active' : ''}">Jobs & Map</a>
                    <a href="/scanner" class="nav-link ${path === '/scanner' ? 'active' : ''}">Scanner</a>
                    <a href="/explorer" class="nav-link ${path === '/explorer' ? 'active' : ''}">Explorer</a>
                    <a href="/companies.html" class="nav-link ${path === '/companies.html' ? 'active' : ''}">Companies</a>

                    ${authLink}
                </nav>
                <button onclick="toggleTheme()" style="background:none; border:none; color:var(--text-main); cursor:pointer; font-size:1.2rem;">
                    <i class="fas fa-adjust"></i>
                </button>
            </div>
        `;
    }

window.logout = function() {
    localStorage.removeItem('nexus_token');
    localStorage.removeItem('nexus_user');
    window.location.reload();
}
    }

    // 3. Inject Footer
    const footer = document.getElementById('app-footer');
    if(footer) {
        footer.innerHTML = `
            <div class="main-footer">
                <div class="footer-links">
                    <a href="/about">About</a>
                    <a href="/api-docs">API Documentation</a>
                    <a href="/privacy">Privacy Policy</a>
                    <a href="/contact">Contact</a>
                </div>
                <div style="font-size:0.8rem; opacity:0.6;">&copy; 2026 Scholar Nexus. Our Team.</div>
            </div>
        `;
    }
});

function toggleTheme() {
    const html = document.documentElement;
    const current = html.getAttribute('data-theme');
    const next = current === 'dark' ? 'light' : 'dark';
    html.setAttribute('data-theme', next);
    localStorage.setItem('theme', next);

    document.querySelectorAll('iframe').forEach(iframe => {
        if(iframe.contentWindow) {
            iframe.contentWindow.postMessage({ type: 'THEME_CHANGE', theme: next }, '*');
        }
    });
}

function showSuccessToast(message) {
    const toast = document.createElement('div');
    toast.className = 'toast-success';
    toast.innerText = message;
    document.body.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = '0';
        setTimeout(() => toast.remove(), 500);
    }, 3000);
}