/* public/js/layout.js */
document.addEventListener("DOMContentLoaded", () => {
    // 1. Theme Check
    const savedTheme = localStorage.getItem('theme') || 'dark';
    document.documentElement.setAttribute('data-theme', savedTheme);

    // 2. Inject Header
    const header = document.getElementById('app-header');
    const path = window.location.pathname;
    
    // Inject CSS for Dropdowns dynamically so it works immediately
    const style = document.createElement('style');
    style.textContent = `
        .nav-item { position: relative; height: 100%; display: flex; align-items: center; }
        .dropdown-trigger { cursor: pointer; display: flex; align-items: center; gap: 5px; height: 100%; }
        .dropdown-menu {
            display: none;
            position: absolute;
            top: 100%;
            left: 0;
            background-color: var(--bg-card);
            min-width: 200px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
            border-radius: 8px;
            border: 1px solid var(--border);
            z-index: 1000;
            flex-direction: column;
            padding: 5px 0;
        }
        .nav-item:hover .dropdown-menu { display: flex; }
        .dropdown-item {
            padding: 10px 15px;
            color: var(--text-main);
            text-decoration: none;
            transition: background 0.2s;
            display: block;
        }
        .dropdown-item:hover { background-color: var(--bg-main); color: var(--accent); }
        .dropdown-item.active { color: var(--accent); font-weight: bold; }
    `;
    document.head.appendChild(style);
    
    if(header) {
        const user = JSON.parse(localStorage.getItem('nexus_user'));
        
        // Auth Section
        const authLink = user 
            ? `<div style="display:flex; align-items:center; gap:15px;">
                 <span style="color:var(--accent); font-weight:bold;"><i class="fas fa-user-circle"></i> ${user.name}</span>
                 <button onclick="logout()" style="background:var(--bg-card); color:var(--text-main); border:1px solid var(--border); padding:5px 10px; border-radius:6px; cursor:pointer;">Logout</button>
               </div>`
            : `<a href="/login" class="nav-link" style="color:var(--accent); font-weight:bold;"><i class="fas fa-sign-in-alt"></i> Login</a>`;

        // Define Navigation Groups
        // Check if any sub-link is active to highlight the parent dropdown
        const isAcademicActive = ['/scanner', '/explorer','/local-search', '/grad-form.html', '/grad-dashboard'].includes(path);
        const isAdminActive = ['/jobs', '/companies.html'].includes(path);

        header.innerHTML = `
            <div class="main-header">
                <div class="brand" onclick="window.location.href='/'">
                    <i class="fas fa-atom"></i> NEXUS
                </div>
                
                <nav class="nav-links">
    <a href="/" class="nav-link ${path === '/' ? 'active' : ''}">Home</a>

    <!-- ACADEMIC / RESEARCH DROPDOWN -->
    <div class="nav-item">
        <span class="nav-link dropdown-trigger ${['/scanner','/explorer','/local-search'].some(x=>path.includes(x)) ? 'active' : ''}">
            Research <i class="fas fa-chevron-down" style="font-size: 0.8em;"></i>
        </span>
        <div class="dropdown-menu">
            <a href="/scanner" class="dropdown-item"><i class="fas fa-user-astronaut"></i> Target Scanner</a>
            <a href="/explorer" class="dropdown-item"><i class="fas fa-search"></i> Paper Explorer</a>
            <a href="/local-search" class="dropdown-item"><i class="fas fa-map-marker-alt"></i> Local Researchers</a> 
            <a href="/grad-dashboard" class="dropdown-item"><i class="fas fa-database"></i> Database Stats</a> 
            <a href="/grad-form.html" class="dropdown-item"><i class="fas fa-file-signature"></i> Register Project</a>
        </div>
    </div>

    <!-- NEW JOBS DROPDOWN -->
    <div class="nav-item">
        <span class="nav-link dropdown-trigger ${['/jobs','/companies.html'].some(x=>path.includes(x)) ? 'active' : ''}">
            Jobs & Market <i class="fas fa-chevron-down" style="font-size: 0.8em;"></i>
        </span>
        <div class="dropdown-menu">
            <a href="/jobs" class="dropdown-item"><i class="fab fa-linkedin"></i> Job Search & Map</a>
            <a href="/companies.html" class="dropdown-item"><i class="fas fa-building"></i> Companies List</a>
        </div>
    </div>

    <a href="/team.html" class="nav-link ${path === '/team.html' ? 'active' : ''}">Team</a>
    
    ${authLink}
</nav>

                <button onclick="toggleTheme()" style="background:none; border:none; color:var(--text-main); cursor:pointer; font-size:1.2rem;">
                    <i class="fas fa-adjust"></i>
                </button>
            </div>
        `;

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
                    <a href="/privacy">Privacy Policy</a>
                    <a href="/contact">Contact</a>
                </div>
                <div style="font-size:0.8rem; opacity:0.6;">&copy; 2026 Nexus. Our Team.</div>
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