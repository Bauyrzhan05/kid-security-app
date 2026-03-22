// ===== KID SECURITY — CORE JS =====

// ===== THREAT DETECTION ENGINE =====
const ThreatEngine = {
  keywords: {
    high: [
      'өлтіремін', 'өлтіреміз', 'өлтіреді', 'өлтіреміз',
      'зорлаймын', 'зорлайды', 'зорлаймыз',
      'ұрып өлтіремін', 'өліп кетесің',
      'ақша бер', 'ақша аудар',
      'суреттерің менде', 'видеоң менде',
      'жерден іздейсің', 'мектепте өзіңді',
    ],
    medium: [
      'ешкімге айтпа', 'ешкімге айтсаң',
      'жек көреді', 'жек көремін',
      'ұсқынсызсың', 'жаман адамсың',
      'күтемін сені', 'сені күтемін',
      'өкінесің', 'қорқытам',
      'ұрамын', 'соғамын',
    ],
    low: [
      'ренжітем', 'мазақтаймын',
      'достарыңа айтамын', 'бәрі білсін',
      'бұзамын', 'жоямын',
    ]
  },

  threatTypes: {
    'өлтіремін': 'threat', 'өлтіреміз': 'threat', 'өліп': 'threat',
    'зорлаймын': 'blackmail', 'зорлайды': 'blackmail',
    'ақша бер': 'extortion', 'ақша аудар': 'extortion',
    'суреттерің': 'blackmail', 'видеоң': 'blackmail',
    'ешкімге айтпа': 'stalking', 'күтемін': 'stalking',
    'жек көреді': 'bullying', 'ұсқынсызсың': 'bullying',
    'ұрып': 'threat',
  },

  typeLabels: {
    threat: '⚔️ Қауіп-қатер',
    extortion: '💰 Бопсалау',
    blackmail: '🔐 Шантаж',
    bullying: '👊 Мектептік зорлық',
    stalking: '👁️ Бақылау',
    harassment: '😡 Қудалау',
  },

  analyze(text) {
    const lower = text.toLowerCase();
    let maxSeverity = null;
    let foundKeywords = [];
    let threatType = null;

    for (const kw of this.keywords.high) {
      if (lower.includes(kw)) {
        maxSeverity = 'high';
        foundKeywords.push(kw);
        if (!threatType) threatType = this.detectType(kw);
      }
    }
    if (!maxSeverity) {
      for (const kw of this.keywords.medium) {
        if (lower.includes(kw)) {
          maxSeverity = 'medium';
          foundKeywords.push(kw);
          if (!threatType) threatType = this.detectType(kw);
        }
      }
    }
    if (!maxSeverity) {
      for (const kw of this.keywords.low) {
        if (lower.includes(kw)) {
          maxSeverity = 'low';
          foundKeywords.push(kw);
          if (!threatType) threatType = this.detectType(kw);
        }
      }
    }

    return {
      isThreat: maxSeverity !== null,
      severity: maxSeverity,
      keywords: foundKeywords,
      type: threatType || 'harassment',
    };
  },

  detectType(keyword) {
    for (const [kw, type] of Object.entries(this.threatTypes)) {
      if (keyword.includes(kw)) return type;
    }
    return 'harassment';
  },

  highlightKeywords(text) {
    let result = text;
    const allKeywords = [
      ...this.keywords.high,
      ...this.keywords.medium,
      ...this.keywords.low
    ].sort((a, b) => b.length - a.length);

    for (const kw of allKeywords) {
      const regex = new RegExp(kw, 'gi');
      result = result.replace(regex, `<span class="keyword-highlight">${kw}</span>`);
    }
    return result;
  }
};

// ===== AUTH MANAGER =====
const Auth = {
  USERS_KEY: 'ks_users',
  SESSION_KEY: 'ks_session',

  init() {
    const existing = localStorage.getItem(this.USERS_KEY);
    if (!existing) {
      const defaultUsers = [
        { id: 1, name: 'Гүлнар Сейткали', email: 'parent@kidsecurity.kz', password: 'parent123', role: 'parent', avatar: 'ГС', avatarColor: '#7C4DFF', child: 'Айдана Сейткали', childAge: 14 },
        { id: 2, name: 'Айдана Сейткали', email: 'child@kidsecurity.kz', password: 'child123', role: 'child', avatar: 'АС', avatarColor: '#FF4081', age: 14, school: '№45 мектеп' }
      ];
      localStorage.setItem(this.USERS_KEY, JSON.stringify(defaultUsers));
    }
  },

  login(email, password) {
    const users = JSON.parse(localStorage.getItem(this.USERS_KEY) || '[]');
    const user = users.find(u => u.email === email && u.password === password);
    if (user) {
      const session = { ...user, loginTime: new Date().toISOString() };
      delete session.password;
      localStorage.setItem(this.SESSION_KEY, JSON.stringify(session));
      return { success: true, user: session };
    }
    return { success: false, message: 'Қате email немесе құпия сөз' };
  },

  register(data) {
    const users = JSON.parse(localStorage.getItem(this.USERS_KEY) || '[]');
    if (users.find(u => u.email === data.email)) {
      return { success: false, message: 'Бұл email тіркелген' };
    }
    const newUser = { id: Date.now(), ...data, avatar: data.name.slice(0, 2).toUpperCase(), avatarColor: '#7C4DFF' };
    users.push(newUser);
    localStorage.setItem(this.USERS_KEY, JSON.stringify(users));
    return { success: true, user: newUser };
  },

  logout() {
    localStorage.removeItem(this.SESSION_KEY);
    window.location.href = '../pages/login.html';
  },

  getUser() {
    const session = localStorage.getItem(this.SESSION_KEY);
    return session ? JSON.parse(session) : null;
  },

  isLoggedIn() {
    return !!this.getUser();
  },

  requireAuth() {
    if (!this.isLoggedIn()) {
      window.location.href = '../pages/login.html';
      return false;
    }
    return true;
  }
};

// ===== ALERTS MANAGER =====
const AlertsManager = {
  KEY: 'ks_alerts',

  getAll() {
    const stored = localStorage.getItem(this.KEY);
    return stored ? JSON.parse(stored) : [];
  },

  add(alert) {
    const alerts = this.getAll();
    const newAlert = {
      id: Date.now(),
      timestamp: new Date().toISOString(),
      notifiedParent: false,
      status: 'active',
      ...alert,
    };
    alerts.unshift(newAlert);
    localStorage.setItem(this.KEY, JSON.stringify(alerts));
    return newAlert;
  },

  markNotified(id) {
    const alerts = this.getAll();
    const alert = alerts.find(a => a.id === id);
    if (alert) {
      alert.notifiedParent = true;
      localStorage.setItem(this.KEY, JSON.stringify(alerts));
    }
  },

  updateStatus(id, status) {
    const alerts = this.getAll();
    const alert = alerts.find(a => a.id === id);
    if (alert) {
      alert.status = status;
      localStorage.setItem(this.KEY, JSON.stringify(alerts));
    }
  },

  getStats() {
    const alerts = this.getAll();
    return {
      total: alerts.length,
      high: alerts.filter(a => a.severity === 'high').length,
      medium: alerts.filter(a => a.severity === 'medium').length,
      low: alerts.filter(a => a.severity === 'low').length,
      notified: alerts.filter(a => a.notifiedParent).length,
      active: alerts.filter(a => a.status === 'active').length,
    };
  },

  initFromJSON(jsonAlerts) {
    const stored = localStorage.getItem(this.KEY);
    if (!stored || JSON.parse(stored).length === 0) {
      localStorage.setItem(this.KEY, JSON.stringify(jsonAlerts));
    }
  }
};

// ===== TOAST MANAGER =====
const Toast = {
  container: null,

  init() {
    this.container = document.getElementById('toast-container');
    if (!this.container) {
      this.container = document.createElement('div');
      this.container.className = 'toast-container';
      this.container.id = 'toast-container';
      document.body.appendChild(this.container);
    }
  },

  show(title, msg, type = 'warning', duration = 5000) {
    this.init();
    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.innerHTML = `
      <div class="toast-stripe ${type}"></div>
      <div class="toast-body">
        <div class="toast-title">
          ${type === 'danger' ? '🚨' : type === 'warning' ? '⚠️' : '✅'}
          ${title}
        </div>
        <div class="toast-msg">${msg}</div>
        <div class="toast-progress"><div class="toast-progress-bar"></div></div>
      </div>
    `;
    this.container.appendChild(toast);

    setTimeout(() => {
      toast.classList.add('removing');
      setTimeout(() => toast.remove(), 300);
    }, duration);
  },

  danger(title, msg) { this.show(title, msg, 'danger'); },
  warning(title, msg) { this.show(title, msg, 'warning'); },
  success(title, msg) { this.show(title, msg, 'success'); },
};

// ===== THEME MANAGER =====
const Theme = {
  KEY: 'ks_theme',

  get() { return localStorage.getItem(this.KEY) || 'light'; },

  apply(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem(this.KEY, theme);
  },

  toggle() {
    const current = this.get();
    const next = current === 'light' ? 'dark' : 'light';
    this.apply(next);
    return next;
  },

  init() { this.apply(this.get()); }
};

// ===== SIDEBAR MANAGER =====
const Sidebar = {
  init() {
    const menuBtn = document.getElementById('mobile-menu-btn');
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebar-overlay');

    if (menuBtn && sidebar) {
      menuBtn.addEventListener('click', () => {
        sidebar.classList.toggle('open');
        overlay?.classList.toggle('show');
      });
      overlay?.addEventListener('click', () => {
        sidebar.classList.remove('open');
        overlay.classList.remove('show');
      });
    }
  },

  setActive(page) {
    document.querySelectorAll('.nav-item').forEach(item => {
      item.classList.remove('active');
      if (item.dataset.page === page) item.classList.add('active');
    });
  }
};

// ===== SOUND ALERT =====
const SoundAlert = {
  play() {
    try {
      const ctx = new (window.AudioContext || window.webkitAudioContext)();
      const playBeep = (freq, start, dur) => {
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();
        osc.connect(gain);
        gain.connect(ctx.destination);
        osc.frequency.value = freq;
        osc.type = 'sine';
        gain.gain.setValueAtTime(0.3, ctx.currentTime + start);
        gain.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + start + dur);
        osc.start(ctx.currentTime + start);
        osc.stop(ctx.currentTime + start + dur);
      };
      playBeep(880, 0, 0.2);
      playBeep(660, 0.25, 0.2);
      playBeep(880, 0.5, 0.4);
    } catch(e) {}
  }
};

// ===== UTILS =====
const Utils = {
  formatTime(dateStr) {
    const d = new Date(dateStr);
    const now = new Date();
    const diff = now - d;
    const mins = Math.floor(diff / 60000);
    const hours = Math.floor(diff / 3600000);
    const days = Math.floor(diff / 86400000);

    if (mins < 1) return 'Жаңа ғана';
    if (mins < 60) return `${mins} мин бұрын`;
    if (hours < 24) return `${hours} сағ бұрын`;
    return d.toLocaleDateString('kk-KZ', { day: 'numeric', month: 'short' });
  },

  formatDateTime(dateStr) {
    const d = new Date(dateStr);
    return d.toLocaleString('kk-KZ', {
      day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit'
    });
  },

  severityLabel(s) {
    return s === 'high' ? '🔴 Жоғары' : s === 'medium' ? '🟡 Орта' : '🟢 Төмен';
  },

  platformIcon(p) {
    const icons = { 'WhatsApp': '💬', 'Telegram': '✈️', 'Instagram': '📸', 'TikTok': '🎵' };
    return icons[p] || '📱';
  },

  truncate(str, len = 80) {
    return str.length > len ? str.slice(0, len) + '...' : str;
  }
};

// ===== RENDER SIDEBAR =====
function renderSidebar(activePage) {
  const user = Auth.getUser();
  if (!user) return;

  const alerts = AlertsManager.getAll();
  const activeAlerts = alerts.filter(a => a.status === 'active').length;

  const sidebarHTML = `
    <div class="sidebar-brand">
      <div class="brand-icon">🛡️</div>
      <div class="brand-text">
        <h2>KidSecurity</h2>
        <p>Балалар қорғанысы</p>
      </div>
    </div>
    <nav class="sidebar-nav">
      <div class="nav-section-label">Негізгі</div>
      <a href="../index.html" class="nav-item" data-page="home">
        <span class="nav-icon">🏠</span> Басты бет
      </a>
      <a href="dashboard.html" class="nav-item" data-page="dashboard">
        <span class="nav-icon">📊</span> Бақылау панелі
      </a>
      <a href="messages.html" class="nav-item" data-page="messages">
        <span class="nav-icon">💬</span> Хабарламалар
      </a>

      <div class="nav-section-label">Қауіпсіздік</div>
      <a href="alerts.html" class="nav-item" data-page="alerts">
        <span class="nav-icon">⚠️</span> Қауіптер
        ${activeAlerts > 0 ? `<span class="nav-badge">${activeAlerts}</span>` : ''}
      </a>
      <a href="notifications.html" class="nav-item" data-page="notifications">
        <span class="nav-icon">🔔</span> Ата-ана хабары
      </a>

      <div class="nav-section-label">Жүйе</div>
      <a href="settings.html" class="nav-item" data-page="settings">
        <span class="nav-icon">⚙️</span> Баптаулар
      </a>
    </nav>
    <div class="sidebar-footer">
      <div class="sidebar-user">
        <div class="sidebar-user-avatar" style="background: ${user.avatarColor || '#7C4DFF'}">${user.avatar || '??'}</div>
        <div class="sidebar-user-info">
          <div class="sidebar-user-name">${user.name}</div>
          <div class="sidebar-user-role">${user.role === 'parent' ? '👨‍👩‍👧 Ата-ана' : '🧒 Бала'}</div>
        </div>
      </div>
      <button onclick="Auth.logout()" class="btn btn-outline btn-sm" style="width:100%;margin-top:8px;justify-content:center">
        🚪 Шығу
      </button>
    </div>
  `;

  const sidebar = document.getElementById('sidebar');
  if (sidebar) {
    sidebar.innerHTML = sidebarHTML;
    // Set active
    sidebar.querySelectorAll('.nav-item').forEach(item => {
      if (item.dataset.page === activePage) item.classList.add('active');
    });
  }
}

// ===== HEADER RENDER =====
function renderHeader(title, subtitle) {
  const themeIcon = Theme.get() === 'dark' ? '☀️' : '🌙';
  const alerts = AlertsManager.getAll();
  const hasAlerts = alerts.some(a => a.status === 'active');

  return `
    <button class="mobile-menu-btn" id="mobile-menu-btn">☰</button>
    <div class="header-title">
      <h1>${title}</h1>
      ${subtitle ? `<p>${subtitle}</p>` : ''}
    </div>
    <div class="header-actions">
      <button class="header-btn" id="theme-toggle" title="Тема">
        ${themeIcon}
      </button>
      <a href="alerts.html" class="header-btn" title="Ескертулер">
        🔔
        ${hasAlerts ? '<span class="alert-indicator"></span>' : ''}
      </a>
      <a href="notifications.html" class="header-btn" title="Ата-ана">
        👨‍👩‍👧
      </a>
    </div>
  `;
}

// ===== INIT COMMON =====
function initCommon(activePage, title, subtitle) {
  Theme.init();
  Auth.init();

  // Load alerts from JSON if empty
  fetch('../data/alerts.json')
    .then(r => r.json())
    .then(data => {
      AlertsManager.initFromJSON(data);
      updateBottomNavBadge();
    })
    .catch(() => {});

  renderSidebar(activePage);

  const header = document.getElementById('app-header');
  if (header) header.innerHTML = renderHeader(title, subtitle);

  // Theme toggle
  document.addEventListener('click', e => {
    if (e.target.closest('#theme-toggle')) {
      const newTheme = Theme.toggle();
      e.target.closest('#theme-toggle').textContent = newTheme === 'dark' ? '☀️' : '🌙';
    }
  });

  Sidebar.init();
  updateBottomNavBadge();

  // Set active state on bottom nav
  const bnItems = document.querySelectorAll('.bottom-nav-item');
  bnItems.forEach(item => {
    if (item.dataset.page === activePage) item.classList.add('active');
    else item.classList.remove('active');
  });
}

// ===== BOTTOM NAV BADGE =====
function updateBottomNavBadge() {
  const badge = document.getElementById('bn-alert-count');
  if (!badge) return;
  const alerts = AlertsManager.getAll();
  const active = alerts.filter(a => a.status === 'active').length;
  if (active > 0) {
    badge.textContent = active > 9 ? '9+' : active;
    badge.style.display = 'flex';
  } else {
    badge.style.display = 'none';
  }
}

// Init Auth always
Auth.init();
Theme.init();
