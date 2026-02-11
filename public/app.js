function urlBase64ToUint8Array(base64String) {
  const padding = '='.repeat((4 - base64String.length % 4) % 4);
  const base64 = (base64String + padding).replace(/-/g, '+').replace(/_/g, '/');
  const raw = atob(base64);
  return Uint8Array.from([...raw].map(c => c.charCodeAt(0)));
}

function dinnerRoulette() {
  return {
    // Auth
    loggedIn: false,
    username: '',
    userId: null,
    email: '',
    isAdmin: false,
    authMode: 'login',
    authForm: { username: '', password: '', confirmPassword: '', email: '', remember: false },
    authError: '',
    resetMode: false,
    resetEmail: '',
    resetToken: '',
    resetNewPassword: '',
    resetConfirmPassword: '',
    resetTokenValid: false,
    resetUsername: '',

    // Theme
    theme: 'auto',

    // UI sections
    sections: { auth: true, places: true, plan: true, account: false },
    activeTab: 'places',

    // Toast
    toast: { message: '', type: '', visible: false, action: null },
    toastTimer: null,

    // Confirm modal
    confirmModal: { visible: false, message: '', onConfirm: null, onCancel: null },

    // Places
    placeSearch: '',
    predictions: [],
    searching: false,
    searchedOnce: false,
    highlightedIndex: -1,
    selectedPlace: null,
    likes: [],
    dislikes: [],
    wantToTry: [],
    placeFilter: '',
    placeTypeFilter: '',
    placeSortBy: 'name',
    editingNote: null,
    noteText: '',

    // Quick Pick
    quickPickResult: null,
    quickPicking: false,

    // Suggestions
    suggestions: [],
    currentSuggestions: new Set(),

    // Friends
    friendUsername: '',
    friends: [],
    friendRequests: [],
    viewingFriendLikes: null,
    commonPlaces: [],
    commonFriend: '',

    // Sessions
    sessions: [],
    newSessionName: '',
    joinCode: '',
    activeSession: null,
    sessionPlaceSearch: '',
    sessionPredictions: [],
    sessionSearching: false,
    sessionSearchedOnce: false,
    sessionHighlightedIndex: -1,
    sessionInviteUsername: '',
    sessionDislikes: [],
    sessionWantToTry: {},
    sessionSuggestSort: 'votes',

    // Picking
    picking: false,
    closingSession: false,
    winner: null,
    userLat: null,
    userLng: null,

    // Account
    accountForm: { currentPassword: '', newPassword: '', confirmNewPassword: '', newEmail: '', deletePassword: '' },

    // Loading states
    loading: { places: false, friends: false, sessions: false },

    // Network
    online: typeof navigator !== 'undefined' ? navigator.onLine : true,

    // Notifications
    notificationsEnabled: false,
    notificationsSupported: false,

    // Cuisine filter (sessions)
    sessionCuisineFilter: '',

    // Recent suggestions
    recentSuggestions: [],

    // Invite
    pendingInviteCode: null,

    // Deadline
    deadlineInput: '',
    deadlineCountdown: '',
    deadlineTimer: null,

    // Chat
    chatMessages: [],
    chatInput: '',
    chatVisible: false,

    // Map
    mapView: false,
    mapInstance: null,
    mapMarkers: [],
    mapsLoaded: false,

    // Swipe
    swipeState: { name: null, startX: 0, currentX: 0, swiping: false },
    touchEnabled: false,

    // Socket.IO
    socket: null,

    // Admin
    adminTab: 'dashboard',
    adminStats: null,
    adminUsers: [],
    adminSmtp: { host: '', port: 587, user: '', password: '', from: '', secure: false },
    adminVapid: { publicKey: '', source: '' },
    adminSettings: { jwt_expiry: '12h', cookie_secure: 'false' },
    adminGoogleKey: '',
    adminResetPwUser: null,
    adminResetPwValue: '',
    adminTestEmail: '',

    // ── Helpers ──
    getInitials(username) {
      if (!username) return '?';
      const parts = username.trim().split(/\s+/);
      if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase();
      return username.slice(0, 2).toUpperCase();
    },

    hashColor(username) {
      if (!username) return 'hsl(0, 50%, 50%)';
      let hash = 0;
      for (let i = 0; i < username.length; i++) {
        hash = username.charCodeAt(i) + ((hash << 5) - hash);
      }
      const hue = Math.abs(hash) % 360;
      return `hsl(${hue}, 55%, 45%)`;
    },

    createConfetti() {
      const canvas = document.createElement('canvas');
      canvas.className = 'confetti-canvas';
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
      document.body.appendChild(canvas);
      const ctx = canvas.getContext('2d');
      const particles = [];
      const colors = ['#e74c3c', '#f39c12', '#27ae60', '#3498db', '#9b59b6', '#e91e63', '#ff9800'];
      for (let i = 0; i < 150; i++) {
        particles.push({
          x: canvas.width / 2 + (Math.random() - 0.5) * 200,
          y: canvas.height / 2,
          vx: (Math.random() - 0.5) * 16,
          vy: Math.random() * -18 - 4,
          color: colors[Math.floor(Math.random() * colors.length)],
          size: Math.random() * 6 + 3,
          rotation: Math.random() * 360,
          rotationSpeed: (Math.random() - 0.5) * 10,
          gravity: 0.3 + Math.random() * 0.2,
        });
      }
      const startTime = Date.now();
      const animate = () => {
        const elapsed = Date.now() - startTime;
        if (elapsed > 3000) { canvas.remove(); return; }
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        for (const p of particles) {
          p.x += p.vx;
          p.vy += p.gravity;
          p.y += p.vy;
          p.rotation += p.rotationSpeed;
          p.vx *= 0.99;
          ctx.save();
          ctx.translate(p.x, p.y);
          ctx.rotate((p.rotation * Math.PI) / 180);
          ctx.fillStyle = p.color;
          ctx.globalAlpha = Math.max(0, 1 - elapsed / 3000);
          ctx.fillRect(-p.size / 2, -p.size / 2, p.size, p.size * 0.6);
          ctx.restore();
        }
        requestAnimationFrame(animate);
      };
      animate();
    },

    formatPlaceType(types) {
      if (!types?.length) return '';
      const ignore = new Set(['point_of_interest', 'establishment', 'geocode', 'political']);
      const meaningful = types.filter(t => !ignore.has(t));
      if (!meaningful.length) return '';
      return meaningful[0].replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
    },

    priceDisplay(level) {
      if (level == null || level === 0) return '';
      return '$'.repeat(level);
    },

    googleReviewsUrl(name, placeId) {
      if (placeId) {
        return `https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(name)}&query_place_id=${placeId}`;
      }
      return `https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(name)}`;
    },

    // ── Computed ──
    get uniqueRestaurantTypes() {
      const types = new Set();
      this.likes.forEach(p => { if (p.restaurant_type) types.add(p.restaurant_type); });
      this.dislikes.forEach(p => { if (p.restaurant_type) types.add(p.restaurant_type); });
      this.wantToTry.forEach(p => { if (p.restaurant_type) types.add(p.restaurant_type); });
      return [...types].sort();
    },
    get filteredLikes() {
      const f = this.placeFilter.toLowerCase();
      let list = f ? this.likes.filter(p => p.name.toLowerCase().includes(f)) : [...this.likes];
      if (this.placeTypeFilter) list = list.filter(p => p.restaurant_type === this.placeTypeFilter);
      if (this.placeSortBy === 'type') {
        list.sort((a, b) => (a.restaurant_type || '').localeCompare(b.restaurant_type || '') || a.name.localeCompare(b.name));
      } else {
        list.sort((a, b) => a.name.localeCompare(b.name));
      }
      return list;
    },
    get filteredDislikes() {
      const f = this.placeFilter.toLowerCase();
      let list = f ? this.dislikes.filter(p => p.name.toLowerCase().includes(f)) : [...this.dislikes];
      if (this.placeTypeFilter) list = list.filter(p => p.restaurant_type === this.placeTypeFilter);
      return list.sort((a, b) => a.name.localeCompare(b.name));
    },
    get filteredWantToTry() {
      const f = this.placeFilter.toLowerCase();
      let list = f ? this.wantToTry.filter(p => p.name.toLowerCase().includes(f)) : [...this.wantToTry];
      if (this.placeTypeFilter) list = list.filter(p => p.restaurant_type === this.placeTypeFilter);
      return list.sort((a, b) => a.name.localeCompare(b.name));
    },
    get quickPickMapUrl() {
      if (!this.quickPickResult) return '#';
      return `https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(this.quickPickResult.name)}`;
    },
    get activeSessions() {
      return this.sessions.filter(s => s.status === 'open');
    },
    get historySessions() {
      return this.sessions.filter(s => s.status === 'closed');
    },
    get winnerDistanceText() {
      if (!this.winner?.distance) return '';
      const km = this.winner.distance.toFixed(1);
      const mi = (this.winner.distance * 0.621371).toFixed(1);
      return `${km} km (${mi} mi) away`;
    },
    get winnerMapUrl() {
      if (!this.winner) return '#';
      if (this.winner.distance != null && this.userLat != null) {
        return `https://www.google.com/maps/dir/?api=1&origin=${this.userLat},${this.userLng}&destination=${encodeURIComponent(this.winner.place)}`;
      }
      return `https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(this.winner.place)}`;
    },

    get uniqueSessionCuisines() {
      const types = new Set();
      (this.activeSession?.suggestions || []).forEach(s => {
        if (s.restaurant_type) types.add(s.restaurant_type);
      });
      return [...types].sort();
    },

    get sortedSessionSuggestions() {
      let suggestions = this.activeSession?.suggestions || [];
      if (this.sessionCuisineFilter) {
        suggestions = suggestions.filter(s => s.restaurant_type === this.sessionCuisineFilter);
      }
      const sorted = [...suggestions];
      if (this.sessionSuggestSort === 'votes') {
        sorted.sort((a, b) => b.vote_count - a.vote_count || a.place.localeCompare(b.place));
      } else if (this.sessionSuggestSort === 'name') {
        sorted.sort((a, b) => a.place.localeCompare(b.place));
      } else if (this.sessionSuggestSort === 'suggester') {
        sorted.sort((a, b) => (a.suggested_by || '').localeCompare(b.suggested_by || '') || b.vote_count - a.vote_count);
      }
      return sorted;
    },

    get sessionRecap() {
      if (!this.activeSession || !this.winner) return null;
      const suggestions = this.activeSession.suggestions || [];
      const totalVotes = suggestions.reduce((sum, s) => sum + (s.vote_count || 0), 0);
      const winnerSugg = suggestions.find(s => s.place === this.winner.place);
      const topPlaces = [...suggestions].sort((a, b) => b.vote_count - a.vote_count).slice(0, 3);
      return {
        totalSuggestions: suggestions.length,
        totalVotes,
        suggestedBy: winnerSugg?.suggested_by || 'Unknown',
        topPlaces,
      };
    },

    // ── Init ──
    async init() {
      this.theme = document.cookie.replace(/(?:(?:^|.*;\s*)theme\s*=\s*([^;]*).*$)|^.*$/, '$1') || 'auto';
      document.documentElement.setAttribute('data-theme', this.theme);
      window.addEventListener('online', () => { this.online = true; });
      window.addEventListener('offline', () => { this.online = false; });
      this.touchEnabled = 'ontouchstart' in window;
      this.notificationsSupported = 'Notification' in window && 'PushManager' in window;

      // Detect invite URL (/invite/CODE)
      const inviteMatch = window.location.pathname.match(/^\/invite\/([A-Za-z0-9]{6})$/);
      if (inviteMatch) {
        this.pendingInviteCode = inviteMatch[1].toUpperCase();
      }

      // Detect password reset URL (/reset/TOKEN)
      const resetMatch = window.location.pathname.match(/^\/reset\/([a-f0-9]{64})$/);
      if (resetMatch) {
        this.resetToken = resetMatch[1];
        this.resetMode = true;
        await this.checkResetToken();
      }

      // Tab deep linking
      const validTabs = ['places', 'friends', 'sessions', 'account', 'admin'];
      const hash = window.location.hash.replace('#', '');
      if (validTabs.includes(hash)) this.activeTab = hash;
      window.addEventListener('hashchange', () => {
        const h = window.location.hash.replace('#', '');
        if (validTabs.includes(h)) this.activeTab = h;
      });

      try {
        const resp = await fetch('/api/me', { credentials: 'same-origin' });
        if (resp.ok) {
          const data = await resp.json();
          this.loggedIn = true;
          this.username = data.username;
          this.userId = data.id;
          this.email = data.email || '';
          this.isAdmin = !!data.is_admin;
          this.connectSocket();
          await this.loadAppData();
          if (this.notificationsSupported && Notification.permission === 'granted') {
            this.notificationsEnabled = true;
          }
          if (this.pendingInviteCode) {
            await this.autoJoinInvite();
          }
        }
      } catch (e) {
        // Not logged in
      }
    },

    async loadAppData() {
      await Promise.all([
        this.loadSuggestions(),
        this.loadPlaces(),
        this.loadFriends(),
        this.loadFriendRequests(),
        this.loadSessions(),
        this.loadRecentSuggestions(),
      ]);
    },

    // ── Socket.IO ──
    connectSocket() {
      if (this.socket) return;
      this.socket = io({ withCredentials: true });

      this.socket.on('session:member-joined', (data) => {
        if (!this.activeSession) return;
        const already = this.activeSession.members.some(m => m.id === data.userId);
        if (!already) {
          this.activeSession.members.push({ id: data.userId, username: data.username });
          this.showToast(`${data.username} joined the session`);
        }
      });

      this.socket.on('session:suggestion-added', (data) => {
        if (!this.activeSession) return;
        const already = this.activeSession.suggestions.some(s => s.id === data.id);
        if (!already) {
          this.activeSession.suggestions.push(data);
        }
      });

      this.socket.on('session:vote-updated', (data) => {
        if (!this.activeSession) return;
        const s = this.activeSession.suggestions.find(s => s.id === data.suggestion_id);
        if (s) {
          s.vote_count = data.vote_count;
          // Update user_voted for the current user
          if (data.user_id === this.userId) {
            s.user_voted = data.action === 'vote';
          }
        }
      });

      this.socket.on('session:winner-picked', (data) => {
        if (!this.activeSession) return;
        this.winner = data.winner;
        this.createConfetti();
      });

      this.socket.on('session:deadline-updated', (data) => {
        if (!this.activeSession) return;
        this.activeSession.session.voting_deadline = data.deadline;
        this.startDeadlineCountdown();
      });

      this.socket.on('session:message', (data) => {
        if (!this.activeSession) return;
        this.chatMessages.push(data);
        this.$nextTick(() => {
          const el = document.getElementById('chat-messages');
          if (el) el.scrollTop = el.scrollHeight;
        });
      });

      this.socket.on('session:closed', () => {
        if (!this.activeSession) return;
        this.activeSession.session.status = 'closed';
        this.showToast('Session has been closed');
      });

      this.socket.on('session:deleted', (data) => {
        this.sessions = this.sessions.filter(s => s.id !== data.sessionId);
        if (this.activeSession && this.activeSession.session.id === data.sessionId) {
          this.activeSession = null;
          this.winner = null;
          this.showToast('This session has been deleted', 'error');
        }
      });
    },

    disconnectSocket() {
      if (this.socket) {
        this.socket.disconnect();
        this.socket = null;
      }
    },

    // ── Toast ──
    showToast(message, type = 'success', actionLabel = null, actionCallback = null) {
      if (this.toastTimer) clearTimeout(this.toastTimer);
      const action = actionLabel ? { label: actionLabel, callback: actionCallback } : null;
      const timeout = action ? 5000 : 3000;
      this.toast = { message, type, visible: true, action };
      this.toastTimer = setTimeout(() => { this.toast.visible = false; this.toast.action = null; }, timeout);
    },

    showConfirm(message) {
      return new Promise((resolve) => {
        this.confirmModal = {
          visible: true,
          message,
          onConfirm: () => { this.confirmModal.visible = false; resolve(true); },
          onCancel: () => { this.confirmModal.visible = false; resolve(false); },
        };
      });
    },

    // ── Tabs ──
    switchTab(tab) {
      this.activeTab = tab;
      window.location.hash = tab;
    },

    // ── Tab Swipe ──
    tabSwipeStartX: 0,
    tabSwipeStartY: 0,

    handleTabSwipeStart(e) {
      this.tabSwipeStartX = e.touches[0].clientX;
      this.tabSwipeStartY = e.touches[0].clientY;
    },

    // ── Pull to Refresh ──
    pullStartY: 0,
    pullDistance: 0,
    pulling: false,
    refreshing: false,

    handlePullStart(e) {
      if (window.scrollY === 0) {
        this.pullStartY = e.touches[0].clientY;
        this.pulling = true;
      }
    },

    handlePullMove(e) {
      if (!this.pulling) return;
      const dy = e.touches[0].clientY - this.pullStartY;
      if (dy > 0 && window.scrollY === 0) {
        this.pullDistance = Math.min(dy * 0.5, 80);
      }
    },

    handlePullEnd() {
      if (this.pullDistance > 50) {
        this.refreshTab();
      }
      this.pulling = false;
      this.pullDistance = 0;
    },

    async refreshTab() {
      this.refreshing = true;
      if (this.activeTab === 'places') {
        await this.loadPlaces();
      } else if (this.activeTab === 'friends') {
        await Promise.all([this.loadFriends(), this.loadFriendRequests()]);
      } else if (this.activeTab === 'sessions') {
        await this.loadSessions();
        if (this.activeSession) await this.refreshSession();
      }
      this.refreshing = false;
      this.showToast('Refreshed!');
    },

    handleTabSwipeEnd(e) {
      const dx = e.changedTouches[0].clientX - this.tabSwipeStartX;
      const dy = e.changedTouches[0].clientY - this.tabSwipeStartY;
      if (Math.abs(dx) < 50 || Math.abs(dx) < Math.abs(dy)) return;
      const tabs = ['places', 'friends', 'sessions', 'account'];
      if (this.isAdmin) tabs.push('admin');
      const idx = tabs.indexOf(this.activeTab);
      if (idx === -1) return;
      if (dx < 0 && idx < tabs.length - 1) this.switchTab(tabs[idx + 1]);
      else if (dx > 0 && idx > 0) this.switchTab(tabs[idx - 1]);
    },

    fabAction() {
      if (this.activeTab === 'places') {
        window.scrollTo({ top: 0, behavior: 'smooth' });
        this.$nextTick(() => this.$refs.placeSearch?.focus());
      } else if (this.activeTab === 'friends') {
        window.scrollTo({ top: 0, behavior: 'smooth' });
        this.$nextTick(() => this.$refs.friendInput?.focus());
      } else if (this.activeTab === 'sessions') {
        if (!this.activeSession) {
          this.createSession();
        } else {
          window.scrollTo({ top: 0, behavior: 'smooth' });
        }
      }
    },

    // ── Theme ──
    toggleTheme() {
      const order = ['auto', 'light', 'dark'];
      this.theme = order[(order.indexOf(this.theme) + 1) % order.length];
      document.documentElement.setAttribute('data-theme', this.theme);
      document.cookie = `theme=${this.theme};path=/;max-age=${365 * 24 * 60 * 60}`;
    },

    // ── Auth ──
    async register() {
      this.authError = '';
      if (this.authForm.password !== this.authForm.confirmPassword) {
        this.authError = 'Passwords do not match.';
        return;
      }
      if (!this.authForm.email.trim()) {
        this.authError = 'Email is required.';
        return;
      }
      try {
        const resp = await fetch('/api/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'same-origin',
          body: JSON.stringify({
            username: this.authForm.username,
            password: this.authForm.password,
            email: this.authForm.email.trim(),
            remember: this.authForm.remember,
          }),
        });
        if (!resp.ok) {
          const err = await resp.json();
          this.authError = err.error || 'Registration failed.';
          return;
        }
        const data = await resp.json();
        this.loggedIn = true;
        this.username = data.username;
        this.showToast('Account created!');
        await this.fetchMe();
        this.connectSocket();
        await this.loadAppData();
        if (this.pendingInviteCode) await this.autoJoinInvite();
      } catch (e) {
        this.authError = 'Unexpected error during registration.';
      }
    },

    async login() {
      this.authError = '';
      try {
        const resp = await fetch('/api/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'same-origin',
          body: JSON.stringify({
            username: this.authForm.username,
            password: this.authForm.password,
            remember: this.authForm.remember,
          }),
        });
        if (!resp.ok) {
          const err = await resp.json();
          this.authError = err.error || 'Login failed.';
          return;
        }
        const data = await resp.json();
        this.loggedIn = true;
        this.username = data.username;
        this.showToast('Welcome back!');
        await this.fetchMe();
        this.connectSocket();
        await this.loadAppData();
        if (this.pendingInviteCode) await this.autoJoinInvite();
      } catch (e) {
        this.authError = 'Unexpected error during login.';
      }
    },

    async forgotPassword() {
      this.authError = '';
      if (!this.resetEmail.trim()) {
        this.authError = 'Please enter your email address.';
        return;
      }
      try {
        const resp = await fetch('/api/forgot-password', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: this.resetEmail.trim() }),
        });
        const data = await resp.json();
        if (!resp.ok) {
          this.authError = data.error || 'Failed to send reset email.';
          return;
        }
        this.showToast(data.message || 'If an account with that email exists, a reset link has been sent.');
        this.resetMode = false;
        this.authMode = 'login';
      } catch (e) {
        this.authError = 'Failed to send reset email.';
      }
    },

    async checkResetToken() {
      if (!this.resetToken) return;
      try {
        const resp = await fetch(`/api/reset-password/${this.resetToken}`);
        const data = await resp.json();
        if (data.valid) {
          this.resetTokenValid = true;
          this.resetUsername = data.username;
        } else {
          this.resetTokenValid = false;
          this.showToast('Reset link is invalid or expired', 'error');
        }
      } catch (e) {
        this.resetTokenValid = false;
      }
    },

    async submitPasswordReset() {
      this.authError = '';
      if (this.resetNewPassword !== this.resetConfirmPassword) {
        this.authError = 'Passwords do not match.';
        return;
      }
      if (this.resetNewPassword.length < 6) {
        this.authError = 'Password must be at least 6 characters.';
        return;
      }
      try {
        const resp = await fetch('/api/reset-password', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token: this.resetToken, newPassword: this.resetNewPassword }),
        });
        if (!resp.ok) {
          const data = await resp.json();
          this.authError = data.error || 'Failed to reset password.';
          return;
        }
        this.showToast('Password reset! You can now log in.');
        this.resetToken = '';
        this.resetTokenValid = false;
        this.resetNewPassword = '';
        this.resetConfirmPassword = '';
        this.resetMode = false;
        this.authMode = 'login';
        window.history.replaceState(null, '', '/');
      } catch (e) {
        this.authError = 'Failed to reset password.';
      }
    },

    async fetchMe() {
      try {
        const resp = await fetch('/api/me', { credentials: 'same-origin' });
        if (resp.ok) {
          const data = await resp.json();
          this.userId = data.id;
          this.username = data.username;
          this.email = data.email || '';
          this.isAdmin = !!data.is_admin;
        }
      } catch (e) { /* ignore */ }
    },

    async logout() {
      this.disconnectSocket();
      await fetch('/api/logout', { method: 'POST', credentials: 'same-origin' });
      this.loggedIn = false;
      this.username = '';
      this.userId = null;
      this.email = '';
      this.isAdmin = false;
      this.likes = [];
      this.dislikes = [];
      this.suggestions = [];
      this.friends = [];
      this.friendRequests = [];
      this.viewingFriendLikes = null;
      this.sessions = [];
      this.activeSession = null;
      this.winner = null;
    },

    // ── API Helper ──
    async api(url, opts = {}) {
      opts.credentials = 'same-origin';
      opts.headers = { 'Content-Type': 'application/json', ...(opts.headers || {}) };
      const resp = await fetch(url, opts);
      if (resp.status === 401) {
        this.loggedIn = false;
        throw new Error('Unauthorized');
      }
      return resp;
    },

    // ── Places ──
    async searchPlaces() {
      this.highlightedIndex = -1;
      const q = this.placeSearch.trim();
      if (!q) { this.predictions = []; this.searchedOnce = false; return; }
      this.searching = true;
      try {
        const resp = await this.api(`/api/autocomplete?input=${encodeURIComponent(q)}`);
        const data = await resp.json();
        this.predictions = data.predictions || [];
        this.searchedOnce = true;
      } catch (e) {
        this.predictions = [];
      } finally {
        this.searching = false;
      }
    },

    selectPlace(pred) {
      const restaurantType = this.formatPlaceType(pred.types);
      this.selectedPlace = { name: pred.description, place_id: pred.place_id, restaurant_type: restaurantType };
      this.placeSearch = pred.description;
      this.predictions = [];
      this.highlightedIndex = -1;
      this.api('/api/place', {
        method: 'POST',
        body: JSON.stringify({ place: pred.description, place_id: pred.place_id, restaurant_type: restaurantType || null }),
      });
    },

    handlePlaceKeydown(event) {
      if (this.predictions.length === 0) return;
      if (event.key === 'ArrowDown') {
        this.highlightedIndex = (this.highlightedIndex + 1) % this.predictions.length;
      } else if (event.key === 'ArrowUp') {
        this.highlightedIndex = this.highlightedIndex <= 0 ? this.predictions.length - 1 : this.highlightedIndex - 1;
      } else if (event.key === 'Enter' && this.highlightedIndex >= 0) {
        this.selectPlace(this.predictions[this.highlightedIndex]);
      }
    },

    handleSessionKeydown(event) {
      if (this.sessionPredictions.length === 0) return;
      if (event.key === 'ArrowDown') {
        this.sessionHighlightedIndex = (this.sessionHighlightedIndex + 1) % this.sessionPredictions.length;
      } else if (event.key === 'ArrowUp') {
        this.sessionHighlightedIndex = this.sessionHighlightedIndex <= 0 ? this.sessionPredictions.length - 1 : this.sessionHighlightedIndex - 1;
      } else if (event.key === 'Enter' && this.sessionHighlightedIndex >= 0) {
        const pred = this.sessionPredictions[this.sessionHighlightedIndex];
        this.suggestToSession(pred.description, pred.place_id, this.formatPlaceType(pred.types));
      }
    },

    async likePlace() {
      if (!this.selectedPlace) return;
      const resp = await this.api('/api/places', {
        method: 'POST',
        body: JSON.stringify({ type: 'likes', place: this.selectedPlace.name, place_id: this.selectedPlace.place_id, restaurant_type: this.selectedPlace.restaurant_type || null }),
      });
      const data = await resp.json();
      this.showToast(data.movedFrom === 'dislikes' ? 'Moved from dislikes to likes!' : 'Place liked!');
      this.selectedPlace = null;
      this.placeSearch = '';
      await this.loadPlaces();
    },

    async dislikePlace() {
      if (!this.selectedPlace) return;
      const resp = await this.api('/api/places', {
        method: 'POST',
        body: JSON.stringify({ type: 'dislikes', place: this.selectedPlace.name, place_id: this.selectedPlace.place_id, restaurant_type: this.selectedPlace.restaurant_type || null }),
      });
      const data = await resp.json();
      this.showToast(data.movedFrom === 'likes' ? 'Moved from likes to dislikes.' : 'Place disliked.');
      this.selectedPlace = null;
      this.placeSearch = '';
      await this.loadPlaces();
    },

    async wantToTryPlace() {
      if (!this.selectedPlace) return;
      const resp = await this.api('/api/places', {
        method: 'POST',
        body: JSON.stringify({ type: 'want_to_try', place: this.selectedPlace.name, place_id: this.selectedPlace.place_id, restaurant_type: this.selectedPlace.restaurant_type || null }),
      });
      const data = await resp.json();
      this.showToast(data.movedFrom === 'dislikes' ? 'Moved from dislikes to want to try!' : 'Added to want to try!');
      this.selectedPlace = null;
      this.placeSearch = '';
      await this.loadPlaces();
    },

    isWantToTry(placeName) {
      return (this.sessionWantToTry[placeName] || []).length > 0;
    },
    getWantToTryUsers(placeName) {
      return this.sessionWantToTry[placeName] || [];
    },

    async removePlace(type, placeName) {
      const list = type === 'likes' ? 'likes' : type === 'want_to_try' ? 'wantToTry' : 'dislikes';
      const removedItem = this[list].find(p => p.name === placeName);
      if (!removedItem) return;
      this[list] = this[list].filter(p => p.name !== placeName);

      let undone = false;
      const timer = setTimeout(async () => {
        if (undone) return;
        await this.api('/api/places', {
          method: 'POST',
          body: JSON.stringify({ type, place: placeName, remove: true }),
        });
      }, 5000);

      this.showToast(`Removed "${placeName}"`, 'success', 'Undo', () => {
        undone = true;
        clearTimeout(timer);
        this[list].push(removedItem);
        this[list].sort((a, b) => a.name.localeCompare(b.name));
        this.toast.visible = false;
      });
    },

    async loadPlaces() {
      this.loading.places = true;
      try {
        const resp = await this.api('/api/places');
        const data = await resp.json();
        this.likes = data.likes || [];
        this.dislikes = data.dislikes || [];
        this.wantToTry = data.want_to_try || [];
      } catch (e) { /* ignore */ }
      this.loading.places = false;
    },

    openMap(place) {
      window.open(`https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(place)}`, '_blank');
    },

    // ── Quick Pick ──
    async quickPick() {
      if (this.quickPicking || this.likes.length === 0) return;
      this.quickPicking = true;
      this.quickPickResult = null;

      let cycles = 15;
      let delay = 60;
      let i = 0;

      await new Promise(resolve => {
        const spin = () => {
          this.quickPickResult = this.likes[i % this.likes.length];
          i++;
          cycles--;
          if (cycles > 0) {
            delay += 20;
            setTimeout(spin, delay);
          } else {
            resolve();
          }
        };
        spin();
      });

      // Final random pick
      this.quickPickResult = this.likes[Math.floor(Math.random() * this.likes.length)];
      this.quickPicking = false;
    },

    // ── Notes ──
    startEditNote(place) {
      this.editingNote = place.name;
      this.noteText = place.notes || '';
    },

    async saveNote(place) {
      try {
        await this.api('/api/places/notes', {
          method: 'POST',
          body: JSON.stringify({ place: place.name, notes: this.noteText.trim() }),
        });
        place.notes = this.noteText.trim() || null;
        this.editingNote = null;
        this.noteText = '';
        this.showToast('Note saved');
      } catch (e) {
        this.showToast('Failed to save note', 'error');
      }
    },

    cancelEditNote() {
      this.editingNote = null;
      this.noteText = '';
    },

    // ── Suggestions ──
    async suggestPersonal(place) {
      await this.api('/api/suggest', {
        method: 'POST',
        body: JSON.stringify({ place: place.name, place_id: place.place_id, restaurant_type: place.restaurant_type || null }),
      });
      this.showToast('Suggested!');
      await this.loadSuggestions();
    },

    async removeSuggestion(placeName) {
      const removedItem = this.suggestions.find(s => s.name === placeName);
      if (!removedItem) return;
      this.suggestions = this.suggestions.filter(s => s.name !== placeName);
      this.currentSuggestions = new Set(this.suggestions.map(s => s.name));

      let undone = false;
      const timer = setTimeout(async () => {
        if (undone) return;
        await this.api('/api/suggestions/remove', {
          method: 'POST',
          body: JSON.stringify({ place: placeName }),
        });
      }, 5000);

      this.showToast(`Removed "${placeName}"`, 'success', 'Undo', () => {
        undone = true;
        clearTimeout(timer);
        this.suggestions.push(removedItem);
        this.currentSuggestions = new Set(this.suggestions.map(s => s.name));
        this.toast.visible = false;
      });
    },

    async loadSuggestions() {
      try {
        const resp = await this.api('/api/suggestions');
        const data = await resp.json();
        this.suggestions = data.suggestions || [];
        this.currentSuggestions = new Set(this.suggestions.map(s => s.name));
      } catch (e) { /* ignore */ }
    },

    // ── Friends ──
    async inviteFriend() {
      if (!this.friendUsername.trim()) return;
      try {
        const resp = await this.api('/api/invite', {
          method: 'POST',
          body: JSON.stringify({ friendUsername: this.friendUsername.trim() }),
        });
        if (!resp.ok) {
          const err = await resp.json();
          this.showToast(err.error || 'Failed to invite', 'error');
          return;
        }
        this.showToast('Friend request sent!');
        this.friendUsername = '';
        await Promise.all([this.loadFriends(), this.loadFriendRequests()]);
      } catch (e) {
        this.showToast('Failed to invite friend', 'error');
      }
    },

    async loadFriends() {
      this.loading.friends = true;
      try {
        const resp = await this.api('/api/friends');
        const data = await resp.json();
        this.friends = data.friends || [];
      } catch (e) { /* ignore */ }
      this.loading.friends = false;
    },

    async loadCommonPlaces(friendUsername) {
      this.commonFriend = friendUsername;
      try {
        const resp = await this.api(`/api/common-places?friendUsername=${encodeURIComponent(friendUsername)}`);
        const data = await resp.json();
        this.commonPlaces = data.common || [];
      } catch (e) {
        this.commonPlaces = [];
      }
    },

    async loadFriendRequests() {
      try {
        const resp = await this.api('/api/friend-requests');
        const data = await resp.json();
        this.friendRequests = data.requests || [];
      } catch (e) { /* ignore */ }
    },

    async acceptFriend(userId) {
      try {
        const resp = await this.api(`/api/friend-requests/${userId}/accept`, { method: 'POST' });
        if (!resp.ok) {
          const err = await resp.json();
          this.showToast(err.error || 'Failed to accept', 'error');
          return;
        }
        this.showToast('Friend request accepted!');
        await Promise.all([this.loadFriends(), this.loadFriendRequests()]);
      } catch (e) {
        this.showToast('Failed to accept request', 'error');
      }
    },

    async rejectFriend(userId) {
      try {
        await this.api(`/api/friend-requests/${userId}/reject`, { method: 'POST' });
        this.showToast('Friend request declined.');
        await this.loadFriendRequests();
      } catch (e) {
        this.showToast('Failed to decline request', 'error');
      }
    },

    async viewFriendLikes(friendId, friendUsername) {
      try {
        const resp = await this.api(`/api/friends/${friendId}/likes`);
        if (!resp.ok) {
          const err = await resp.json();
          this.showToast(err.error || 'Failed to load likes', 'error');
          return;
        }
        const data = await resp.json();
        this.viewingFriendLikes = { username: friendUsername, likes: data.likes || [] };
      } catch (e) {
        this.showToast('Failed to load friend\'s likes', 'error');
      }
    },

    async addFriendPlace(place) {
      try {
        const resp = await this.api('/api/places', {
          method: 'POST',
          body: JSON.stringify({ type: 'likes', place: place.name, place_id: place.place_id, restaurant_type: place.restaurant_type || null }),
        });
        if (!resp.ok) {
          this.showToast('Failed to add place', 'error');
          return;
        }
        this.showToast(`Added "${place.name}" to your likes!`);
        await this.loadPlaces();
      } catch (e) {
        this.showToast('Failed to add place', 'error');
      }
    },

    async removeFriend(friendId) {
      if (!await this.showConfirm('Remove this friend? This action is mutual.')) return;
      try {
        const resp = await this.api(`/api/friends/${friendId}`, { method: 'DELETE' });
        if (!resp.ok) {
          const err = await resp.json();
          this.showToast(err.error || 'Failed to remove friend', 'error');
          return;
        }
        this.showToast('Friend removed.');
        this.viewingFriendLikes = null;
        this.commonPlaces = [];
        await this.loadFriends();
      } catch (e) {
        this.showToast('Failed to remove friend', 'error');
      }
    },

    formatDate(dateStr) {
      if (!dateStr) return '';
      const d = new Date(dateStr + 'Z');
      return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
    },

    // ── Sessions ──
    async loadSessions() {
      this.loading.sessions = true;
      try {
        const resp = await this.api('/api/sessions');
        const data = await resp.json();
        this.sessions = data.sessions || [];
      } catch (e) { /* ignore */ }
      this.loading.sessions = false;
    },

    async createSession() {
      const name = this.newSessionName.trim() || 'Dinner Session';
      try {
        const resp = await this.api('/api/sessions', {
          method: 'POST',
          body: JSON.stringify({ name }),
        });
        const data = await resp.json();
        this.newSessionName = '';
        this.showToast(`Session created! Code: ${data.code}`);
        await this.loadSessions();
      } catch (e) {
        this.showToast('Failed to create session', 'error');
      }
    },

    async joinSession() {
      const code = this.joinCode.trim().toUpperCase();
      if (!code) return;
      try {
        const resp = await this.api('/api/sessions/join', {
          method: 'POST',
          body: JSON.stringify({ code }),
        });
        if (!resp.ok) {
          const err = await resp.json();
          this.showToast(err.error || 'Failed to join', 'error');
          return;
        }
        this.joinCode = '';
        this.showToast('Joined session!');
        await this.loadSessions();
      } catch (e) {
        this.showToast('Failed to join session', 'error');
      }
    },

    async openSession(sessionId) {
      try {
        const resp = await this.api(`/api/sessions/${sessionId}`);
        const data = await resp.json();
        this.sessionWantToTry = data.want_to_try || {};
        this.activeSession = data;
        this.winner = null;
        this.sessionCuisineFilter = '';
        this.mapView = false;
        if (this.activeSession.session.winner_place) {
          this.winner = { place: this.activeSession.session.winner_place };
        }
        if (this.socket) this.socket.emit('join-session', sessionId);
        try {
          const dResp = await this.api(`/api/sessions/${sessionId}/dislikes`);
          const dData = await dResp.json();
          this.sessionDislikes = dData.dislikes || [];
        } catch (e) { this.sessionDislikes = []; }
        await this.loadChatMessages();
        this.startDeadlineCountdown();
      } catch (e) {
        this.showToast('Failed to open session', 'error');
      }
    },

    async refreshSession() {
      if (!this.activeSession) return;
      try {
        const resp = await this.api(`/api/sessions/${this.activeSession.session.id}`);
        const data = await resp.json();
        this.sessionWantToTry = data.want_to_try || {};
        this.activeSession = data;
      } catch (e) { /* ignore */ }
    },

    closeActiveSession() {
      if (this.socket && this.activeSession) {
        this.socket.emit('leave-session', this.activeSession.session.id);
      }
      this.activeSession = null;
      this.winner = null;
      this.closingSession = false;
      this.sessionPlaceSearch = '';
      this.sessionPredictions = [];
      this.chatMessages = [];
      this.chatInput = '';
      this.chatVisible = false;
      this.sessionCuisineFilter = '';
      this.mapView = false;
      if (this.deadlineTimer) { clearInterval(this.deadlineTimer); this.deadlineTimer = null; }
      this.deadlineCountdown = '';
      this.deadlineInput = '';
      if (this.mapInstance) { this.mapInstance = null; this.mapMarkers = []; }
      this.loadSessions();
    },

    closeSession() {
      if (!this.activeSession) return;
      this.closingSession = true;
    },

    cancelClose() {
      this.closingSession = false;
    },

    async closeWithWinner(place) {
      if (!this.activeSession) return;
      await this.api(`/api/sessions/${this.activeSession.session.id}/close`, {
        method: 'POST',
        body: JSON.stringify({ winner_place: place }),
      });
      this.closingSession = false;
      this.winner = { place };
      this.showToast(`Session closed! Winner: ${place}`);
      await this.refreshSession();
    },

    async closeWithoutWinner() {
      if (!this.activeSession) return;
      if (!await this.showConfirm('Close without selecting a winner?')) return;
      await this.api(`/api/sessions/${this.activeSession.session.id}/close`, {
        method: 'POST',
        body: JSON.stringify({}),
      });
      this.closingSession = false;
      this.showToast('Session closed.');
      await this.refreshSession();
    },

    async deleteSession(sessionId) {
      if (!await this.showConfirm('Permanently delete this session? This cannot be undone.')) return;
      try {
        const resp = await this.api(`/api/sessions/${sessionId}`, { method: 'DELETE' });
        if (!resp.ok) {
          const err = await resp.json();
          this.showToast(err.error || 'Failed to delete session', 'error');
          return;
        }
        this.sessions = this.sessions.filter(s => s.id !== sessionId);
        if (this.activeSession && this.activeSession.session.id === sessionId) {
          this.activeSession = null;
          this.winner = null;
        }
        this.showToast('Session deleted.');
      } catch (e) {
        this.showToast('Failed to delete session', 'error');
      }
    },

    async inviteToSession() {
      if (!this.sessionInviteUsername.trim() || !this.activeSession) return;
      try {
        const resp = await this.api(`/api/sessions/${this.activeSession.session.id}/invite`, {
          method: 'POST',
          body: JSON.stringify({ username: this.sessionInviteUsername.trim() }),
        });
        if (!resp.ok) {
          const err = await resp.json();
          this.showToast(err.error || 'Failed to invite', 'error');
          return;
        }
        const data = await resp.json();
        this.showToast(data.alreadyMember ? 'User is already a member' : `Invited ${this.sessionInviteUsername.trim()}!`);
        this.sessionInviteUsername = '';
        await this.refreshSession();
      } catch (e) {
        this.showToast('Failed to invite user', 'error');
      }
    },

    quickInviteFriend(friendUsername) {
      this.sessionInviteUsername = friendUsername;
      this.inviteToSession();
    },

    isSessionDisliked(placeName) {
      return this.sessionDislikes.includes(placeName);
    },

    copyCode() {
      const code = this.activeSession?.session?.code;
      if (code) {
        navigator.clipboard.writeText(code);
        this.showToast('Code copied!');
      }
    },

    // ── Session Suggest ──
    async searchSessionPlaces() {
      this.sessionHighlightedIndex = -1;
      const q = this.sessionPlaceSearch.trim();
      if (!q) { this.sessionPredictions = []; this.sessionSearchedOnce = false; return; }
      this.sessionSearching = true;
      try {
        const resp = await this.api(`/api/autocomplete?input=${encodeURIComponent(q)}`);
        const data = await resp.json();
        this.sessionPredictions = data.predictions || [];
        this.sessionSearchedOnce = true;
      } catch (e) {
        this.sessionPredictions = [];
      } finally {
        this.sessionSearching = false;
      }
    },

    async suggestToSession(place, placeId, restaurantType) {
      if (!this.activeSession) return;
      try {
        const resp = await this.api(`/api/sessions/${this.activeSession.session.id}/suggest`, {
          method: 'POST',
          body: JSON.stringify({ place, place_id: placeId || null, restaurant_type: restaurantType || null }),
        });
        if (!resp.ok) {
          const err = await resp.json();
          this.showToast(err.error || 'Failed to suggest', 'error');
          return;
        }
        this.sessionPlaceSearch = '';
        this.sessionPredictions = [];
        this.showToast('Place suggested!');
        await this.refreshSession();
      } catch (e) {
        this.showToast('Failed to suggest', 'error');
      }
    },

    // ── Voting ──
    async toggleVote(suggestion) {
      if (!this.activeSession) return;
      const endpoint = suggestion.user_voted ? 'unvote' : 'vote';
      await this.api(`/api/sessions/${this.activeSession.session.id}/${endpoint}`, {
        method: 'POST',
        body: JSON.stringify({ suggestion_id: suggestion.id }),
      });
      await this.refreshSession();
    },

    // ── Random Pick ──
    async randomPick() {
      if (!this.activeSession || this.picking) return;
      this.picking = true;
      this.winner = null;

      const names = (this.activeSession.suggestions || []).map(s => s.place);
      if (names.length === 0) {
        this.showToast('No suggestions to pick from!', 'error');
        this.picking = false;
        return;
      }

      // Enhanced spinning animation
      const winnerEl = document.getElementById('winner-text');
      let cycles = 25;
      let delay = 40;
      let i = 0;

      await new Promise(resolve => {
        const spin = () => {
          this.winner = { place: names[i % names.length] };
          if (winnerEl) {
            winnerEl.classList.remove('spin-enhanced');
            void winnerEl.offsetWidth;
            winnerEl.classList.add('spin-enhanced');
          }
          i++;
          cycles--;
          if (cycles > 0) {
            delay = Math.floor(delay * 1.12);
            setTimeout(spin, delay);
          } else {
            resolve();
          }
        };
        spin();
      });

      // Fetch actual server-side weighted pick
      try {
        const resp = await this.api(`/api/sessions/${this.activeSession.session.id}/pick`, {
          method: 'POST',
          body: JSON.stringify({ mode: 'random' }),
        });
        const data = await resp.json();
        this.winner = data.winner;
        if (winnerEl) {
          winnerEl.classList.remove('spin-enhanced');
          winnerEl.classList.add('winner-bounce');
        }
        this.showToast(`Winner: ${data.winner.place}`);
        this.createConfetti();
      } catch (e) {
        this.showToast('Failed to pick', 'error');
      }
      this.picking = false;
    },

    // ── Closest Pick ──
    async closestPick() {
      if (!this.activeSession || this.picking) return;
      this.picking = true;
      this.winner = null;

      if (!navigator.geolocation) {
        this.showToast('Geolocation not supported by your browser', 'error');
        this.picking = false;
        return;
      }

      this.winner = { place: 'Getting your location...' };

      try {
        const position = await new Promise((resolve, reject) => {
          navigator.geolocation.getCurrentPosition(resolve, reject, {
            enableHighAccuracy: true,
            timeout: 10000,
          });
        });

        this.userLat = position.coords.latitude;
        this.userLng = position.coords.longitude;
        this.winner = { place: 'Finding closest restaurant...' };

        const resp = await this.api(`/api/sessions/${this.activeSession.session.id}/pick`, {
          method: 'POST',
          body: JSON.stringify({ mode: 'closest', lat: this.userLat, lng: this.userLng }),
        });

        if (!resp.ok) {
          const err = await resp.json();
          this.winner = null;
          this.showToast(err.error || 'Failed to find closest', 'error');
          this.picking = false;
          return;
        }

        const data = await resp.json();
        this.winner = data.winner;
        this.showToast(`Closest: ${data.winner.place}`);
        this.createConfetti();
      } catch (e) {
        this.winner = null;
        if (e.code === 1) {
          this.showToast('Location access denied. Please enable location permissions.', 'error');
        } else {
          this.showToast('Failed to get location', 'error');
        }
      }
      this.picking = false;
    },

    // ── Swipe Gestures ──
    onTouchStart(event, placeName) {
      if (!this.touchEnabled) return;
      this.swipeState = { name: placeName, startX: event.touches[0].clientX, currentX: 0, swiping: true };
    },

    onTouchMove(event, placeName) {
      if (!this.swipeState.swiping || this.swipeState.name !== placeName) return;
      this.swipeState.currentX = event.touches[0].clientX - this.swipeState.startX;
    },

    onTouchEnd(type, place) {
      if (!this.swipeState.swiping) return;
      const offset = this.swipeState.currentX;
      this.swipeState = { name: null, startX: 0, currentX: 0, swiping: false };
      if (offset > 80) {
        this.suggestPersonal(place);
      } else if (offset < -80) {
        this.removePlace(type, place.name);
      }
    },

    getSwipeTransform(placeName) {
      if (this.swipeState.name === placeName && this.swipeState.swiping) {
        return `translateX(${this.swipeState.currentX}px)`;
      }
      return '';
    },

    getSwipeBg(placeName) {
      if (this.swipeState.name !== placeName || !this.swipeState.swiping) return '';
      if (this.swipeState.currentX > 40) return 'rgba(39, 174, 96, 0.15)';
      if (this.swipeState.currentX < -40) return 'rgba(231, 76, 60, 0.15)';
      return '';
    },

    // ── Share ──
    async shareWinner() {
      if (!this.winner) return;
      const text = `We picked ${this.winner.place}! -- from Dinner Roulette`;
      if (navigator.share) {
        try { await navigator.share({ title: 'Dinner Roulette', text }); } catch (e) { /* user cancelled */ }
      } else if (navigator.clipboard) {
        await navigator.clipboard.writeText(text);
        this.showToast('Result copied to clipboard!');
      }
    },

    // ── Recent Suggestions ──
    async loadRecentSuggestions() {
      try {
        const resp = await this.api('/api/suggestions/recent');
        const data = await resp.json();
        this.recentSuggestions = data.recent || [];
      } catch (e) { /* ignore */ }
    },

    // ── Invite Non-App Users ──
    async autoJoinInvite() {
      if (!this.pendingInviteCode) return;
      const code = this.pendingInviteCode;
      this.pendingInviteCode = null;
      window.history.replaceState(null, '', '/');
      try {
        const resp = await this.api('/api/sessions/join', {
          method: 'POST',
          body: JSON.stringify({ code }),
        });
        if (resp.ok) {
          const data = await resp.json();
          this.showToast('Joined session!');
          this.activeTab = 'sessions';
          await this.loadSessions();
          await this.openSession(data.id);
        } else {
          const err = await resp.json();
          this.showToast(err.error || 'Failed to join session', 'error');
        }
      } catch (e) {
        this.showToast('Failed to join session', 'error');
      }
    },

    async shareSessionInvite() {
      if (!this.activeSession) return;
      const code = this.activeSession.session.code;
      const url = `${window.location.origin}/invite/${code}`;
      const text = `Join my Dinner Roulette session! Use code ${code} or click: ${url}`;
      if (navigator.share) {
        try { await navigator.share({ title: 'Dinner Roulette Invite', text, url }); } catch (e) { /* cancelled */ }
      } else if (navigator.clipboard) {
        await navigator.clipboard.writeText(url);
        this.showToast('Invite link copied!');
      }
    },

    // ── Deadline ──
    async setDeadline() {
      if (!this.deadlineInput || !this.activeSession) return;
      try {
        await this.api(`/api/sessions/${this.activeSession.session.id}/deadline`, {
          method: 'POST',
          body: JSON.stringify({ deadline: this.deadlineInput }),
        });
        this.activeSession.session.voting_deadline = this.deadlineInput;
        this.startDeadlineCountdown();
        this.showToast('Deadline set!');
      } catch (e) {
        this.showToast('Failed to set deadline', 'error');
      }
    },

    async removeDeadline() {
      if (!this.activeSession) return;
      try {
        await this.api(`/api/sessions/${this.activeSession.session.id}/deadline`, {
          method: 'POST',
          body: JSON.stringify({ deadline: null }),
        });
        this.activeSession.session.voting_deadline = null;
        if (this.deadlineTimer) { clearInterval(this.deadlineTimer); this.deadlineTimer = null; }
        this.deadlineCountdown = '';
        this.deadlineInput = '';
        this.showToast('Deadline removed');
      } catch (e) {
        this.showToast('Failed to remove deadline', 'error');
      }
    },

    startDeadlineCountdown() {
      if (this.deadlineTimer) { clearInterval(this.deadlineTimer); this.deadlineTimer = null; }
      this.deadlineCountdown = '';
      const deadline = this.activeSession?.session?.voting_deadline;
      if (!deadline) return;

      const update = () => {
        const now = new Date();
        const end = new Date(deadline);
        const diff = end - now;
        if (diff <= 0) {
          this.deadlineCountdown = 'Deadline passed!';
          clearInterval(this.deadlineTimer);
          this.deadlineTimer = null;
          return;
        }
        const hours = Math.floor(diff / 3600000);
        const mins = Math.floor((diff % 3600000) / 60000);
        const secs = Math.floor((diff % 60000) / 1000);
        if (hours > 0) {
          this.deadlineCountdown = `${hours}h ${mins}m ${secs}s remaining`;
        } else if (mins > 0) {
          this.deadlineCountdown = `${mins}m ${secs}s remaining`;
        } else {
          this.deadlineCountdown = `${secs}s remaining`;
        }
      };
      update();
      this.deadlineTimer = setInterval(update, 1000);
    },

    // ── Chat ──
    async loadChatMessages() {
      if (!this.activeSession) return;
      try {
        const resp = await this.api(`/api/sessions/${this.activeSession.session.id}/messages`);
        const data = await resp.json();
        this.chatMessages = data.messages || [];
      } catch (e) { this.chatMessages = []; }
    },

    async sendChatMessage() {
      if (!this.chatInput.trim() || !this.activeSession) return;
      try {
        await this.api(`/api/sessions/${this.activeSession.session.id}/messages`, {
          method: 'POST',
          body: JSON.stringify({ message: this.chatInput.trim() }),
        });
        this.chatInput = '';
      } catch (e) {
        this.showToast('Failed to send message', 'error');
      }
    },

    formatChatTime(dateStr) {
      if (!dateStr) return '';
      const d = new Date(dateStr + (dateStr.includes('Z') ? '' : 'Z'));
      return d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
    },

    // ── Map View ──
    async loadMapsApi() {
      if (this.mapsLoaded || window.google?.maps) { this.mapsLoaded = true; return; }
      try {
        const resp = await this.api('/api/config/maps-key');
        const data = await resp.json();
        await new Promise((resolve, reject) => {
          const script = document.createElement('script');
          script.src = `https://maps.googleapis.com/maps/api/js?key=${data.key}`;
          script.onload = resolve;
          script.onerror = reject;
          document.head.appendChild(script);
        });
        this.mapsLoaded = true;
      } catch (e) {
        this.showToast('Failed to load maps', 'error');
      }
    },

    async toggleMapView() {
      this.mapView = !this.mapView;
      if (this.mapView) {
        await this.loadMapsApi();
        this.$nextTick(() => this.initMap());
      }
    },

    initMap() {
      if (!window.google?.maps) return;
      const container = document.getElementById('session-map');
      if (!container) return;
      const suggestions = this.activeSession?.suggestions || [];
      const withCoords = suggestions.filter(s => s.lat != null && s.lng != null);
      const center = withCoords.length > 0
        ? { lat: withCoords[0].lat, lng: withCoords[0].lng }
        : { lat: 40.7128, lng: -74.006 };
      this.mapInstance = new google.maps.Map(container, {
        center,
        zoom: 13,
        mapTypeControl: false,
        streetViewControl: false,
      });
      this.updateMapMarkers();
    },

    updateMapMarkers() {
      if (!this.mapInstance) return;
      this.mapMarkers.forEach(m => m.setMap(null));
      this.mapMarkers = [];
      const suggestions = this.activeSession?.suggestions || [];
      const withCoords = suggestions.filter(s => s.lat != null && s.lng != null);
      const bounds = new google.maps.LatLngBounds();
      withCoords.forEach((s, idx) => {
        const marker = new google.maps.Marker({
          position: { lat: s.lat, lng: s.lng },
          map: this.mapInstance,
          title: s.place,
          label: { text: String(idx + 1), color: 'white', fontWeight: 'bold' },
        });
        const infoWindow = new google.maps.InfoWindow({
          content: `<strong>${s.place}</strong>${s.restaurant_type ? `<br><small>${s.restaurant_type}</small>` : ''}<br><small>${s.vote_count} vote${s.vote_count !== 1 ? 's' : ''}</small>`,
        });
        marker.addListener('click', () => infoWindow.open(this.mapInstance, marker));
        this.mapMarkers.push(marker);
        bounds.extend(marker.getPosition());
      });
      if (withCoords.length > 1) this.mapInstance.fitBounds(bounds);
      else if (withCoords.length === 1) this.mapInstance.setCenter(withCoords[0]);
    },

    // ── Notifications ──
    async enableNotifications() {
      if (!this.notificationsSupported) return;
      const permission = await Notification.requestPermission();
      if (permission !== 'granted') {
        this.showToast('Notification permission denied', 'error');
        return;
      }
      try {
        const resp = await this.api('/api/push/vapid-key');
        const { publicKey } = await resp.json();
        const reg = await navigator.serviceWorker.ready;
        const sub = await reg.pushManager.subscribe({
          userVisibleOnly: true,
          applicationServerKey: urlBase64ToUint8Array(publicKey),
        });
        await this.api('/api/push/subscribe', {
          method: 'POST',
          body: JSON.stringify(sub.toJSON()),
        });
        this.notificationsEnabled = true;
        this.showToast('Notifications enabled!');
      } catch (e) {
        this.showToast('Failed to enable notifications', 'error');
      }
    },

    async disableNotifications() {
      try {
        const reg = await navigator.serviceWorker.ready;
        const sub = await reg.pushManager.getSubscription();
        if (sub) {
          await this.api('/api/push/subscribe', {
            method: 'DELETE',
            body: JSON.stringify({ endpoint: sub.endpoint }),
          });
          await sub.unsubscribe();
        }
        this.notificationsEnabled = false;
        this.showToast('Notifications disabled');
      } catch (e) {
        this.showToast('Failed to disable notifications', 'error');
      }
    },

    // ── Account ──
    async changePassword() {
      if (this.accountForm.newPassword !== this.accountForm.confirmNewPassword) {
        this.showToast('New passwords do not match', 'error');
        return;
      }
      try {
        const resp = await this.api('/api/change-password', {
          method: 'POST',
          body: JSON.stringify({
            currentPassword: this.accountForm.currentPassword,
            newPassword: this.accountForm.newPassword,
          }),
        });
        if (!resp.ok) {
          const err = await resp.json();
          this.showToast(err.error || 'Failed to change password', 'error');
          return;
        }
        this.accountForm.currentPassword = '';
        this.accountForm.newPassword = '';
        this.accountForm.confirmNewPassword = '';
        this.showToast('Password changed!');
      } catch (e) {
        this.showToast('Failed to change password', 'error');
      }
    },

    async updateEmail() {
      const newEmail = this.accountForm.newEmail.trim();
      if (!newEmail) {
        this.showToast('Please enter an email address', 'error');
        return;
      }
      try {
        const resp = await this.api('/api/update-email', {
          method: 'POST',
          body: JSON.stringify({ email: newEmail }),
        });
        if (!resp.ok) {
          const err = await resp.json();
          this.showToast(err.error || 'Failed to update email', 'error');
          return;
        }
        this.email = newEmail;
        this.accountForm.newEmail = '';
        this.showToast('Email updated!');
      } catch (e) {
        this.showToast('Failed to update email', 'error');
      }
    },

    async deleteAccount() {
      if (!await this.showConfirm('Are you sure? This cannot be undone.')) return;
      try {
        const resp = await this.api('/api/delete-account', {
          method: 'POST',
          body: JSON.stringify({ password: this.accountForm.deletePassword }),
        });
        if (!resp.ok) {
          const err = await resp.json();
          this.showToast(err.error || 'Failed to delete account', 'error');
          return;
        }
        this.loggedIn = false;
        this.username = '';
        this.showToast('Account deleted.');
      } catch (e) {
        this.showToast('Failed to delete account', 'error');
      }
    },

    // ── Admin ──
    async switchAdminTab(tab) {
      this.adminTab = tab;
      if (tab === 'dashboard') {
        await this.loadAdminStats();
      } else if (tab === 'users') {
        await this.loadAdminUsers();
      } else if (tab === 'smtp') {
        await this.loadAdminSmtp();
      } else if (tab === 'vapid') {
        await this.loadAdminVapid();
      } else if (tab === 'settings') {
        await Promise.all([this.loadAdminSettings(), this.loadAdminGoogleKey()]);
      }
    },

    async loadAdminStats() {
      try {
        const resp = await this.api('/api/admin/stats');
        if (resp.ok) {
          this.adminStats = await resp.json();
        }
      } catch (e) {
        this.showToast('Failed to load admin stats', 'error');
      }
    },

    async loadAdminUsers() {
      try {
        const resp = await this.api('/api/admin/users');
        if (resp.ok) {
          const data = await resp.json();
          this.adminUsers = data.users || [];
        }
      } catch (e) {
        this.showToast('Failed to load users', 'error');
      }
    },

    async adminResetPassword(userId) {
      if (this.adminResetPwUser === userId) {
        if (!this.adminResetPwValue.trim()) {
          this.showToast('Please enter a new password', 'error');
          return;
        }
        try {
          const resp = await this.api(`/api/admin/users/${userId}/reset-password`, {
            method: 'POST',
            body: JSON.stringify({ password: this.adminResetPwValue }),
          });
          if (!resp.ok) {
            const err = await resp.json();
            this.showToast(err.error || 'Failed to reset password', 'error');
            return;
          }
          this.showToast('Password reset successfully');
          this.adminResetPwUser = null;
          this.adminResetPwValue = '';
        } catch (e) {
          this.showToast('Failed to reset password', 'error');
        }
      } else {
        this.adminResetPwUser = userId;
        this.adminResetPwValue = '';
      }
    },

    adminCancelResetPassword() {
      this.adminResetPwUser = null;
      this.adminResetPwValue = '';
    },

    async adminToggleAdmin(userId) {
      try {
        const resp = await this.api(`/api/admin/users/${userId}/toggle-admin`, {
          method: 'POST',
        });
        if (!resp.ok) {
          const err = await resp.json();
          this.showToast(err.error || 'Failed to toggle admin', 'error');
          return;
        }
        this.showToast('Admin status toggled');
        await this.loadAdminUsers();
      } catch (e) {
        this.showToast('Failed to toggle admin', 'error');
      }
    },

    async adminDeleteUser(userId) {
      if (!await this.showConfirm('Permanently delete this user and all their data? This cannot be undone.')) return;
      try {
        const resp = await this.api(`/api/admin/users/${userId}`, {
          method: 'DELETE',
        });
        if (!resp.ok) {
          const err = await resp.json();
          this.showToast(err.error || 'Failed to delete user', 'error');
          return;
        }
        this.showToast('User deleted');
        await this.loadAdminUsers();
      } catch (e) {
        this.showToast('Failed to delete user', 'error');
      }
    },

    async loadAdminSmtp() {
      try {
        const resp = await this.api('/api/admin/smtp');
        if (resp.ok) {
          const data = await resp.json();
          this.adminSmtp = {
            host: data.host || '',
            port: data.port || 587,
            user: data.user || '',
            password: '',
            from: data.from || '',
            secure: !!data.secure,
          };
        }
      } catch (e) {
        this.showToast('Failed to load SMTP settings', 'error');
      }
    },

    async saveAdminSmtp() {
      try {
        const resp = await this.api('/api/admin/smtp', {
          method: 'POST',
          body: JSON.stringify(this.adminSmtp),
        });
        if (!resp.ok) {
          const err = await resp.json();
          this.showToast(err.error || 'Failed to save SMTP settings', 'error');
          return;
        }
        this.showToast('SMTP settings saved');
      } catch (e) {
        this.showToast('Failed to save SMTP settings', 'error');
      }
    },

    async testSmtp() {
      if (!this.adminTestEmail.trim()) {
        this.showToast('Please enter a test email address', 'error');
        return;
      }
      try {
        const resp = await this.api('/api/admin/smtp/test', {
          method: 'POST',
          body: JSON.stringify({ email: this.adminTestEmail.trim() }),
        });
        const data = await resp.json();
        if (resp.ok) {
          this.showToast(data.message || 'Test email sent successfully');
        } else {
          this.showToast(data.error || 'Failed to send test email', 'error');
        }
      } catch (e) {
        this.showToast('Failed to send test email', 'error');
      }
    },

    async loadAdminVapid() {
      try {
        const resp = await this.api('/api/admin/vapid');
        if (resp.ok) {
          const data = await resp.json();
          this.adminVapid = {
            publicKey: data.publicKey || '',
            source: data.source || 'none',
          };
        }
      } catch (e) {
        this.showToast('Failed to load VAPID settings', 'error');
      }
    },

    async generateVapid() {
      if (!await this.showConfirm('Generate new VAPID keys? This will invalidate all existing push notification subscriptions. Users will need to re-enable notifications.')) return;
      try {
        const resp = await this.api('/api/admin/vapid/generate', {
          method: 'POST',
        });
        if (!resp.ok) {
          const err = await resp.json();
          this.showToast(err.error || 'Failed to generate VAPID keys', 'error');
          return;
        }
        this.showToast('New VAPID keys generated');
        await this.loadAdminVapid();
      } catch (e) {
        this.showToast('Failed to generate VAPID keys', 'error');
      }
    },

    async loadAdminSettings() {
      try {
        const resp = await this.api('/api/admin/settings');
        if (resp.ok) {
          const data = await resp.json();
          this.adminSettings = {
            jwt_expiry: data.jwt_expiry || '12h',
            cookie_secure: data.cookie_secure || 'false',
          };
        }
      } catch (e) {
        this.showToast('Failed to load settings', 'error');
      }
    },

    async saveAdminSettings() {
      try {
        const resp = await this.api('/api/admin/settings', {
          method: 'POST',
          body: JSON.stringify(this.adminSettings),
        });
        if (!resp.ok) {
          const err = await resp.json();
          this.showToast(err.error || 'Failed to save settings', 'error');
          return;
        }
        this.showToast('Settings saved');
      } catch (e) {
        this.showToast('Failed to save settings', 'error');
      }
    },

    async loadAdminGoogleKey() {
      try {
        const resp = await this.api('/api/admin/google-api-key');
        if (resp.ok) {
          const data = await resp.json();
          this.adminGoogleKey = data.key || '';
        }
      } catch (e) {
        this.showToast('Failed to load Google API key', 'error');
      }
    },

    async saveAdminGoogleKey() {
      try {
        const resp = await this.api('/api/admin/google-api-key', {
          method: 'POST',
          body: JSON.stringify({ key: this.adminGoogleKey }),
        });
        if (!resp.ok) {
          const err = await resp.json();
          this.showToast(err.error || 'Failed to save Google API key', 'error');
          return;
        }
        this.showToast('Google API key saved');
        await this.loadAdminGoogleKey();
      } catch (e) {
        this.showToast('Failed to save Google API key', 'error');
      }
    },
  };
}
