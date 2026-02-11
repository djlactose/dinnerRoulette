function dinnerRoulette() {
  return {
    // Auth
    loggedIn: false,
    username: '',
    userId: null,
    authForm: { username: '', password: '', remember: false },
    authError: '',

    // Theme
    theme: 'light',

    // UI sections
    sections: { auth: true, places: true, plan: true, account: false },

    // Toast
    toast: { message: '', type: '', visible: false },

    // Places
    placeSearch: '',
    predictions: [],
    selectedPlace: null,
    likes: [],
    dislikes: [],
    placeFilter: '',
    placeTypeFilter: '',
    placeSortBy: 'name',

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

    // Picking
    picking: false,
    winner: null,
    userLat: null,
    userLng: null,

    // Account
    accountForm: { currentPassword: '', newPassword: '', deletePassword: '' },

    // Socket.IO
    socket: null,

    // ── Helpers ──
    formatPlaceType(types) {
      if (!types?.length) return '';
      const ignore = new Set(['point_of_interest', 'establishment', 'geocode', 'political']);
      const meaningful = types.filter(t => !ignore.has(t));
      if (!meaningful.length) return '';
      return meaningful[0].replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
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
      return [...types].sort();
    },
    get filteredLikes() {
      const f = this.placeFilter.toLowerCase();
      let list = f ? this.likes.filter(p => p.name.toLowerCase().includes(f)) : [...this.likes];
      if (this.placeTypeFilter) list = list.filter(p => p.restaurant_type === this.placeTypeFilter);
      if (this.placeSortBy === 'type') {
        list.sort((a, b) => (a.restaurant_type || '').localeCompare(b.restaurant_type || '') || a.name.localeCompare(b.name));
      } else if (this.placeSortBy === 'visited') {
        list.sort((a, b) => (a.visited_at ? 1 : 0) - (b.visited_at ? 1 : 0) || a.name.localeCompare(b.name));
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

    // ── Init ──
    async init() {
      this.theme = document.cookie.replace(/(?:(?:^|.*;\s*)theme\s*=\s*([^;]*).*$)|^.*$/, '$1') || 'light';
      document.documentElement.setAttribute('data-theme', this.theme);

      try {
        const resp = await fetch('/api/me', { credentials: 'same-origin' });
        if (resp.ok) {
          const data = await resp.json();
          this.loggedIn = true;
          this.username = data.username;
          this.userId = data.id;
          this.connectSocket();
          await this.loadAppData();
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
    showToast(message, type = 'success') {
      this.toast = { message, type, visible: true };
      setTimeout(() => { this.toast.visible = false; }, 3000);
    },

    // ── Theme ──
    toggleTheme() {
      this.theme = this.theme === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', this.theme);
      document.cookie = `theme=${this.theme};path=/;max-age=${365 * 24 * 60 * 60}`;
    },

    // ── Auth ──
    async register() {
      this.authError = '';
      try {
        const resp = await fetch('/api/register', {
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
      } catch (e) {
        this.authError = 'Unexpected error during login.';
      }
    },

    async fetchMe() {
      try {
        const resp = await fetch('/api/me', { credentials: 'same-origin' });
        if (resp.ok) {
          const data = await resp.json();
          this.userId = data.id;
          this.username = data.username;
        }
      } catch (e) { /* ignore */ }
    },

    async logout() {
      this.disconnectSocket();
      await fetch('/api/logout', { method: 'POST', credentials: 'same-origin' });
      this.loggedIn = false;
      this.username = '';
      this.userId = null;
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
      const q = this.placeSearch.trim();
      if (!q) { this.predictions = []; return; }
      try {
        const resp = await this.api(`/api/autocomplete?input=${encodeURIComponent(q)}`);
        const data = await resp.json();
        this.predictions = data.predictions || [];
      } catch (e) {
        this.predictions = [];
      }
    },

    selectPlace(pred) {
      const restaurantType = this.formatPlaceType(pred.types);
      this.selectedPlace = { name: pred.description, place_id: pred.place_id, restaurant_type: restaurantType };
      this.placeSearch = pred.description;
      this.predictions = [];
      this.api('/api/place', {
        method: 'POST',
        body: JSON.stringify({ place: pred.description, place_id: pred.place_id, restaurant_type: restaurantType || null }),
      });
    },

    async likePlace() {
      if (!this.selectedPlace) return;
      await this.api('/api/places', {
        method: 'POST',
        body: JSON.stringify({ type: 'likes', place: this.selectedPlace.name, place_id: this.selectedPlace.place_id, restaurant_type: this.selectedPlace.restaurant_type || null }),
      });
      this.showToast('Place liked!');
      this.selectedPlace = null;
      this.placeSearch = '';
      await this.loadPlaces();
    },

    async dislikePlace() {
      if (!this.selectedPlace) return;
      await this.api('/api/places', {
        method: 'POST',
        body: JSON.stringify({ type: 'dislikes', place: this.selectedPlace.name, place_id: this.selectedPlace.place_id, restaurant_type: this.selectedPlace.restaurant_type || null }),
      });
      this.showToast('Place disliked.');
      this.selectedPlace = null;
      this.placeSearch = '';
      await this.loadPlaces();
    },

    async removePlace(type, place) {
      await this.api('/api/places', {
        method: 'POST',
        body: JSON.stringify({ type, place, remove: true }),
      });
      this.showToast('Place removed.');
      await this.loadPlaces();
    },

    async loadPlaces() {
      try {
        const resp = await this.api('/api/places');
        const data = await resp.json();
        this.likes = data.likes || [];
        this.dislikes = data.dislikes || [];
      } catch (e) { /* ignore */ }
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

    // ── Visited Tracking ──
    async markVisited(place) {
      try {
        await this.api('/api/places/visit', {
          method: 'POST',
          body: JSON.stringify({ place: place.name }),
        });
        this.showToast(`Marked "${place.name}" as visited`);
        await this.loadPlaces();
      } catch (e) {
        this.showToast('Failed to mark as visited', 'error');
      }
    },

    async unmarkVisited(place) {
      try {
        await this.api('/api/places/unvisit', {
          method: 'POST',
          body: JSON.stringify({ place: place.name }),
        });
        this.showToast(`Unmarked "${place.name}"`);
        await this.loadPlaces();
      } catch (e) {
        this.showToast('Failed to unmark', 'error');
      }
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
      await this.api('/api/suggestions/remove', {
        method: 'POST',
        body: JSON.stringify({ place: placeName }),
      });
      await this.loadSuggestions();
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
      try {
        const resp = await this.api('/api/friends');
        const data = await resp.json();
        this.friends = data.friends || [];
      } catch (e) { /* ignore */ }
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
      if (!confirm('Remove this friend? This action is mutual.')) return;
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
      try {
        const resp = await this.api('/api/sessions');
        const data = await resp.json();
        this.sessions = data.sessions || [];
      } catch (e) { /* ignore */ }
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
        this.activeSession = await resp.json();
        this.winner = null;
        if (this.activeSession.session.winner_place) {
          this.winner = { place: this.activeSession.session.winner_place };
        }
        if (this.socket) this.socket.emit('join-session', sessionId);
      } catch (e) {
        this.showToast('Failed to open session', 'error');
      }
    },

    async refreshSession() {
      if (!this.activeSession) return;
      try {
        const resp = await this.api(`/api/sessions/${this.activeSession.session.id}`);
        this.activeSession = await resp.json();
      } catch (e) { /* ignore */ }
    },

    closeActiveSession() {
      if (this.socket && this.activeSession) {
        this.socket.emit('leave-session', this.activeSession.session.id);
      }
      this.activeSession = null;
      this.winner = null;
      this.sessionPlaceSearch = '';
      this.sessionPredictions = [];
      this.loadSessions();
    },

    async closeSession() {
      if (!this.activeSession) return;
      if (!confirm('Close this session? No more suggestions or votes will be allowed.')) return;
      await this.api(`/api/sessions/${this.activeSession.session.id}/close`, { method: 'POST' });
      this.showToast('Session closed.');
      await this.refreshSession();
    },

    async deleteSession(sessionId) {
      if (!confirm('Permanently delete this session? This cannot be undone.')) return;
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

    copyCode() {
      const code = this.activeSession?.session?.code;
      if (code) {
        navigator.clipboard.writeText(code);
        this.showToast('Code copied!');
      }
    },

    // ── Session Suggest ──
    async searchSessionPlaces() {
      const q = this.sessionPlaceSearch.trim();
      if (!q) { this.sessionPredictions = []; return; }
      try {
        const resp = await this.api(`/api/autocomplete?input=${encodeURIComponent(q)}`);
        const data = await resp.json();
        this.sessionPredictions = data.predictions || [];
      } catch (e) {
        this.sessionPredictions = [];
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

      // Spinning animation
      const winnerEl = document.getElementById('winner-text');
      let cycles = 20;
      let delay = 50;
      let i = 0;

      await new Promise(resolve => {
        const spin = () => {
          this.winner = { place: names[i % names.length] };
          if (winnerEl) {
            winnerEl.classList.remove('spinning');
            void winnerEl.offsetWidth;
            winnerEl.classList.add('spinning');
          }
          i++;
          cycles--;
          if (cycles > 0) {
            delay += 15;
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
        this.showToast(`Winner: ${data.winner.place}`);
        if (winnerEl) winnerEl.classList.remove('spinning');
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

    // ── Account ──
    async changePassword() {
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
        this.showToast('Password changed!');
      } catch (e) {
        this.showToast('Failed to change password', 'error');
      }
    },

    async deleteAccount() {
      if (!confirm('Are you sure? This cannot be undone.')) return;
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
  };
}
