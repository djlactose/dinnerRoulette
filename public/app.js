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
    sessionSuggestSort: 'votes',

    // Picking
    picking: false,
    closingSession: false,
    winner: null,
    userLat: null,
    userLng: null,

    // Account
    accountForm: { currentPassword: '', newPassword: '', deletePassword: '' },

    // Network
    online: typeof navigator !== 'undefined' ? navigator.onLine : true,

    // Swipe
    swipeState: { name: null, startX: 0, currentX: 0, swiping: false },
    touchEnabled: false,

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

    get sortedSessionSuggestions() {
      const suggestions = this.activeSession?.suggestions || [];
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
      this.theme = document.cookie.replace(/(?:(?:^|.*;\s*)theme\s*=\s*([^;]*).*$)|^.*$/, '$1') || 'light';
      document.documentElement.setAttribute('data-theme', this.theme);
      window.addEventListener('online', () => { this.online = true; });
      window.addEventListener('offline', () => { this.online = false; });
      this.touchEnabled = 'ontouchstart' in window;

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

    async removePlace(type, placeName) {
      const list = type === 'likes' ? 'likes' : 'dislikes';
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
        try {
          const dResp = await this.api(`/api/sessions/${sessionId}/dislikes`);
          const dData = await dResp.json();
          this.sessionDislikes = dData.dislikes || [];
        } catch (e) { this.sessionDislikes = []; }
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
      this.closingSession = false;
      this.sessionPlaceSearch = '';
      this.sessionPredictions = [];
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
  };
}
