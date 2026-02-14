function urlBase64ToUint8Array(base64String) {
  const padding = '='.repeat((4 - base64String.length % 4) % 4);
  const base64 = (base64String + padding).replace(/-/g, '+').replace(/_/g, '/');
  const raw = atob(base64);
  return Uint8Array.from([...raw].map(c => c.charCodeAt(0)));
}

function dinnerRoulette() {
  return {
    // ── State ────────────────────────────────────────────────────────────────

    // Auth
    loggedIn: false,
    username: '',
    userId: null,
    email: '',
    isAdmin: false,
    profileName: '',
    profilePic: null,
    profileForm: { displayName: '', profilePicPreview: null, profilePicData: undefined },
    profileSaving: false,
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

    // Accent Color
    accentColor: 'coral',
    accentPreview: null,
    accentPalettes: {
      coral:    { name: 'Coral',        light: { accent: '#E07A5F', hover: '#C96A52' }, dark: { accent: '#E8896F', hover: '#F09A82' } },
      ocean:    { name: 'Ocean Blue',   light: { accent: '#4A90D9', hover: '#3A7BC8' }, dark: { accent: '#5DA0E8', hover: '#70B0F0' } },
      forest:   { name: 'Forest Green', light: { accent: '#5B9A6F', hover: '#4A8360' }, dark: { accent: '#6DAF81', hover: '#7FC093' } },
      royal:    { name: 'Royal Purple', light: { accent: '#8B6BB5', hover: '#7A5AA4' }, dark: { accent: '#9B7BC5', hover: '#AB8BD5' } },
      amber:    { name: 'Golden Amber', light: { accent: '#D4952B', hover: '#C08520' }, dark: { accent: '#E0A53B', hover: '#EAB54B' } },
      rose:     { name: 'Rose Pink',    light: { accent: '#D4648A', hover: '#C45478' }, dark: { accent: '#E4749A', hover: '#F084AA' } },
      slate:    { name: 'Slate',        light: { accent: '#6B8299', hover: '#5A7188' }, dark: { accent: '#7B92A9', hover: '#8BA2B9' } },
      lavender: { name: 'Lavender',     light: { accent: '#9B8EC1', hover: '#8A7DB0' }, dark: { accent: '#AB9ED1', hover: '#BBAEE1' } },
    },

    // UI sections
    sections: { auth: true, places: true, plan: true, account: false },
    activeTab: 'places',

    // Toast
    toast: { message: '', type: '', visible: false, action: null },
    toastTimer: null,

    // Confirm modal
    confirmModal: { visible: false, message: '', onConfirm: null, onCancel: null },

    // QR modal
    qrModal: { visible: false, dataUrl: '' },

    // Post-login prompts
    promptModal: { visible: false, type: null },
    promptEmailValue: '',

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
    filtersOpen: false,
    cardMenuOpen: null,
    planHeaderMenuOpen: false,
    placeSections: { favorites: true, likes: true, dislikes: false, wantToTry: false },
    suggestSectionOpen: false,
    suggestionMenuOpen: null,

    // Quick Pick
    quickPickResult: null,
    quickPicking: false,

    // Mood Pick
    moodPickResult: null,
    moodPicking: false,
    moodPickType: '',
    moodIncludeWantToTry: false,

    // Meal Type Tags
    MEAL_TYPES: ['Breakfast', 'Brunch', 'Lunch', 'Dinner', 'Late Night', 'Dessert/Coffee'],
    placeMealTypeFilter: '',
    nearbyPlaces: [],
    nearbyLoading: false,
    nearbyError: '',

    // Friends
    leaderboard: [],
    leaderboardMetric: 'plans',
    activityFeed: [],
    activityFeedLoaded: false,
    friendUsername: '',
    friends: [],
    friendRequests: [],
    sentFriendRequests: [],
    friendSections: {},

    // Friend Groups
    friendGroups: [],
    groupModal: { visible: false, editingId: null, name: '', selectedMembers: [] },

    // History Timeline
    historyTimeline: [],
    historyLoading: false,
    historyFilterFrom: '',
    historyFilterTo: '',
    historyFilterMember: '',
    historyVisible: false,

    // Recurring Plans
    recurringPlans: [],
    recurringLoading: false,
    showRecurringForm: false,
    recurringForm: { name: '', frequency: 'weekly', members: [], vetoLimit: 1 },

    // Plans
    plans: [],
    showCreatePlanForm: false,
    newPlanName: '',
    joinCode: '',
    activePlan: null,
    planPlaceSearch: '',
    planPredictions: [],
    planSearching: false,
    planSearchedOnce: false,
    planHighlightedIndex: -1,
    planInviteUsername: '',
    planDislikes: [],
    planWantToTry: {},
    planSuggestSort: 'votes',
    planVetoLimitInput: 1,
    planMealType: '',
    planDietaryTags: [],
    dietaryOptions: ['Vegetarian', 'Vegan', 'Gluten-Free', 'Halal', 'Kosher', 'Nut-Free', 'Dairy-Free'],
    planMealTypeFilter: '',
    planSuggestionMealFilter: '',
    planLikesMealFilter: '',

    // Picking
    picking: false,
    closingPlan: false,
    winner: null,
    userLat: null,
    userLng: null,
    spinningWheel: false,
    wheelAngle: 0,

    // Account
    accountForm: { currentPassword: '', newPassword: '', confirmNewPassword: '', newEmail: '', deletePassword: '' },

    // Loading states
    loading: { places: false, friends: false, plans: false },

    // Network
    online: typeof navigator !== 'undefined' ? navigator.onLine : true,

    // Notifications
    notificationsEnabled: false,
    notificationsSupported: false,

    // Cuisine filter (plans)
    planCuisineFilter: '',
    planPriceFilter: [],

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
    chatDrawerOpen: false,
    speedDialOpen: false,
    unreadChatCount: 0,
    emojiPickerVisible: false,
    gifSearchVisible: false,
    gifSearchQuery: '',
    gifResults: [],
    gifLoading: false,
    gifError: '',
    reactionPickerMessageId: null,
    editingMessageId: null,
    editingMessageText: '',
    gifPreview: null,
    typingUsers: [],
    typingTimeout: null,
    messageReads: [],

    // Mentions
    mentionDropdownVisible: false,
    mentionStartPos: null,
    mentionQuery: '',
    mentionSelectedIndex: 0,

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

    // Onboarding
    onboarding: { active: false, step: 0 },
    onboardingSteps: [
      { text: 'Search for restaurants you love and add them to your list.', tab: 'places', highlight: 'placeSearch' },
      { text: 'Add friends to plan dinner together.', tab: 'friends', highlight: 'friendInput' },
      { text: 'Start a plan to vote and pick a dinner spot!', tab: 'plans', highlight: null },
      { text: "You're all set! Enjoy Dinner Roulette!", tab: null, highlight: null },
    ],

    // Account
    accountTab: 'profile',
    userStats: null,
    statsLoading: false,
    badges: [],
    badgesLoading: false,

    // Admin
    adminTab: 'dashboard',
    adminStats: null,
    adminUsers: [],
    adminSmtp: { host: '', port: 587, user: '', password: '', from: '', secure: false },
    adminVapid: { publicKey: '', source: '' },
    adminSettings: { jwt_expiry: '12h', cookie_secure: 'false' },
    adminGoogleKey: '',
    adminGiphyKey: '',
    adminResetPwUser: null,
    adminResetPwValue: '',
    adminEditUser: null,
    adminEditForm: { username: '', email: '' },
    adminTestEmail: '',
    adminPlans: [],
    adminBackingUp: false,
    adminRepulling: false,

    // ── Helpers ──────────────────────────────────────────────────────────────
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

    avatarStyle(user) {
      if (user && user.profile_pic) return { backgroundImage: `url(${user.profile_pic})` };
      const name = user ? (user.display_name || user.username) : '';
      return { background: this.hashColor(name || '') };
    },

    memberLookup(username) {
      if (!this.activePlan?.members) return null;
      return this.activePlan.members.find(m => m.username === username);
    },

    async handleProfilePicUpload(event) {
      const file = event.target.files[0];
      if (!file) return;
      if (!file.type.startsWith('image/')) {
        this.showToast('Please select an image file', 'error');
        return;
      }
      try {
        const dataUri = await this.resizeImage(file, 128);
        this.profileForm.profilePicPreview = dataUri;
        this.profileForm.profilePicData = dataUri;
        await this.updateProfile();
      } catch (e) {
        this.showToast('Failed to process image', 'error');
      }
      event.target.value = '';
    },

    resizeImage(file, size) {
      return new Promise((resolve, reject) => {
        const img = new Image();
        img.onload = () => {
          const canvas = document.createElement('canvas');
          canvas.width = size;
          canvas.height = size;
          const ctx = canvas.getContext('2d');
          const min = Math.min(img.width, img.height);
          const sx = (img.width - min) / 2;
          const sy = (img.height - min) / 2;
          ctx.drawImage(img, sx, sy, min, min, 0, 0, size, size);
          const dataUri = canvas.toDataURL('image/jpeg', 0.8);
          if (dataUri.length > 266000) { reject(new Error('Image too large after compression')); return; }
          resolve(dataUri);
        };
        img.onerror = reject;
        img.src = URL.createObjectURL(file);
      });
    },

    async updateProfile() {
      this.profileSaving = true;
      try {
        const body = { displayName: this.profileForm.displayName || null };
        if (this.profileForm.profilePicData !== undefined) {
          body.profilePic = this.profileForm.profilePicData;
        }
        const resp = await fetch('/api/profile', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'same-origin',
          body: JSON.stringify(body),
        });
        if (!resp.ok) { const d = await resp.json(); throw new Error(d.error); }
        const data = await resp.json();
        this.profileName = data.display_name || '';
        this.profilePic = data.profile_pic || null;
        this.profileForm.profilePicPreview = null;
        this.profileForm.profilePicData = undefined;
        this.showToast('Profile updated!', 'success');
      } catch (e) {
        this.showToast(e.message || 'Failed to update profile', 'error');
      }
      this.profileSaving = false;
    },

    async removeProfilePic() {
      this.profileForm.profilePicPreview = null;
      this.profileForm.profilePicData = null;
      await this.updateProfile();
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
      const generic = new Set(['restaurant', 'food', 'meal_delivery', 'meal_takeaway', 'store']);
      const meaningful = types.filter(t => !ignore.has(t));
      if (!meaningful.length) return '';
      const specific = meaningful.filter(t => !generic.has(t));
      const best = specific.length ? specific[0] : meaningful[0];
      return best.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
    },

    displayName(p) {
      const name = p.name || p.place;
      if (p.address) return name;
      const idx = name.indexOf(', ');
      return idx > 0 ? name.substring(0, idx) : name;
    },

    displayAddress(p) {
      if (p.address) return p.address;
      const name = p.name || p.place;
      const idx = name.indexOf(', ');
      return idx > 0 ? name.substring(idx + 2) : null;
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

    // ── Computed ─────────────────────────────────────────────────────────────
    get uniqueRestaurantTypes() {
      const types = new Set();
      this.likes.forEach(p => { if (p.restaurant_type) types.add(p.restaurant_type); });
      this.dislikes.forEach(p => { if (p.restaurant_type) types.add(p.restaurant_type); });
      this.wantToTry.forEach(p => { if (p.restaurant_type) types.add(p.restaurant_type); });
      return [...types].sort();
    },
    get filteredLikes() {
      const f = this.placeFilter.toLowerCase();
      let list = f ? this.likes.filter(p => p.name.toLowerCase().includes(f) || (p.address && p.address.toLowerCase().includes(f))) : [...this.likes];
      list = list.filter(p => !p.starred);
      if (this.placeTypeFilter) list = list.filter(p => p.restaurant_type === this.placeTypeFilter);
      if (this.placeMealTypeFilter) list = list.filter(p => (p.meal_types || []).includes(this.placeMealTypeFilter));
      if (this.placeSortBy === 'type') {
        list.sort((a, b) => (a.restaurant_type || '').localeCompare(b.restaurant_type || '') || a.name.localeCompare(b.name));
      } else {
        list.sort((a, b) => a.name.localeCompare(b.name));
      }
      return list;
    },
    get filteredDislikes() {
      const f = this.placeFilter.toLowerCase();
      let list = f ? this.dislikes.filter(p => p.name.toLowerCase().includes(f) || (p.address && p.address.toLowerCase().includes(f))) : [...this.dislikes];
      if (this.placeTypeFilter) list = list.filter(p => p.restaurant_type === this.placeTypeFilter);
      return list.sort((a, b) => a.name.localeCompare(b.name));
    },
    get filteredWantToTry() {
      const f = this.placeFilter.toLowerCase();
      let list = f ? this.wantToTry.filter(p => p.name.toLowerCase().includes(f) || (p.address && p.address.toLowerCase().includes(f))) : [...this.wantToTry];
      list = list.filter(p => !p.starred);
      if (this.placeTypeFilter) list = list.filter(p => p.restaurant_type === this.placeTypeFilter);
      if (this.placeMealTypeFilter) list = list.filter(p => (p.meal_types || []).includes(this.placeMealTypeFilter));
      return list.sort((a, b) => a.name.localeCompare(b.name));
    },
    get quickPickMapUrl() {
      if (!this.quickPickResult) return '#';
      return `https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(this.quickPickResult.name)}`;
    },
    get moodPickTypes() {
      const types = new Set();
      this.likes.forEach(p => { if (p.restaurant_type) types.add(p.restaurant_type); });
      if (this.moodIncludeWantToTry) {
        this.wantToTry.forEach(p => { if (p.restaurant_type) types.add(p.restaurant_type); });
      }
      return [...types].sort();
    },
    get moodPickMapUrl() {
      if (!this.moodPickResult) return '#';
      return `https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(this.moodPickResult.name)}`;
    },
    get activePlans() {
      let list = this.plans.filter(s => s.status === 'open');
      if (this.planMealTypeFilter) list = list.filter(s => s.meal_type === this.planMealTypeFilter);
      return list;
    },
    get historyPlans() {
      let list = this.plans.filter(s => s.status === 'closed');
      if (this.planMealTypeFilter) list = list.filter(s => s.meal_type === this.planMealTypeFilter);
      return list;
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
    placePhotoUrl(photoRef) {
      if (!photoRef) return null;
      return `/api/place-photo?ref=${encodeURIComponent(photoRef)}&maxwidth=300`;
    },
    openTableUrl(name) {
      return `https://www.opentable.com/s?term=${encodeURIComponent(name)}&covers=2`;
    },
    yelpUrl(name) {
      return `https://www.yelp.com/search?find_desc=${encodeURIComponent(name)}`;
    },
    reservationSearchUrl(name) {
      return `https://www.google.com/search?q=${encodeURIComponent(name + ' reservations')}`;
    },

    get uniquePlanCuisines() {
      const types = new Set();
      (this.activePlan?.suggestions || []).forEach(s => {
        if (s.restaurant_type) types.add(s.restaurant_type);
      });
      return [...types].sort();
    },

    get sortedPlanSuggestions() {
      let suggestions = this.activePlan?.suggestions || [];
      if (this.planCuisineFilter) {
        suggestions = suggestions.filter(s => s.restaurant_type === this.planCuisineFilter);
      }
      if (this.planPriceFilter.length > 0) {
        suggestions = suggestions.filter(s => s.price_level == null || this.planPriceFilter.includes(s.price_level));
      }
      if (this.planSuggestionMealFilter) {
        suggestions = suggestions.filter(s => (s.meal_types || []).includes(this.planSuggestionMealFilter));
      }
      const sorted = [...suggestions];
      if (this.planSuggestSort === 'votes') {
        sorted.sort((a, b) => (b.vote_count - (b.downvote_count || 0)) - (a.vote_count - (a.downvote_count || 0)) || a.place.localeCompare(b.place));
      } else if (this.planSuggestSort === 'name') {
        sorted.sort((a, b) => a.place.localeCompare(b.place));
      } else if (this.planSuggestSort === 'suggester') {
        sorted.sort((a, b) => (a.suggested_by || '').localeCompare(b.suggested_by || '') || (b.vote_count - (b.downvote_count || 0)) - (a.vote_count - (a.downvote_count || 0)));
      }
      return sorted;
    },

    get planRecap() {
      if (!this.activePlan || !this.winner) return null;
      const suggestions = this.activePlan.suggestions || [];
      const totalVotes = suggestions.reduce((sum, s) => sum + (s.vote_count || 0), 0);
      const totalDownvotes = suggestions.reduce((sum, s) => sum + (s.downvote_count || 0), 0);
      const winnerSugg = suggestions.find(s => s.place === this.winner.place);
      const topPlaces = [...suggestions].sort((a, b) => (b.vote_count - (b.downvote_count || 0)) - (a.vote_count - (a.downvote_count || 0))).slice(0, 3);
      return {
        totalSuggestions: suggestions.length,
        totalVotes,
        totalDownvotes,
        suggestedBy: winnerSugg?.suggested_by || 'Unknown',
        topPlaces,
      };
    },

    // ── Init ─────────────────────────────────────────────────────────────────
    async init() {
      this.theme = document.cookie.replace(/(?:(?:^|.*;\s*)theme\s*=\s*([^;]*).*$)|^.*$/, '$1') || 'auto';
      document.documentElement.setAttribute('data-theme', this.theme);
      this.initAccentColor();
      window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
        this.applyAccentColor(this.accentColor);
      });
      window.addEventListener('online', () => { this.online = true; });
      window.addEventListener('offline', () => { this.online = false; });
      this.touchEnabled = 'ontouchstart' in window;
      this.notificationsSupported = 'Notification' in window && 'PushManager' in window;

      // Global ripple effect on buttons
      document.addEventListener('click', (e) => {
        const btn = e.target.closest('button:not(.tab-btn):not(.theme-toggle):not([disabled]):not(.accent-swatch)');
        if (btn) this.createRipple(e);
      });

      // Global Escape key handler for modals/drawers
      document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
          if (this.confirmModal.visible) this.confirmModal.onCancel();
          else if (this.qrModal.visible) this.qrModal.visible = false;
          else if (this.chatDrawerOpen) this.chatDrawerOpen = false;
          else if (this.emojiPickerVisible) this.emojiPickerVisible = false;
          else if (this.gifSearchVisible) this.gifSearchVisible = false;
          else if (this.reactionPickerMessageId) this.reactionPickerMessageId = null;
          else if (this.editingMessageId) this.cancelEditMessage();
        }
      });

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
      const validTabs = ['places', 'friends', 'plans', 'account', 'admin'];
      let hash = window.location.hash.replace('#', '');
      if (hash === 'sessions') hash = 'plans';
      if (validTabs.includes(hash)) this.activeTab = hash;
      window.addEventListener('hashchange', () => {
        let h = window.location.hash.replace('#', '');
        if (h === 'sessions') h = 'plans';
        if (validTabs.includes(h)) this.activeTab = h;
      });

      window.addEventListener('beforeunload', () => {
        if (this.deadlineTimer) { clearInterval(this.deadlineTimer); this.deadlineTimer = null; }
        if (this.socket) { this.socket.close(); this.socket = null; }
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
          this.profileName = data.display_name || '';
          this.profilePic = data.profile_pic || null;
          if (data.accent_color && !localStorage.getItem('accent-color')) {
            this.accentColor = data.accent_color;
            this.applyAccentColor(data.accent_color);
          }
          this.connectSocket();
          await this.loadAppData();
          if (this.notificationsSupported && Notification.permission === 'granted') {
            try {
              const reg = await navigator.serviceWorker.ready;
              const sub = await reg.pushManager.getSubscription();
              this.notificationsEnabled = !!sub;
            } catch (e) {
              this.notificationsEnabled = false;
            }
          }
          if (this.pendingInviteCode) {
            await this.autoJoinInvite();
          }
          this.$nextTick(() => this.runPostLoginPrompts());
        }
      } catch (e) {
        // Not logged in
      }
    },

    async loadAppData() {
      await Promise.all([
        this.loadPlaces(),
        this.loadFriends(),
        this.loadFriendRequests(),
        this.loadSentFriendRequests(),
        this.loadPlans(),
        this.loadRecentSuggestions(),
        this.loadFriendGroups(),
        this.loadRecurringPlans(),
      ]);
    },

    // ── Socket.IO ────────────────────────────────────────────────────────────
    connectSocket() {
      if (this.socket) return;
      this.socket = io({ withCredentials: true });

      this.socket.on('plan:member-joined', (data) => {
        if (!this.activePlan) return;
        const already = this.activePlan.members.some(m => m.id === data.userId);
        if (!already) {
          this.activePlan.members.push({ id: data.userId, username: data.username, display_name: data.display_name || null, profile_pic: data.profile_pic || null });
          this.showToast(`${data.display_name || data.username} joined the plan`);
        }
      });

      this.socket.on('plan:updated', (data) => {
        if (!this.activePlan) return;
        if (data.meal_type !== undefined) this.activePlan.plan.meal_type = data.meal_type;
      });

      this.socket.on('plan:suggestion-added', (data) => {
        if (!this.activePlan) return;
        const already = this.activePlan.suggestions.some(s => s.id === data.id);
        if (!already) {
          this.activePlan.suggestions.push(data);
        }
      });

      this.socket.on('plan:suggestion-removed', (data) => {
        if (!this.activePlan) return;
        this.activePlan.suggestions = this.activePlan.suggestions.filter(s => s.id !== data.suggestion_id);
      });

      this.socket.on('plan:vote-updated', (data) => {
        if (!this.activePlan) return;
        const s = this.activePlan.suggestions.find(s => s.id === data.suggestion_id);
        if (s) {
          s.vote_count = data.vote_count;
          if (data.downvote_count !== undefined) s.downvote_count = data.downvote_count;
          if (!s.voters) s.voters = [];
          if (!s.downvoters) s.downvoters = [];

          if (data.action === 'vote') {
            if (data.username && !s.voters.includes(data.username)) s.voters.push(data.username);
            s.downvoters = s.downvoters.filter(v => v !== data.username);
          } else if (data.action === 'unvote') {
            s.voters = s.voters.filter(v => v !== data.username);
          } else if (data.action === 'downvote') {
            if (data.username && !s.downvoters.includes(data.username)) s.downvoters.push(data.username);
            s.voters = s.voters.filter(v => v !== data.username);
          } else if (data.action === 'undownvote') {
            s.downvoters = s.downvoters.filter(v => v !== data.username);
          }

          if (data.user_id === this.userId) {
            s.user_voted = (data.action === 'vote');
            s.user_downvoted = (data.action === 'downvote');
          }
        }
      });

      this.socket.on('plan:winner-picked', (data) => {
        if (!this.activePlan) return;
        this.winner = data.winner;
        this.createConfetti();
      });

      this.socket.on('plan:deadline-updated', (data) => {
        if (!this.activePlan) return;
        this.activePlan.plan.voting_deadline = data.deadline;
        this.startDeadlineCountdown();
      });

      this.socket.on('plan:veto-updated', (data) => {
        if (!this.activePlan) return;
        const s = this.activePlan.suggestions.find(s => s.id === data.suggestion_id);
        if (s) {
          s.veto_count = data.veto_count;
          s.vetoers = data.vetoers || [];
          if (data.user_id === this.userId) {
            s.user_vetoed = (data.action === 'veto');
            if (data.action === 'veto') {
              this.activePlan.vetoesRemaining = Math.max(0, (this.activePlan.vetoesRemaining || 0) - 1);
            } else {
              this.activePlan.vetoesRemaining = (this.activePlan.vetoesRemaining || 0) + 1;
            }
          }
        }
      });

      this.socket.on('plan:veto-limit-updated', (data) => {
        if (!this.activePlan) return;
        this.activePlan.plan.veto_limit = data.veto_limit;
        this.refreshPlan();
      });

      this.socket.on('plan:message', (data) => {
        if (!this.activePlan) return;
        if (!data.reactions) data.reactions = [];
        if (data.mentions && data.user_id !== this.userId) {
          if (data.mentions.includes('all') || data.mentions.includes(this.userId)) {
            this.showToast(`${data.display_name || data.username} mentioned you`, 'info');
          }
        }
        this.chatMessages.push(data);
        if (!this.chatDrawerOpen) this.unreadChatCount++;
        this.$nextTick(() => {
          const el = document.getElementById('chat-messages');
          if (el) el.scrollTop = el.scrollHeight;
        });
      });

      this.socket.on('plan:reaction-updated', (data) => {
        if (!this.activePlan) return;
        const msg = this.chatMessages.find(m => m.id === data.message_id);
        if (msg) msg.reactions = data.reactions;
      });

      this.socket.on('plan:closed', () => {
        if (!this.activePlan) return;
        this.activePlan.plan.status = 'closed';
        this.showToast('Plan has been closed');
      });

      this.socket.on('plan:deleted', (data) => {
        this.plans = this.plans.filter(s => s.id !== data.planId);
        if (this.activePlan && this.activePlan.plan.id === data.planId) {
          this.activePlan = null;
          this.winner = null;
          this.showToast('This plan has been deleted', 'error');
        }
      });

      this.socket.on('plan:message-deleted', (data) => {
        if (!this.activePlan) return;
        this.chatMessages = this.chatMessages.filter(m => m.id !== data.message_id);
      });

      this.socket.on('plan:message-edited', (data) => {
        if (!this.activePlan) return;
        const msg = this.chatMessages.find(m => m.id === data.message_id);
        if (msg) { msg.message = data.message; msg.edited_at = data.edited_at; }
      });

      this.socket.on('user-typing', (data) => {
        if (!this.activePlan) return;
        if (!this.typingUsers.find(u => u.user_id === data.user_id)) {
          this.typingUsers.push(data);
        }
        setTimeout(() => {
          this.typingUsers = this.typingUsers.filter(u => u.user_id !== data.user_id);
        }, 3000);
      });

      this.socket.on('user-stopped-typing', (data) => {
        if (!this.activePlan) return;
        this.typingUsers = this.typingUsers.filter(u => u.user_id !== data.user_id);
      });

      this.socket.on('plan:messages-read', (data) => {
        if (!this.activePlan) return;
        const existing = this.messageReads.find(r => r.user_id === data.user_id);
        if (existing) { existing.last_read_message_id = data.last_read_message_id; }
        else { this.messageReads.push(data); }
      });

      this.socket.on('user:profile-updated', (data) => {
        const { userId, username, display_name, profile_pic } = data;
        const update = (obj) => {
          if (!obj) return;
          if (obj.user_id === userId || obj.id === userId) {
            obj.display_name = display_name;
            obj.profile_pic = profile_pic;
          }
        };
        // Friends list
        this.friends.forEach(update);
        // Friend requests
        this.friendRequests.forEach(update);
        this.sentFriendRequests.forEach(update);
        // Friend groups
        this.friendGroups.forEach(g => g.members.forEach(update));
        // Active plan members & suggestions
        if (this.activePlan) {
          this.activePlan.members.forEach(update);
          this.activePlan.suggestions.forEach(s => {
            if (s.suggested_by === username) {
              s.suggested_by_display_name = display_name;
              s.suggested_by_profile_pic = profile_pic;
            }
            if (s.want_to_try) s.want_to_try.forEach(update);
          });
        }
        // Chat messages
        this.chatMessages.forEach(update);
        // Plans list (creator info)
        this.plans.forEach(p => {
          if (p.creator_username === username) {
            p.creator_display_name = display_name;
            p.creator_profile_pic = profile_pic;
          }
        });
        // History timeline members
        this.historyTimeline.forEach(entry => {
          entry.members.forEach(m => {
            if (m.username === username) {
              m.display_name = display_name;
              m.profile_pic = profile_pic;
            }
          });
        });
      });
    },

    disconnectSocket() {
      if (this.socket) {
        this.socket.disconnect();
        this.socket = null;
      }
    },

    // ── Toast ────────────────────────────────────────────────────────────────
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

    // ── Tabs ─────────────────────────────────────────────────────────────────
    switchTab(tab) {
      const tabs = ['places', 'friends', 'plans', 'account', 'admin'];
      const oldIdx = tabs.indexOf(this.activeTab);
      const newIdx = tabs.indexOf(tab);
      const direction = newIdx > oldIdx ? '20px' : newIdx < oldIdx ? '-20px' : '0';
      document.documentElement.style.setProperty('--tab-slide-from', direction);
      this.activeTab = tab;
      this.speedDialOpen = false;
      window.location.hash = tab;
    },

    // ── Tab Swipe ────────────────────────────────────────────────────────────
    tabSwipeStartX: 0,
    tabSwipeStartY: 0,

    handleTabSwipeStart(e) {
      this.tabSwipeStartX = e.touches[0].clientX;
      this.tabSwipeStartY = e.touches[0].clientY;
    },

    // ── Pull to Refresh ──────────────────────────────────────────────────────
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
        await Promise.all([this.loadFriends(), this.loadFriendRequests(), this.loadSentFriendRequests()]);
      } else if (this.activeTab === 'plans') {
        await this.loadPlans();
        if (this.activePlan) await this.refreshPlan();
      }
      this.refreshing = false;
      this.showToast('Refreshed!');
    },

    handleTabSwipeEnd(e) {
      const dx = e.changedTouches[0].clientX - this.tabSwipeStartX;
      const dy = e.changedTouches[0].clientY - this.tabSwipeStartY;
      if (Math.abs(dx) < 50 || Math.abs(dx) < Math.abs(dy)) return;
      const tabs = ['places', 'friends', 'plans', 'account'];
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
      } else if (this.activeTab === 'plans') {
        if (!this.activePlan) {
          this.createPlan();
        } else {
          window.scrollTo({ top: 0, behavior: 'smooth' });
        }
      }
    },

    goToActivePlan() {
      const plans = this.plans.filter(s => s.status === 'open');
      this.switchTab('plans');
      if (plans.length === 1) {
        this.openPlan(plans[0].id);
      }
    },

    // ── Theme ────────────────────────────────────────────────────────────────
    toggleTheme() {
      const order = ['auto', 'light', 'dark'];
      this.theme = order[(order.indexOf(this.theme) + 1) % order.length];
      document.documentElement.setAttribute('data-theme', this.theme);
      document.cookie = `theme=${this.theme};path=/;max-age=${365 * 24 * 60 * 60}`;
      this.applyAccentColor(this.accentColor);
    },

    applyAccentColor(colorKey, preview = false) {
      const palette = this.accentPalettes[colorKey];
      if (!palette) return;
      const isDark = document.documentElement.getAttribute('data-theme') === 'dark' ||
        (document.documentElement.getAttribute('data-theme') === 'auto' &&
         window.matchMedia('(prefers-color-scheme: dark)').matches);
      const colors = isDark ? palette.dark : palette.light;
      document.documentElement.style.setProperty('--accent', colors.accent);
      document.documentElement.style.setProperty('--accent-hover', colors.hover);
      const meta = document.querySelector('meta[name="theme-color"]');
      if (meta) meta.setAttribute('content', colors.accent);
      if (!preview) {
        this.accentColor = colorKey;
        this.accentPreview = null;
        localStorage.setItem('accent-color', colorKey);
        if (this.loggedIn) {
          this.api('/api/accent-color', {
            method: 'POST',
            body: JSON.stringify({ accentColor: colorKey }),
          }).catch(() => {});
        }
      } else {
        this.accentPreview = colorKey;
      }
    },

    resetAccentPreview() {
      if (this.accentPreview) {
        this.applyAccentColor(this.accentColor);
        this.accentPreview = null;
      }
    },

    initAccentColor() {
      const stored = localStorage.getItem('accent-color');
      if (stored && this.accentPalettes[stored]) {
        this.accentColor = stored;
        this.applyAccentColor(stored);
      }
    },

    createRipple(event) {
      const button = event.currentTarget || event.target.closest('button');
      if (!button || button.disabled) return;
      const rect = button.getBoundingClientRect();
      const size = Math.max(rect.width, rect.height);
      const x = event.clientX - rect.left - size / 2;
      const y = event.clientY - rect.top - size / 2;
      const ripple = document.createElement('span');
      ripple.className = 'ripple';
      ripple.style.width = ripple.style.height = size + 'px';
      ripple.style.left = x + 'px';
      ripple.style.top = y + 'px';
      button.appendChild(ripple);
      ripple.addEventListener('animationend', () => ripple.remove());
    },

    // ── Auth ─────────────────────────────────────────────────────────────────
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
        this.$nextTick(() => this.startOnboarding());
        this.$nextTick(() => this.runPostLoginPrompts());
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
        this.$nextTick(() => this.runPostLoginPrompts());
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
      if (this.resetNewPassword.length < 8) {
        this.authError = 'Password must be at least 8 characters.';
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
          this.profileName = data.display_name || '';
          this.profilePic = data.profile_pic || null;
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
      this.profileName = '';
      this.profilePic = null;
      this.likes = [];
      this.dislikes = [];
      this.friends = [];
      this.friendRequests = [];
      this.sentFriendRequests = [];
      this.friendSections = {};
      this.plans = [];
      this.activePlan = null;
      this.winner = null;
    },

    // ── API Helper ───────────────────────────────────────────────────────────
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

    // ── Places ───────────────────────────────────────────────────────────────
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

    async selectPlace(pred) {
      const restaurantType = this.formatPlaceType(pred.types);
      const mainText = pred.structured_formatting?.main_text || pred.description;
      const address = pred.structured_formatting?.secondary_text || null;
      this.selectedPlace = { name: mainText, place_id: pred.place_id, restaurant_type: restaurantType, address, photo_ref: null };
      this.placeSearch = pred.description;
      this.predictions = [];
      this.highlightedIndex = -1;
      if (pred.place_id) {
        try {
          const resp = await this.api(`/api/place-details?place_id=${encodeURIComponent(pred.place_id)}`);
          const data = await resp.json();
          if (data.result?.types) {
            const betterType = this.formatPlaceType(data.result.types);
            if (betterType && betterType !== 'Restaurant' && betterType !== 'Food') {
              this.selectedPlace.restaurant_type = betterType;
            }
          }
          if (data.result?.photo_reference) {
            this.selectedPlace.photo_ref = data.result.photo_reference;
          }
        } catch (e) { /* keep autocomplete type */ }
      }
      this.api('/api/place', {
        method: 'POST',
        body: JSON.stringify({ place: mainText, place_id: pred.place_id, restaurant_type: this.selectedPlace.restaurant_type || null, address, photo_ref: this.selectedPlace.photo_ref }),
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

    handlePlanKeydown(event) {
      if (this.planPredictions.length === 0) return;
      if (event.key === 'ArrowDown') {
        this.planHighlightedIndex = (this.planHighlightedIndex + 1) % this.planPredictions.length;
      } else if (event.key === 'ArrowUp') {
        this.planHighlightedIndex = this.planHighlightedIndex <= 0 ? this.planPredictions.length - 1 : this.planHighlightedIndex - 1;
      } else if (event.key === 'Enter' && this.planHighlightedIndex >= 0) {
        const pred = this.planPredictions[this.planHighlightedIndex];
        this.suggestToPlan(pred.description, pred.place_id, this.formatPlaceType(pred.types));
      }
    },

    async likePlace() {
      if (!this.selectedPlace) return;
      const resp = await this.api('/api/places', {
        method: 'POST',
        body: JSON.stringify({ type: 'likes', place: this.selectedPlace.name, place_id: this.selectedPlace.place_id, restaurant_type: this.selectedPlace.restaurant_type || null, address: this.selectedPlace.address || null, photo_ref: this.selectedPlace.photo_ref || null }),
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
        body: JSON.stringify({ type: 'dislikes', place: this.selectedPlace.name, place_id: this.selectedPlace.place_id, restaurant_type: this.selectedPlace.restaurant_type || null, address: this.selectedPlace.address || null, photo_ref: this.selectedPlace.photo_ref || null }),
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
        body: JSON.stringify({ type: 'want_to_try', place: this.selectedPlace.name, place_id: this.selectedPlace.place_id, restaurant_type: this.selectedPlace.restaurant_type || null, address: this.selectedPlace.address || null, photo_ref: this.selectedPlace.photo_ref || null }),
      });
      const data = await resp.json();
      this.showToast(data.movedFrom === 'dislikes' ? 'Moved from dislikes to want to try!' : 'Added to want to try!');
      this.selectedPlace = null;
      this.placeSearch = '';
      await this.loadPlaces();
    },

    isWantToTry(placeName) {
      return (this.planWantToTry[placeName] || []).length > 0;
    },
    getWantToTryUsers(placeName) {
      return this.planWantToTry[placeName] || [];
    },

    togglePlaceSection(section) {
      this.placeSections[section] = !this.placeSections[section];
    },
    toggleCardMenu(placeName) {
      this.cardMenuOpen = this.cardMenuOpen === placeName ? null : placeName;
    },
    closeCardMenu() {
      this.cardMenuOpen = null;
    },
    toggleSuggestionMenu(id) {
      this.suggestionMenuOpen = this.suggestionMenuOpen === id ? null : id;
    },
    closeSuggestionMenu() {
      this.suggestionMenuOpen = null;
    },

    suggestionInList(placeName) {
      if (this.likes.some(l => l.name === placeName)) return 'likes';
      if (this.dislikes.some(d => d.name === placeName)) return 'dislikes';
      if (this.wantToTry.some(w => w.name === placeName)) return 'want_to_try';
      return null;
    },

    async addSuggestionToList(suggestion, action) {
      const type = action === 'dislike' ? 'dislikes' : action === 'want_to_try' ? 'want_to_try' : 'likes';
      try {
        const resp = await this.api('/api/places', {
          method: 'POST',
          body: JSON.stringify({ type, place: suggestion.place, place_id: suggestion.place_id, restaurant_type: suggestion.restaurant_type || null }),
        });
        if (!resp.ok) {
          this.showToast('Failed to add place', 'error');
          return;
        }
        if (action === 'favorite') {
          await this.api('/api/places/likes/star', {
            method: 'POST',
            body: JSON.stringify({ place: suggestion.place }),
          });
          this.showToast(`Added "${suggestion.place}" to your favorites!`);
        } else if (action === 'dislike') {
          this.showToast(`Added "${suggestion.place}" to your dislikes.`);
        } else if (action === 'want_to_try') {
          this.showToast(`Added "${suggestion.place}" to your want-to-try list!`);
        } else {
          this.showToast(`Added "${suggestion.place}" to your likes!`);
        }
        await this.loadPlaces();
      } catch (e) {
        this.showToast('Failed to add place', 'error');
      }
    },

    async removePlace(type, placeName) {
      this.closeCardMenu();
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

    async movePlace(fromType, toType, place) {
      const fromList = fromType === 'likes' ? 'likes' : fromType === 'want_to_try' ? 'wantToTry' : 'dislikes';
      const toList = toType === 'likes' ? 'likes' : toType === 'want_to_try' ? 'wantToTry' : 'dislikes';
      const labels = { likes: 'likes', wantToTry: 'want to try', dislikes: 'dislikes' };
      this[fromList] = this[fromList].filter(p => p.name !== place.name);
      this[toList].push({ ...place, starred: false });
      this[toList].sort((a, b) => a.name.localeCompare(b.name));
      try {
        await this.api('/api/places', {
          method: 'POST',
          body: JSON.stringify({ type: toType, place: place.name, place_id: place.place_id, restaurant_type: place.restaurant_type, address: place.address || null }),
        });
        this.showToast(`Moved "${place.name}" to ${labels[toList]}`);
      } catch (e) {
        this[toList] = this[toList].filter(p => p.name !== place.name);
        this[fromList].push(place);
        this[fromList].sort((a, b) => a.name.localeCompare(b.name));
        this.showToast('Failed to move place', 'error');
      }
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

    // ── Explore Nearby ───────────────────────────────────────────────────────
    async exploreNearby() {
      this.nearbyLoading = true;
      this.nearbyError = '';
      this.nearbyPlaces = [];
      try {
        const pos = await new Promise((resolve, reject) => {
          navigator.geolocation.getCurrentPosition(resolve, reject, { timeout: 10000 });
        });
        const resp = await this.api(`/api/places/nearby?lat=${pos.coords.latitude}&lng=${pos.coords.longitude}`);
        const data = await resp.json();
        if (data.error) throw new Error(data.error);
        // Filter out places already in likes/dislikes/want-to-try
        const existingIds = new Set([...this.likes, ...this.dislikes, ...this.wantToTry].map(p => p.place_id));
        this.nearbyPlaces = (data.places || []).filter(p => !existingIds.has(p.place_id));
      } catch (e) {
        this.nearbyError = e.message === 'User denied Geolocation' ? 'Location access denied' : (e.message || 'Failed to find nearby places');
      }
      this.nearbyLoading = false;
    },

    async addNearbyToList(place, list) {
      try {
        await this.api('/api/places', {
          method: 'POST',
          body: JSON.stringify({ place: place.name, place_id: place.place_id, type: list, restaurant_type: (place.types || []).find(t => !['restaurant','food','point_of_interest','establishment'].includes(t)) || 'Restaurant', address: place.address, photo_ref: place.photo_ref }),
        });
        this.nearbyPlaces = this.nearbyPlaces.filter(p => p.place_id !== place.place_id);
        await this.loadPlaces();
        this.showToast(`Added to ${list === 'like' ? 'likes' : list === 'dislike' ? 'dislikes' : 'want to try'}`);
      } catch (e) { this.showToast('Failed to add place', 'error'); }
    },

    // ── Quick Pick ───────────────────────────────────────────────────────────
    async quickPick() {
      if (this.quickPicking || this.likes.length === 0) return;
      this.quickPicking = true;
      this.quickPickResult = null;
      this.moodPickResult = null;
      this.moodPickType = '';

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

    // ── Mood Pick ────────────────────────────────────────────────────────────
    async moodPick(cuisineType) {
      if (this.moodPicking) return;
      let pool = this.likes.filter(p => p.restaurant_type === cuisineType);
      if (this.moodIncludeWantToTry) {
        pool = pool.concat(this.wantToTry.filter(p => p.restaurant_type === cuisineType));
      }
      if (pool.length === 0) return;
      this.moodPicking = true;
      this.moodPickType = cuisineType;
      this.moodPickResult = null;
      this.quickPickResult = null;

      let cycles = 12;
      let delay = 60;
      let i = 0;

      await new Promise(resolve => {
        const spin = () => {
          this.moodPickResult = pool[i % pool.length];
          i++;
          cycles--;
          if (cycles > 0) {
            delay += 25;
            setTimeout(spin, delay);
          } else {
            resolve();
          }
        };
        spin();
      });

      this.moodPickResult = pool[Math.floor(Math.random() * pool.length)];
      this.moodPicking = false;
    },
    async moodSurpriseMe() {
      const types = this.moodPickTypes;
      if (types.length === 0) return;
      const randomType = types[Math.floor(Math.random() * types.length)];
      await this.moodPick(randomType);
    },
    clearMoodPick() {
      this.moodPickResult = null;
      this.moodPickType = '';
    },

    // ── Meal Type Tags ───────────────────────────────────────────────────────
    hasMealType(place, mealType) {
      return (place.meal_types || []).includes(mealType);
    },
    async toggleMealType(listType, place, mealType) {
      const types = [...(place.meal_types || [])];
      const idx = types.indexOf(mealType);
      if (idx >= 0) types.splice(idx, 1);
      else types.push(mealType);
      try {
        const resp = await fetch('/api/places/meal-types', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ place: place.name, meal_types: types, list_type: listType }),
        });
        if (resp.ok) {
          place.meal_types = types;
        }
      } catch (e) { /* ignore */ }
    },

    // ── Notes ────────────────────────────────────────────────────────────────
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

    // ── Star/Favorites ───────────────────────────────────────────────────────
    async toggleStar(type, placeName) {
      try {
        const resp = await this.api(`/api/places/${type}/star`, {
          method: 'POST',
          body: JSON.stringify({ place: placeName }),
        });
        if (!resp.ok) {
          this.showToast('Failed to update star', 'error');
          return;
        }
        const data = await resp.json();
        const list = type === 'likes' ? this.likes : this.wantToTry;
        const item = list.find(p => p.name === placeName);
        if (item) item.starred = data.starred;
        this.showToast(data.starred ? 'Starred!' : 'Unstarred');
      } catch (e) {
        this.showToast('Failed to update star', 'error');
      }
    },

    isAlreadySuggestedToPlan(placeName) {
      return this.activePlan?.suggestions?.some(s => s.place === placeName) || false;
    },

    get starredPlaces() {
      return [
        ...this.likes.filter(p => p.starred).map(p => ({ ...p, _type: 'likes' })),
        ...this.wantToTry.filter(p => p.starred).map(p => ({ ...p, _type: 'want_to_try' })),
      ];
    },

    // ── Recurring Plans ──────────────────────────────────────────────────────
    async loadRecurringPlans() {
      this.recurringLoading = true;
      try {
        const resp = await this.api('/api/recurring-plans');
        this.recurringPlans = await resp.json();
      } catch (e) { /* ignore */ }
      this.recurringLoading = false;
    },
    async createRecurringPlan() {
      if (!this.recurringForm.name.trim()) {
        this.showToast('Enter a plan name', 'error');
        return;
      }
      try {
        await this.api('/api/recurring-plans', {
          method: 'POST',
          body: JSON.stringify({
            name: this.recurringForm.name,
            frequency: this.recurringForm.frequency,
            memberIds: this.recurringForm.members,
            vetoLimit: this.recurringForm.vetoLimit,
          }),
        });
        this.showToast('Recurring plan created');
        this.showRecurringForm = false;
        this.recurringForm = { name: '', frequency: 'weekly', members: [], vetoLimit: 1 };
        await this.loadRecurringPlans();
      } catch (e) { this.showToast('Failed to create recurring plan', 'error'); }
    },
    async pauseRecurring(id, pause) {
      try {
        await this.api(`/api/recurring-plans/${id}`, {
          method: 'PATCH',
          body: JSON.stringify({ paused: pause }),
        });
        this.showToast(pause ? 'Paused' : 'Resumed');
        await this.loadRecurringPlans();
      } catch (e) { this.showToast('Failed', 'error'); }
    },
    async skipRecurring(id) {
      try {
        await this.api(`/api/recurring-plans/${id}/skip`, { method: 'POST' });
        this.showToast('Skipped next occurrence');
        await this.loadRecurringPlans();
      } catch (e) { this.showToast('Failed', 'error'); }
    },
    async deleteRecurring(id) {
      if (!confirm('Delete this recurring plan?')) return;
      try {
        await this.api(`/api/recurring-plans/${id}`, { method: 'DELETE' });
        this.showToast('Recurring plan deleted');
        await this.loadRecurringPlans();
      } catch (e) { this.showToast('Failed', 'error'); }
    },
    toggleRecurringMember(friendId) {
      const idx = this.recurringForm.members.indexOf(friendId);
      if (idx >= 0) this.recurringForm.members.splice(idx, 1);
      else this.recurringForm.members.push(friendId);
    },
    formatNextOccurrence(dateStr) {
      if (!dateStr) return '';
      const d = new Date(dateStr);
      return d.toLocaleDateString(undefined, { weekday: 'short', month: 'short', day: 'numeric' });
    },

    // ── History Timeline ─────────────────────────────────────────────────────
    async loadHistory() {
      this.historyLoading = true;
      try {
        const params = new URLSearchParams();
        if (this.historyFilterFrom) params.set('from', this.historyFilterFrom);
        if (this.historyFilterTo) params.set('to', this.historyFilterTo);
        if (this.historyFilterMember) params.set('member', this.historyFilterMember);
        const resp = await this.api(`/api/history?${params.toString()}`);
        this.historyTimeline = await resp.json();
      } catch (e) { /* ignore */ }
      this.historyLoading = false;
    },
    formatTimelineDate(dateStr) {
      if (!dateStr) return '';
      const d = new Date(dateStr);
      return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
    },

    // ── Friend Groups ────────────────────────────────────────────────────────
    async loadFriendGroups() {
      try {
        const resp = await this.api('/api/friend-groups');
        this.friendGroups = await resp.json();
      } catch (e) { /* ignore */ }
    },
    openCreateGroup() {
      this.groupModal = { visible: true, editingId: null, name: '', selectedMembers: [] };
    },
    openEditGroup(group) {
      this.groupModal = { visible: true, editingId: group.id, name: group.name, selectedMembers: group.members.map(m => m.user_id) };
    },
    toggleGroupMember(friendId) {
      const idx = this.groupModal.selectedMembers.indexOf(friendId);
      if (idx >= 0) this.groupModal.selectedMembers.splice(idx, 1);
      else this.groupModal.selectedMembers.push(friendId);
    },
    async saveGroup() {
      if (!this.groupModal.name.trim() || this.groupModal.selectedMembers.length === 0) {
        this.showToast('Enter a name and select at least one member', 'error');
        return;
      }
      try {
        if (this.groupModal.editingId) {
          await this.api(`/api/friend-groups/${this.groupModal.editingId}`, {
            method: 'PUT',
            body: JSON.stringify({ name: this.groupModal.name, memberIds: this.groupModal.selectedMembers }),
          });
          this.showToast('Group updated');
        } else {
          await this.api('/api/friend-groups', {
            method: 'POST',
            body: JSON.stringify({ name: this.groupModal.name, memberIds: this.groupModal.selectedMembers }),
          });
          this.showToast('Group created');
        }
        this.groupModal.visible = false;
        await this.loadFriendGroups();
      } catch (e) { this.showToast('Failed to save group', 'error'); }
    },
    async deleteGroup(groupId) {
      if (!confirm('Delete this group?')) return;
      try {
        await this.api(`/api/friend-groups/${groupId}`, { method: 'DELETE' });
        this.showToast('Group deleted');
        await this.loadFriendGroups();
      } catch (e) { this.showToast('Failed to delete group', 'error'); }
    },
    async inviteGroupToPlan(groupId) {
      if (!this.activePlan) return;
      try {
        const resp = await this.api(`/api/plans/${this.activePlan.plan.id}/invite-group`, {
          method: 'POST',
          body: JSON.stringify({ groupId }),
        });
        const data = await resp.json();
        this.showToast(`Invited group — ${data.added} new member(s) added`);
        await this.openPlan(this.activePlan.plan.id);
      } catch (e) { this.showToast('Failed to invite group', 'error'); }
    },

    // ── Friends ──────────────────────────────────────────────────────────────
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
        await Promise.all([this.loadFriends(), this.loadFriendRequests(), this.loadSentFriendRequests()]);
      } catch (e) {
        this.showToast('Failed to invite friend', 'error');
      }
    },

    planFriendMembers() {
      if (!this.activePlan?.members) return [];
      const friendIds = new Set(this.friends.map(f => f.id));
      return this.activePlan.members.filter(m => m.id !== this.userId && friendIds.has(m.id));
    },

    planNonFriendMembers() {
      if (!this.activePlan?.members) return [];
      const friendIds = new Set(this.friends.map(f => f.id));
      return this.activePlan.members.filter(m => m.id !== this.userId && !friendIds.has(m.id));
    },

    hasSentRequestTo(userId) {
      return this.sentFriendRequests.some(r => r.id === userId);
    },

    hasIncomingRequestFrom(userId) {
      return this.friendRequests.some(r => r.id === userId);
    },

    async sendFriendRequestToMember(username) {
      if (!confirm(`Send a friend request to ${username}?`)) return;
      try {
        const resp = await this.api('/api/invite', {
          method: 'POST',
          body: JSON.stringify({ friendUsername: username }),
        });
        if (!resp.ok) {
          const err = await resp.json();
          this.showToast(err.error || 'Failed to send request', 'error');
          return;
        }
        const data = await resp.json();
        if (data.autoAccepted) {
          this.showToast(`You and ${username} are now friends!`);
        } else {
          this.showToast(`Friend request sent to ${username}!`);
        }
        await Promise.all([this.loadFriends(), this.loadFriendRequests(), this.loadSentFriendRequests()]);
      } catch (e) {
        this.showToast('Failed to send friend request', 'error');
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

    getFriendSection(friendId) {
      if (!this.friendSections[friendId]) {
        this.friendSections[friendId] = { likesOpen: false, commonOpen: false, likes: null, commonPlaces: null };
      }
      return this.friendSections[friendId];
    },

    async toggleFriendLikes(friendId) {
      const sec = this.getFriendSection(friendId);
      sec.likesOpen = !sec.likesOpen;
      if (sec.likesOpen && sec.likes === null) {
        try {
          const resp = await this.api(`/api/friends/${friendId}/likes`);
          if (!resp.ok) {
            this.showToast('Failed to load likes', 'error');
            sec.likesOpen = false;
            return;
          }
          const data = await resp.json();
          sec.likes = data.likes || [];
        } catch (e) {
          this.showToast('Failed to load friend\'s likes', 'error');
          sec.likesOpen = false;
        }
      }
    },

    async toggleFriendCommon(friendId, friendUsername) {
      const sec = this.getFriendSection(friendId);
      sec.commonOpen = !sec.commonOpen;
      if (sec.commonOpen && sec.commonPlaces === null) {
        try {
          const resp = await this.api(`/api/common-places?friendUsername=${encodeURIComponent(friendUsername)}`);
          const data = await resp.json();
          sec.commonPlaces = data.common || [];
        } catch (e) {
          sec.commonPlaces = [];
        }
      }
    },

    async loadFriendRequests() {
      try {
        const resp = await this.api('/api/friend-requests');
        const data = await resp.json();
        this.friendRequests = data.requests || [];
      } catch (e) { /* ignore */ }
    },

    async loadSentFriendRequests() {
      try {
        const resp = await this.api('/api/friend-requests/outgoing');
        const data = await resp.json();
        this.sentFriendRequests = data.requests || [];
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


    async addFriendPlace(place, action) {
      try {
        const type = action === 'dislike' ? 'dislikes' : 'likes';
        const resp = await this.api('/api/places', {
          method: 'POST',
          body: JSON.stringify({ type, place: place.name, place_id: place.place_id, restaurant_type: place.restaurant_type || null, address: place.address || null, photo_ref: place.photo_ref || null }),
        });
        if (!resp.ok) {
          this.showToast('Failed to add place', 'error');
          return;
        }
        if (action === 'favorite') {
          await this.api('/api/places/likes/star', {
            method: 'POST',
            body: JSON.stringify({ place: place.name }),
          });
          this.showToast(`Added "${place.name}" to your favorites!`);
        } else if (action === 'dislike') {
          this.showToast(`Added "${place.name}" to your dislikes.`);
        } else {
          this.showToast(`Added "${place.name}" to your likes!`);
        }
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
        delete this.friendSections[friendId];
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

    // ── Plans ────────────────────────────────────────────────────────────────
    async loadPlans() {
      this.loading.plans = true;
      try {
        const resp = await this.api('/api/plans');
        const data = await resp.json();
        this.plans = data.plans || [];
      } catch (e) { /* ignore */ }
      this.loading.plans = false;
    },

    async createPlan() {
      const name = this.newPlanName.trim() || 'Dinner Plan';
      const veto_limit = parseInt(this.planVetoLimitInput) || 1;
      const meal_type = this.planMealType || null;
      const dietary_tags = this.planDietaryTags.length > 0 ? this.planDietaryTags : null;
      try {
        const resp = await this.api('/api/plans', {
          method: 'POST',
          body: JSON.stringify({ name, veto_limit, meal_type, dietary_tags }),
        });
        const data = await resp.json();
        this.newPlanName = '';
        this.planVetoLimitInput = 1;
        this.planMealType = '';
        this.planDietaryTags = [];
        this.showCreatePlanForm = false;
        this.showToast(`Plan created! Code: ${data.code}`);
        await this.loadPlans();
      } catch (e) {
        this.showToast('Failed to create plan', 'error');
      }
    },

    async joinPlan() {
      const code = this.joinCode.trim().toUpperCase();
      if (!code) return;
      try {
        const resp = await this.api('/api/plans/join', {
          method: 'POST',
          body: JSON.stringify({ code }),
        });
        if (!resp.ok) {
          const err = await resp.json();
          this.showToast(err.error || 'Failed to join', 'error');
          return;
        }
        this.joinCode = '';
        this.showToast('Joined plan!');
        await this.loadPlans();
      } catch (e) {
        this.showToast('Failed to join plan', 'error');
      }
    },

    async openPlan(planId) {
      try {
        const resp = await this.api(`/api/plans/${planId}`);
        const data = await resp.json();
        this.planWantToTry = data.want_to_try || {};
        this.activePlan = data;
        this.winner = null;
        this.planCuisineFilter = '';
        this.planPriceFilter = [];
        this.mapView = false;
        if (this.activePlan.plan.winner_place) {
          this.winner = { place: this.activePlan.plan.winner_place };
        }
        if (this.socket) this.socket.emit('join-plan', planId);
        try {
          const dResp = await this.api(`/api/plans/${planId}/dislikes`);
          const dData = await dResp.json();
          this.planDislikes = dData.dislikes || [];
        } catch (e) { this.planDislikes = []; }
        await this.loadChatMessages();
        this.startDeadlineCountdown();
      } catch (e) {
        this.showToast('Failed to open plan', 'error');
      }
    },

    async refreshPlan() {
      if (!this.activePlan) return;
      try {
        const resp = await this.api(`/api/plans/${this.activePlan.plan.id}`);
        const data = await resp.json();
        this.planWantToTry = data.want_to_try || {};
        this.activePlan = data;
      } catch (e) { /* ignore */ }
    },

    closeActivePlan() {
      if (this.socket && this.activePlan) {
        this.socket.emit('leave-plan', this.activePlan.plan.id);
      }
      this.activePlan = null;
      this.winner = null;
      this.closingPlan = false;
      this.planPlaceSearch = '';
      this.planPredictions = [];
      this.chatMessages = [];
      this.chatInput = '';
      this.chatDrawerOpen = false;
      this.unreadChatCount = 0;
      this.emojiPickerVisible = false;
      this.gifSearchVisible = false;
      this.gifSearchQuery = '';
      this.gifResults = [];
      this.reactionPickerMessageId = null;
      this.planCuisineFilter = '';
      this.planPriceFilter = [];
      this.mapView = false;
      if (this.deadlineTimer) { clearInterval(this.deadlineTimer); this.deadlineTimer = null; }
      this.deadlineCountdown = '';
      this.deadlineInput = '';
      if (this.mapInstance) { this.mapInstance = null; this.mapMarkers = []; }
      this.loadPlans();
    },

    closePlan() {
      if (!this.activePlan) return;
      this.closingPlan = true;
    },

    cancelClose() {
      this.closingPlan = false;
    },

    async closeWithWinner(place) {
      if (!this.activePlan) return;
      await this.api(`/api/plans/${this.activePlan.plan.id}/close`, {
        method: 'POST',
        body: JSON.stringify({ winner_place: place }),
      });
      this.closingPlan = false;
      this.winner = { place };
      this.showToast(`Plan closed! Winner: ${place}`);
      await this.refreshPlan();
    },

    async closeWithoutWinner() {
      if (!this.activePlan) return;
      if (!await this.showConfirm('Close without selecting a winner?')) return;
      await this.api(`/api/plans/${this.activePlan.plan.id}/close`, {
        method: 'POST',
        body: JSON.stringify({}),
      });
      this.closingPlan = false;
      this.showToast('Plan closed.');
      await this.refreshPlan();
    },

    async deletePlan(planId) {
      if (!await this.showConfirm('Permanently delete this plan? This cannot be undone.')) return;
      try {
        const resp = await this.api(`/api/plans/${planId}`, { method: 'DELETE' });
        if (!resp.ok) {
          const err = await resp.json();
          this.showToast(err.error || 'Failed to delete plan', 'error');
          return;
        }
        this.plans = this.plans.filter(s => s.id !== planId);
        this.historyTimeline = this.historyTimeline.filter(e => e.id !== planId);
        if (this.activePlan && this.activePlan.plan.id === planId) {
          this.activePlan = null;
          this.winner = null;
        }
        this.showToast('Plan deleted.');
      } catch (e) {
        this.showToast('Failed to delete plan', 'error');
      }
    },

    async inviteToPlan() {
      if (!this.planInviteUsername.trim() || !this.activePlan) return;
      try {
        const resp = await this.api(`/api/plans/${this.activePlan.plan.id}/invite`, {
          method: 'POST',
          body: JSON.stringify({ username: this.planInviteUsername.trim() }),
        });
        if (!resp.ok) {
          const err = await resp.json();
          this.showToast(err.error || 'Failed to invite', 'error');
          return;
        }
        const data = await resp.json();
        this.showToast(data.alreadyMember ? 'User is already a member' : `Invited ${this.planInviteUsername.trim()}!`);
        this.planInviteUsername = '';
        await this.refreshPlan();
      } catch (e) {
        this.showToast('Failed to invite user', 'error');
      }
    },

    quickInviteFriend(friendUsername) {
      this.planInviteUsername = friendUsername;
      this.inviteToPlan();
    },

    isPlanDisliked(placeName) {
      return this.planDislikes.includes(placeName);
    },

    copyCode() {
      const code = this.activePlan?.plan?.code;
      if (code) {
        navigator.clipboard.writeText(code);
        this.showToast('Code copied!');
      }
    },

    async updatePlanMealType() {
      if (!this.activePlan) return;
      const meal_type = this.activePlan.plan.meal_type || null;
      try {
        await this.api(`/api/plans/${this.activePlan.plan.id}/meal-type`, {
          method: 'PUT',
          body: JSON.stringify({ meal_type }),
        });
      } catch (e) { /* ignore */ }
    },

    // ── Plan Suggest ─────────────────────────────────────────────────────────
    async searchPlanPlaces() {
      this.planHighlightedIndex = -1;
      const q = this.planPlaceSearch.trim();
      if (!q) { this.planPredictions = []; this.planSearchedOnce = false; return; }
      this.planSearching = true;
      try {
        const resp = await this.api(`/api/autocomplete?input=${encodeURIComponent(q)}`);
        const data = await resp.json();
        this.planPredictions = data.predictions || [];
        this.planSearchedOnce = true;
      } catch (e) {
        this.planPredictions = [];
      } finally {
        this.planSearching = false;
      }
    },

    async suggestToPlan(place, placeId, restaurantType) {
      if (!this.activePlan) return;
      try {
        const resp = await this.api(`/api/plans/${this.activePlan.plan.id}/suggest`, {
          method: 'POST',
          body: JSON.stringify({ place, place_id: placeId || null, restaurant_type: restaurantType || null }),
        });
        if (!resp.ok) {
          const err = await resp.json();
          this.showToast(err.error || 'Failed to suggest', 'error');
          return;
        }
        this.planPlaceSearch = '';
        this.planPredictions = [];
        this.showToast('Place suggested!');
        await this.refreshPlan();
      } catch (e) {
        this.showToast('Failed to suggest', 'error');
      }
    },

    async removeSuggestion(suggestion) {
      if (!this.activePlan) return;
      if (!await this.showConfirm(`Remove "${suggestion.place}" from this plan?`)) return;
      suggestion._removing = true;
      await new Promise(r => setTimeout(r, 200));
      try {
        const resp = await this.api(`/api/plans/${this.activePlan.plan.id}/suggestion/${suggestion.id}`, {
          method: 'DELETE',
        });
        if (!resp.ok) {
          suggestion._removing = false;
          const err = await resp.json();
          this.showToast(err.error || 'Failed to remove', 'error');
          return;
        }
        this.showToast('Suggestion removed');
        await this.refreshPlan();
      } catch (e) {
        suggestion._removing = false;
        this.showToast('Failed to remove suggestion', 'error');
      }
    },

    // ── Voting ───────────────────────────────────────────────────────────────
    async toggleVote(suggestion) {
      if (!this.activePlan) return;
      const endpoint = suggestion.user_voted ? 'unvote' : 'vote';
      await this.api(`/api/plans/${this.activePlan.plan.id}/${endpoint}`, {
        method: 'POST',
        body: JSON.stringify({ suggestion_id: suggestion.id }),
      });
      await this.refreshPlan();
    },

    async toggleDownvote(suggestion) {
      if (!this.activePlan) return;
      const endpoint = suggestion.user_downvoted ? 'undownvote' : 'downvote';
      await this.api(`/api/plans/${this.activePlan.plan.id}/${endpoint}`, {
        method: 'POST',
        body: JSON.stringify({ suggestion_id: suggestion.id }),
      });
      await this.refreshPlan();
    },

    async toggleVeto(suggestion) {
      if (!this.activePlan) return;
      if (!suggestion.user_vetoed && (this.activePlan.vetoesRemaining || 0) <= 0) {
        this.showToast('No vetoes remaining', 'error');
        return;
      }
      const endpoint = suggestion.user_vetoed ? 'unveto' : 'veto';
      try {
        const resp = await this.api(`/api/plans/${this.activePlan.plan.id}/${endpoint}`, {
          method: 'POST',
          body: JSON.stringify({ suggestion_id: suggestion.id }),
        });
        if (!resp.ok) {
          const err = await resp.json();
          this.showToast(err.error || 'Failed to veto', 'error');
          return;
        }
        await this.refreshPlan();
      } catch (e) {
        this.showToast('Failed to veto', 'error');
      }
    },

    async setVetoLimit() {
      if (!this.activePlan) return;
      const limit = parseInt(this.planVetoLimitInput);
      if (isNaN(limit) || limit < 0) return;
      try {
        await this.api(`/api/plans/${this.activePlan.plan.id}/veto-limit`, {
          method: 'POST',
          body: JSON.stringify({ veto_limit: limit }),
        });
        this.showToast('Veto limit updated');
      } catch (e) {
        this.showToast('Failed to update veto limit', 'error');
      }
    },

    // ── Random Pick ──────────────────────────────────────────────────────────
    async randomPick() {
      if (!this.activePlan || this.picking) return;
      this.picking = true;
      this.winner = null;

      const suggestions = this.activePlan.suggestions || [];
      if (suggestions.length === 0) {
        this.showToast('No suggestions to pick from!', 'error');
        this.picking = false;
        return;
      }

      // Fetch actual server-side weighted pick first
      let serverWinner;
      try {
        const resp = await this.api(`/api/plans/${this.activePlan.plan.id}/pick`, {
          method: 'POST',
          body: JSON.stringify({ mode: 'random' }),
        });
        const data = await resp.json();
        serverWinner = data.winner;
      } catch (e) {
        this.showToast('Failed to pick', 'error');
        this.picking = false;
        return;
      }

      // Spin the wheel with only top-voted suggestions (tiebreaker)
      const nonVetoed = suggestions.filter(s => !(s.veto_count > 0));
      const maxVotes = Math.max(...nonVetoed.map(s => (s.vote_count || 0) - (s.downvote_count || 0)));
      const eligible = nonVetoed.filter(s => (s.vote_count || 0) - (s.downvote_count || 0) === maxVotes);
      if (eligible.length <= 1) {
        // Skip wheel for single top-voted option
        this.winner = serverWinner;
        this.showToast(`Winner: ${serverWinner.place}`);
        this.createConfetti();
        this.picking = false;
        return;
      }
      await this.spinWheel(eligible.map(s => s.place), serverWinner.place);

      this.winner = serverWinner;
      this.showToast(`Winner: ${serverWinner.place}`);
      this.createConfetti();
      this.picking = false;
    },

    spinWheel(names, winnerName) {
      return new Promise(resolve => {
        this.spinningWheel = true;
        const canvas = document.getElementById('spin-wheel-canvas');
        if (!canvas) { this.spinningWheel = false; resolve(); return; }
        const ctx = canvas.getContext('2d');

        // HiDPI support
        const dpr = window.devicePixelRatio || 1;
        const cssSize = Math.min(window.innerWidth - 48, 380);
        canvas.style.width = cssSize + 'px';
        canvas.style.height = cssSize + 'px';
        canvas.width = cssSize * dpr;
        canvas.height = cssSize * dpr;
        ctx.scale(dpr, dpr);

        const cx = cssSize / 2;
        const cy = cssSize / 2;
        const r = cssSize / 2 - 12;
        const segAngle = (Math.PI * 2) / names.length;
        const colors = [
          '#E07A5F', '#5B9A6F', '#E8A838', '#6B8FBF',
          '#C96A52', '#4A8360', '#D49530', '#8B7E74',
          '#D64545', '#7B68AE', '#3D9970', '#F4A460'
        ];

        // Resolve CSS color for pointer
        const cs = getComputedStyle(document.documentElement);
        const pointerColor = cs.getPropertyValue('--text-primary').trim() || '#2D2A26';

        // Calculate target angle so winner lands at top (pointer)
        // Uses the same segIdx formula in reverse:
        //   segIdx = floor((1.5π − finalAngle + 2π) mod 2π / segAngle)
        // Solving for finalAngle when segIdx = winnerIdx (center of segment):
        const winnerIdx = names.indexOf(winnerName);
        const finalAngle = ((Math.PI * 1.5 - winnerIdx * segAngle - segAngle / 2) % (Math.PI * 2) + Math.PI * 2) % (Math.PI * 2);
        const extraSpins = 5 + Math.floor(Math.random() * 4);
        const totalRotation = Math.PI * 2 * extraSpins + finalAngle;
        let startTime = null;
        const duration = 4000;
        let lastSegIdx = -1;

        // Quartic ease-out with slight settle
        const easeOut = t => {
          if (t < 0.95) return 1 - Math.pow(1 - (t / 0.95), 4);
          const p = (t - 0.95) / 0.05;
          return 1 + 0.003 * Math.sin(p * Math.PI);
        };

        const draw = (angle, highlight) => {
          ctx.clearRect(0, 0, cssSize, cssSize);
          for (let i = 0; i < names.length; i++) {
            const start = angle + i * segAngle;
            const end = start + segAngle;
            ctx.beginPath();
            ctx.moveTo(cx, cy);
            ctx.arc(cx, cy, r, start, end);
            ctx.closePath();
            ctx.fillStyle = colors[i % colors.length];
            ctx.fill();
            ctx.strokeStyle = 'rgba(255,255,255,0.4)';
            ctx.lineWidth = 2;
            ctx.stroke();

            // Label
            const fontSize = Math.max(11, Math.min(15, (segAngle * r) / 6));
            ctx.save();
            ctx.translate(cx, cy);
            ctx.rotate(start + segAngle / 2);
            ctx.textAlign = 'right';
            ctx.textBaseline = 'middle';
            ctx.fillStyle = '#fff';
            ctx.shadowColor = 'rgba(0,0,0,0.4)';
            ctx.shadowBlur = 2;
            ctx.font = `bold ${fontSize}px 'Segoe UI', sans-serif`;
            const maxLen = Math.floor(r / (fontSize * 0.55));
            const label = names[i].length > maxLen ? names[i].slice(0, maxLen - 1) + '\u2026' : names[i];
            ctx.fillText(label, r - 16, 0);
            ctx.shadowBlur = 0;
            ctx.restore();
          }

          // Winner highlight glow
          if (highlight && winnerIdx >= 0) {
            const wStart = angle + winnerIdx * segAngle;
            const wEnd = wStart + segAngle;
            ctx.save();
            ctx.beginPath();
            ctx.moveTo(cx, cy);
            ctx.arc(cx, cy, r, wStart, wEnd);
            ctx.closePath();
            ctx.shadowColor = '#FFD700';
            ctx.shadowBlur = 20;
            ctx.strokeStyle = '#FFD700';
            ctx.lineWidth = 4;
            ctx.stroke();
            ctx.shadowBlur = 0;
            ctx.restore();
          }

          // Pointer triangle at top
          const pSize = 14;
          ctx.beginPath();
          ctx.moveTo(cx, cy - r + 2);
          ctx.lineTo(cx - pSize, cy - r - 24);
          ctx.lineTo(cx + pSize, cy - r - 24);
          ctx.closePath();
          ctx.fillStyle = pointerColor;
          ctx.fill();
          ctx.strokeStyle = 'rgba(0,0,0,0.15)';
          ctx.lineWidth = 1;
          ctx.stroke();

          // Center circle
          ctx.beginPath();
          ctx.arc(cx, cy, 18, 0, Math.PI * 2);
          ctx.fillStyle = '#fff';
          ctx.fill();
          ctx.strokeStyle = 'rgba(0,0,0,0.1)';
          ctx.lineWidth = 2;
          ctx.stroke();
        };

        const animate = (timestamp) => {
          if (!startTime) startTime = timestamp;
          const elapsed = timestamp - startTime;
          const progress = Math.min(elapsed / duration, 1);
          const easedProgress = easeOut(progress);
          this.wheelAngle = easedProgress * totalRotation;
          draw(this.wheelAngle, false);

          // Visual tick when segment boundary crosses pointer
          const currentAngle = ((this.wheelAngle % (Math.PI * 2)) + Math.PI * 2) % (Math.PI * 2);
          const segIdx = Math.floor(((Math.PI * 1.5 - currentAngle + Math.PI * 2) % (Math.PI * 2)) / segAngle);
          if (segIdx !== lastSegIdx) {
            lastSegIdx = segIdx;
            canvas.style.filter = 'brightness(1.06)';
            setTimeout(() => { canvas.style.filter = ''; }, 40);
          }

          if (progress < 1) {
            requestAnimationFrame(animate);
          } else {
            // Final frame with winner highlight
            draw(this.wheelAngle, true);
            setTimeout(() => {
              this.spinningWheel = false;
              resolve();
            }, 1200);
          }
        };

        requestAnimationFrame(animate);
      });
    },

    // ── Closest Pick ─────────────────────────────────────────────────────────
    async closestPick() {
      if (!this.activePlan || this.picking) return;
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

        const resp = await this.api(`/api/plans/${this.activePlan.plan.id}/pick`, {
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

    // ── Swipe Gestures ───────────────────────────────────────────────────────
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
        if (this.activePlan && this.activePlan.plan.status === 'open') {
          this.suggestToPlan(place.name, place.place_id, place.restaurant_type);
        }
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

    // ── Share ────────────────────────────────────────────────────────────────
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

    // ── Recent Suggestions ───────────────────────────────────────────────────
    async loadRecentSuggestions() {
      try {
        const resp = await this.api('/api/suggestions/recent');
        const data = await resp.json();
        this.recentSuggestions = data.recent || [];
      } catch (e) { /* ignore */ }
    },

    // ── Invite Non-App Users ─────────────────────────────────────────────────
    async autoJoinInvite() {
      if (!this.pendingInviteCode) return;
      const code = this.pendingInviteCode;
      this.pendingInviteCode = null;
      window.history.replaceState(null, '', '/');
      try {
        const resp = await this.api('/api/plans/join', {
          method: 'POST',
          body: JSON.stringify({ code }),
        });
        if (resp.ok) {
          const data = await resp.json();
          this.showToast('Joined plan!');
          this.activeTab = 'plans';
          await this.loadPlans();
          await this.openPlan(data.id);
        } else {
          const err = await resp.json();
          this.showToast(err.error || 'Failed to join plan', 'error');
        }
      } catch (e) {
        this.showToast('Failed to join plan', 'error');
      }
    },

    async sharePlanInvite() {
      if (!this.activePlan) return;
      const code = this.activePlan.plan.code;
      const url = `${window.location.origin}/invite/${code}`;
      const text = `Join my Dinner Roulette plan! Use code ${code}`;
      if (navigator.share) {
        try { await navigator.share({ title: 'Dinner Roulette Invite', text, url }); } catch (e) { /* cancelled */ }
      } else if (navigator.clipboard) {
        await navigator.clipboard.writeText(url);
        this.showToast('Invite link copied!');
      }
    },

    showQrCode() {
      if (!this.activePlan) return;
      const code = this.activePlan.plan.code;
      const url = `${window.location.origin}/invite/${code}`;
      const qr = qrcode(0, 'M');
      qr.addData(url);
      qr.make();
      this.qrModal.dataUrl = qr.createDataURL(8, 4);
      this.qrModal.visible = true;
    },

    downloadQr() {
      if (!this.qrModal.dataUrl) return;
      const code = this.activePlan?.plan?.code || 'invite';
      const a = document.createElement('a');
      a.href = this.qrModal.dataUrl;
      a.download = `dinner-roulette-${code}.png`;
      a.click();
    },

    // ── Deadline ─────────────────────────────────────────────────────────────
    async setDeadline() {
      if (!this.deadlineInput || !this.activePlan) return;
      try {
        await this.api(`/api/plans/${this.activePlan.plan.id}/deadline`, {
          method: 'POST',
          body: JSON.stringify({ deadline: this.deadlineInput }),
        });
        this.activePlan.plan.voting_deadline = this.deadlineInput;
        this.startDeadlineCountdown();
        this.showToast('Deadline set!');
      } catch (e) {
        this.showToast('Failed to set deadline', 'error');
      }
    },

    async removeDeadline() {
      if (!this.activePlan) return;
      try {
        await this.api(`/api/plans/${this.activePlan.plan.id}/deadline`, {
          method: 'POST',
          body: JSON.stringify({ deadline: null }),
        });
        this.activePlan.plan.voting_deadline = null;
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
      const deadline = this.activePlan?.plan?.voting_deadline;
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

    // ── Chat ─────────────────────────────────────────────────────────────────
    toggleChatDrawer() {
      this.chatDrawerOpen = !this.chatDrawerOpen;
      if (this.chatDrawerOpen) {
        this.unreadChatCount = 0;
        this.markMessagesRead();
        this.loadMessageReads();
        this.$nextTick(() => {
          const el = document.getElementById('chat-messages');
          if (el) el.scrollTop = el.scrollHeight;
        });
      } else {
        this.emojiPickerVisible = false;
        this.gifSearchVisible = false;
        this.reactionPickerMessageId = null;
      }
    },

    async markMessagesRead() {
      if (!this.activePlan || !this.chatDrawerOpen) return;
      try {
        await this.api(`/api/plans/${this.activePlan.plan.id}/messages/read`, { method: 'POST', body: '{}' });
      } catch (e) { /* ignore */ }
    },

    async loadMessageReads() {
      if (!this.activePlan) return;
      try {
        const resp = await this.api(`/api/plans/${this.activePlan.plan.id}/messages/reads`);
        this.messageReads = await resp.json();
      } catch (e) { this.messageReads = []; }
    },

    seenBy(msgId) {
      const readers = this.messageReads.filter(r => r.last_read_message_id >= msgId && r.user_id !== this.userId);
      if (readers.length === 0) return '';
      const names = readers.map(r => r.display_name || r.username);
      if (names.length <= 2) return 'Seen by ' + names.join(' and ');
      return `Seen by ${names[0]} and ${names.length - 1} others`;
    },

    isLastReadForSomeone(msgId, idx) {
      // Show "seen by" only on the last message that each reader has read
      if (idx < this.chatMessages.length - 1) {
        const nextMsgId = this.chatMessages[idx + 1]?.id;
        const readersHere = this.messageReads.filter(r => r.last_read_message_id >= msgId && r.last_read_message_id < nextMsgId && r.user_id !== this.userId);
        return readersHere.length > 0;
      }
      // Last message — show all readers
      return this.messageReads.some(r => r.last_read_message_id >= msgId && r.user_id !== this.userId);
    },

    async loadChatMessages() {
      if (!this.activePlan) return;
      try {
        const resp = await this.api(`/api/plans/${this.activePlan.plan.id}/messages`);
        const data = await resp.json();
        this.chatMessages = data.messages || [];
      } catch (e) { this.chatMessages = []; }
    },

    async sendChatMessage() {
      if (!this.chatInput.trim() || !this.activePlan) return;
      try {
        await this.api(`/api/plans/${this.activePlan.plan.id}/messages`, {
          method: 'POST',
          body: JSON.stringify({ message: this.chatInput.trim(), message_type: 'text' }),
        });
        this.chatInput = '';
      } catch (e) {
        this.showToast('Failed to send message', 'error');
      }
    },

    async deleteChatMessage(messageId) {
      if (!this.activePlan) return;
      this.confirmModal = {
        visible: true,
        message: 'Delete this message?',
        onConfirm: async () => {
          this.confirmModal.visible = false;
          try {
            await this.api(`/api/plans/${this.activePlan.plan.id}/messages/${messageId}`, { method: 'DELETE' });
          } catch (e) { this.showToast('Failed to delete message', 'error'); }
        },
        onCancel: () => { this.confirmModal.visible = false; }
      };
    },

    editChatMessage(msg) {
      this.editingMessageId = msg.id;
      this.editingMessageText = msg.message;
    },

    cancelEditMessage() {
      this.editingMessageId = null;
      this.editingMessageText = '';
    },

    async saveMessageEdit() {
      if (!this.activePlan || !this.editingMessageId) return;
      const text = this.editingMessageText.trim();
      if (!text) return;
      try {
        await this.api(`/api/plans/${this.activePlan.plan.id}/messages/${this.editingMessageId}`, {
          method: 'PATCH',
          body: JSON.stringify({ message: text }),
        });
        this.editingMessageId = null;
        this.editingMessageText = '';
      } catch (e) { this.showToast('Failed to edit message', 'error'); }
    },

    handleChatTyping() {
      if (!this.socket || !this.activePlan) return;
      this.socket.emit('typing-start', this.activePlan.plan.id);
      clearTimeout(this.typingTimeout);
      this.typingTimeout = setTimeout(() => {
        if (this.socket && this.activePlan) this.socket.emit('typing-stop', this.activePlan.plan.id);
      }, 1000);
    },

    get typingText() {
      if (this.typingUsers.length === 0) return '';
      const names = this.typingUsers.map(u => u.display_name || u.username);
      if (names.length === 1) return `${names[0]} is typing...`;
      if (names.length === 2) return `${names[0]} and ${names[1]} are typing...`;
      return `${names.length} people are typing...`;
    },

    formatChatTime(dateStr) {
      if (!dateStr) return '';
      const d = new Date(dateStr + (dateStr.includes('Z') ? '' : 'Z'));
      return d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
    },

    // ── Mentions ─────────────────────────────────────────────────────────────
    formatMessageWithMentions(text) {
      if (!text) return '';
      const escaped = text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;');
      return escaped.replace(/@(all|[\w_-]+)/g, (match, name) => {
        const isMine = name === 'all' || name === this.username;
        return `<span class="mention${isMine ? ' mention-me' : ''}">${match}</span>`;
      });
    },

    getMentionOptions() {
      if (!this.activePlan) return [];
      const q = this.mentionQuery.toLowerCase();
      const options = [];
      if ('all'.startsWith(q)) options.push({ id: 'all', username: 'all', isAll: true });
      for (const m of this.activePlan.members) {
        if (m.id !== this.userId && (m.username.toLowerCase().startsWith(q) || (m.display_name && m.display_name.toLowerCase().startsWith(q)))) {
          options.push(m);
        }
      }
      return options;
    },

    onChatInput() {
      const input = this.$refs.chatInputField;
      if (!input) return;
      const cursorPos = input.selectionStart;
      const textBefore = this.chatInput.slice(0, cursorPos);
      const lastAtPos = textBefore.lastIndexOf('@');
      if (lastAtPos === -1 || (lastAtPos > 0 && /\S/.test(textBefore[lastAtPos - 1]))) {
        this.mentionDropdownVisible = false;
        return;
      }
      const afterAt = textBefore.slice(lastAtPos + 1);
      if (/\s/.test(afterAt)) {
        this.mentionDropdownVisible = false;
        return;
      }
      this.mentionStartPos = lastAtPos;
      this.mentionQuery = afterAt;
      const options = this.getMentionOptions();
      if (options.length > 0) {
        this.mentionDropdownVisible = true;
        this.mentionSelectedIndex = 0;
      } else {
        this.mentionDropdownVisible = false;
      }
    },

    selectMention(index) {
      const options = this.getMentionOptions();
      if (index < 0 || index >= options.length) return;
      const selected = options[index];
      const input = this.$refs.chatInputField;
      if (input && this.mentionStartPos !== null) {
        const before = this.chatInput.slice(0, this.mentionStartPos);
        const after = this.chatInput.slice(input.selectionStart);
        this.chatInput = `${before}@${selected.username} ${after}`;
        this.$nextTick(() => {
          const newPos = this.mentionStartPos + selected.username.length + 2;
          input.focus();
          input.setSelectionRange(newPos, newPos);
        });
      }
      this.mentionDropdownVisible = false;
      this.mentionStartPos = null;
    },

    onMentionKeydown(e) {
      if (!this.mentionDropdownVisible) return;
      const options = this.getMentionOptions();
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        this.mentionSelectedIndex = Math.min(this.mentionSelectedIndex + 1, options.length - 1);
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        this.mentionSelectedIndex = Math.max(this.mentionSelectedIndex - 1, 0);
      } else if (e.key === 'Enter') {
        e.preventDefault();
        this.selectMention(this.mentionSelectedIndex);
      } else if (e.key === 'Escape') {
        e.preventDefault();
        this.mentionDropdownVisible = false;
      }
    },

    // ── Emoji Picker ─────────────────────────────────────────────────────────
    emojiCategories() {
      return {
        'Smileys': ['😀','😃','😄','😁','😆','😅','🤣','😂','🙂','😊','😇','🥰','😍','🤩','😘','😋','😛','😜','🤪','😝','🤑','🤗','🤭','🤫','🤔','😐','😑','😶','😏','😒','🙄','😬','🤥','😌','😔','😪','🤤','😴','😷','🤒','🤕','🤢','🤮','🥵','🥶','🥴','😵','🤯','🤠','🥳','🥸','😎','🤓','🧐'],
        'Gestures': ['👍','👎','👏','🙌','🤝','🙏','💪','✌️','🤞','🤟','🤘','👌','🤙','👋','🤚','✋','👐','🫶'],
        'Hearts': ['❤️','🧡','💛','💚','💙','💜','🖤','🤍','🤎','💔','💕','💞','💓','💗','💖','💝'],
        'Food': ['🍕','🍔','🍟','🌭','🍿','🥓','🥩','🍗','🍖','🌮','🌯','🥙','🍣','🍱','🍛','🍜','🍝','🍲','🥘','🍳','🥗','🍰','🎂','🍩','🍪','🍫','🧁','🍦'],
        'Drinks': ['☕','🍵','🥤','🧃','🍺','🍻','🥂','🍷','🥃','🍹','🍸','🧋'],
        'Celebration': ['🎉','🎊','🎈','🎁','🏆','🥇','🥈','🥉','⭐','🌟','✨','💫','🔥','💯','🎯'],
        'Misc': ['👀','💬','💭','✅','❌','⚠️','💡','📌','🔔','⏰','🕐','📍','🏠','🚗','😈'],
      };
    },

    toggleEmojiPicker() {
      this.emojiPickerVisible = !this.emojiPickerVisible;
      this.gifSearchVisible = false;
    },

    insertEmoji(emoji) {
      const input = this.$refs.chatInputField;
      if (input) {
        const start = input.selectionStart || this.chatInput.length;
        const end = input.selectionEnd || this.chatInput.length;
        this.chatInput = this.chatInput.slice(0, start) + emoji + this.chatInput.slice(end);
        this.$nextTick(() => {
          input.focus();
          const pos = start + emoji.length;
          input.setSelectionRange(pos, pos);
        });
      } else {
        this.chatInput += emoji;
      }
    },

    // ── GIF Search ───────────────────────────────────────────────────────────
    toggleGifSearch() {
      this.gifSearchVisible = !this.gifSearchVisible;
      this.emojiPickerVisible = false;
      if (this.gifSearchVisible && this.gifResults.length === 0) {
        this.loadTrendingGifs();
      }
    },

    async loadTrendingGifs() {
      this.gifLoading = true;
      this.gifError = '';
      try {
        const resp = await this.api('/api/giphy/trending');
        const data = await resp.json();
        if (!resp.ok) { this.gifError = data.error || 'Failed to load GIFs'; this.gifResults = []; }
        else {
          this.gifResults = (data.data || []).map(r => ({
            id: r.id,
            preview: r.images?.fixed_height_small?.url || r.images?.fixed_height?.url,
            url: r.images?.original?.url,
          }));
        }
      } catch (e) { this.gifResults = []; this.gifError = 'Failed to load GIFs'; }
      this.gifLoading = false;
    },

    async searchGifs() {
      if (!this.gifSearchQuery.trim()) { this.loadTrendingGifs(); return; }
      this.gifLoading = true;
      this.gifError = '';
      try {
        const resp = await this.api(`/api/giphy/search?q=${encodeURIComponent(this.gifSearchQuery.trim())}`);
        const data = await resp.json();
        if (!resp.ok) { this.gifError = data.error || 'Search failed'; this.gifResults = []; }
        else {
          this.gifResults = (data.data || []).map(r => ({
            id: r.id,
            preview: r.images?.fixed_height_small?.url || r.images?.fixed_height?.url,
            url: r.images?.original?.url,
          }));
        }
      } catch (e) { this.gifResults = []; this.gifError = 'Search failed'; }
      this.gifLoading = false;
    },

    async sendGif(gifUrl) {
      if (!this.activePlan || !gifUrl) return;
      try {
        await this.api(`/api/plans/${this.activePlan.plan.id}/messages`, {
          method: 'POST',
          body: JSON.stringify({ message: gifUrl, message_type: 'gif' }),
        });
        this.gifSearchVisible = false;
        this.gifSearchQuery = '';
      } catch (e) {
        this.showToast('Failed to send GIF', 'error');
      }
    },

    // ── Reactions ────────────────────────────────────────────────────────────
    openReactionPicker(messageId) {
      this.reactionPickerMessageId = this.reactionPickerMessageId === messageId ? null : messageId;
    },

    async toggleReaction(messageId, emoji) {
      if (!this.activePlan) return;
      const msg = this.chatMessages.find(m => m.id === messageId);
      if (!msg) return;
      const existing = (msg.reactions || []).find(r => r.emoji === emoji && r.user_id === this.userId);
      try {
        if (existing) {
          await this.api(`/api/plans/${this.activePlan.plan.id}/messages/${messageId}/react`, {
            method: 'DELETE',
            body: JSON.stringify({ emoji }),
          });
        } else {
          await this.api(`/api/plans/${this.activePlan.plan.id}/messages/${messageId}/react`, {
            method: 'POST',
            body: JSON.stringify({ emoji }),
          });
        }
      } catch (e) {
        this.showToast('Failed to react', 'error');
      }
      this.reactionPickerMessageId = null;
    },

    groupedReactions(reactions) {
      if (!reactions || reactions.length === 0) return [];
      const map = {};
      reactions.forEach(r => {
        if (!map[r.emoji]) map[r.emoji] = { emoji: r.emoji, count: 0, users: [], userReacted: false };
        map[r.emoji].count++;
        map[r.emoji].users.push(r.username);
        if (r.user_id === this.userId) map[r.emoji].userReacted = true;
      });
      return Object.values(map);
    },

    // ── Map View ─────────────────────────────────────────────────────────────
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
      const container = document.getElementById('plan-map');
      if (!container) return;
      const suggestions = this.activePlan?.suggestions || [];
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
      const suggestions = this.activePlan?.suggestions || [];
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
          content: `<strong>${s.place}</strong>${s.restaurant_type ? `<br><small>${s.restaurant_type}</small>` : ''}<br><small>+${s.vote_count} / -${s.downvote_count || 0}</small>`,
        });
        marker.addListener('click', () => infoWindow.open(this.mapInstance, marker));
        this.mapMarkers.push(marker);
        bounds.extend(marker.getPosition());
      });
      if (withCoords.length > 1) this.mapInstance.fitBounds(bounds);
      else if (withCoords.length === 1) this.mapInstance.setCenter(withCoords[0]);
    },

    // ── Notifications ────────────────────────────────────────────────────────
    async enableNotifications() {
      if (!this.notificationsSupported) return;
      const permission = await Notification.requestPermission();
      if (permission !== 'granted') {
        this.showToast('Notification permission denied', 'error');
        return;
      }
      try {
        const resp = await this.api('/api/push/vapid-key');
        if (!resp.ok) throw new Error(`VAPID key fetch failed: ${resp.status}`);
        const { publicKey } = await resp.json();
        if (!publicKey) throw new Error('Server returned empty VAPID key');
        const reg = await navigator.serviceWorker.ready;
        // Unsubscribe any stale subscription (e.g. from old VAPID key)
        const existing = await reg.pushManager.getSubscription();
        if (existing) await existing.unsubscribe();
        const sub = await reg.pushManager.subscribe({
          userVisibleOnly: true,
          applicationServerKey: urlBase64ToUint8Array(publicKey),
        });
        const subResp = await this.api('/api/push/subscribe', {
          method: 'POST',
          body: JSON.stringify(sub.toJSON()),
        });
        if (!subResp.ok) throw new Error(`Subscribe POST failed: ${subResp.status}`);
        this.notificationsEnabled = true;
        this.showToast('Notifications enabled!');
      } catch (e) {
        console.error('enableNotifications failed:', e);
        this.showToast(`Failed to enable notifications: ${e.message}`, 'error');
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

    // ── Stats ────────────────────────────────────────────────────────────────
    async loadStats() {
      if (this.statsLoading) return;
      this.statsLoading = true;
      try {
        const resp = await this.api('/api/stats');
        this.userStats = await resp.json();
      } catch (e) { /* ignore */ }
      this.statsLoading = false;
    },

    // ── Badges ───────────────────────────────────────────────────────────────
    async loadBadges() {
      if (this.badgesLoading) return;
      this.badgesLoading = true;
      try {
        const resp = await this.api('/api/badges');
        const newBadges = await resp.json();
        // Check for newly earned badges
        const prevEarned = JSON.parse(localStorage.getItem('earnedBadges') || '[]');
        const nowEarned = newBadges.filter(b => b.earned).map(b => b.id);
        const newlyEarned = nowEarned.filter(id => !prevEarned.includes(id));
        if (newlyEarned.length > 0) {
          const badge = newBadges.find(b => b.id === newlyEarned[0]);
          if (badge) this.showToast(`Badge unlocked: ${badge.icon} ${badge.name}!`, 'success');
          localStorage.setItem('earnedBadges', JSON.stringify(nowEarned));
        }
        this.badges = newBadges;
      } catch (e) { /* ignore */ }
      this.badgesLoading = false;
    },
    get earnedBadges() {
      return this.badges.filter(b => b.earned);
    },
    get unearnedBadges() {
      return this.badges.filter(b => !b.earned);
    },

    // ── Leaderboard ──────────────────────────────────────────────────────────
    async loadLeaderboard() {
      try {
        const resp = await this.api('/api/friends/leaderboard');
        const data = await resp.json();
        this.leaderboard = this.sortLeaderboard(data);
      } catch (e) { this.leaderboard = []; }
    },

    sortLeaderboard(data) {
      const key = this.leaderboardMetric;
      return [...data].sort((a, b) => (b[key] || 0) - (a[key] || 0));
    },

    switchLeaderboardMetric(metric) {
      this.leaderboardMetric = metric;
      this.leaderboard = this.sortLeaderboard(this.leaderboard);
    },

    // ── Activity Feed ────────────────────────────────────────────────────────
    async loadActivityFeed() {
      try {
        const resp = await this.api('/api/activity');
        this.activityFeed = await resp.json();
      } catch (e) { this.activityFeed = []; }
      this.activityFeedLoaded = true;
    },

    activityText(item) {
      const name = item.display_name || item.username;
      if (item.type === 'like') return `${name} liked ${item.place}`;
      if (item.type === 'plan_created') return `${name} created "${item.name}"`;
      if (item.type === 'plan_closed') return `${name}'s plan "${item.name}" picked ${item.winner_place || 'a winner'}`;
      return `${name} did something`;
    },

    activityTime(item) {
      const d = new Date((item.picked_at || item.created_at) + (item.created_at?.includes('Z') ? '' : 'Z'));
      const now = new Date();
      const diff = now - d;
      if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
      if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
      return `${Math.floor(diff / 86400000)}d ago`;
    },

    // ── Account ──────────────────────────────────────────────────────────────
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

    exportCalendar(planId) {
      window.open(`/api/plans/${planId}/calendar`, '_blank');
    },

    async exportData() {
      try {
        const resp = await fetch('/api/account/export', { credentials: 'same-origin' });
        if (!resp.ok) throw new Error('Export failed');
        const blob = await resp.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `dinner-roulette-export-${Date.now()}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        this.showToast('Data exported successfully');
      } catch (e) { this.showToast('Failed to export data', 'error'); }
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

    // ── Onboarding ───────────────────────────────────────────────────────────
    startOnboarding() {
      if (localStorage.getItem('onboarding-done')) return;
      this.onboarding = { active: true, step: 0 };
      const step = this.onboardingSteps[0];
      if (step.tab) this.switchTab(step.tab);
    },

    nextOnboardingStep() {
      const next = this.onboarding.step + 1;
      if (next >= this.onboardingSteps.length) {
        this.finishOnboarding();
        return;
      }
      this.onboarding.step = next;
      const step = this.onboardingSteps[next];
      if (step.tab) this.switchTab(step.tab);
    },

    skipOnboarding() {
      this.finishOnboarding();
    },

    finishOnboarding() {
      this.onboarding = { active: false, step: 0 };
      localStorage.setItem('onboarding-done', 'true');
    },

    // ── Post-Login Prompts ───────────────────────────────────────────────────
    async runPostLoginPrompts() {
      await this.waitForOnboarding();
      if (!this.email) {
        await this.showEmailPrompt();
      }
      // Sync notification state from browser before deciding whether to prompt
      if (this.notificationsSupported && Notification.permission === 'granted') {
        try {
          const reg = await navigator.serviceWorker.ready;
          const sub = await reg.pushManager.getSubscription();
          this.notificationsEnabled = !!sub;
        } catch (e) {
          this.notificationsEnabled = false;
        }
      }
      if (
        this.notificationsSupported &&
        !this.notificationsEnabled &&
        Notification.permission === 'default' &&
        localStorage.getItem('notifications-prompt-dismissed') !== 'true'
      ) {
        await this.showNotificationPrompt();
      }
    },

    waitForOnboarding() {
      return new Promise((resolve) => {
        if (!this.onboarding.active) return resolve();
        const check = setInterval(() => {
          if (!this.onboarding.active) {
            clearInterval(check);
            resolve();
          }
        }, 200);
      });
    },

    showEmailPrompt() {
      return new Promise((resolve) => {
        this.promptEmailValue = '';
        this.promptModal = {
          visible: true,
          type: 'email',
          onSubmit: async () => {
            const val = this.promptEmailValue.trim();
            if (!val) return;
            try {
              const resp = await this.api('/api/update-email', {
                method: 'POST',
                body: JSON.stringify({ email: val }),
              });
              if (resp.ok) {
                this.email = val;
                this.showToast('Email saved!');
              } else {
                const err = await resp.json();
                this.showToast(err.error || 'Invalid email', 'error');
                return;
              }
            } catch (e) {
              this.showToast('Failed to save email', 'error');
              return;
            }
            this.promptModal.visible = false;
            resolve();
          },
          onSkip: () => {
            this.promptModal.visible = false;
            resolve();
          },
        };
      });
    },

    showNotificationPrompt() {
      return new Promise((resolve) => {
        this.promptModal = {
          visible: true,
          type: 'notifications',
          onEnable: async () => {
            this.promptModal.visible = false;
            await this.enableNotifications();
            resolve();
          },
          onNotNow: () => {
            this.promptModal.visible = false;
            resolve();
          },
          onDontAskAgain: () => {
            localStorage.setItem('notifications-prompt-dismissed', 'true');
            this.promptModal.visible = false;
            resolve();
          },
        };
      });
    },

    // ── Admin ────────────────────────────────────────────────────────────────
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
        await Promise.all([this.loadAdminSettings(), this.loadAdminGoogleKey(), this.loadAdminGiphyKey()]);
      } else if (tab === 'plans') {
        await this.loadAdminPlans();
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
        } else {
          const err = await resp.json().catch(() => ({}));
          this.showToast(err.error || 'Failed to load users', 'error');
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
            body: JSON.stringify({ newPassword: this.adminResetPwValue }),
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

    adminStartEdit(user) {
      this.adminEditUser = user.id;
      this.adminEditForm = { username: user.username, email: user.email || '' };
    },

    adminCancelEdit() {
      this.adminEditUser = null;
      this.adminEditForm = { username: '', email: '' };
    },

    async adminSaveEdit(userId) {
      try {
        const resp = await this.api(`/api/admin/users/${userId}/edit`, {
          method: 'POST',
          body: JSON.stringify(this.adminEditForm),
        });
        if (!resp.ok) {
          const err = await resp.json();
          this.showToast(err.error || 'Failed to save changes', 'error');
          return;
        }
        this.showToast('User updated');
        this.adminEditUser = null;
        this.adminEditForm = { username: '', email: '' };
        await this.loadAdminUsers();
      } catch (e) {
        this.showToast('Failed to save changes', 'error');
      }
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

    async adminRepullPlaces() {
      if (!await this.showConfirm('Re-fetch all place data from Google? This updates names, photos, addresses, and types for every saved place.')) return;
      this.adminRepulling = true;
      try {
        const resp = await this.api('/api/admin/repull-places', { method: 'POST' });
        const data = await resp.json();
        if (!resp.ok) {
          this.showToast(data.error || 'Repull failed', 'error');
          return;
        }
        this.showToast(`Updated ${data.updated}/${data.total} places (${data.failed} failed)`);
      } catch (e) {
        this.showToast('Failed to repull places', 'error');
      } finally {
        this.adminRepulling = false;
      }
    },

    async loadAdminGiphyKey() {
      try {
        const resp = await this.api('/api/admin/giphy-api-key');
        if (resp.ok) {
          const data = await resp.json();
          this.adminGiphyKey = data.key || '';
        }
      } catch (e) {
        this.showToast('Failed to load Giphy API key', 'error');
      }
    },

    async saveAdminGiphyKey() {
      try {
        const resp = await this.api('/api/admin/giphy-api-key', {
          method: 'POST',
          body: JSON.stringify({ key: this.adminGiphyKey }),
        });
        if (!resp.ok) {
          const err = await resp.json();
          this.showToast(err.error || 'Failed to save Giphy API key', 'error');
          return;
        }
        this.showToast('Giphy API key saved');
        await this.loadAdminGiphyKey();
      } catch (e) {
        this.showToast('Failed to save Giphy API key', 'error');
      }
    },

    async loadAdminPlans() {
      try {
        const resp = await this.api('/api/admin/plans');
        if (resp.ok) {
          const data = await resp.json();
          this.adminPlans = data.plans;
        }
      } catch (e) {
        this.showToast('Failed to load plans', 'error');
      }
    },

    async adminClosePlan(planId) {
      if (!confirm('Close this plan?')) return;
      try {
        const resp = await this.api(`/api/admin/plans/${planId}/close`, { method: 'POST' });
        if (!resp.ok) {
          const err = await resp.json();
          this.showToast(err.error || 'Failed to close plan', 'error');
          return;
        }
        this.showToast('Plan closed');
        await this.loadAdminPlans();
      } catch (e) {
        this.showToast('Failed to close plan', 'error');
      }
    },

    async adminDeletePlan(planId) {
      if (!confirm('Permanently delete this plan and all its data?')) return;
      try {
        const resp = await this.api(`/api/admin/plans/${planId}`, { method: 'DELETE' });
        if (!resp.ok) {
          const err = await resp.json();
          this.showToast(err.error || 'Failed to delete plan', 'error');
          return;
        }
        this.showToast('Plan deleted');
        await this.loadAdminPlans();
      } catch (e) {
        this.showToast('Failed to delete plan', 'error');
      }
    },

    async adminBackup() {
      this.adminBackingUp = true;
      try {
        const resp = await this.api('/api/admin/backup', { method: 'POST' });
        if (!resp.ok) { const err = await resp.json(); this.showToast(err.error || 'Backup failed', 'error'); return; }
        const data = await resp.json();
        this.showToast(`Backup created: ${data.file}`);
      } catch (e) {
        this.showToast('Backup failed', 'error');
      } finally {
        this.adminBackingUp = false;
      }
    },
  };
}
