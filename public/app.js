document.addEventListener('DOMContentLoaded', () => {
  const authSection    = document.getElementById('auth');
  const pmSection      = document.getElementById('place-management');
  const planSection    = document.getElementById('plan-dinner');
  const logoutBtn      = document.getElementById('btn-logout');

  const btnRegister    = document.getElementById('btn-register');
  const btnLogin       = document.getElementById('btn-login');

  const userInput      = document.getElementById('username');
  const passInput      = document.getElementById('password');
  const authErrorMsg   = document.getElementById('auth-error');

  const input          = document.getElementById('place-input');
  const listEl         = document.getElementById('autocomplete-list');
  const addLikeBtn     = document.getElementById('add-like');
  const addDislikeBtn  = document.getElementById('add-dislike');
  const likesList      = document.getElementById('likes-list');
  const dislikesList   = document.getElementById('dislikes-list');
  const mapLink        = document.getElementById('map-link');

  const friendInput    = document.getElementById('friend-username');
  const inviteBtn      = document.getElementById('invite-friend');
  const commonList     = document.getElementById('common-places');

  let selectedPlace    = null;

  function setAuthMessage(msg) {
    authErrorMsg.textContent = msg || '';
  }

  function authFetch(url, opts = {}) {
    opts.headers = opts.headers || {};
    opts.headers['Content-Type'] = 'application/json';
    const token = localStorage.getItem('token');
    if (!token) {
      logoutAndReset();
      throw new Error('No token found');
    }
    opts.headers['Authorization'] = 'Bearer ' + token;
    return fetch(url, opts).then(async resp => {
      if (resp.status === 401) {
        logoutAndReset();
        throw new Error('Unauthorized');
      }
      return resp;
    });
  }

  btnRegister.onclick = async () => {
    setAuthMessage('');
    try {
      const resp = await fetch('/api/register', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({
          username: userInput.value,
          password: passInput.value
        })
      });

      if (!resp.ok) {
        const err = await resp.json();
        setAuthMessage(err.error || 'Registration failed.');
        return;
      }

      const { token } = await resp.json();
      onAuthSuccess(token);
    } catch (err) {
      console.error('Registration error:', err);
      setAuthMessage('Unexpected error during registration.');
    }
  };

  btnLogin.onclick = async () => {
    setAuthMessage('');
    try {
      const resp = await fetch('/api/login', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({
          username: userInput.value,
          password: passInput.value
        })
      });

      if (!resp.ok) {
        const err = await resp.json();
        setAuthMessage(err.error || 'Login failed.');
        return;
      }

      const { token } = await resp.json();
      onAuthSuccess(token);
    } catch (err) {
      console.error('Login error:', err);
      setAuthMessage('Unexpected error during login.');
    }
  };

  logoutBtn.onclick = logoutAndReset;

  function logoutAndReset() {
    localStorage.removeItem('token');
    authSection.classList.remove('hidden');
    pmSection.classList.add('hidden');
    planSection.classList.add('hidden');
    logoutBtn.classList.add('hidden');
  }

  function onAuthSuccess(token) {
    localStorage.setItem('token', token);
    authSection.classList.add('hidden');
    pmSection.classList.remove('hidden');
    planSection.classList.remove('hidden');
    logoutBtn.classList.remove('hidden');
    initApp();
  }

  function initApp() {
    input.addEventListener('input', async () => {
      const q = input.value.trim();
      if (!q) {
        listEl.classList.add('hidden');
        return;
      }

      try {
        const resp = await authFetch(`/api/autocomplete?input=${encodeURIComponent(q)}`);
        const data = await resp.json();

        if (!data.predictions || !Array.isArray(data.predictions)) {
          listEl.classList.add('hidden');
          return;
        }

        listEl.innerHTML = '';
        data.predictions.forEach(pred => {
          const li = document.createElement('li');
          li.textContent = pred.description;
          li.onclick = () => selectPlace(pred.description);
          listEl.append(li);
        });
        listEl.classList.remove('hidden');
      } catch (err) {
        console.error('Autocomplete error:', err);
        listEl.classList.add('hidden');
      }
    });

    inviteBtn.onclick = async () => {
      try {
        await authFetch('/api/invite', {
          method: 'POST',
          body: JSON.stringify({ friendUsername: friendInput.value })
        });
        loadCommonPlaces();
      } catch (err) {
        console.error('Failed to invite friend:', err);
      }
    };

    function selectPlace(name) {
      input.value = name;
      selectedPlace = name;
      listEl.classList.add('hidden');
      addLikeBtn.disabled = false;
      addDislikeBtn.disabled = false;

      authFetch('/api/place', {
        method: 'POST',
        body: JSON.stringify({ place: name })
      });

      const anchor = mapLink.querySelector('a');
      anchor.href = `https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(name)}`;
      mapLink.classList.remove('hidden');
    }

    function resetSelection() {
      input.value = '';
      selectedPlace = null;
      addLikeBtn.disabled = true;
      addDislikeBtn.disabled = true;
      mapLink.classList.add('hidden');
    }

    function createPlaceItem(place, type, reloadCallback) {
      const li = document.createElement('li');
      li.textContent = place;

      const mapAnchor = document.createElement('a');
      mapAnchor.href = `https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(place)}`;
      mapAnchor.target = '_blank';
      mapAnchor.textContent = ' [View on Map]';
      mapAnchor.style.marginLeft = '0.5rem';
      mapAnchor.style.fontSize = '0.85rem';

      const btn = document.createElement('button');
      btn.textContent = 'Remove';
      btn.className = 'remove-btn';
      btn.onclick = async () => {
        await authFetch('/api/places', {
          method: 'POST',
          body: JSON.stringify({ type, place, remove: true })
        });
        reloadCallback();
      };

      li.append(mapAnchor, btn);
      return li;
    }

    async function loadPlaces() {
      try {
        const resp = await authFetch('/api/places');
        const { likes = [], dislikes = [] } = await resp.json();

        likesList.innerHTML = '';
        likes.forEach(place => likesList.append(createPlaceItem(place, 'likes', loadPlaces)));

        dislikesList.innerHTML = '';
        dislikes.forEach(place => dislikesList.append(createPlaceItem(place, 'dislikes', loadPlaces)));
      } catch (err) {
        console.error('Failed to load places:', err);
      }
    }

    addLikeBtn.onclick = async () => {
      await authFetch('/api/places', {
        method: 'POST',
        body: JSON.stringify({ type: 'likes', place: selectedPlace })
      });
      resetSelection();
      loadPlaces();
    };

    addDislikeBtn.onclick = async () => {
      await authFetch('/api/places', {
        method: 'POST',
        body: JSON.stringify({ type: 'dislikes', place: selectedPlace })
      });
      resetSelection();
      loadPlaces();
    };

    async function loadCommonPlaces() {
      const resp = await authFetch(`/api/common-places?friendUsername=${encodeURIComponent(friendInput.value)}`);
      const { common } = await resp.json();
      commonList.innerHTML = '';
      common.forEach(place => {
        const li = document.createElement('li');
        li.textContent = place;

        const mapAnchor = document.createElement('a');
        mapAnchor.href = `https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(place)}`;
        mapAnchor.target = '_blank';
        mapAnchor.textContent = ' [View on Map]';
        mapAnchor.style.marginLeft = '0.5rem';
        mapAnchor.style.fontSize = '0.85rem';

        li.append(mapAnchor);
        commonList.append(li);
      });
    }

    loadPlaces();
  }

  // Initialize state based on token
  const token = localStorage.getItem('token');
  if (token) {
    onAuthSuccess(token);
  } else {
    logoutAndReset();
  }
});
