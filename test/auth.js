/* ════════════════════════════════════════════════════════════════════
   Studio Hub — shared login (auth.js)
   Loaded by every page. One place for: signing in, staying signed in,
   knowing who the user is (name + role come from the database, never
   from the page address), and attaching the user's own login token to
   every call the pages make to Supabase.
   ════════════════════════════════════════════════════════════════════ */
(function(){
  'use strict';

  var SUPABASE_URL = 'https://pgsgjafgetdvuctmpibf.supabase.co';
  var ANON_KEY     = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InBnc2dqYWZnZXRkdnVjdG1waWJmIiwicm9sZSI6ImFub24iLCJpYXQiOjE3Nzg1MjQ0MjMsImV4cCI6MjA5NDEwMDQyM30.-IhrtiBgzpnYol4XuesDzYJ0XBLDYDrMzmTx0XsAsmc';          // public key: safe to be in the page
  var SESSION_KEY  = 'cbre_auth_session';     // tokens + cached profile (this browser only)
  var LOGIN_PAGE   = 'index.html';

  var origFetch = window.fetch.bind(window);

  // ── tiny helpers ────────────────────────────────────────────────
  function nowSec(){ return Math.floor(Date.now() / 1000); }

  // Where the saved login lives. Normally the browser's localStorage (shared by all tabs).
  // Several pages also cache whole projects in localStorage (about 5 MB in total), so it
  // can fill up and refuse the write. That must never fail silently, so we fall back to
  // this tab's own storage, then to memory, and report which one we ended up with.
  var memSession = null;
  var storageMode = 'local';          // 'local' | 'tab' | 'memory'

  function validSession(s){ return !!(s && s.access_token && s.refresh_token && s.user && s.user.id); }
  function readFrom(store){
    try { var s = JSON.parse(store.getItem(SESSION_KEY) || 'null'); return validSession(s) ? s : null; }
    catch(e){ return null; }
  }
  function tryWrite(store, json){
    try { store.setItem(SESSION_KEY, json); return store.getItem(SESSION_KEY) === json; }
    catch(e){ return false; }
  }
  function load(){
    return readFrom(window.localStorage) || readFrom(window.sessionStorage) || (validSession(memSession) ? memSession : null);
  }
  function save(s){
    memSession = s;
    var json = JSON.stringify(s);
    if (tryWrite(window.localStorage, json)){
      try { window.sessionStorage.removeItem(SESSION_KEY); } catch(e){}
      storageMode = 'local'; return storageMode;
    }
    // Refused (usually "storage full"). Our own old copy may be what is in the way: drop it and retry once.
    try { window.localStorage.removeItem(SESSION_KEY); } catch(e){}
    if (tryWrite(window.localStorage, json)){ storageMode = 'local'; return storageMode; }
    if (tryWrite(window.sessionStorage, json)){ storageMode = 'tab'; return storageMode; }
    storageMode = 'memory'; return storageMode;
  }
  function clear(){
    memSession = null;
    try { window.localStorage.removeItem(SESSION_KEY); } catch(e){}
    try { window.sessionStorage.removeItem(SESSION_KEY); } catch(e){}
  }

  function parseJson(res){
    return res.json().then(function(d){ return { ok: res.ok, status: res.status, d: d || {} }; },
                           function(){ return { ok: res.ok, status: res.status, d: {} }; });
  }
  function errMsg(x, fallback){
    var d = x.d || {};
    return d.error_description || d.msg || d.message || d.error || fallback;
  }

  function sessionFromToken(d, prev){
    return {
      access_token:  d.access_token,
      refresh_token: d.refresh_token,
      expires_at:    d.expires_at || (nowSec() + (d.expires_in || 3600)),
      user:          d.user || (prev && prev.user) || null,
      profile:       prev ? prev.profile : null
    };
  }

  // ── token: valid now? / refresh it ──────────────────────────────
  function tokenSync(){
    var s = load();
    return (s && (s.expires_at - nowSec()) > 15) ? s.access_token : null;
  }

  var refreshing = null;
  function refresh(){
    if (refreshing) return refreshing;
    var run = function(){
      var s = load();
      if (!s) return Promise.reject(new Error('Your session has ended. Please reload the page and sign in again.'));
      // Another tab may already have refreshed while we waited for the lock.
      if ((s.expires_at - nowSec()) > 60) return Promise.resolve(s);
      return origFetch(SUPABASE_URL + '/auth/v1/token?grant_type=refresh_token', {
        method: 'POST',
        headers: { 'apikey': ANON_KEY, 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token: s.refresh_token })
      }).then(parseJson).then(function(x){
        if (!x.ok || !x.d.access_token){
          // Only a definite "no" from the server ends the session.
          if (x.status === 400 || x.status === 401 || x.status === 403) clear();
          throw new Error('Session refresh failed');
        }
        var n = sessionFromToken(x.d, s);
        save(n);
        return n;
      });
    };
    var p = (navigator.locks && navigator.locks.request)
      ? navigator.locks.request('cbre_auth_refresh', run)
      : run();
    refreshing = p.then(function(r){ refreshing = null; return r; },
                        function(e){ refreshing = null; throw e; });
    return refreshing;
  }

  function getToken(){
    var t = tokenSync();
    if (t) return Promise.resolve(t);
    return refresh().then(function(s){ return s.access_token; });
  }

  // ── fetch wrapper: swap the public key for the user's own token ──
  // Existing page code keeps sending "Authorization: Bearer <public key>".
  // This replaces that one header with the signed-in user's token, so no
  // page call can be missed and no page code has to be rewritten.
  function headersToObject(h){
    var o = {};
    if (!h) return o;
    if (typeof Headers !== 'undefined' && h instanceof Headers){ h.forEach(function(v, k){ o[k] = v; }); }
    else if (Array.isArray(h)){ h.forEach(function(p){ o[p[0]] = p[1]; }); }
    else { for (var k in h){ if (Object.prototype.hasOwnProperty.call(h, k)) o[k] = h[k]; } }
    return o;
  }
  function findKey(o, lower){
    for (var k in o){ if (k.toLowerCase() === lower) return k; }
    return null;
  }
  function withToken(init, o, key, token){
    var copy = {};
    for (var p in init){ if (Object.prototype.hasOwnProperty.call(init, p)) copy[p] = init[p]; }
    var h = {};
    for (var k in o){ h[k] = o[k]; }
    h[key] = 'Bearer ' + token;
    copy.headers = h;
    return copy;
  }

  window.fetch = function(input, init){
    if (typeof input !== 'string' || input.indexOf(SUPABASE_URL) !== 0 ||
        input.indexOf(SUPABASE_URL + '/auth/v1') === 0){
      return origFetch(input, init);
    }
    var o   = headersToObject(init && init.headers);
    var key = findKey(o, 'authorization');
    if (key === null || o[key] !== 'Bearer ' + ANON_KEY) return origFetch(input, init);

    var tok = tokenSync();
    if (tok) return origFetch(input, withToken(init || {}, o, key, tok));   // same tick: safe in unload handlers

    return refresh().then(function(s){
      return origFetch(input, withToken(init || {}, o, key, s.access_token));
    }, function(){
      if (!load() && !isLoginPage) redirectToLogin();
      return origFetch(input, init);
    });
  };

  // ── profile (name + role live in the database) ──────────────────
  function fetchProfile(token, uid){
    return origFetch(SUPABASE_URL + '/rest/v1/profiles?id=eq.' + encodeURIComponent(uid) +
        '&select=id,name,email,role,must_change_password,password_expires_at', {
      headers: { 'apikey': ANON_KEY, 'Authorization': 'Bearer ' + token }
    }).then(function(res){
      if (!res.ok) return { status: res.status, profile: null };
      return res.json().then(function(rows){
        return { status: 200, profile: (rows && rows[0]) || null };
      });
    });
  }

  function needsChange(p){
    return !!(p && (p.must_change_password ||
      (p.password_expires_at && new Date(p.password_expires_at) <= new Date())));
  }

  function profile(){ var s = load(); return (s && s.profile) || null; }
  function isSignedIn(){ return !!load(); }

  // ── sign in / out ───────────────────────────────────────────────
  function signIn(email, password){
    return origFetch(SUPABASE_URL + '/auth/v1/token?grant_type=password', {
      method: 'POST',
      headers: { 'apikey': ANON_KEY, 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: email, password: password })
    }).then(parseJson, function(){
      throw new Error('Could not reach the server. Check your connection and try again.');
    }).then(function(x){
      if (x.status === 429) throw new Error('Too many attempts. Please wait a minute and try again.');
      if (!x.ok || !x.d.access_token) throw new Error('Incorrect email or password.');
      var s = sessionFromToken(x.d, null);
      return fetchProfile(s.access_token, s.user.id).then(function(r){
        if (!r.profile) throw new Error('Your account is not set up for the Hub yet. Please contact an administrator.');
        s.profile = r.profile;
        if (save(s) === 'memory'){
          clear();
          throw new Error("Your browser could not save your sign-in because its storage for this site is full. " +
            "Open the site in a private/incognito window, or clear this site's saved data (Chrome: Settings > Privacy and security > " +
            "Third-party cookies > See all site data, search for this site, and delete it), then sign in again.");
        }
        return r.profile;
      });
    });
  }

  function signOut(){
    var s = load();
    clear();
    if (!s) return Promise.resolve();
    return origFetch(SUPABASE_URL + '/auth/v1/logout?scope=local', {
      method: 'POST',
      headers: { 'apikey': ANON_KEY, 'Authorization': 'Bearer ' + s.access_token }
    }).then(function(){}, function(){});
  }

  // Confirms the saved session is still good and refreshes the cached profile.
  // Resolves with the profile, or null if the person must sign in again.
  function verify(){
    if (!load()) return Promise.resolve(null);
    return getToken().then(function(tok){
      var s = load();
      if (!s) return null;
      return fetchProfile(tok, s.user.id).then(function(r){
        if (r.status === 401 || r.status === 403 || (r.status === 200 && !r.profile)){ clear(); return null; }
        if (r.status !== 200) return profile();            // server hiccup: keep working with what we have
        var cur = load();
        if (!cur) return null;
        cur.profile = r.profile;
        save(cur);
        return r.profile;
      });
    }).catch(function(){
      return load() ? profile() : null;                    // offline: keep working; the server still enforces access
    });
  }

  function changePassword(newPassword){
    return getToken().then(function(tok){
      return origFetch(SUPABASE_URL + '/auth/v1/user', {
        method: 'PUT',
        headers: { 'apikey': ANON_KEY, 'Authorization': 'Bearer ' + tok, 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: newPassword })
      }).then(parseJson).then(function(x){
        if (!x.ok) throw new Error(errMsg(x, 'Could not save password — please try again.'));
        return origFetch(SUPABASE_URL + '/rest/v1/rpc/complete_password_change', {
          method: 'POST',
          headers: { 'apikey': ANON_KEY, 'Authorization': 'Bearer ' + tok, 'Content-Type': 'application/json' },
          body: '{}'
        });
      }).then(function(res){
        if (!res.ok) throw new Error('Password saved, but the reminder could not be cleared. Please sign in again.');
        return verify();
      });
    });
  }

  // Admin-only user management (runs on the server, which re-checks the caller is an admin).
  function adminUsers(action, data){
    var body = { action: action };
    for (var k in (data || {})){ body[k] = data[k]; }
    return getToken().then(function(tok){
      return origFetch(SUPABASE_URL + '/functions/v1/admin-users', {
        method: 'POST',
        headers: { 'apikey': ANON_KEY, 'Authorization': 'Bearer ' + tok, 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });
    }).then(parseJson).then(function(x){
      if (!x.ok || x.d.error) throw new Error(x.d.error || ('Request failed (status ' + x.status + ')'));
      return x.d;
    });
  }

  // ── guarding pages ──────────────────────────────────────────────
  var scriptEl = document.currentScript;
  var isLoginPage = !!(scriptEl && scriptEl.getAttribute('data-page') === 'login');

  function currentRel(){
    var file = location.pathname.split('/').pop() || 'index.html';
    return file + location.search;
  }
  function redirectToLogin(){
    try { document.documentElement.style.visibility = 'hidden'; } catch(e){}
    location.replace(LOGIN_PAGE + '?next=' + encodeURIComponent(currentRel()));
  }
  // Only a plain page name in this same folder is accepted (no other sites).
  function safeNext(){
    var n = null;
    try { n = new URLSearchParams(location.search).get('next'); } catch(e){}
    return (n && /^[A-Za-z0-9_\-]+\.html(\?[^#]*)?$/.test(n)) ? n : null;
  }

  function requireLogin(){
    if (!load()){ redirectToLogin(); return false; }
    verify().then(function(p){
      if (!p || needsChange(p)) redirectToLogin();   // index.html shows the "set your password" screen
    });
    return true;
  }

  // Keep tokens fresh while a page stays open (long editing sessions).
  setInterval(function(){
    var s = load();
    if (s && (s.expires_at - nowSec()) < 300) refresh().catch(function(){});
  }, 60000);

  // Signed out in another tab? This one follows.
  window.addEventListener('storage', function(e){
    if (e.key === SESSION_KEY && !e.newValue){
      if (isLoginPage) location.reload(); else redirectToLogin();
    }
  });

  window.Auth = {
    signIn: signIn, signOut: signOut, verify: verify, changePassword: changePassword,
    adminUsers: adminUsers, profile: profile, isSignedIn: isSignedIn, needsChange: needsChange,
    tokenSync: tokenSync, getToken: getToken, safeNext: safeNext, storageMode: function(){ return storageMode; },
    redirectToLogin: redirectToLogin, require: requireLogin
  };

  // Every page except the login page requires a signed-in user.
  if (!isLoginPage) requireLogin();
})();
