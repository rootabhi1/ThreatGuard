/* Auth.js — token storage, fetch wrapper, role redirects, nav rendering. */
(function () {
  'use strict';

  const TOKEN_KEY = 'tm_access_token';
  const REFRESH_KEY = 'tm_refresh_token';
  const USER_KEY = 'tm_user';
  const PERMS_KEY = 'tm_perms';

  const Auth = {
    getToken() { return localStorage.getItem(TOKEN_KEY); },
    getRefreshToken() { return localStorage.getItem(REFRESH_KEY); },
    getUser() {
      const raw = localStorage.getItem(USER_KEY);
      return raw ? JSON.parse(raw) : null;
    },
    getPermissions() {
      const raw = localStorage.getItem(PERMS_KEY);
      return raw ? JSON.parse(raw) : [];
    },
    hasPermission(perm) {
      return this.getPermissions().includes(perm);
    },

    setSession(loginResponse) {
      localStorage.setItem(TOKEN_KEY, loginResponse.access_token);
      if (loginResponse.refresh_token) {
        localStorage.setItem(REFRESH_KEY, loginResponse.refresh_token);
      }
      localStorage.setItem(USER_KEY, JSON.stringify(loginResponse.user));
      if (loginResponse.permissions) {
        localStorage.setItem(PERMS_KEY, JSON.stringify(loginResponse.permissions));
      }
    },

    /* Convenience: same as setSession, used by login/register templates that
       call setToken(access, refresh, user) with positional args. */
    setToken(accessToken, refreshToken, user, permissions) {
      if (typeof accessToken === 'object' && accessToken !== null) {
        // Caller passed a full login response object
        return this.setSession(accessToken);
      }
      localStorage.setItem(TOKEN_KEY, accessToken);
      if (refreshToken) localStorage.setItem(REFRESH_KEY, refreshToken);
      if (user) localStorage.setItem(USER_KEY, JSON.stringify(user));
      if (permissions) localStorage.setItem(PERMS_KEY, JSON.stringify(permissions));
    },

    clearToken() {
      localStorage.removeItem(TOKEN_KEY);
      localStorage.removeItem(REFRESH_KEY);
      localStorage.removeItem(USER_KEY);
      localStorage.removeItem(PERMS_KEY);
    },

    async fetchMe() {
      const r = await this.fetch('/api/auth/me');
      if (!r.ok) throw new Error('Auth check failed');
      const data = await r.json();
      localStorage.setItem(USER_KEY, JSON.stringify(data.user));
      localStorage.setItem(PERMS_KEY, JSON.stringify(data.permissions));
      return data;
    },

    /* Same as fetchMe but returns null on failure instead of throwing. */
    async fetchMeOptional() {
      try { return await this.fetchMe(); } catch (e) { return null; }
    },

    /* Authenticated fetch with automatic refresh on 401. */
    async fetch(url, options = {}) {
      options.headers = options.headers || {};
      const token = this.getToken();
      if (token) {
        options.headers['Authorization'] = 'Bearer ' + token;
      }

      let r = await fetch(url, options);

      if (r.status === 401 && this.getRefreshToken()) {
        // Try refresh once
        const refreshed = await this._tryRefresh();
        if (refreshed) {
          options.headers['Authorization'] = 'Bearer ' + this.getToken();
          r = await fetch(url, options);
        } else {
          // Refresh failed — clear and bounce to login
          this.clearToken();
          if (window.location.pathname !== '/') {
            window.location.href = '/';
          }
        }
      }

      return r;
    },

    async _tryRefresh() {
      try {
        const r = await fetch('/api/auth/refresh', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ refresh_token: this.getRefreshToken() }),
        });
        if (!r.ok) return false;
        const data = await r.json();
        localStorage.setItem(TOKEN_KEY, data.access_token);
        if (data.refresh_token) {
          localStorage.setItem(REFRESH_KEY, data.refresh_token);
        }
        return true;
      } catch (e) {
        return false;
      }
    },

    async logout() {
      try {
        await this.fetch('/api/auth/logout', { method: 'POST' });
      } catch (e) { /* swallow */ }
      this.clearToken();
      window.location.href = '/';
    },

    redirectForRole(role) {
      if (role === 'admin') window.location.href = '/admin';
      else if (role === 'management') window.location.href = '/management';
      else window.location.href = '/dashboard';
    },

    /* Verifies the user has access to this page based on required role list.
       If not authenticated, redirects to /. If wrong role, redirects to their landing. */
    async requireRole(allowedRoles) {
      if (!this.getToken()) {
        window.location.href = '/';
        return null;
      }
      try {
        const me = await this.fetchMe();
        if (!allowedRoles.includes(me.user.role)) {
          this.redirectForRole(me.user.role);
          return null;
        }
        return me;
      } catch (e) {
        this.clearToken();
        window.location.href = '/';
        return null;
      }
    },

    renderNav() {
      const nav = document.getElementById('main-nav');
      if (!nav) return;
      const user = this.getUser();
      if (!user) {
        nav.innerHTML = `
          <a href="/" class="text-slate-300 hover:text-white">Sign in</a>
          <a href="/register" class="bg-brand-600 hover:bg-brand-700 text-white px-3 py-1.5 rounded text-sm">Register</a>
        `;
        return;
      }
      const links = [];
      if (user.role === 'user' || user.role === 'admin' || user.role === 'management') {
        links.push(`<a href="/dashboard" class="text-slate-300 hover:text-white">My Threat Models</a>`);
      }
      if (user.role === 'management' || user.role === 'admin') {
        links.push(`<a href="/management" class="text-slate-300 hover:text-white">Management</a>`);
      }
      if (user.role === 'admin') {
        links.push(`<a href="/admin" class="text-slate-300 hover:text-white">Admin</a>`);
      }
      links.push(`
        <span class="text-slate-500">|</span>
        <span class="text-sm text-slate-300">${escapeHtml(user.full_name || user.email)}</span>
        <span class="role-badge role-${user.role}">${user.role}</span>
        <button onclick="Auth.logout()" class="text-slate-300 hover:text-white text-sm">Sign out</button>
      `);
      nav.innerHTML = links.join(' ');
    },
  };

  function escapeHtml(s) {
    if (s == null) return '';
    return String(s).replace(/[&<>"']/g, c => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    })[c]);
  }

  window.Auth = Auth;
  window.escapeHtml = escapeHtml;

  // Auto-render the nav on every page that includes this script
  document.addEventListener('DOMContentLoaded', () => Auth.renderNav());
})();
