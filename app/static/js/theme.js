/**
 * CipherBallot — theme.js
 * Dark / light mode toggle with localStorage persistence.
 *
 * IMPORTANT: Ballot data or vote choices are NEVER stored in localStorage.
 * Only the UI theme preference ('light' | 'dark') is persisted here.
 *
 * Usage:
 *   - Load this script in <head> (before CSS) to prevent flash of wrong theme.
 *   - Call CipherBallotTheme.toggle() from a button click handler.
 */

'use strict';

(function () {
  const STORAGE_KEY = 'cb_theme';    // 'cb_' prefix namespaces the key
  const DARK        = 'dark';
  const LIGHT       = 'light';

  /**
   * Read the saved theme from localStorage.
   * Falls back to the OS preference, then to 'light'.
   *
   * @returns {'dark'|'light'}
   */
  function getSavedTheme() {
    try {
      const saved = localStorage.getItem(STORAGE_KEY);
      if (saved === DARK || saved === LIGHT) return saved;
    } catch (_) {
      // localStorage may be blocked in some privacy contexts
    }
    // Respect OS preference
    if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
      return DARK;
    }
    return LIGHT;
  }

  /**
   * Apply a theme to the document root and body.
   *
   * @param {'dark'|'light'} theme
   */
  function applyTheme(theme) {
    const isDark = theme === DARK;
    document.documentElement.setAttribute('data-theme', theme);
    if (document.body) {
      document.body.setAttribute('data-theme', theme);
    }
    if (isDark) {
      document.documentElement.classList.add('dark');
      if (document.body) document.body.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
      if (document.body) document.body.classList.remove('dark');
    }
    // Update any toggle buttons
    updateToggleButtons(theme);
    // Update meta theme-color for mobile browsers
    updateMetaThemeColor(theme);

    // Dispatch event so all components react immediately
    try {
      window.dispatchEvent(new CustomEvent('cipherballot:themechange', { detail: { theme } }));
    } catch (_) {}
  }

  /**
   * Save the theme to localStorage (never stores sensitive data).
   *
   * @param {'dark'|'light'} theme
   */
  function saveTheme(theme) {
    try {
      localStorage.setItem(STORAGE_KEY, theme);
    } catch (_) {
      // Silently ignore localStorage errors (private browsing, quota, etc.)
    }
  }

  /**
   * Toggle between dark and light mode.
   *
   * @returns {'dark'|'light'} The newly active theme.
   */
  function toggleTheme() {
    const current = document.documentElement.getAttribute('data-theme') || LIGHT;
    const next    = current === DARK ? LIGHT : DARK;
    applyTheme(next);
    saveTheme(next);
    return next;
  }

  /**
   * Update all theme toggle buttons with the correct icon and aria-label.
   *
   * @param {'dark'|'light'} theme
   */
  function updateToggleButtons(theme) {
    document.querySelectorAll('[data-theme-toggle]').forEach((btn) => {
      // Do not overwrite custom sidebar switch buttons or inject text into them
      if (btn.id === 'sidebar-theme-toggle' || btn.classList.contains('sidebar-theme-switch-btn')) {
        const isDark = theme === DARK;
        btn.setAttribute('aria-label', isDark ? 'Switch to light mode' : 'Switch to dark mode');
        btn.setAttribute('title', isDark ? 'Switch to Light Theme' : 'Switch to Dark Theme');
        btn.setAttribute('aria-checked', isDark ? 'true' : 'false');
        return;
      }

      const isDark = theme === DARK;
      btn.setAttribute('aria-label', isDark ? 'Switch to light mode' : 'Switch to dark mode');
      btn.setAttribute('title',      isDark ? 'Switch to light mode' : 'Switch to dark mode');

      // Update icon if present
      const iconEl = btn.querySelector('[data-theme-icon]');
      if (iconEl) {
        iconEl.innerHTML = isDark ? sunIcon() : moonIcon();
      } else {
        // The button itself is the icon container
        btn.innerHTML = isDark ? sunIcon() : moonIcon();
      }
    });
  }

  function updateMetaThemeColor(theme) {
    let meta = document.querySelector('meta[name="theme-color"]');
    if (!meta) {
      meta = document.createElement('meta');
      meta.name = 'theme-color';
      document.head.appendChild(meta);
    }
    meta.content = theme === DARK ? '#0F172A' : '#4F46E5';
  }

  function moonIcon() {
    return `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="none"
      viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" aria-hidden="true">
      <path stroke-linecap="round" stroke-linejoin="round"
        d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/>
    </svg>`;
  }

  function sunIcon() {
    return `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="none"
      viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" aria-hidden="true">
      <circle cx="12" cy="12" r="5" stroke-linecap="round" stroke-linejoin="round"/>
      <path stroke-linecap="round" stroke-linejoin="round"
        d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42
           M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/>
    </svg>`;
  }

  // -------------------------------------------------------------------------
  // Apply saved theme immediately (before paint — prevents FOUC)
  // -------------------------------------------------------------------------
  const initialTheme = getSavedTheme();
  applyTheme(initialTheme);

  // -------------------------------------------------------------------------
  // Wire up toggle buttons after DOM is ready
  // -------------------------------------------------------------------------
  document.addEventListener('DOMContentLoaded', () => {
    // Buttons with data-theme-toggle attribute
    document.querySelectorAll('[data-theme-toggle]').forEach((btn) => {
      btn.addEventListener('click', () => toggleTheme());
    });

    // Sync button state with current theme
    updateToggleButtons(
      document.documentElement.getAttribute('data-theme') || LIGHT
    );

    // Listen for OS preference changes (e.g., system dark-mode toggle)
    if (window.matchMedia) {
      window.matchMedia('(prefers-color-scheme: dark)').addEventListener(
        'change',
        (e) => {
          // Only follow OS if the user hasn't explicitly set a preference
          try {
            if (!localStorage.getItem(STORAGE_KEY)) {
              applyTheme(e.matches ? DARK : LIGHT);
            }
          } catch (_) {
            applyTheme(e.matches ? DARK : LIGHT);
          }
        }
      );
    }
  });

  // -------------------------------------------------------------------------
  // Expose public API on window
  // -------------------------------------------------------------------------
  window.CipherBallotTheme = {
    toggle:     toggleTheme,
    getTheme:   () => document.documentElement.getAttribute('data-theme') || LIGHT,
    setTheme:   (t) => { applyTheme(t); saveTheme(t); },
    DARK,
    LIGHT,
  };
})();
