/**
 * CipherBallot — Sidebar Controller (sidebar.js)
 * Manages mobile drawer, instant Dark/Light theme switch sync, and interactive states.
 */

'use strict';

(function () {
  /**
   * Mobile Drawer Controls
   */
  function initMobileDrawer() {
    const sidebar = document.getElementById('sidebar');
    const toggleBtn = document.getElementById('sidebar-toggle');
    if (!sidebar || !toggleBtn) return;

    let backdrop = document.getElementById('sidebar-backdrop');
    if (!backdrop) {
      backdrop = document.createElement('div');
      backdrop.id = 'sidebar-backdrop';
      backdrop.className = 'sidebar-backdrop';
      backdrop.setAttribute('aria-hidden', 'true');
      document.body.appendChild(backdrop);
    }

    function openMobileSidebar() {
      sidebar.classList.add('open');
      backdrop.classList.add('show');
      toggleBtn.setAttribute('aria-expanded', 'true');
      document.body.style.overflow = 'hidden';
    }

    function closeMobileSidebar() {
      sidebar.classList.remove('open');
      backdrop.classList.remove('show');
      toggleBtn.setAttribute('aria-expanded', 'false');
      document.body.style.overflow = '';
    }

    toggleBtn.addEventListener('click', (e) => {
      e.preventDefault();
      if (sidebar.classList.contains('open')) {
        closeMobileSidebar();
      } else {
        openMobileSidebar();
      }
    });

    backdrop.addEventListener('click', closeMobileSidebar);

    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && sidebar.classList.contains('open')) {
        closeMobileSidebar();
      }
    });

    sidebar.querySelectorAll('.sidebar-nav-link').forEach((link) => {
      link.addEventListener('click', () => {
        if (window.innerWidth <= 768) {
          closeMobileSidebar();
        }
      });
    });
  }

  /**
   * Dark / Light Theme Toggle Synchronizer
   */
  function initThemeToggle() {
    const themeBtn = document.getElementById('sidebar-theme-toggle');
    const thumbIcon = document.getElementById('theme-thumb-icon');
    if (!themeBtn) return;

    function syncThemeUI(theme) {
      const isDark = theme === 'dark';
      themeBtn.setAttribute('aria-checked', isDark ? 'true' : 'false');
      themeBtn.setAttribute(
        'title',
        isDark ? 'Switch to Light Theme' : 'Switch to Dark Theme'
      );
      themeBtn.setAttribute(
        'aria-label',
        isDark ? 'Switch to light mode' : 'Switch to dark mode'
      );

      if (thumbIcon) {
        thumbIcon.className = isDark ? 'bi bi-moon-stars-fill' : 'bi bi-sun-fill';
      }
    }

    // Initialize from current root attribute
    const initialTheme = document.documentElement.getAttribute('data-theme') || 'dark';
    syncThemeUI(initialTheme);

    themeBtn.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      let nextTheme;
      if (window.CipherBallotTheme && typeof window.CipherBallotTheme.toggle === 'function') {
        nextTheme = window.CipherBallotTheme.toggle();
      } else {
        const cur = document.documentElement.getAttribute('data-theme') || 'dark';
        nextTheme = cur === 'dark' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-theme', nextTheme);
        try {
          localStorage.setItem('cb_theme', nextTheme);
        } catch (_) {}
      }
      syncThemeUI(nextTheme);
    });

    // Observe external attribute changes on <html>
    const observer = new MutationObserver(() => {
      const current = document.documentElement.getAttribute('data-theme') || 'dark';
      syncThemeUI(current);
    });
    observer.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ['data-theme', 'class']
    });

    window.addEventListener('cipherballot:themechange', (e) => {
      if (e.detail && e.detail.theme) {
        syncThemeUI(e.detail.theme);
      }
    });
  }

  /**
   * DOM Ready Initializer
   */
  function init() {
    initMobileDrawer();
    initThemeToggle();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
