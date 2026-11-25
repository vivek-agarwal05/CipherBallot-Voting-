/**
 * CipherBallot — main.js
 * Core UI utilities: toasts, sidebar, confirms, alerts, form helpers.
 *
 * No external dependencies — vanilla ES2020.
 */

'use strict';

// ===========================================================================
// 1. Toast notification system
// ===========================================================================

/**
 * Show a toast notification.
 *
 * @param {string} message  - Text to display.
 * @param {'success'|'danger'|'warning'|'info'} type - Visual style.
 * @param {number} duration - Auto-dismiss delay in ms (0 = never).
 */
function showToast(message, type = 'info', duration = 4000) {
  const container = getOrCreateToastContainer();

  const icons = {
    success: `<svg class="toast-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" style="color:#0D9488"><path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7"/></svg>`,
    danger:  `<svg class="toast-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" style="color:#EF4444"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"/></svg>`,
    warning: `<svg class="toast-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" style="color:#F59E0B"><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v4m0 4h.01M12 3a9 9 0 110 18A9 9 0 0112 3z"/></svg>`,
    info:    `<svg class="toast-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" style="color:#3B82F6"><path stroke-linecap="round" stroke-linejoin="round" d="M13 16h-1v-4h-1m1-4h.01M12 3a9 9 0 110 18A9 9 0 0112 3z"/></svg>`,
  };

  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.setAttribute('role', 'alert');
  toast.setAttribute('aria-live', 'polite');
  toast.innerHTML = `
    ${icons[type] || icons.info}
    <span class="toast-message">${escapeHtml(message)}</span>
    <button class="toast-close" aria-label="Dismiss notification">&times;</button>
  `;

  const closeBtn = toast.querySelector('.toast-close');
  const dismiss = () => dismissToast(toast);
  closeBtn.addEventListener('click', dismiss);

  container.appendChild(toast);

  // Auto-dismiss
  let timerId = null;
  if (duration > 0) {
    timerId = setTimeout(dismiss, duration);
  }

  // Cancel auto-dismiss on hover (accessibility)
  toast.addEventListener('mouseenter', () => {
    if (timerId) clearTimeout(timerId);
  });
  toast.addEventListener('mouseleave', () => {
    if (duration > 0) timerId = setTimeout(dismiss, duration);
  });

  return toast;
}

function dismissToast(toast) {
  toast.classList.add('dismissing');
  toast.addEventListener('animationend', () => toast.remove(), { once: true });
  // Fallback if animation doesn't fire
  setTimeout(() => toast.remove(), 400);
}

function getOrCreateToastContainer() {
  let container = document.getElementById('toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    container.className = 'toast-container';
    container.setAttribute('aria-live', 'polite');
    container.setAttribute('aria-atomic', 'false');
    document.body.appendChild(container);
  }
  return container;
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// ===========================================================================
// 2. Sidebar toggle (mobile)
// ===========================================================================

function initSidebar() {
  const toggleBtn = document.getElementById('sidebar-toggle');
  const sidebar   = document.getElementById('sidebar');
  if (!toggleBtn || !sidebar) return;

  let backdrop = null;

  function openSidebar() {
    sidebar.classList.add('open');
    toggleBtn.setAttribute('aria-expanded', 'true');
    // Create backdrop
    backdrop = document.createElement('div');
    backdrop.className = 'sidebar-backdrop';
    backdrop.setAttribute('aria-hidden', 'true');
    document.body.appendChild(backdrop);
    backdrop.addEventListener('click', closeSidebar);
    // Trap focus within sidebar
    sidebar.querySelector('a, button')?.focus();
  }

  function closeSidebar() {
    sidebar.classList.remove('open');
    toggleBtn.setAttribute('aria-expanded', 'false');
    if (backdrop) {
      backdrop.remove();
      backdrop = null;
    }
    toggleBtn.focus();
  }

  toggleBtn.addEventListener('click', () => {
    if (sidebar.classList.contains('open')) {
      closeSidebar();
    } else {
      openSidebar();
    }
  });

  // Close on Escape
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && sidebar.classList.contains('open')) {
      closeSidebar();
    }
  });
}

// ===========================================================================
// 3. Confirm dialog helper
// ===========================================================================

/**
 * Show a native confirm dialog before submitting a form.
 * Usage: <form data-confirm="Are you sure?">
 */
function initConfirmForms() {
  document.addEventListener('submit', (e) => {
    const form = e.target.closest('form[data-confirm]');
    if (!form) return;
    const message = form.dataset.confirm || 'Are you sure?';
    if (!window.confirm(message)) {
      e.preventDefault();
    }
  });

  // Also handle buttons with data-confirm
  document.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-confirm]');
    if (!btn || btn.tagName === 'FORM') return;
    const message = btn.dataset.confirm || 'Are you sure?';
    if (!window.confirm(message)) {
      e.preventDefault();
      e.stopPropagation();
    }
  });
}

// ===========================================================================
// 4. Auto-dismiss flash alerts
// ===========================================================================

function initAlerts() {
  // Wire up close buttons
  document.querySelectorAll('.alert-close').forEach((btn) => {
    btn.addEventListener('click', () => {
      const alert = btn.closest('.alert');
      if (alert) {
        alert.style.transition = 'opacity 200ms ease';
        alert.style.opacity = '0';
        setTimeout(() => alert.remove(), 220);
      }
    });
  });

  // Auto-dismiss non-error alerts after 6 seconds
  document.querySelectorAll('.alert-success, .alert-info').forEach((alert) => {
    setTimeout(() => {
      if (!document.body.contains(alert)) return;
      alert.style.transition = 'opacity 400ms ease';
      alert.style.opacity = '0';
      setTimeout(() => alert.remove(), 420);
    }, 6000);
  });
}

// ===========================================================================
// 5. Form validation UI helpers
// ===========================================================================

function initFormValidation() {
  // Show validation feedback on blur
  document.querySelectorAll('.form-control[required]').forEach((input) => {
    input.addEventListener('blur', () => {
      if (!input.value.trim()) {
        input.classList.add('is-invalid');
      } else {
        input.classList.remove('is-invalid');
      }
    });
    input.addEventListener('input', () => {
      if (input.value.trim()) {
        input.classList.remove('is-invalid');
      }
    });
  });

  // Password strength indicator (if element exists)
  const pwInput = document.getElementById('password');
  const strengthBar = document.getElementById('password-strength');
  if (pwInput && strengthBar) {
    pwInput.addEventListener('input', () => {
      const strength = getPasswordStrength(pwInput.value);
      updateStrengthBar(strengthBar, strength);
    });
  }
}

function getPasswordStrength(password) {
  let score = 0;
  if (password.length >= 8)  score++;
  if (password.length >= 12) score++;
  if (/[A-Z]/.test(password)) score++;
  if (/[a-z]/.test(password)) score++;
  if (/[0-9]/.test(password)) score++;
  if (/[^A-Za-z0-9]/.test(password)) score++;
  if (score <= 2) return 'weak';
  if (score <= 4) return 'fair';
  return 'strong';
}

function updateStrengthBar(bar, strength) {
  bar.className = `password-strength password-strength-${strength}`;
  const labels = { weak: 'Weak', fair: 'Fair', strong: 'Strong' };
  bar.textContent = labels[strength] || '';
}

// ===========================================================================
// 6. Copy to clipboard helper
// ===========================================================================

function copyToClipboard(text, feedbackEl = null) {
  navigator.clipboard.writeText(text).then(() => {
    showToast('Copied to clipboard!', 'success', 2500);
    if (feedbackEl) {
      const original = feedbackEl.textContent;
      feedbackEl.textContent = 'Copied!';
      setTimeout(() => { feedbackEl.textContent = original; }, 2000);
    }
  }).catch(() => {
    showToast('Could not copy to clipboard.', 'warning');
  });
}

// Wire up [data-copy] buttons
function initCopyButtons() {
  document.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-copy]');
    if (!btn) return;
    const text = btn.dataset.copy || '';
    copyToClipboard(text, btn);
  });
}

// ===========================================================================
// 7. Active nav link highlighting
// ===========================================================================

function initActiveNav() {
  const path = window.location.pathname;
  document.querySelectorAll('.sidebar-nav a').forEach((link) => {
    const href = link.getAttribute('href');
    if (href && path.startsWith(href) && href !== '/') {
      link.classList.add('active');
    } else if (href === '/' && path === '/') {
      link.classList.add('active');
    }
  });
}

// ===========================================================================
// 8. Initialise everything on DOMContentLoaded
// ===========================================================================

document.addEventListener('DOMContentLoaded', () => {
  initSidebar();
  initConfirmForms();
  initAlerts();
  initFormValidation();
  initCopyButtons();
  initActiveNav();
});

// Expose public API
window.CipherBallot = {
  showToast,
  copyToClipboard,
};
