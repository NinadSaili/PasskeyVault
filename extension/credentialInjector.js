/**
 * CredentialInjector - Detects login forms and injects credentials.
 *
 * Used by content scripts to auto-fill username/password fields
 * on Microsoft login pages.
 */
const CredentialInjector = (() => {
  'use strict';

  function detectLoginForm() {
    const username =
      document.querySelector('input[type=email]') ||
      document.querySelector('input[name=loginfmt]');
    const password =
      document.querySelector('input[type=password]');
    return { username, password };
  }

  function inject(usernameValue, passwordValue) {
    const fields = detectLoginForm();
    if (!fields.username || !fields.password) return false;
    fields.username.value = usernameValue;
    fields.password.value = passwordValue;
    const form = fields.password.closest('form');
    if (form) {
      setTimeout(() => form.submit(), 400);
    }
    return true;
  }

  return { inject };
})();
