/**
 * AuthOrchestrator - Coordinates credential retrieval and injection
 * on login pages.
 */
const AuthOrchestrator = (() => {
  'use strict';

  async function handleLoginPage() {
    const domain = window.location.hostname;
    const credential = await chrome.runtime.sendMessage({
      action: 'vault.getCredential',
      payload: { domain }
    });
    if (!credential) return;
    CredentialInjector.inject(credential.username, credential.password);
  }

  return { handleLoginPage };
})();
