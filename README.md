# PasskeyVault - Entra ID Passkey Authenticator

Browser extension that provides an extension-managed passkey vault and authentication orchestrator for Microsoft Entra ID (Azure AD) environments.

## Architecture

```
extension/
├── manifest.json           # Manifest V3 (Chrome + Edge)
├── background.js           # Service worker - orchestration hub
├── content.js              # Content script - page-level WebAuthn interception
├── popup.html / popup.js   # Vault management UI
├── cryptoEngine.js         # Web Crypto API operations (AES-256-GCM, ECDSA P-256)
├── vaultEngine.js          # Encrypted credential storage engine
├── authEngine.js           # WebAuthn key generation and challenge signing
├── federationDetector.js   # Entra federation flow detection (OIDC/SAML/WS-Fed/ADFS)
├── securityValidator.js    # Origin, RP ID, and TLS validation
├── styles/popup.css        # Popup stylesheet
└── icons/                  # Extension icons
```

### Module Responsibilities

| Module | Purpose |
|---|---|
| **CryptoEngine** | PBKDF2 key derivation, AES-256-GCM encrypt/decrypt, P-256 key pair generation, ECDSA signing |
| **VaultEngine** | Encrypted vault lifecycle (create/unlock/lock), passkey CRUD, user management, auto-lock timeout |
| **AuthEngine** | WebAuthn passkey registration, challenge signing, authenticator data construction, DER signature encoding |
| **FederationDetector** | Detect OIDC authorize, SAML POST, WS-Federation, ADFS redirects; classify managed vs federated domains |
| **SecurityValidator** | Validate origins against trusted Microsoft domains, RP ID suffix checks, phishing prevention |

## Authentication Flow

1. User navigates to `portal.azure.com` or any Entra-protected resource.
2. Extension detects Microsoft login redirect via `FederationDetector`.
3. Content script intercepts `navigator.credentials.get()` on the login page.
4. Background worker checks vault for matching passkeys.
5. If a passkey exists, `AuthEngine` signs the WebAuthn challenge.
6. Signed assertion is returned to the page, completing authentication.

## Security Model

- **Vault encryption**: AES-256-GCM with PBKDF2-derived keys (600,000 iterations).
- **Private keys**: Never stored in plaintext. Encrypted at rest, decrypted only in memory during signing, then zeroed.
- **Origin validation**: Only trusted Microsoft authentication domains can trigger credential operations.
- **RP ID validation**: Enforces WebAuthn RP ID suffix matching per spec.
- **Auto-lock**: Vault locks after configurable timeout (default 5 minutes).
- **No platform dependency**: Keys are managed entirely by the extension, independent of OS passkey stores.

## Loading the Extension

### Chrome

1. Open `chrome://extensions/`
2. Enable **Developer mode** (toggle in top-right)
3. Click **Load unpacked**
4. Select the `extension/` directory from this repository
5. The PasskeyVault icon appears in the toolbar

### Microsoft Edge

1. Open `edge://extensions/`
2. Enable **Developer mode** (toggle in bottom-left)
3. Click **Load unpacked**
4. Select the `extension/` directory from this repository
5. The PasskeyVault icon appears in the toolbar

## First-Time Setup

1. Click the PasskeyVault extension icon.
2. Create a vault PIN (minimum 4 characters). This PIN protects your encrypted vault.
3. Register a passkey: enter your display name, Entra UPN (email), and RP ID.
4. Navigate to a Microsoft login page. The extension will automatically handle WebAuthn challenges.

## Development

The extension uses no build tools or external dependencies. All cryptographic operations use the browser's native Web Crypto API.

To modify and test:
1. Edit files in `extension/`
2. Go to `chrome://extensions/` and click the reload button on the extension card
3. Open DevTools on the extension's service worker (click "Inspect views: service worker") for background logs
