# express-easy-auth

Full-stack authentication for Express — passwords, TOTP, passkeys, API keys, and session management, wired up in one line.

```sh
npm install @javagt/express-easy-auth
```

> Requires Node.js ≥ 22.10.0

---

## Quick Start

```js
import express from 'express';
import { EasyAuth } from '@javagt/express-easy-auth';

const app = express();
app.use(express.json());

const { auth, authManager } = await EasyAuth.create(app, {
    session: { secret: process.env.SESSION_SECRET }
});

app.get('/profile', auth.requireAuth, (req, res) => res.json(req.user));

app.listen(3000);
```

That's it. Auth routes are live at `/auth`, sessions are persisted in SQLite at `./data/auth.db`, and `auth` is ready to protect your routes.

---

## What You Get Out of the Box

| Feature | Endpoint(s) |
|---|---|
| Password login + registration | `POST /auth/login`, `POST /auth/register` |
| TOTP two-factor auth | `POST /auth/totp/*` |
| Passkeys (WebAuthn) | `POST /auth/passkeys/*` |
| User-managed API keys | `GET/POST/PATCH/DELETE /auth/keys` |
| Session management | `GET/DELETE /auth/sessions` |
| Password reset flow | `POST /auth/password-reset/*` |
| Email verification | `POST /auth/verify-email` |
| SQLite session store | `./data/auth.db` (auto-created) |
| Rate limiting on sensitive routes | 20 req / 15 min per IP |
| Browser client | `GET /auth/client.js` |
| OpenAPI spec | `GET /auth/openapi.json` |

---

## Configuration

All options are optional. Sane defaults apply everywhere.

```js
const { auth, authManager } = await EasyAuth.create(app, {
    // --- Database ---
    databasePath: './data/auth.db',   // default
    mkdirp:       true,               // auto-create parent dirs (default)

    // --- Session ---
    session: {
        secret:  process.env.SESSION_SECRET,
        cookie:  { maxAge: 7 * 24 * 60 * 60 * 1000 },
    },

    // --- Routing ---
    basePath:      '/auth',   // default
    exposeOpenApi: true,      // serve /auth/openapi.json (default)

    // --- Rate limiting ---
    rateLimit: { windowMs: 15 * 60 * 1000, max: 20 },  // default, or false to disable

    // --- Auth features ---
    requireEmailVerification: false,
    identifierTypes: ['email', 'phone', 'username'],

    // --- Scopes ---
    serverScopes:  ['users.read', 'users.write'],   // app-defined admin capabilities
    projectScopes: ['docs:read', 'docs:write'],     // app-defined project permissions

    // --- WebAuthn ---
    webAuthn: { rpName: 'My App' },

    // --- TOTP ---
    totp: { issuer: 'My App' },
});
```

### Using a pre-built AuthManager

Use the lower-level API when you need the `authManager` before wiring up the Express app, or for testing:

```js
import { AuthManager, EasyAuth } from '@javagt/express-easy-auth';

const authManager = new AuthManager({ databasePath: './data/auth.db' });
await authManager.init();

const auth = EasyAuth.attach(app, authManager, {
    session: { secret: process.env.SESSION_SECRET }
});
```

---

## Protecting Routes

The `auth` object is an `AuthMiddleware` instance. All methods are pre-bound and can be passed directly to Express.

### Require a session

```js
app.get('/me', auth.requireAuth, (req, res) => {
    // req.user    = { id, email, display_name }
    // req.authType = 'session'
    res.json(req.user);
});
```

### Require an API key

```js
app.get('/data', auth.useApiKey, (req, res) => {
    // req.user   = { id, email, display_name }
    // req.apiKey = { id, name, prefix, grants }
    res.json({ key: req.apiKey.name });
});
```

### Accept either (session or API key)

```js
app.get('/feed', auth.requireAuthOrApiKey, handler);
```

### Require a fresh session

Rejects requests where the user authenticated more than 5 minutes ago. Also rejects API key callers — fresh auth is interactive-only.

```js
app.delete('/account', auth.requireFreshAuth, handler);
```

### Fresh session with a personal scope check

```js
app.post('/me/totp', auth.requireFreshAuth(['personal:auth.write']), handler);
```

### Server scopes (admin capabilities)

Defined by your app in the `serverScopes` config option. Assigned to users with `authManager.grantServerScope()`.

```js
app.get('/admin/users',
    auth.requireAuth,
    auth.requireServerScope('users.read'),
    handler
);
```

### Personal scopes (account-level access)

Session users implicitly hold all personal scopes. API keys must declare the scope at creation.

```js
app.get('/keys',
    auth.requireAuthOrApiKey,
    auth.requirePersonalScope('personal:apikeys.read'),
    handler
);
```

### Project scopes

Your app resolves the user's permissions for a project and sets `req.projectPermissions`. The library enforces the ceiling declared on the API key (if any).

```js
async function loadProjectPermissions(req, res, next) {
    const membership = await db.getMembership(req.params.projectId, req.user.id);
    req.projectPermissions = membership?.permissions ?? [];
    next();
}

app.get('/projects/:projectId/docs',
    auth.requireAuthOrApiKey,
    loadProjectPermissions,
    auth.requireProjectAccess('docs:read'),
    handler
);
```

For API key callers, the effective scope is `declared ∩ app-provided permissions`. For session callers, it is the app-provided permissions directly.

### Project ownership

```js
app.delete('/projects/:projectId',
    auth.requireFreshAuth,
    auth.requireProjectOwner,
    handler
);
```

### Rate limiting

Each `rateLimit()` call returns an **independent** limiter with its own bucket.

```js
const tight = auth.rateLimit({ windowMs: 60_000, max: 5 });
app.post('/submit', tight, handler);
```

---

## `req` Properties

| Property | Set by | Value |
|---|---|---|
| `req.user` | Any auth middleware | `{ id, email, display_name }` |
| `req.authType` | Any auth middleware | `'session'` or `'api_key'` |
| `req.lastAuthenticatedAt` | Session middleware | `Date.now()` of last login (ms) |
| `req.apiKey` | API key middleware | `{ id, name, prefix, grants }` |
| `req.serverScopes` | `requireServerScope()` | Effective server scopes array |
| `req.effectiveProjectScopes` | `requireProjectAccess()` | Effective project scopes array |

---

## AuthManager API

Use `authManager` in your own routes, admin panels, background jobs, or tests.

### Users

```js
await authManager.registerUser(email, password, displayName?)
await authManager.getUserById(userId)
await authManager.listUsers()
await authManager.deleteUser(userId)
// Returns { deleted: true, warnings: [...] } for orphaned projects
```

### Server Scopes

```js
await authManager.grantServerScope(userId, 'users.read', grantorId?)
await authManager.revokeServerScope(userId, 'users.read')
await authManager.getUserServerScopes(userId)
```

`grantorId` must already hold the scope. Pass `null` for server-side bootstrap.

### API Keys

```js
// Create — raw key returned once, never stored
const { key, id, prefix, grants } = await authManager.createApiKey(userId, {
    name:      'CI pipeline',
    expiresAt: Date.now() + 30 * 24 * 60 * 60 * 1000,
    grants: {
        server:   ['users.read'],
        personal: ['personal:profile.read'],
        projects: [{ projectId: 'proj_abc', scopes: ['docs:read'] }],
    },
});

await authManager.listApiKeys(userId)
await authManager.revokeApiKey(userId, keyId)
await authManager.revokeApiKeyAsAdmin(keyId)
await authManager.updateApiKey(userId, keyId, { name?, expiresAt?, clearExpiry? })
```

Keys sent as `Authorization: Bearer sk_...` or `X-API-Key: sk_...`.

### Projects

```js
// Call when your app creates or deletes a project
await authManager.registerProject(projectId, ownerId)   // idempotent
await authManager.unregisterProject(projectId)

await authManager.isProjectOwner(projectId, userId)
await authManager.getOwnedProjects(userId)
await authManager.transferProjectOwnership(projectId, newOwnerId)
```

### TOTP

```js
const { secret, qrCode } = await authManager.generateTotpSetup(userId)
await authManager.verifyAndEnableTotp(userId, code, secret)
await authManager.disableTotp(userId)
await authManager.getTotpStatus(userId)
```

### Passkeys

```js
const options = await authManager.generateRegistrationOptions(user, cfg)
await authManager.verifyRegistration(user, response, challenge, name, cfg)

const options = await authManager.generateAuthenticationOptions(cfg)
const { user } = await authManager.verifyAuthentication(response, challenge, cfg)

await authManager.getPasskeys(userId)
await authManager.updatePasskeyName(userId, credentialId, name)
await authManager.deletePasskey(userId, credentialId)
```

### Password reset

```js
await authManager.requestPasswordReset(identifier)  // silently no-ops for unknown identifiers
await authManager.resetPassword(token, newPassword)
await authManager.changePassword(userId, newPassword)
```

### Scope taxonomy

```js
// Returns { server: [...], personal: [...], project: [...] }
authManager.getScopeTaxonomy()
```

---

## Scope System

### Three levels

| Level | Who holds it | Stored where | Checked by |
|---|---|---|---|
| **Server** | Admin users | DB (`user_server_scopes`) | `requireServerScope()` |
| **Personal** | All authenticated users | Implicit (session) / declared (API key) | `requirePersonalScope()` |
| **Project** | App-managed | App sets `req.projectPermissions` | `requireProjectAccess()` |

### API key scope ceiling

A key can only be granted scopes the creating user already holds. If a user loses a scope after creation, all their keys immediately lose it too — scope checks are live, not snapshot.

### Personal scopes

| Scope | Meaning | API key? |
|---|---|---|
| `personal:profile.read` | Read own profile | ✅ |
| `personal:profile.write` | Update display name, email | ✅ |
| `personal:auth.read` | View 2FA / passkey config | ✅ |
| `personal:auth.write` | Change password, configure 2FA | ✅ |
| `personal:apikeys.read` | List own API keys | ✅ |
| `personal:apikeys.write` | Create or revoke keys | ❌ Session only |

`personal:apikeys.write` is session-only unconditionally. A key can never create other keys.

---

## Custom Adaptors

### Database adaptor

Swap out SQLite for any database by extending `DatabaseAdaptor`:

```js
import { DatabaseAdaptor, EasyAuth } from '@javagt/express-easy-auth';

class PostgresAdaptor extends DatabaseAdaptor {
    async createUser(email, passwordHash, displayName) { /* ... */ }
    // implement remaining abstract methods ...
}

const { auth } = await EasyAuth.create(app, {
    databaseAdapter: new PostgresAdaptor(pool),
    session: { secret: process.env.SESSION_SECRET },
});
```

### Contact adaptor

Deliver verification codes and password-reset links via your own transport:

```js
import { ContactAdaptor, EasyAuth } from '@javagt/express-easy-auth';

class SendgridAdaptor extends ContactAdaptor {
    async sendUserSignupCode(user, code)   { /* send verification email */ }
    async sendUserLoginCode(user, code)    { /* send login code */ }
    async sendUserRecoveryCode(user, code) { /* send password reset link */ }
}

const { auth } = await EasyAuth.create(app, {
    contactAdaptors: [new SendgridAdaptor()],
    session: { secret: process.env.SESSION_SECRET },
});
```

The default `ConsoleContactAdaptor` logs codes to the console and redacts them in production.

### Challenge store

For multi-instance deployments, replace the default in-memory WebAuthn challenge store:

```js
import { ChallengeStore, EasyAuth } from '@javagt/express-easy-auth';

class RedisStore extends ChallengeStore {
    async set(key, value, ttlMs) { await redis.set(key, JSON.stringify(value), 'PX', ttlMs); }
    async get(key)               { const v = await redis.get(key); return v ? JSON.parse(v) : null; }
    async delete(key)            { await redis.del(key); }
}

const { auth } = await EasyAuth.create(app, {
    challengeStore: new RedisStore(redisClient),
    session: { secret: process.env.SESSION_SECRET },
});
```

---

## Browser Client

The library ships a ready-to-use browser client. Load it from the auth route:

```html
<script type="module">
import { EasyAuthClient } from '/auth/client.js';

const auth = new EasyAuthClient();
await auth.login('user@example.com', 'password');
console.log(auth.user);  // { id, email, display_name }
</script>
```

Or install from npm for bundled apps:

```js
import { EasyAuthClient } from '@javagt/express-easy-auth/client';
```

Key methods: `register`, `login`, `logout`, `me`, `setupTotp`, `verifyTotp`, `registerPasskey`, `loginWithPasskey`, `createApiKey`, `listApiKeys`, `revokeApiKey`, `changePassword`, `requestPasswordReset`.

---

## All Auth Routes

| Method | Path | Requires | Description |
|---|---|---|---|
| POST | `/auth/register` | — | Create account |
| POST | `/auth/login` | — | Password login (+ TOTP if enabled) |
| POST | `/auth/logout` | Session | Destroy current session |
| GET | `/auth/me` | Session or API key | Current identity and auth type |
| DELETE | `/auth/account` | Fresh session | Delete own account |
| POST | `/auth/verify-email` | — | Consume email verification token |
| GET | `/auth/totp/status` | Session | Is TOTP enabled? |
| POST | `/auth/totp/setup` | Fresh session | Begin TOTP setup, returns QR code |
| POST | `/auth/totp/verify` | Fresh session | Confirm code, enables 2FA |
| POST | `/auth/totp/disable` | Fresh session | Disable TOTP |
| POST | `/auth/passkeys/register/options` | Session | Start passkey registration |
| POST | `/auth/passkeys/register/verify` | Session | Complete passkey registration |
| POST | `/auth/passkeys/login/options` | — | Start passkey login |
| POST | `/auth/passkeys/login/verify` | — | Complete passkey login |
| POST | `/auth/passkeys/verify/options` | Session | Start step-up passkey verification |
| POST | `/auth/passkeys/verify/verify` | Session | Complete step-up verification |
| GET | `/auth/passkeys` | Session | List registered passkeys |
| PATCH | `/auth/passkeys/:id/name` | Session | Rename a passkey |
| DELETE | `/auth/passkeys/:id` | Session | Remove a passkey |
| GET | `/auth/keys` | Session or API key | List API keys (metadata only) |
| POST | `/auth/keys` | Session | Create API key |
| PATCH | `/auth/keys/:id` | Session | Update name or expiry |
| DELETE | `/auth/keys/:id` | Session | Revoke API key |
| GET | `/auth/scopes` | — | Available scope taxonomy |
| POST | `/auth/password-reset/request` | — | Send password reset code |
| POST | `/auth/password-reset/reset` | — | Apply reset token, invalidates all sessions |
| POST | `/auth/password/change` | Fresh session | Change password |
| GET | `/auth/identifiers` | Session | List login identifiers |
| POST | `/auth/identifiers` | Session | Add identifier (email, phone, username) |
| DELETE | `/auth/identifiers/:type/:value` | Fresh session | Remove identifier |
| GET | `/auth/sessions` | Session | List active sessions |
| DELETE | `/auth/sessions/:id` | Session | Revoke a specific session |
| GET | `/auth/client.js` | — | Browser client script |
| GET | `/auth/openapi.json` | — | OpenAPI spec |

---

## Running the Demos

```sh
npm run start        # demo1 — basic auth + API keys
npm run dev:chat     # demo2 — chat app with scoped identities
npm run dev:docuflow # demo3 — document workflow with project scopes
```

---

## Design

See [DESIGN.md](DESIGN.md) for the full architectural specification: scope system, data model, threat model, and migration guide from v3.
