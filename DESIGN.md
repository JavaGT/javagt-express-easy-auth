# express-easy-auth — v4 Design Specification

## 1. What This Library Is (and Isn't)

This library is responsible for **authentication** and **identity-bound authorization primitives**. It is not an application permission framework.

**In scope:**
- Credential verification (password, TOTP, WebAuthn, login codes)
- Session management
- API key issuance, storage, and validation
- Project ownership records (who owns what — nothing more)
- Server-scope assignments (which human admin users have which elevated capabilities)
- Personal-scope definitions (what an authenticated user can do to their own account)
- Middleware that checks scopes the app has already resolved onto `req`

**Out of scope:**
- Application-level project membership or roles
- Enforcement of role promotion rules
- Storing project metadata
- Defining what app-level permission strings mean
- Member management logic

The dividing line is: **the auth library enforces what is on `req`; the app is responsible for putting the right things there.**

---

## 2. Problems with v3

| Problem | Detail |
|---|---|
| Scopes are global | No way to express "user has `files:write` on project A, `files:read` on project B" |
| Roles are global app concepts stored in auth DB | Role names like `editor` are meaningless to an auth library |
| API key authority is snapshot-based | Scopes validated once at creation; losing a permission doesn't revoke the key |
| `createApiKey` trust boundary is implicit | `callerScopes` option silently changes validation behaviour |
| Raw API key stored in DB | Should store only a hash; key shown once and never retrievable |
| No concept of ownership | Library has no way to know "this user owns this project" |
| `last_used_at` written synchronously on every request | Single write-lock per validation under SQLite; becomes a bottleneck at load |
| `UNIQUE(api_key_id, project_id)` with nullable `project_id` | `NULL != NULL` in SQL unique constraints; duplicate global grants are possible |

---

## 3. Three Scope Levels

### 3.1 Server Scopes

Capabilities assigned to specific human admin users. Stored in the auth database. Checked with server-scope middleware. The app defines which scope strings are valid — the library stores and checks them, nothing more.

Examples an app might define:
```
users.read       — view user list / user data
users.write      — create or modify any user account
users.delete     — delete user accounts
projects.list    — admin overview of all projects
projects.delete  — force-delete any project
```

Server scopes are never inferred from project membership. They are assigned explicitly by other admin users (or directly in the database for the initial admin).

### 3.2 Personal Scopes

A fixed set defined by the library. Describe what an authenticated user can do to their own account. All authenticated session users implicitly hold all personal scopes. API keys can be limited to a declared subset.

| Scope | Meaning |
|---|---|
| `personal:profile.read` | Read own profile data |
| `personal:profile.write` | Update own profile (display name, email, etc.) |
| `personal:auth.read` | View own 2FA / passkey configuration |
| `personal:auth.write` | Configure own 2FA, passkeys; change password |
| `personal:apikeys.read` | List own API keys (metadata only) |
| `personal:apikeys.write` | **Session-only.** Create or revoke API keys. Blocked on all API key requests — a key can never create other keys. |

`personal:apikeys.write` being session-only is enforced by the library unconditionally. There is no override.

### 3.3 Project Scopes

Entirely app-defined. The auth library does not know what they mean, does not validate them at creation time, and does not store them anywhere except as declared ceilings on API key grants.

At request validation time, the effective scope set for a project is:

```
effective = declared_on_api_key ∩ app_provided_current_permissions
```

The app is responsible for loading the user's current permissions from its own database and attaching them to `req.projectPermissions` before calling `auth.requireProjectAccess`. See §7 and the demo in §11 for exactly how this works.

Because the intersection is computed at validation time, no key rotation is needed when user permissions change. If a user loses a project permission, their keys immediately lose it too. If restored, they regain it automatically.

---

## 4. Data Model

### 4.1 Retained (unchanged)

`users`, `user_identifiers`, `sessions`, `express_sessions`, `authenticators`, `password_hashes`, `password_reset_tokens`, `email_verification_tokens`

### 4.2 Removed

`roles`, `user_roles` — replaced by `user_server_scopes` and app-side project membership

### 4.3 New and Modified Tables

#### `projects`
Stores only what the auth library needs to know: that a project exists and who owns it.

```sql
CREATE TABLE projects (
  id         TEXT PRIMARY KEY,   -- opaque string, supplied by the app
  owner_id   INTEGER             -- SET NULL on user delete (see §8)
             REFERENCES users(id) ON DELETE SET NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX idx_projects_owner ON projects(owner_id);
```

The app is the source of truth for all other project data. The auth library only needs the `(id, owner_id)` pair.

#### `user_server_scopes`

```sql
CREATE TABLE user_server_scopes (
  id         INTEGER PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  scope      TEXT NOT NULL,
  granted_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
  created_at INTEGER NOT NULL,
  UNIQUE(user_id, scope)
);
CREATE INDEX idx_uss_user ON user_server_scopes(user_id);
```

#### `api_keys` (modified)

The raw key is shown once at creation and never stored. Only a SHA-256 hash is persisted. SHA-256 is appropriate here because the key has sufficient entropy (≥128 bits of randomness) to make preimage attacks computationally infeasible; bcrypt's cost factor would add latency with no security benefit for high-entropy inputs.

```sql
CREATE TABLE api_keys (
  id           INTEGER PRIMARY KEY,
  user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  key_hash     TEXT UNIQUE NOT NULL,  -- SHA-256(raw_key)
  key_prefix   TEXT NOT NULL,         -- first 12 chars for display: 'sk_ab12cd34ef56'
  name         TEXT NOT NULL,
  expires_at   INTEGER,
  created_at   INTEGER NOT NULL,
  last_used_at INTEGER               -- updated best-effort, non-blocking
);
```

#### `api_key_server_grant`

At most one row per API key. Stores declared server-scope ceiling.

```sql
CREATE TABLE api_key_server_grant (
  api_key_id INTEGER PRIMARY KEY REFERENCES api_keys(id) ON DELETE CASCADE,
  scopes     TEXT NOT NULL            -- JSON array
);
```

#### `api_key_personal_grant`

At most one row per API key.

```sql
CREATE TABLE api_key_personal_grant (
  api_key_id INTEGER PRIMARY KEY REFERENCES api_keys(id) ON DELETE CASCADE,
  scopes     TEXT NOT NULL            -- JSON array; personal:apikeys.write rejected at write time
);
```

#### `api_key_project_grants`

One row per (key, project) pair. `project_id` is NOT NULL here — the NULL footgun is avoided by using separate tables for server and personal grants.

```sql
CREATE TABLE api_key_project_grants (
  id         INTEGER PRIMARY KEY,
  api_key_id INTEGER NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  scopes     TEXT NOT NULL,           -- JSON array; app-defined strings
  UNIQUE(api_key_id, project_id)
);
CREATE INDEX idx_akpg_key     ON api_key_project_grants(api_key_id);
CREATE INDEX idx_akpg_project ON api_key_project_grants(project_id);
```

---

## 5. Configuration

The library no longer accepts application role definitions. Roles belong to the app.

```js
const auth = new EasyAuth({
  // --- existing options (unchanged) ---
  db: { path: './auth.db' },
  session: { secret: process.env.SESSION_SECRET },
  webauthn: { rpName: 'My App', rpId: 'myapp.com', origin: 'https://myapp.com' },

  // --- new: server scope taxonomy ---
  // Defines which scope strings are valid for server grants.
  // Attempting to assign an unlisted scope throws at runtime.
  serverScopes: [
    'users.read',
    'users.write',
    'users.delete',
    'projects.list',
    'projects.delete',
  ],

  // --- new: project scope taxonomy (optional but recommended) ---
  // If provided, project scopes on API keys are validated against this list at
  // creation time. If omitted, any string is accepted (app is fully responsible
  // for scope string governance).
  projectScopes: [
    'docs:read',
    'docs:write',
    'docs:delete',
    'members:read',
    'members:manage',
  ],
});
```

---

## 6. AuthManager API

### 6.1 Projects

```ts
// Register a project in the auth system. Call this when the app creates a project.
// Does not store any app metadata — only the ID and owner relationship.
registerProject(projectId: string, ownerId: number): Promise<void>

// Remove the auth record for a project. Call this when the app deletes a project.
// Cascades to api_key_project_grants.
unregisterProject(projectId: string): Promise<void>

// Transfer ownership. Caller is responsible for ensuring the current owner
// is authenticated freshly (use requireFreshAuth on the route).
// The new owner must be a registered user; they need not currently be a member
// (membership is the app's concern).
transferProjectOwnership(projectId: string, newOwnerId: number): Promise<void>

// Returns true if userId is the current owner of projectId.
isProjectOwner(projectId: string, userId: number): Promise<boolean>

// Returns all project IDs owned by a user.
getOwnedProjects(userId: number): Promise<string[]>
```

### 6.2 Server Scopes

```ts
// Assign a server scope to a user.
// grantorId must already hold that scope (enforced).
// Initial setup: use grantorId = null (server-side bootstrap call only).
grantServerScope(userId: number, scope: string, grantorId: number | null): Promise<void>

// Remove a server scope from a user.
revokeServerScope(userId: number, scope: string): Promise<void>

// Return all server scopes currently held by a user.
getUserServerScopes(userId: number): Promise<string[]>
```

### 6.3 API Keys

```ts
interface ApiKeyGrants {
  // Server-scope ceiling. Validated: requested ⊆ user's current server scopes.
  server?: string[];

  // Personal-scope ceiling. Validated against fixed taxonomy.
  // personal:apikeys.write is silently removed if present — it is always session-only.
  personal?: string[];

  // Per-project declared ceilings. NOT validated against user's current project
  // permissions at creation time (auth library does not know them). The app
  // should validate before calling. The intersection at request time is the
  // ultimate enforcement.
  projects?: Array<{ projectId: string; scopes: string[] }>;
}

interface CreateApiKeyOptions {
  name: string;           // required; user-visible label
  grants: ApiKeyGrants;
  expiresAt?: number;
}

// Returns the raw key (shown once only) and metadata.
createApiKey(userId: number, options: CreateApiKeyOptions): Promise<{
  key: string;            // raw key — store securely, never retrievable again
  id: number;
  prefix: string;         // e.g. 'sk_ab12cd34ef56' — safe to display
  name: string;
  grants: ApiKeyGrants;   // as stored (personal:apikeys.write stripped)
  createdAt: number;
}>

// User can only revoke their own keys.
revokeApiKey(userId: number, keyId: number): Promise<void>

// Admin revoke: server code revoking any key without user context.
revokeApiKeyAsAdmin(keyId: number): Promise<void>

// Returns metadata only. Raw key and hash never exposed.
listApiKeys(userId: number): Promise<ApiKeyMeta[]>

// Update name or expiry. Does NOT allow changing grants after creation —
// revoke and reissue instead.
updateApiKey(userId: number, keyId: number, patch: { name?: string; expiresAt?: number }): Promise<void>
```

### 6.4 User Deletion

```ts
interface DeleteUserResult {
  deleted: true;
  warnings: DeleteUserWarning[];
}

interface DeleteUserWarning {
  code: 'USER_OWNS_PROJECTS';
  projectIds: string[];   // projects now ownerless (owner_id set to NULL)
  message: string;
}

// Deletes the user and cascades sessions, API keys, server scopes.
// Projects owned by this user have owner_id SET NULL — they are NOT deleted.
// Returns warnings if any projects were orphaned.
// The app should check warnings and reassign or archive those projects.
deleteUser(userId: number): Promise<DeleteUserResult>
```

---

## 7. Middleware API

### 7.1 Authentication (unchanged semantics)

```js
auth.requireAuth              // session only; sets req.user, req.authType = 'session'
auth.useApiKey            // api key only; sets req.user, req.apiKey, req.authType = 'api_key'
auth.requireAuthOrApiKey      // either; sets above fields appropriately
auth.requireFreshAuth         // session, re-authed within 5 min
auth.requireFreshAuth(['personal:auth.write'])  // + personal scope check
```

After any of the above, `req` has:
```ts
req.user       // { id, email, displayName }
req.authType   // 'session' | 'api_key'
req.apiKey     // present if api_key: { id, name, prefix, grants }
```

### 7.2 Server-Scope Routes

```js
// Factory: authenticates (session or api key) then checks server scope.
auth.requireServerScope('users.read')
auth.requireServerScope(['users.read', 'projects.list'])

// Example:
app.get('/admin/users',
  auth.requireServerScope('users.read'),
  listUsers
);
```

For API key requests, `effective_server_scopes = declared_server_scopes ∩ user's_current_server_scopes`.

### 7.3 Personal Routes

```js
// Factory: authenticates, then checks personal scope.
auth.requirePersonalScope('personal:profile.write')

// personal:apikeys.write automatically rejects non-session requests.
app.get('/me/api-keys',
  auth.requirePersonalScope('personal:apikeys.read'),
  listMyKeys
);

app.post('/me/api-keys',
  auth.requirePersonalScope('personal:apikeys.write'),  // blocks API key callers
  createKey
);
```

### 7.4 Project-Scoped Routes

**This is where model C matters.** The app loads project permissions from its own database and attaches them to `req` before the auth library's scope check runs. The auth library does not call into the app — it only reads from `req`.

```js
// auth.requireProjectAccess(scopes) — factory that:
//   1. Confirms req.user is set (call requireAuth or requireAuthOrApiKey first)
//   2. Reads req.projectPermissions (set by your app middleware)
//   3. For session: checks req.projectPermissions ⊇ required scopes
//   4. For api key: computes effective = declared_for_project ∩ req.projectPermissions
//                   checks effective ⊇ required scopes
//   5. Sets req.effectiveProjectScopes
//
// If req.projectPermissions is not set, throws 500 (misconfiguration).
// If req.projectPermissions is [], throws 403 NOT_A_MEMBER.
auth.requireProjectAccess(scopes: string | string[])

// Owner-only check. Reads the auth DB; does not use req.projectPermissions.
// Use for destructive operations (delete project, transfer ownership).
// Resolves project ID from req.params.projectId ?? req.params.id ?? req.projectId.
// Set req.projectId manually for non-standard param names.
auth.requireProjectOwner
```

**The contract for `req.projectPermissions`:**
```ts
// Your app middleware must set this before requireProjectAccess runs.
// It is the user's current permissions on the project being accessed.
// For owners: always set this to ['*'] or the full permission set.
// For non-members: set to [] or do not set (middleware will return 403).
req.projectPermissions: string[]

// The auth library sets this after requireProjectAccess succeeds.
req.effectiveProjectScopes: string[]
```

**Full middleware chain example:**
```js
app.post('/projects/:id/docs',
  auth.requireAuthOrApiKey,
  loadProjectPermissions,           // your app middleware (see §11)
  auth.requireProjectAccess('docs:write'),
  createDocument
);

app.delete('/projects/:id',
  auth.requireAuthOrApiKey,
  auth.requireFreshAuth,
  auth.requireProjectOwner,
  deleteProject
);
```

---

## 8. User Deletion and Orphaned Projects

When `deleteUser` is called:

1. Library queries `projects` for all rows where `owner_id = userId`.
2. If any exist, a `USER_OWNS_PROJECTS` warning is built (includes project IDs).
3. Deletion proceeds: user row deleted, cascading to sessions, API keys, server scopes.
4. `projects.owner_id` becomes NULL for affected rows (via `ON DELETE SET NULL`).
5. `deleteUser` returns `{ deleted: true, warnings }`.

The app **must** handle the returned warnings. Recommended handling:

```js
const result = await auth.deleteUser(userId);

if (result.warnings.length > 0) {
  for (const w of result.warnings) {
    if (w.code === 'USER_OWNS_PROJECTS') {
      // Archive or reassign each orphaned project.
      // auth.getOwnedProjects() will now return [] for this user.
      await myApp.archiveOrphanedProjects(w.projectIds);
    }
  }
}
```

The library documentation should prominently instruct developers to **transfer project ownership before deleting a user** if continuity matters. `transferProjectOwnership` + `deleteUser` is the safe sequence; `deleteUser` alone is the force path.

---

## 9. API Key Lifecycle

### Creation

```js
// App has loaded user's server scopes and current project permissions.
// App validates project scope requests don't exceed user's permissions (recommended).
// Auth library will enforce this at request time via intersection regardless.

const { key, prefix, id } = await auth.createApiKey(userId, {
  name: 'CI/CD Deploy Key',
  grants: {
    server: [],                                      // no server access
    personal: ['personal:profile.read'],
    projects: [
      { projectId: 'proj_acme-docs', scopes: ['docs:read', 'docs:write'] },
      { projectId: 'proj_acme-blog', scopes: ['docs:read'] },
    ],
  },
  expiresAt: Date.now() + 90 * 24 * 3600 * 1000,
});

// `key` is shown once: 'sk_ab12cd34ef56xxxxxxxx...'
// `prefix` is 'sk_ab12cd34ef56' — safe to store client-side for display
```

### Validation (internal, happens inside middleware)

1. Extract key from `Authorization: Bearer sk_...` (or `X-API-Key` header).
2. SHA-256 hash → lookup `api_keys.key_hash`. 404 → `INVALID_API_KEY`.
3. Check expiry. Expired → `API_KEY_EXPIRED`.
4. Load appropriate grant table (server / personal / project) for the route type.
5. Load user's current scopes (from DB for server; from `req` for project).
6. `effective = declared ∩ current`. Check `effective ⊇ required`.
7. Non-blocking fire-and-forget update to `last_used_at`.
8. Populate `req.effectiveProjectScopes` / `req.apiKey`.

### Display

```json
{
  "id": 42,
  "name": "CI/CD Deploy Key",
  "prefix": "sk_ab12cd34ef56",
  "grants": {
    "server": [],
    "personal": ["personal:profile.read"],
    "projects": [
      { "projectId": "proj_acme-docs", "scopes": ["docs:read", "docs:write"] },
      { "projectId": "proj_acme-blog", "scopes": ["docs:read"] }
    ]
  },
  "expiresAt": 1775000000000,
  "createdAt": 1713400000000,
  "lastUsedAt": 1713500000000
}
```

Declared scopes are shown (what the key was issued for). Effective scopes at any moment depend on the user's current permissions and are not cached.

---

## 10. Security Properties

| Property | Mechanism |
|---|---|
| API key cannot exceed user's current permissions | `effective = declared ∩ current` computed at request time |
| Losing project access revokes API key access immediately | Intersection drops to `[]` without any DB mutation |
| Server scope grant requires grantor to hold the scope | `grantServerScope` validates at write time |
| Raw keys never stored | SHA-256 only; key returned once at creation |
| A key can never create other keys | `personal:apikeys.write` stripped from all API key grants |
| Session hijacking protected on high-stakes operations | `transferProjectOwnership` route should use `requireFreshAuth` |
| `last_used_at` never blocks request path | Fire-and-forget; failure is silent and non-fatal |
| Duplicate global grants impossible | Server/personal grants use separate tables with PK = `api_key_id` |

---

## 11. Migration from v3

| v3 | v4 |
|---|---|
| `config.roles` | Removed. Roles are app concerns. Use `config.serverScopes` and `config.projectScopes`. |
| `auth.assignRole(userId, role)` | `auth.grantServerScope(userId, scope, grantorId)` for server-level; app manages project membership |
| `auth.createApiKey(userId, scopes)` | `auth.createApiKey(userId, { name, grants: { server, personal, projects } })` |
| `req.scopes` | `req.effectiveProjectScopes` (project), `req.serverScopes` (server), or check via middleware |
| `auth.requireFreshAuth(['scope'])` | `auth.requireFreshAuth` + `auth.requireServerScope` or `auth.requireProjectAccess` |
| `user_roles` table | Removed |
| `roles` table | Removed |
| `api_keys.scopes` (JSON in row) | Three separate grant tables |
| `api_keys.api_key` (raw key) | `api_keys.key_hash` + `api_keys.key_prefix` |

---

## 12. Demo: Multi-Project App with Full Scoped Auth

This demo shows a document-collaboration app ("DocuFlow") that uses express-easy-auth v4. DocuFlow manages its own project membership in its own database. The auth library handles authentication, ownership, API key validation, and scope enforcement.

### App Database (DocuFlow's own DB, separate from auth)

```sql
-- DocuFlow manages its own membership. Auth library is not involved.
CREATE TABLE project_members (
  project_id   TEXT NOT NULL,
  user_id      INTEGER NOT NULL,
  permissions  TEXT NOT NULL,  -- JSON array of app-defined scope strings
  PRIMARY KEY (project_id, user_id)
);
```

### Setup

```js
// auth.js — shared auth instance
import { EasyAuth } from '@javagt/express-easy-auth';

export const auth = new EasyAuth({
  db: { path: './auth.db' },
  session: { secret: process.env.SESSION_SECRET, cookie: { secure: true } },
  webauthn: { rpName: 'DocuFlow', rpId: 'docuflow.app', origin: 'https://docuflow.app' },

  serverScopes: ['users.read', 'users.write', 'users.delete', 'projects.list'],

  projectScopes: ['docs:read', 'docs:write', 'docs:delete', 'members:read', 'members:manage'],
});
```

### App-Side Middleware: Loading Project Permissions

This middleware is the critical bridge between DocuFlow's membership model and the auth library's scope enforcement. It runs before `auth.requireProjectAccess` on any project route.

```js
// middleware/loadProjectPermissions.js
import { db } from '../db.js';        // DocuFlow's own database
import { auth } from '../auth.js';

export async function loadProjectPermissions(req, res, next) {
  const projectId = req.params.projectId || req.params.id;
  if (!projectId) return next(new Error('loadProjectPermissions: no projectId on req.params'));

  const userId = req.user?.id;
  if (!userId) return next(new Error('loadProjectPermissions must run after requireAuth'));

  try {
    // Owners bypass the membership table — they always have full access.
    const isOwner = await auth.isProjectOwner(projectId, userId);
    if (isOwner) {
      req.projectPermissions = ['*'];
      return next();
    }

    // Non-owners: load from DocuFlow's own membership table.
    const row = await db.get(
      'SELECT permissions FROM project_members WHERE project_id = ? AND user_id = ?',
      [projectId, userId]
    );

    // Not a member: empty array → auth.requireProjectAccess will return 403.
    req.projectPermissions = row ? JSON.parse(row.permissions) : [];
    next();
  } catch (err) {
    next(err);
  }
}
```

### Creating a Project

When DocuFlow creates a project, it must register it with the auth library so ownership and API key scoping work.

```js
// routes/projects.js
import { auth } from '../auth.js';
import { db } from '../db.js';

app.post('/projects',
  auth.requireAuth,
  async (req, res, next) => {
    try {
      const projectId = `proj_${crypto.randomUUID()}`;

      // 1. Create in DocuFlow's database.
      await db.run(
        'INSERT INTO projects (id, name, owner_id) VALUES (?, ?, ?)',
        [projectId, req.body.name, req.user.id]
      );

      // 2. Register with auth library (establishes ownership for API key scoping
      //    and requireProjectOwner middleware).
      await auth.registerProject(projectId, req.user.id);

      res.status(201).json({ id: projectId });
    } catch (err) {
      next(err);
    }
  }
);
```

### Project Routes

```js
// GET /projects/:id/docs — any member with docs:read
app.get('/projects/:id/docs',
  auth.requireAuthOrApiKey,
  loadProjectPermissions,
  auth.requireProjectAccess('docs:read'),
  async (req, res) => {
    // req.effectiveProjectScopes is set by the middleware above.
    // For API keys it's already been intersected with declared grants.
    const docs = await db.all('SELECT * FROM docs WHERE project_id = ?', [req.params.id]);
    res.json(docs);
  }
);

// POST /projects/:id/docs — needs docs:write
app.post('/projects/:id/docs',
  auth.requireAuthOrApiKey,
  loadProjectPermissions,
  auth.requireProjectAccess('docs:write'),
  createDoc
);

// DELETE /projects/:id — owner only, fresh session required
app.delete('/projects/:id',
  auth.requireAuth,          // no API keys for destructive operations
  auth.requireFreshAuth,
  auth.requireProjectOwner,
  async (req, res, next) => {
    try {
      await auth.unregisterProject(req.params.id);
      await db.run('DELETE FROM projects WHERE id = ?', [req.params.id]);
      res.status(204).end();
    } catch (err) {
      next(err);
    }
  }
);

// Transfer ownership — owner only, fresh session required
app.put('/projects/:id/owner',
  auth.requireAuth,
  auth.requireFreshAuth,
  auth.requireProjectOwner,
  async (req, res, next) => {
    try {
      const { newOwnerId } = req.body;
      await auth.transferProjectOwnership(req.params.id, newOwnerId);
      // Also update DocuFlow's own record if it keeps a denormalised owner field.
      await db.run('UPDATE projects SET owner_id = ? WHERE id = ?', [newOwnerId, req.params.id]);
      res.json({ ok: true });
    } catch (err) {
      next(err);
    }
  }
);
```

### Member Management (entirely app-side)

Member management is DocuFlow's responsibility. The auth library is not involved. When DocuFlow changes a user's permissions on a project, it updates its own `project_members` table. The auth library's scope enforcement picks this up automatically at the next request because `loadProjectPermissions` re-reads from DocuFlow's DB on every request.

```js
// PUT /projects/:id/members/:userId — requires members:manage
app.put('/projects/:id/members/:userId',
  auth.requireAuth,
  loadProjectPermissions,
  auth.requireProjectAccess('members:manage'),
  async (req, res, next) => {
    try {
      const { permissions } = req.body;  // ['docs:read', 'docs:write']

      // DocuFlow enforces its own ceiling: members:manage cannot grant permissions
      // they don't hold themselves. This is app logic, not auth library logic.
      const callerPerms = req.effectiveProjectScopes;
      if (callerPerms[0] !== '*') {
        const exceeds = permissions.filter(p => !callerPerms.includes(p));
        if (exceeds.length > 0) {
          return res.status(403).json({ error: 'Cannot grant permissions you do not hold' });
        }
      }

      await db.run(
        `INSERT INTO project_members (project_id, user_id, permissions)
         VALUES (?, ?, ?)
         ON CONFLICT(project_id, user_id) DO UPDATE SET permissions = excluded.permissions`,
        [req.params.id, req.params.userId, JSON.stringify(permissions)]
      );
      res.json({ ok: true });
    } catch (err) {
      next(err);
    }
  }
);
```

### Admin Routes (server scopes)

```js
// GET /admin/users — requires server scope users.read
app.get('/admin/users',
  auth.requireAuth,
  auth.requireServerScope('users.read'),
  async (req, res) => {
    const users = await auth.listUsers();
    res.json(users);
  }
);

// DELETE /admin/users/:id
app.delete('/admin/users/:id',
  auth.requireAuth,
  auth.requireFreshAuth,
  auth.requireServerScope('users.delete'),
  async (req, res, next) => {
    try {
      const result = await auth.deleteUser(Number(req.params.id));

      if (result.warnings.length > 0) {
        // In production: notify the deleted user's team, trigger an async
        // ownership-reassignment workflow, or archive orphaned projects.
        // Warnings are also returned to the admin caller for visibility.
        for (const w of result.warnings) {
          if (w.code === 'USER_OWNS_PROJECTS') {
            await myApp.flagOrphanedProjects(w.projectIds);
          }
        }
      }

      res.json({ deleted: true, warnings: result.warnings });
    } catch (err) {
      next(err);
    }
  }
);
```

### Personal Routes and API Key Management

```js
// GET /me — session or personal-scoped api key
app.get('/me',
  auth.requireAuthOrApiKey,
  auth.requirePersonalScope('personal:profile.read'),
  async (req, res) => {
    res.json(req.user);
  }
);

// GET /me/api-keys — list keys (session or api key with personal:apikeys.read)
app.get('/me/api-keys',
  auth.requireAuthOrApiKey,
  auth.requirePersonalScope('personal:apikeys.read'),
  async (req, res) => {
    const keys = await auth.listApiKeys(req.user.id);
    res.json(keys);
  }
);

// POST /me/api-keys — CREATE: session only (personal:apikeys.write blocks api keys)
app.post('/me/api-keys',
  auth.requireAuthOrApiKey,
  auth.requirePersonalScope('personal:apikeys.write'),  // rejects api key callers
  async (req, res, next) => {
    try {
      const { name, grants, expiresAt } = req.body;

      // Recommended: validate project scopes don't exceed user's current permissions
      // before calling createApiKey. Auth library enforces via intersection at runtime,
      // but surfacing this early gives a better developer/user experience.
      if (grants.projects) {
        for (const g of grants.projects) {
          const isOwner = await auth.isProjectOwner(g.projectId, req.user.id);
          if (!isOwner) {
            const membership = await myApp.getProjectMembership(g.projectId, req.user.id);
            if (!membership) {
              return res.status(403).json({ error: `Not a member of project ${g.projectId}` });
            }
            const exceeds = g.scopes.filter(s => !membership.permissions.includes(s));
            if (exceeds.length > 0) {
              return res.status(403).json({
                error: `Scopes exceed your permissions on ${g.projectId}`,
                scopes: exceeds
              });
            }
          }
        }
      }

      const result = await auth.createApiKey(req.user.id, { name, grants, expiresAt });

      // Key is returned once here. After this response, it is gone.
      res.status(201).json(result);
    } catch (err) {
      next(err);
    }
  }
);

// DELETE /me/api-keys/:keyId — revoke; session only (same reason as create)
app.delete('/me/api-keys/:keyId',
  auth.requireAuth,
  async (req, res, next) => {
    try {
      await auth.revokeApiKey(req.user.id, Number(req.params.keyId));
      res.status(204).end();
    } catch (err) {
      next(err);
    }
  }
);
```

### Syncing Projects from App to Auth — Integration Notes

The auth library should be treated as a secondary store for the fields it needs. The app's database is the source of truth for everything else. The sync contract is:

| App event | Auth library call |
|---|---|
| User creates a project | `auth.registerProject(projectId, ownerId)` |
| User deletes a project | `auth.unregisterProject(projectId)` |
| Owner transfers ownership via UI | `auth.transferProjectOwnership(projectId, newOwnerId)` |
| Admin deletes a user | `auth.deleteUser(userId)` → handle `USER_OWNS_PROJECTS` warnings |
| Permissions change on a project | Nothing — app updates its own DB; auth picks up on next request |

**Idempotency:** `registerProject` should be safe to call multiple times with the same ID (upsert). This makes it safe to call during project creation retries or re-sync jobs.

**Consistency:** If the app's `registerProject` call fails after the project row is created in the app DB, the project exists in the app but not in auth. The symptom: `auth.requireProjectOwner` fails and API key project grants for that ID are rejected. The fix: retry `registerProject` on startup or via a background sync job. The library docs should describe this failure mode explicitly.
