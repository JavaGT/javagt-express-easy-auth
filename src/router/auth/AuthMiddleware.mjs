import { ERROR, AuthError } from './util/errors.mjs';
import MultiError from './util/MultiError.mjs';
import { SESSION_ONLY_SCOPES } from './util/PersonalScopes.mjs';

export class AuthMiddleware {
    #authManager;

    constructor(authManager) {
        this.#authManager = authManager;

        this.useApiKey              = this.useApiKey.bind(this);
        this.requireAuth            = this.requireAuth.bind(this);
        this.requireAuthOrApiKey    = this.requireAuthOrApiKey.bind(this);
        this.requireFreshAuth       = this.requireFreshAuth.bind(this);
        this.requireServerScope     = this.requireServerScope.bind(this);
        this.requirePersonalScope   = this.requirePersonalScope.bind(this);
        this.requireProjectAccess   = this.requireProjectAccess.bind(this);
        this.requireProjectOwner    = this.requireProjectOwner.bind(this);
        this.rateLimit              = this.rateLimit.bind(this);
    }

    // -------------------------------------------------------------------------
    // Key extraction & Resolution
    // -------------------------------------------------------------------------

    #extractApiKey(req) {
        if (req.headers['x-api-key']) return req.headers['x-api-key'];
        const auth = req.headers['authorization'];
        if (auth?.startsWith('Bearer sk_')) return auth.slice('Bearer '.length);
        return null;
    }

    async #resolveSessionUser(req) {
        if (!req.session?.userId) return false;
        try {
            const user = await this.#authManager.getUserById(req.session.userId);
            if (!user) return false;
            req.user                = { id: user.id, email: user.email, display_name: user.display_name };
            req.lastAuthenticatedAt = req.session.lastAuthenticatedAt ?? 0;
            req.authType            = 'session';
            return true;
        } catch (err) {
            if (!(err instanceof MultiError) && !err.type) throw err;
            return false;
        }
    }

    async #resolveApiKeyUser(req, rawKey) {
        const keyToUse = rawKey || this.#extractApiKey(req);
        if (!keyToUse) return false;
        try {
            const authData = await this.#authManager.authenticateApiKey(keyToUse);
            req.user     = authData.user;
            req.apiKey   = { id: authData.keyId, name: authData.keyName, prefix: authData.keyPrefix, grants: authData.grants };
            req.authType = 'api_key';
            return true;
        } catch (err) {
            if (!(err instanceof MultiError) && !err.type) throw err;
            return false;
        }
    }

    // -------------------------------------------------------------------------
    // Core auth middleware
    // -------------------------------------------------------------------------

    async useApiKey(req, res, next) {
        try {
            const success = await this.#resolveApiKeyUser(req);
            if (!success) return next(new AuthError(ERROR.api_key_required));
            next();
        } catch (err) {
            next(err);
        }
    }

    async requireAuth(req, res, next) {
        try {
            const success = await this.#resolveSessionUser(req);
            if (!success) return next(new AuthError(ERROR.invalid_session));
            next();
        } catch (err) {
            next(err);
        }
    }

    async requireAuthOrApiKey(req, res, next) {
        try {
            if (await this.#resolveSessionUser(req)) return next();
            if (await this.#resolveApiKeyUser(req)) return next();
            next(new AuthError(ERROR.invalid_session));
        } catch (err) {
            next(err);
        }
    }

    /**
     * Require a fresh session (re-authenticated within the last 5 minutes).
     * Rejects API key auth. Can be used as plain middleware or as a factory
     * when you also need to check personal scopes on the same route.
     *
     * @example Plain middleware
     * app.delete('/account', auth.requireFreshAuth, handler);
     *
     * @example Factory with scope check
     * app.post('/me/something', auth.requireFreshAuth(['personal:auth.write']), handler);
     */
    requireFreshAuth(scopesOrReq, res, next) {
        if (Array.isArray(scopesOrReq)) {
            const scopes = scopesOrReq;
            return (req, res, next) => this.#runFreshAuth(req, res, next, scopes);
        }
        return this.#runFreshAuth(scopesOrReq, res, next, []);
    }

    async #runFreshAuth(req, res, next, requiredScopes = []) {
        if (req.authType === 'api_key') return next(new AuthError(ERROR.insufficient_scope, 'This action requires an interactive session and cannot be performed with an API key'));
        await this.requireAuth(req, res, (err) => {
            if (err) return next(err);
            const fresh = Date.now() - req.lastAuthenticatedAt <= 5 * 60 * 1000;
            if (!fresh) return next(new AuthError(ERROR.session_step_up_required));
            if (requiredScopes.length > 0) {
                return this.requirePersonalScope(requiredScopes)(req, res, next);
            }
            next();
        });
    }

    // -------------------------------------------------------------------------
    // Server-scope middleware
    // -------------------------------------------------------------------------

    /**
     * Factory. Checks that the authenticated identity holds the required server scope(s).
     * For API key callers: effective = declared ∩ user's current server scopes.
     *
     * @param {string|string[]} scopes
     */
    requireServerScope(scopes) {
        const required = Array.isArray(scopes) ? scopes : [scopes];
        return async (req, res, next) => {
            if (!req.user) return next(new AuthError(ERROR.invalid_session));
            try {
                const userScopes = await this.#authManager.getUserServerScopes(req.user.id);
                let effective;
                if (req.authType === 'api_key') {
                    const declared = req.apiKey?.grants?.server ?? [];
                    effective = declared.filter(s => userScopes.includes(s));
                } else {
                    effective = userScopes;
                }
                if (!required.every(s => effective.includes(s))) {
                    return next(new AuthError(ERROR.insufficient_scope));
                }
                req.serverScopes = effective;
                next();
            } catch (err) {
                next(err);
            }
        };
    }

    // -------------------------------------------------------------------------
    // Personal-scope middleware
    // -------------------------------------------------------------------------

    /**
     * Factory. Checks that the caller holds the required personal scope(s).
     * Session callers implicitly hold all personal scopes.
     * API key callers must have declared the scope; session-only scopes always reject API key callers.
     *
     * @param {string|string[]} scopes
     */
    requirePersonalScope(scopes) {
        const required = Array.isArray(scopes) ? scopes : [scopes];
        return (req, res, next) => {
            if (!req.user) return next(new AuthError(ERROR.invalid_session));

            const sessionOnly = required.filter(s => SESSION_ONLY_SCOPES.includes(s));
            if (sessionOnly.length > 0 && req.authType === 'api_key') {
                return next(new AuthError(
                    ERROR.insufficient_scope,
                    `${sessionOnly[0]} requires an interactive session and cannot be used with an API key`
                ));
            }

            if (req.authType === 'api_key') {
                const declared = req.apiKey?.grants?.personal ?? [];
                if (!required.every(s => declared.includes(s))) {
                    return next(new AuthError(ERROR.insufficient_scope));
                }
            }
            // Session callers implicitly hold all personal scopes.
            next();
        };
    }

    // -------------------------------------------------------------------------
    // Project-scope middleware
    // -------------------------------------------------------------------------

    /**
     * Factory. Checks that the caller has the required scope(s) on the current project.
     *
     * Requires:
     *   - req.user to be set (run requireAuth / requireAuthOrApiKey first)
     *   - req.projectPermissions to be set (run your loadProjectPermissions middleware first)
     *
     * Project ID is resolved from:
     *   req.params.projectId ?? req.params.id ?? req.projectId
     *
     * After successful check, sets req.effectiveProjectScopes.
     *
     * @param {string|string[]} scopes
     */
    requireProjectAccess(scopes) {
        const required = Array.isArray(scopes) ? scopes : [scopes];
        return (req, res, next) => {
            if (!req.user) return next(new AuthError(ERROR.invalid_session));

            if (req.projectPermissions === undefined) {
                return next(new AuthError(ERROR.project_permissions_not_loaded));
            }

            const currentPerms = req.projectPermissions;

            if (currentPerms.length === 0) {
                return next(new AuthError(ERROR.not_a_member));
            }

            let effective;
            if (req.authType === 'api_key') {
                const projectId = req.params?.projectId ?? req.params?.id ?? req.projectId;
                const declared  = req.apiKey?.grants?.projects?.[projectId] ?? [];
                effective = currentPerms.includes('*')
                    ? declared
                    : declared.filter(s => currentPerms.includes(s));
            } else {
                effective = currentPerms;
            }

            const hasAll = required.every(s => effective.includes(s) || effective.includes('*'));
            if (!hasAll) return next(new AuthError(ERROR.insufficient_scope));

            req.effectiveProjectScopes = effective;
            next();
        };
    }

    /**
     * Middleware. Checks that req.user is the owner of the current project.
     * Project ID resolved from: req.params.projectId ?? req.params.id ?? req.projectId
     *
     * Use for destructive operations (delete project, transfer ownership).
     */
    async requireProjectOwner(req, res, next) {
        if (!req.user) return next(new AuthError(ERROR.invalid_session));
        const projectId = req.params?.projectId ?? req.params?.id ?? req.projectId;
        if (!projectId) return next(new AuthError(ERROR.project_not_found, 'Could not resolve project ID from request'));
        try {
            const isOwner = await this.#authManager.isProjectOwner(projectId, req.user.id);
            if (!isOwner) return next(new AuthError(ERROR.not_project_owner));
            next();
        } catch (err) {
            next(err);
        }
    }

    // -------------------------------------------------------------------------
    // Rate limiting
    // -------------------------------------------------------------------------

    rateLimit(options = {}) {
        const windowMs = options.windowMs || 15 * 60 * 1000;
        const max      = options.max      || 100;
        const message  = options.message  || 'Too many requests, please try again later.';

        // Each rateLimit() call gets its own isolated store so independent
        // limiters (e.g. login vs register) do not share buckets.
        const store = new Map();
        setInterval(() => {
            const now = Date.now();
            for (const [ip, record] of store) {
                if (now > record.resetTime) store.delete(ip);
            }
        }, windowMs).unref();

        return (req, res, next) => {
            const ip  = req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress;
            const now = Date.now();

            if (!store.has(ip)) {
                store.set(ip, { count: 1, resetTime: now + windowMs });
                return next();
            }

            const record = store.get(ip);
            if (now > record.resetTime) {
                record.count = 1;
                record.resetTime = now + windowMs;
                return next();
            }

            record.count++;
            if (record.count > max) {
                return res.status(429).json({ success: false, error: 'TOO_MANY_REQUESTS', message });
            }
            next();
        };
    }

    // -------------------------------------------------------------------------
    // Error handling
    // -------------------------------------------------------------------------

    static errorHandler(err, req, res, next) {
        const { status, body } = AuthMiddleware.processError(err);
        res.status(status).json(body);
    }

    static processError(err) {
        if (err instanceof MultiError) {
            return { status: 400, body: { success: false, error: 'VALIDATION_FAILED', errors: err.errors } };
        }
        if (err.toJSON) {
            return { status: typeof err.code === 'number' ? err.code : 400, body: err.toJSON() };
        }
        return {
            status: typeof err.code === 'number' ? err.code : 500,
            body: { success: false, error: 'INTERNAL_ERROR', message: err.message || 'An unexpected error occurred' },
        };
    }
}
