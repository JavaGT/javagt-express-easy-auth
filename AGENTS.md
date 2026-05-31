# AGENTS.md - Express Easy Auth Core Development Guide

Welcome, Agent. This repository is built on **SOLID principles**, **Clean Code** disciplines, and **Modern JavaScript patterns**. Following this guide ensures architectural consistency and superior developer experience.

## 🏗️ Architectural Overview

The Express Easy Auth uses a decoupled, service-oriented architecture designed for extensibility and testability.

### 🛡️ Core Pillars
- **Single Responsibility (SRP)**: Business logic lives in `services/`, orchestration in `AuthManager`, and Express concerns in `AuthMiddleware`.
- **Interface Segregation (ISP) / Liskov Substitution (LSP)**: All data and contact interactions must adhere to the `DatabaseAdaptor` and `ContactAdaptor` protocols.
- **Dependency Inversion (DIP)**: `AuthManager` accepts service injections in its constructor. Always prefer injecting dependencies over instantiating them.

### 🔑 Middleware Patterns
Standardize on the explicit trilogy of guards in `AuthMiddleware`:
- `requireAuth` for human session flows.
- `useApiKey` for programmatic/worker flows.
- `requireAuthOrApiKey` for hybrid endpoints.
- `requireFreshAuth` for sensitive operations requiring recent re-verification.


## 🛠️ Protocols & Extensibility

### 🗄️ Database Adaptors
To add a new database provider (e.g., PostgreSQL):
1. **Extend** `DatabaseAdaptor` from `src/router/auth/database-adaptors/DatabaseAdaptor.mjs`.
2. **Implement** all 28+ required methods. Every method must be `async`.
3. **Register** it in your configuration passed to `AuthManager`.

### 📧 Contact Adaptors
To add a new contact method (e.g., Twilio for SMS):
1. **Extend** `ContactAdaptor` from `src/router/auth/contact-adaptors/ContactAdaptor.mjs`.
2. **Implement** `sendUserLoginCode`, `sendUserSignupCode`, etc.

## 📜 Clean Code Standards

- **Error Handling**: Never return `success: false` for failures. **Throw exceptions**.
  - Use `AuthError` or `ValidationError` from `util/index.mjs` paired with the `ERROR` constants.
  - **Standardized Response**: The `AuthMiddleware.errorHandler` automatically processes these into a unified JSON format (`{ success: false, error, message, ... }`).
  - **Client Propagation**: The `EasyAuthClient` captures these responses and re-throws them as JS `Error` objects, ensuring the `type` and nested `errors` (for multi-errors) are preserved as properties on the error instance.
  - **Internal Requirements**: If a login requirement is missing (like a TOTP code), throw a `MultiError` or `AuthError` containing the `TOTP_CODE_REQUIRED` type to trigger the correct frontend flow.
- **Function Size**: Aim for small, focused functions (4-10 lines). Decompose complex logic into private `#methods`.
- **Naming**: Use intention-revealing names. Booleans should use predicate phrasing (`hasTotpEnabled`).
- **Authorization**: Use `AuthManager.assignRole(userId, roleName)` for bootstrapping permissions. Avoid reaching into `databaseAdapter.db` directly.


## 🚀 Future Improvements Log (Living Document)

This section tracks technical debt and architectural enhancement ideas discovered during development.

| Area | Improvement Idea | Potential Benefit | Status |
| :--- | :--- | :--- | :--- |
| **Session** | Implement JWT-based stateless tokens as an option. | Improved scalability for distributed systems. | Planned |
| **Security** | Implement global Rate Limiting middleware. | Protection against brute-force and DDoS. | [Done] |
| **Storage** | Implement a modular Challenge store. | Distributed WebAuthn support. | [Done] |
| **DX** | Add OpenAPI/Swagger documentation generation. | Automatic, high-fidelity API reference. | [Done] |
| **Testing** | Implement a full testing suite for `AuthServices`. | High-confidence refactoring and regression testing. | Planned |

## 🧪 Verification Commands

- **Development**: `npm run dev` (Starts server with hot-reloading Demo 1).
- **Chat Demo**: `npm run dev:chat` (Starts Chat application demo).
- **Audit**: `npm audit` (Check for dependency vulnerabilities).

---
*Stay Clean. Stay SOLID.*
