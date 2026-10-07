# Changelog

All notable changes to this package are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.9.0] - 2026-10-07
## [0.9.1] - 2026-10-08

### Changed
- Minimum PHP version is now 8.2 (PHP 8.1 is end-of-life, and supported CodeIgniter releases require 8.2).

### Added
- Package-owned `users` table, extensible through host migrations and `$userAllowedFields`, or a custom `UserModel`.
- `auth_identities` credentials table with email, username and phone identifiers (configurable, globally unique) sharing one password.
- Identifier normalization, including E.164 phone normalization with a configurable default country code.
- Password hashing with transparent rehash, configurable policy, and timing-safe failed logins.
- Atomic `UserRegistrar` with field-keyed validation errors.
- Opaque bearer tokens (session tokens and API keys) stored as SHA-256 hashes, with abilities, expiry, idle timeout, per-user session cap and instant revocation.
- Session guard (web) and token guard (API) behind a single `service('auth')`.
- Role/permission authorization with wildcards, a super role, direct grants, multi-tenant scoping and config sync.
- Login throttling per identifier and IP.
- Route filters: `auth`, `can`, `role`, `tenant`.
- Helpers: `auth()`, `user()`, `user_id()`, `can()`, `can_any()`, `has_role()`, `auth_intended_url()`.
- CLI: `auth:publish`, `auth:sync`, `auth:user:create`, `auth:role`, `auth:token`, `auth:prune`.
- Events for registration, login, logout, failures, lockouts, password changes and token issue/revocation.

[Unreleased]: https://github.com/etus-ephraitech/ci4-auth/compare/v0.9.0...HEAD
[0.9.1]: https://github.com/etus-ephraitech/ci4-auth/compare/v0.9.0...v0.9.1
[0.9.0]: https://github.com/etus-ephraitech/ci4-auth/releases/tag/v0.9.0