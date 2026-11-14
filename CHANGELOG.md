# Changelog

All notable changes to this package are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.11.0] - 2026-11-14

### Added
- Roles edited in the app: `service('authRoles')` (`RoleManager`) creates, edits, re-permissions, releases and deletes roles. Roles it touches are marked `app_managed`; `auth:sync` leaves them alone, reports them as "managed in the app" and never prunes them. `release()` hands a config role back to `Config\Auth`. New migration adds `auth_roles.app_managed`.
- Module permissions: any namespace may provide `Config/AuthPermissions.php` extending `Ephraitech\Auth\Config\AuthPermissions`; its permissions, roles and matrix grants are merged into the config (the app's `Config\Auth` wins on clashes, grants are added). `auth:sync` names each module and what it added. Turn off with `$discoverModulePermissions = false`.
- `can_user($user, $permission)` checks a given user regardless of who is signed in, for services, commands, seeders and jobs.
- "Any of" checks as `'a|b'` everywhere a permission or role is accepted: `can()`, `can_any()`, `can_user()`, `has_role()`, the authorizer, and the `can:`/`role:` filters.
- `can:` and `role:` accept a leading guard (`can:session,documents.view`), replacing a separate `auth:session` on the same route.
- `auth:user:create` sets profile columns: `--first-name=Mark --job-title="Director"` (any column in `$userAllowedFields`), prompts for `$registrationFields`, and rejects unknown options instead of ignoring them.

### Fixed
- Commands read options from `$params` only. Reading `CLI::getOptions()` as well made a command run with `command()` inherit the calling process's options.
- `auth_intended_url()` crashed when an app's `$redirects` override lacked `afterLogin`; it now falls back to the default.

### Upgrading
- Run `php spark migrate -n "Ephraitech\Auth"`, then `php spark auth:sync --dry-run`.
- `can:` and `role:` already required sign-in; `auth:session` written beside them can be removed (use `can:session,...` where the guard matters).

## [0.10.3] - 2026-11-14

### Fixed
- The package ignored the app's `Config\Auth` on CodeIgniter 4.4 and later: `config(\Ephraitech\Auth\Config\Auth::class)` returns exactly the package class, so fresh installs ran on the package defaults (its 3 roles instead of the app's, unknown user columns). Every lookup now goes through `ConfigResolver::resolve()`, which prefers `Config\Auth` when it extends the package config. An `app/Config/Auth.php` that doesn't extend it is ignored with a logged warning that says how to fix it.
- Commands silently lost values given as `--option=value` (CodeIgniter's parser only reads `--option value`), so `auth:user:create --email=...` failed with "Provide --password". Both forms now work in every `auth:*` command.
- `auth:sync` rewrote every role-permission link on each run and reported them all as changes. It now writes only the difference.

### Added
- `auth:sync` prints the config class and file it read, how many roles and permissions that config defines, and every permission, role and role-permission link it created, updated, pruned, linked or unlinked. "Nothing to change" when the database already matches.
- `auth:sync --dry-run` shows those changes without writing them.
- `RbacSynchronizer::run($prune, $dryRun)` returns a `SyncReport` with the changes by name. `sync()` still returns counts; its `role_permission_links` now counts links added, and a new `role_permission_links_removed` counts links removed.

### Changed
- `codeigniter4/framework: ^4.7` moved from `require-dev` to `require`, so Composer refuses to install the package next to an older CodeIgniter.

### Upgrading
- Run `php spark auth:sync --dry-run` once after upgrading. If your app's roles were previously synced from the package defaults, it shows what the real sync will add.

## [0.10.2] - 2026-11-12

### Fixed
- `AfricasTalkingNotifier` reported messages as failed ("Delivery over 'sms' failed: Success") when Africa's Talking accepted them with status code 100 (Processed) or 102 (Queued); only 101 (Sent) was accepted. All three now count as accepted. The code had been delivered, but callers treated it as unsent.

## [0.10.0] - 2026-10-08

### Added
- One-time codes (`auth_one_time_codes`) for password reset and email/phone verification: hashed, single-use, expiring, attempt-limited, with resend cooldown.
- Pluggable delivery per channel through `NotifierInterface`: `EmailNotifier` (CodeIgniter Email), `AfricasTalkingNotifier` (SMS) and `LogNotifier` (development only).
- `PasswordResetFlow`: forgot/reset by emailed link or typed code. Never reveals whether an account exists; a reset revokes every token and signs out every browser.
- `VerificationFlow`: email/phone verification, with optional activation of pending users (`$activateOnVerification`).
- Web pages: login, logout, register, forgot/reset password, verify and change password. Bootstrap 5 views render inside the app's own layout (`$viewLayout`), can be overridden per page (`$views`) or copied with `auth:publish --views`. Registered with `service('auth')->routes($routes)`.
- JSON API: login, logout, logout-all, me, register, password forgot/reset/change, verify send/confirm, with consistent error shapes and status codes. Registered with `service('auth')->apiRoutes($routes)`. Response user shape customisable via `$apiUserTransformer`.
- `auth:prune` now also deletes expired one-time codes.
- New events: `IDENTIFIER_VERIFIED`.

### Fixed
- `Config/Registrar.php` was empty in 0.9.x, so the `auth`, `can`, `role` and `tenant` filter aliases were not registered in host apps.

### Upgrading
- Run `php spark migrate -n "Ephraitech\Auth"` to add the new table.
- Existing config overrides keep working: new table names, redirects and views fall back to package defaults.
## [0.9.1] - 2026-10-08
## [0.9.0] - 2026-10-07

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

[Unreleased]: https://github.com/etus-ephraitech/ci4-auth/compare/v0.10.0...HEAD
[0.10.0]: https://github.com/etus-ephraitech/ci4-auth/compare/v0.9.1...v0.10.0
[0.9.1]: https://github.com/etus-ephraitech/ci4-auth/compare/v0.9.0...v0.9.1
[0.9.0]: https://github.com/etus-ephraitech/ci4-auth/releases/tag/v0.9.0