# Ephraitech CI4 Auth: Developer Documentation

Oct 8, 2026 · @Mark Anold

## 1. Introduction

`ephraitech/ci4-auth` gives a CodeIgniter 4 application complete authentication and authorization in one Composer package: users, logins by email, username or phone, web sessions, API tokens, roles and permissions, multi-tenancy, password reset, verification, and ready-made web pages and JSON endpoints. This guide covers version 0.10.0.

What you get:

- **Flexible identifiers.** Users sign in with email, username, phone, or any combination, all sharing one password. Phone numbers are normalized, so `0772 123 456` and `+256772123456` are the same account.
- **Two guards, one API.** Cookie sessions for server-rendered apps and bearer tokens for APIs and mobile apps. `service('auth')` picks the right one per request.
- **Safe tokens.** Only SHA-256 hashes are stored. Abilities, expiry, idle timeout, a per-user device cap and instant revocation are built in.
- **Roles and permissions** with wildcards (`users.*`), a super role, direct grants, and config-driven sync.
- **Multi-tenancy.** Roles, grants and tokens can be scoped per tenant, with global roles for platform administrators.
- **Codes by email and SMS** for password reset and email/phone verification, with pluggable delivery (Africa's Talking included).
- **Ready-made flows.** Bootstrap 5 pages and JSON endpoints for login, registration, forgot/reset password, verification and change password. Both are optional and replaceable.
- **Secure defaults.** Timing-safe login failures, login throttling, session-fixation protection, sign-out everywhere on password change, and open-redirect protection.

### Requirements

| Requirement | Version |
| --- | --- |
| PHP | 8.2 or newer, with `mbstring` and `intl` |
| CodeIgniter | 4.5 or newer |
| Database | MySQL 5.7.7+ / MariaDB 10.2.2+, SQLite 3, or PostgreSQL |

### Where things live

- Package: [packagist.org/packages/ephraitech/ci4-auth](https://packagist.org/packages/ephraitech/ci4-auth)
- Source and issues: [github.com/etus-ephraitech/ci4-auth](https://github.com/etus-ephraitech/ci4-auth)
- Every configuration option is documented inline in `vendor/ephraitech/ci4-auth/src/Config/Auth.php`.

## 2. Installation and quick start

Five commands take a fresh CodeIgniter 4 app to working sign-in with a first administrator.

1. Install the package:

```bash
composer require ephraitech/ci4-auth
```

2. Publish an editable config to `app/Config/Auth.php`:

```bash
php spark auth:publish
```

3. Decide table names, identifiers and tenancy in that file **before** migrating (see section 4), then create the tables:

```bash
php spark migrate -n "Ephraitech\Auth"
```

4. Load the roles and permissions defined in config into the database:

```bash
php spark auth:sync
```

5. Create the first administrator. Omitted values are prompted for, and the password is read without echoing:

```bash
php spark auth:user:create --email=admin@example.com --role=superadmin --tenant=global --verified
```

Services, route filters, CLI commands and helper functions are discovered automatically. No changes to `Config\Filters`, `Config\Services` or `Config\Autoload` are needed.

### Add sign-in pages or API endpoints

In `app/Config/Routes.php`, register the built-in web pages, the JSON API, or both:

```php
service('auth')->routes($routes);      // /login, /register, /forgot-password, ...
service('auth')->apiRoutes($routes);   // /api/auth/login, /api/auth/me, ...
```

Enable CSRF for forms and exclude the API from it in `app/Config/Filters.php`:

```php
public array $globals = [
    'before' => [
        'csrf' => ['except' => ['api/*']],
    ],
];
```

### Protect your first route

```php
$routes->get('dashboard', 'Dashboard::index', ['filter' => 'auth:session']);
$routes->get('api/visits', 'Api\Visits::index', ['filter' => ['auth:token', 'can:visits.view']]);
```

Inside any controller or view:

```php
$user = user();                  // the signed-in User, or null
$id   = user_id();

if (can('visits.create')) {
    // ...
}
```

### Confirm the installation

```bash
php spark filter:check get /api/auth/me
```

The output should list `Ephraitech\Auth\Filters\AuthFilter` among the before filters. If it reports the `auth` alias as undefined, see section 21.

## 3. Core concepts

Six ideas explain the whole package: a user is a person, identities are their credentials, guards decide who is making a request, tokens carry API access, permissions decide what they may do, and tenants scope those permissions.

### Users and identities

The `users` table holds the person and nothing else: `id`, `uuid`, `status`, `status_reason`, `last_login_at`, `last_active_at` and timestamps. Your app adds its own profile columns (section 5).

Credentials live in `auth_identities`, one row per credential:

| Type | `identifier` column | `secret` column | Notes |
| --- | --- | --- | --- |
| `email` | `jane@example.com` (lowercased) | empty | Can receive codes |
| `username` | `jane.doe` (lowercased) | empty | Cannot receive codes |
| `phone` | `+256772123456` (E.164) | empty | Can receive codes by SMS |
| `password` | empty | bcrypt/argon2 hash | One per user, shared by all identifiers |

Each identifier is unique across the whole system, even in multi-tenant mode. Each has its own `verified_at`, so an email can be verified while a phone is not.

### User status

| Status | Can sign in | Typical use |
| --- | --- | --- |
| `active` | Yes | Normal accounts |
| `pending` | No | Awaiting verification or admin approval |
| `suspended` | No | Blocked by an administrator |
| `inactive` | No | Closed or dormant accounts |

Status problems are only revealed to someone who has just given the correct password.

### Guards

A guard answers "who is making this request?".

- **Session guard** (`session`): for server-rendered web apps. Stores the login in the PHP session and re-checks it on every request.
- **Token guard** (`token`): for APIs, mobile apps and integrations. Reads `Authorization: Bearer eph_...` on every request.

`service('auth')` chooses automatically: the token guard when the request carries a bearer token, otherwise the session guard. Route filters can force one (`auth:session`, `auth:token`). Guards are created lazily, so API requests never start a PHP session.

&#91;embedded content: request authentication · 2 guards, 1 permission check\]

A bearer token selects the token guard; anything else uses the session guard. Both end in the same permission check, where token abilities and the active tenant narrow what the user's roles allow.

### Tokens

All tokens live in one table, `auth_access_tokens`, in two kinds:

| Kind | Issued by | Expires | Counts toward device cap |
| --- | --- | --- | --- |
| Session token | API login | 30 days by default, optional idle timeout | Yes (10 by default) |
| API key | `auth:token issue` or `TokenManager::issueApiKey()` | Optional | No |

Only the SHA-256 hash is stored; the plaintext is shown once. Revocation takes effect on the very next request.

### Roles, permissions and abilities

- A **permission** is a dotted name such as `visits.create`.
- A **role** groups permissions. The matrix in config maps roles to permissions and supports wildcards (`visits.*`, `*`).
- The **super role** (`superadmin` by default) passes every check.
- A **direct grant** gives one user one permission without a role.
- A token's **abilities** are a ceiling: a token can never do more than its user, and a token limited to `reports.view` can only view reports, even for a superadmin.

### Tenants

In multi-tenant mode, role assignments, direct grants and tokens carry a tenant ID. A check inside tenant X sees the user's global assignments plus their tenant X assignments, never another tenant's (section 13).

## 4. Configuration reference

All settings live in `Ephraitech\Auth\Config\Auth`. Your `app/Config/Auth.php` extends it, so you declare only what you change; everything else follows the package defaults, including options added in future versions.

```php
<?php

namespace Config;

use Ephraitech\Auth\Config\Auth as BaseAuth;

class Auth extends BaseAuth
{
    public array $identifiers      = ['email', 'phone'];
    public array $loginIdentifiers = ['email', 'phone'];
}
```

Scalar values can also be set from `.env`, for example `auth.maxLoginAttempts = 3`. Invalid combinations throw a clear `LogicException` when the services first start, not halfway through a request.

### Database and users

| Option | Default | Purpose |
| --- | --- | --- |
| `$DBGroup` | `null` | Database group; `null` uses your default |
| `$tables` | `users`, `auth_identities`, ... | Table names; keys you omit fall back to defaults |
| `$userModel` | package `UserModel` | Model class for users; must extend the package model |
| `$userAllowedFields` | `[]` | Extra user columns your migration added |
| `$useUuid` | `true` | Give every user a UUID for public use |
| `$defaultUserStatus` | `active` | Status for new users |

### Identifiers

| Option | Default | Purpose |
| --- | --- | --- |
| `$identifiers` | `['email']` | Identifier types that exist: `email`, `username`, `phone` |
| `$loginIdentifiers` | `['email']` | Types usable to sign in (subset of the above) |
| `$requiredIdentifiers` | `['email']` | Types required at registration; must include a login type |
| `$detectLoginIdentifier` | `true` | Detect the type from a single login field |
| `$requireVerifiedToLogin` | all `false` | Per type: must be verified before sign-in |
| `$emailMaxLength` | `254` | Maximum email length |
| `$usernameMinLength` / `$usernameMaxLength` | `3` / `30` | Username length limits |
| `$usernamePattern` | letters, digits, `.` `_` `-` | Allowed username shape (after lowercasing) |
| `$reservedUsernames` | `root`, `system`, `api`, ... | Usernames nobody can register |
| `$phoneDefaultCountryCode` | `256` | Country code applied to local numbers |
| `$phoneMinDigits` / `$phoneMaxDigits` | `8` / `15` | Digits including the country code |

### Passwords

| Option | Default | Purpose |
| --- | --- | --- |
| `$hashAlgorithm` | `PASSWORD_DEFAULT` (bcrypt) | Passed to `password_hash()` |
| `$hashOptions` | `[]` | e.g. `['cost' => 12]` |
| `$passwordMinLength` | `8` | Minimum characters |
| `$passwordMaxLength` | `72` | Bcrypt's byte limit; raise only with Argon2id |
| `$passwordRequireUppercase` / `Lowercase` / `Symbol` | `false` | Character rules |
| `$passwordRequireNumber` | `true` | Require a digit |
| `$passwordDisallowIdentifiers` | `true` | Reject passwords containing the user's email, username or phone |

### Sessions, tokens and throttling

| Option | Default | Purpose |
| --- | --- | --- |
| `$sessionKey` | `ephraitech_auth` | Session key for the web login |
| `$sessionIdleTimeout` | `0` (off) | Sign out web users after N idle seconds |
| `$regenerateSessionOnLogin` | `true` | New session ID at login (anti-fixation) |
| `$tokenPrefix` | `eph_` | Prefix on every issued token |
| `$tokenBytes` | `32` | Random bytes per token |
| `$tokenHeader` | `Authorization` | Header carrying the bearer token |
| `$sessionTokenLifetime` | `2592000` (30 days) | Absolute lifetime of API session tokens |
| `$sessionTokenIdleTimeout` | `0` (off) | Expire session tokens unused for N seconds |
| `$apiKeyLifetime` | `null` (never) | Default API key lifetime |
| `$tokenLastUsedUpdateInterval` | `60` | Seconds between `last_used_at` writes |
| `$maxSessionTokensPerUser` | `10` | Device cap; oldest revoked first; `0` = unlimited |
| `$defaultTokenAbilities` | `['*']` | Abilities when none are requested |
| `$maxLoginAttempts` | `5` | Failures allowed per identifier and IP |
| `$loginAttemptWindow` / `$lockoutDuration` | `900` / `900` | Seconds |
| `$recordSuccessfulLogins` | `true` | Keep successful logins as an audit trail |
| `$loginAttemptRetentionDays` | `90` | Pruned by `auth:prune` |

### Tenancy and authorization

| Option | Default | Purpose |
| --- | --- | --- |
| `$tenancy` | `single` | `single` or `multi` |
| `$tenantHeader` | `X-Tenant-ID` | Header read by the `tenant` filter |
| `$superRole` | `superadmin` | Role that passes every check; `null` disables |
| `$defaultRoles` | `['user']` | Roles given to new registrations |
| `$roles` | `superadmin`, `admin`, `user` | Role name => title and description |
| `$permissions` | `users.*`, `roles.manage`, `tokens.manage` | Permission => description |
| `$matrix` | see config | Role => permissions, with wildcards |

### Codes and delivery

| Option | Default | Purpose |
| --- | --- | --- |
| `$otpLength` | `6` | Digits per code |
| `$otpLifetime` | `900` | Seconds a code stays valid |
| `$otpMaxAttempts` | `5` | Wrong guesses before a code stops working |
| `$otpResendInterval` | `60` | Seconds between codes to one identifier |
| `$otpRetentionDays` | `7` | Pruned by `auth:prune` |
| `$activateOnVerification` | `false` | Turn `pending` users `active` when they verify |
| `$notifiers` | email: `EmailNotifier`, sms: `null` | Delivery class per channel |
| `$emailFromAddress` / `$emailFromName` | empty (use `Config\Email`) | Sender for auth emails |
| `$appName` | empty | Product name in emails and SMS |
| `$africasTalkingUsername` / `ApiKey` / `SenderId` | empty | Set in `.env` |
| `$africasTalkingSandbox` | `false` | Use the sandbox endpoint |

### Web pages and API

| Option | Default | Purpose |
| --- | --- | --- |
| `$redirects` | `login`, `afterLogin`, `afterLogout`, `forbidden`, `afterRegister` | Redirect targets; missing keys fall back |
| `$allowRegistration` | `true` | Self-registration on web and API |
| `$registrationFields` | `[]` | Extra columns on the signup form: column => label |
| `$viewLayout` / `$viewSection` | package layout / `content` | Layout the pages render in |
| `$views` | `[]` | Per-page view overrides |
| `$apiUserTransformer` | package `UserTransformer` | Shapes the user in API responses |
| `$apiDefaultDeviceName` | `API client` | Token name when none is sent |
| `$apiResetLink` / `$apiVerifyLink` | `null` | Deep-link templates with `{selector}` and `{code}` |

## 5. Users and identifiers

The package owns a lean `users` table; you extend it with your own columns, and optionally your own model and entity, without touching package code.

### Add your own user columns

Write a normal migration in your app:

```php
class AddProfileFieldsToUsers extends \CodeIgniter\Database\Migration
{
    public function up(): void
    {
        $this->forge->addColumn('users', [
            'first_name' => ['type' => 'VARCHAR', 'constraint' => 100, 'null' => true],
            'last_name'  => ['type' => 'VARCHAR', 'constraint' => 100, 'null' => true],
        ]);
    }

    public function down(): void
    {
        $this->forge->dropColumn('users', ['first_name', 'last_name']);
    }
}
```

Then allow the columns in `app/Config/Auth.php`:

```php
public array $userAllowedFields = ['first_name', 'last_name'];
```

The package model merges them into its `allowedFields`, so `insert()`, `update()` and the registrar accept them.

### Use your own model and entity

For relationships, casts, validation or helper methods, extend the package classes:

```php
namespace App\Entities;

class User extends \Ephraitech\Auth\Entities\User
{
    public function getFullName(): string
    {
        return trim($this->attributes['first_name'] . ' ' . $this->attributes['last_name']);
    }
}
```

```php
namespace App\Models;

class UserModel extends \Ephraitech\Auth\Models\UserModel
{
    protected $returnType    = \App\Entities\User::class;
    protected $allowedFields = ['first_name', 'last_name'];

    protected $validationRules = [
        'first_name' => 'required|max_length[100]',
    ];
}
```

```php
public string $userModel = \App\Models\UserModel::class;
```

The base columns (`uuid`, `status`, ...) are always merged into `allowedFields`, so a subclass can't lock them out. Validation rules on your model are reported as field errors during registration.

The package always loads its own models with `preferApp => false`, so an existing `App\Models\UserModel` is only used when `$userModel` points at it.

### The User entity

```php
$user->id;              // int
$user->uuid;            // public identifier for URLs and APIs
$user->status;          // active | pending | suspended | inactive
$user->email;           // from auth_identities, loaded once per entity
$user->username;
$user->phone;           // E.164, e.g. +256772123456

$user->isActive();
$user->hasVerified('email');
$user->getIdentity('phone');   // Identity entity or null
$user->refreshIdentities();    // reload after changing an identifier
```

### Choosing identifiers

| Project type | `$identifiers` | `$loginIdentifiers` | `$requiredIdentifiers` |
| --- | --- | --- | --- |
| Email-only web app (default) | `email` | `email` | `email` |
| Mobile app in Uganda | `email`, `phone` | `email`, `phone` | `phone` |
| School system | `username`, `phone` | `username`, `phone` | `username` |
| Staff system with SSO-style usernames | `email`, `username` | `username` | `email`, `username` |

With several login identifiers, users type into a single field and the type is detected: input containing `@` is an email, input of digits and phone punctuation with at least 7 digits is a phone, anything else is a username.

### Normalization

Every identifier is normalized before it is stored or looked up, so lookups never depend on how someone typed it.

| Type | Rule | Example input | Stored as |
| --- | --- | --- | --- |
| Email | Trim, lowercase, validate | `  Jane@Example.COM ` | `jane@example.com` |
| Username | Trim, lowercase, length, pattern, reserved list | `Jane.Doe` | `jane.doe` |
| Phone | Strip punctuation, add default country code, E.164 | `0772 123 456` | `+256772123456` |

All of these phone inputs resolve to the same account with the default country code `256`: `0772123456`, `772123456`, `256772123456`, `+256 772 123 456`, `00256772123456`, `(0772) 123-456`. Numbers entered with `+` keep their own country code.

### Changing identifiers in code

```php
$identities = model(\Ephraitech\Auth\Models\IdentityModel::class);

$identities->setIdentifier($userId, 'phone', '0772 123 456');          // add or replace
$identities->setIdentifier($userId, 'email', 'new@example.com', true); // mark verified
$identities->markVerified($userId, 'email');
$identities->removeIdentifier($userId, 'username');
$identities->identifierExists('email', 'jane@example.com');
```

Changing a value clears its verification. A value already used by another account throws `IdentifierTakenException`; invalid input throws `InvalidIdentifierException` with a message safe to show on profile forms.

## 6. Registration

`service('authRegistrar')->register()` creates the user row, normalized identities, password hash and default roles in one transaction: a registration fully succeeds or leaves no trace. The built-in register page and API endpoint both use it.

```php
use Ephraitech\Auth\Exceptions\RegistrationException;

try {
    $user = service('authRegistrar')->register(
        identifiers: [
            'email' => $this->request->getPost('email'),
            'phone' => $this->request->getPost('phone'),
        ],
        password: $this->request->getPost('password'),
        attributes: [
            'first_name' => $this->request->getPost('first_name'),
        ],
        options: ['status' => 'pending'],
    );
} catch (RegistrationException $e) {
    return redirect()->back()->with('errors', $e->getFirstErrors());
}
```

### Arguments

| Argument | Type | Notes |
| --- | --- | --- |
| `identifiers` | `array<type, raw value>` | Empty values are ignored; every required identifier must be present |
| `password` | `?string` | `null` only with the `passwordOptional` option |
| `attributes` | `array<column, value>` | Must be in your profile columns (section 5) |
| `options` | `array` | See below |

### Options

| Option | Default | Effect |
| --- | --- | --- |
| `status` | `$defaultUserStatus` | Initial status, e.g. `pending` until verified |
| `roles` | `$defaultRoles` | Roles to assign instead of the defaults |
| `tenant` | current tenant | Tenant for those roles; `''` = global |
| `verified` | `[]` | Identifier types to mark verified (trusted sources only) |
| `enforcePolicy` | `true` | `false` skips password rules (seeders, CLI) |
| `passwordOptional` | `false` | Allow invites without a password |

### Errors

- **`RegistrationException`**: user-facing problems, keyed by form field. `getErrors()` returns every message per field, `getFirstErrors()` one per field, `getFlatErrors()` a flat list. Example: `['email' => ['This email address is already in use.'], 'password' => [...]]`.
- **`AuthException`**: developer mistakes, such as passing `status` or `uuid` in `attributes`, or a column not registered in `$userAllowedFields`. These fail loudly instead of being silently dropped.

All problems are collected before anything is written, so users see every error in one submission. If two people claim the same email at the same instant, the database's unique index rejects one, the whole transaction rolls back, and that person still gets a normal field error.

### Examples

An invited user who sets a password later:

```php
service('authRegistrar')->register(['email' => 'new@example.com'], null, [], ['passwordOptional' => true]);
```

A seeded global superadmin:

```php
service('authRegistrar')->register(
    ['email' => 'admin@example.com'],
    'Initial-Admin-2026',
    options: ['roles' => ['superadmin'], 'tenant' => '', 'verified' => ['email']],
);
```

The `REGISTERED` event fires only after the transaction commits, so a welcome message is never sent for an account that was rolled back.

## 7. Web authentication (session guard)

For server-rendered apps, `auth()->session()` signs users in with a PHP session, re-checks the login on every request, and signs them out everywhere when their password changes. Use the built-in pages (section 9) or call the guard from your own controllers.

### Sign in from your own controller

```php
use Ephraitech\Auth\Exceptions\{AccountNotActiveException, IdentifierNotVerifiedException,
    InvalidCredentialsException, LockedOutException};

public function login()
{
    try {
        auth()->session()->attempt(
            (string) $this->request->getPost('login'),
            (string) $this->request->getPost('password'),
        );
    } catch (InvalidCredentialsException | LockedOutException | AccountNotActiveException $e) {
        return redirect()->back()->with('error', $e->getMessage());
    } catch (IdentifierNotVerifiedException $e) {
        // $e->getUserId(), $e->getIdentifierType(): send them to verify (section 11)
        return redirect()->to('/verify');
    }

    return redirect()->to(auth_intended_url());
}
```

| Exception | Meaning | Safe to show? |
| --- | --- | --- |
| `InvalidCredentialsException` | Wrong login or password (same message for both) | Yes |
| `LockedOutException` | Too many failures; `getRetryAfter()` in seconds | Yes |
| `AccountNotActiveException` | Correct password, but suspended, pending or inactive; `getStatus()`, `getReason()` | Yes |
| `IdentifierNotVerifiedException` | Correct password, identifier must be verified first | Yes |

### Session guard methods

```php
$guard = auth()->session();

$guard->attempt($login, $password, ?$type);   // verify + sign in, returns User
$guard->login($user);                         // sign in an already-verified user (after OTP, signup)
$guard->check();                              // bool
$guard->user();                               // ?User
$guard->id();                                 // ?int
$guard->loggedInAt();                         // ?int unix time of this login
$guard->refresh();                            // re-stamp after the user changed their own password
$guard->logout();
```

### What is checked on every request

1. The user still exists and is `active`.
2. The idle timeout has not passed (`$sessionIdleTimeout`).
3. The password has not changed since this session began. The session stores a fingerprint of the password hash, so a password change or reset signs out every other browser.

Activity is written at most once a minute, so busy pages don't write to the database on every request.

### Logout must be a POST

Put a small form in your layout, so a link or image on another site can't sign your users out:

```php
<form method="post" action="<?= url_to('auth.logout') ?>">
    <?= csrf_field() ?>
    <button type="submit" class="btn btn-link">Sign out</button>
</form>
```

### Returning users to where they were

When the `auth` filter blocks a guest, it remembers the page they wanted. After sign-in, `auth_intended_url()` returns that page, or `$redirects['afterLogin']` when there is none. Only same-site URLs are ever returned, so a crafted link cannot bounce users to another site after login.

## 8. API authentication (tokens and API keys)

APIs, mobile apps and integrations authenticate with opaque bearer tokens: `Authorization: Bearer eph_...`. The built-in API endpoints (section 10) cover login and logout; this section is for issuing and managing tokens in your own code.

### Issue a token after your own login logic

```php
$new = auth()->token()->attempt($login, $password, deviceName: 'Tecno Spark 20');

return $this->response->setJSON($new->toArray());
```

`toArray()` returns:

```json
{
  "token": "eph_Q2x...",
  "token_type": "Bearer",
  "type": "session",
  "name": "Tecno Spark 20",
  "abilities": ["*"],
  "expires_at": "2026-11-07 10:00:00"
}
```

The plaintext token exists only in that response. Store it on the device; the server keeps only its SHA-256 hash.

For a user you have already verified another way (OTP, social login, just registered), skip the password:

```php
$new = auth()->token()->issueFor($user, 'Field Tracker Android', abilities: ['visits.*']);
```

### Token guard methods

```php
$guard = auth()->token();

$guard->user();               // ?User for the bearer token on this request
$guard->token();              // ?AccessToken
$guard->logout();             // revoke this token
$guard->logoutEverywhere();   // revoke every session token of this user
```

### API keys for integrations

API keys are long-lived tokens for server-to-server use. They are not idle-expired and don't count toward the device cap.

```php
$tokens = service('authTokens');

$key = $tokens->issueApiKey(
    userId: $user->id,
    name: 'Reports integration',
    abilities: ['reports.view', 'reports.export'],
    lifetimeSeconds: 90 * 86400,   // null = never expires
);

echo $key->plaintext;   // show once
```

From the terminal: `php spark auth:token issue admin@example.com "Reports integration" --abilities=reports.* --days=90`.

### Abilities

Abilities limit what a token may do, below what its user may do. A permission check passes only when **both** the user holds the permission and the token's abilities allow it.

| Ability | Allows |
| --- | --- |
| `*` | Everything the user may do (the default) |
| `reports.*` | Every permission starting with `reports.` |
| `reports.view` | Only that permission |

This holds even for superadmins: a key issued with `['reports.view']` cannot delete users.

### Managing tokens

```php
$tokens = service('authTokens');

$tokens->listForUser($userId, 'session');             // active tokens, newest first
$tokens->revoke($tokenId, $userId);                   // only if it belongs to $userId
$tokens->revokePlaintext($plaintext);
$tokens->revokeAllForUser($userId, 'api_key');        // returns revoked IDs
$tokens->validate($plaintext);                        // ?AccessToken
```

Revocation is instant: the next request with that token is rejected. Each `AccessToken` offers `isSession()`, `isApiKey()`, `isExpired()`, `abilityList()`, `allows($permission)` and `tenant()`.

### Lifetimes and limits

- Session tokens expire after `$sessionTokenLifetime` (30 days), and optionally after `$sessionTokenIdleTimeout` of inactivity.
- A user may hold `$maxSessionTokensPerUser` (10) session tokens; signing in on another device revokes the oldest.
- `last_used_at` is written at most every `$tokenLastUsedUpdateInterval` (60) seconds, not on every request.
- Changing or resetting a password revokes the user's tokens (a change keeps the device that made it).

## 9. Built-in web pages

One line in `app/Config/Routes.php` gives a web app complete sign-in, registration, password reset, verification and change-password pages, styled with Bootstrap 5 and rendered inside your own layout.

```php
service('auth')->routes($routes);

// Invite-only system, pages under /account:
service('auth')->routes($routes, except: ['register'], prefix: 'account');
```

| Method | Path | Route name | Group | Notes |
| --- | --- | --- | --- | --- |
| GET / POST | `login` | `auth.login` / `auth.login.attempt` | `login` |  |
| POST | `logout` | `auth.logout` | `logout` | POST only, with CSRF |
| GET / POST | `register` | `auth.register` / `auth.register.store` | `register` | Off when `$allowRegistration = false` |
| GET / POST | `forgot-password` | `auth.forgot` / `auth.forgot.send` | `forgot` | Same answer for every input |
| GET / POST | `reset-password` | `auth.reset` / `auth.reset.update` | `reset` | By email link or typed code |
| GET / POST | `verify` | `auth.verify` / `auth.verify.confirm` | `verify` |  |
| POST | `verify/resend` | `auth.verify.resend` | `verify` | Respects the resend cooldown |
| GET | `verify/link` | `auth.verify.link` | `verify` | Target of emailed verification links |
| GET / POST | `account/password` | `auth.password` / `auth.password.update` | `password` | Requires `auth:session` |

Pass group names in `except` to leave pages out. With a `prefix`, update `$redirects['login']` (for example `/account/login`); the package's own links follow the route names automatically.

### Render inside your layout

Point the pages at your app's layout so they get your header, navigation and CSS:

```php
public string $viewLayout  = 'layouts/main';
public string $viewSection = 'content';   // your layout calls renderSection('content')
```

Until you do, a minimal standalone layout with Bootstrap 5 from a CDN is used.

### Collect extra fields at signup

```php
public array $userAllowedFields  = ['first_name', 'last_name'];
public array $registrationFields = [
    'first_name' => 'First name',
    'last_name'  => 'Last name',
];
```

Each listed column becomes a text input on the register page and is validated by your user model's rules.

### Replace one page or all of them

Override a single page and keep the rest:

```php
public array $views = ['login' => 'pages/custom_login'];
```

View keys: `login`, `register`, `forgot`, `reset`, `verify`, `change_password`, `messages` (the flash-message partial).

For full control, copy every page into your app:

```bash
php spark auth:publish --views
```

The command prints the `$views` and `$viewLayout` lines to paste into your config.

### Variables available in the views

| Variable | Content |
| --- | --- |
| `$authLayout`, `$authSection` | Layout and section to extend |
| `$authViews` | Resolved view names, e.g. `$authViews['messages']` |
| `$authConfig` | The auth config |
| `$pageTitle` | Page title |
| `$old` | Safe values to re-display after an error (never passwords) |
| `$errors` | Field errors: `field => message` |
| `$canRegister`, `$canReset` | Whether to show those links |
| `$loginLabel` | "Email", "Email or phone number", ... (login, forgot, reset) |
| `$passwordRules` | Plain-language password requirements (register, reset, change) |
| `$identifierFields`, `$registrationFields` | Fields to render (register) |
| `$mode`, `$selector`, `$code`, `$codeLength` | Reset mode: `link`, `code` or `expired` |
| `$type`, `$destination`, `$resendIn` | Verify page: identifier type, masked destination, seconds until resend |

Flash messages arrive as `session('message')` and `session('error')`.

### How the pages behave

- **Passwords never enter the session.** After a failed submit, only safe fields come back through `$old`; CodeIgniter's `withInput()` is never used.
- **Verification is seamless.** If login or signup needs verification, the user is parked, a code is sent, and they land on the verify page. A correct code signs them in.
- **Links never create sessions elsewhere.** An emailed verification link opened in the browser that just proved the password completes sign-in; opened anywhere else, it verifies and asks the person to sign in.
- **Reset links don't leak.** Pages carrying a code in the URL send `Referrer-Policy: no-referrer`.
- **Changing your password keeps you signed in** on this browser and signs out every other device.

## 10. Built-in API endpoints

`service('auth')->apiRoutes($routes)` registers ten JSON endpoints under `/api/auth`, calling the same flows as the web pages. Bodies may be JSON or form data; phone numbers and codes may be sent as JSON numbers.

```php
service('auth')->apiRoutes($routes);                                       // /api/auth/...
service('auth')->apiRoutes($routes, prefix: 'v1/auth', except: ['register']);
```

Remember to exclude the prefix from CSRF (section 2).

### Endpoints

| Method | Path | Auth | Body | Success |
| --- | --- | --- | --- | --- |
| POST | `login` |  | `login`, `password`, `device_name`?, `abilities`?, `tenant`? | 200 token + user |
| POST | `logout` | token |  | 200 |
| POST | `logout-all` | token |  | 200 |
| GET | `me` | token |  | 200 user |
| POST | `register` |  | identifiers, `password`, registration fields, `device_name`? | 201 |
| POST | `password/forgot` |  | `login` | 202, always |
| POST | `password/reset` |  | `password` + (`login`, `code`) or (`selector`, `code`) | 200 |
| POST | `password/change` | token | `current_password`, `password` | 200 |
| POST | `verify/send` | token, or `login` + `password` | `type`? | 202 |
| POST | `verify/confirm` | token, or `login` | `code`, `type`? | 200 |

Group names for `except`: `login`, `logout`, `me`, `register`, `password`, `change`, `verify`.

### Response shape

Success:

```json
{ "message": "Signed out.", "data": { } }
```

Error (the same shape the route filters return):

```json
{
  "status": 422,
  "error": "validation_failed",
  "message": "The given data was invalid.",
  "errors": { "password": "The password must contain at least one number." }
}
```

| Status | `error` | When |
| --- | --- | --- |
| 401 | `invalid_credentials` | Wrong login or password |
| 401 | `unauthenticated` | Missing, expired or revoked token |
| 403 | `account_inactive` | Correct password; includes `account_status` |
| 403 | `verification_required` | Correct password; identifier must be verified first |
| 403 | `no_tenant_access` | Login asked for a tenant the user doesn't belong to |
| 403 | `forbidden` | Missing permission (route filters) |
| 404 | `not_found` | Registration disabled |
| 409 | `already_verified` | Nothing left to verify |
| 422 | `validation_failed` | Missing or invalid fields; see `errors` |
| 422 | `invalid_code` | Wrong, expired or used code |
| 422 | `invalid_request` | Other invalid input |
| 429 | `locked_out` | Too many failed logins; `retry_after` + `Retry-After` header |
| 429 | `resend_too_soon` | Code requested again too soon; `retry_after` + header |
| 503 | `delivery_failed` | Code could not be sent |

### Login

```http
POST /api/auth/login
Content-Type: application/json

{ "login": "0772123456", "password": "...", "device_name": "Tecno Spark 20" }
```

```json
{
  "data": {
    "token": { "token": "eph_...", "token_type": "Bearer", "type": "session",
               "name": "Tecno Spark 20", "abilities": ["*"], "expires_at": "2026-11-07 10:00:00" },
    "user": { "...": "see below" }
  }
}
```

`abilities` (a list) narrows the token, never widens it. In multi-tenant mode, `tenant` binds the token to that tenant; a user without access gets 403 before any token is issued.

### The user object

```json
{
  "id": 12,
  "uuid": "3f2a9c1e-5b7d-4e8a-9c21-7d4e5f6a8b90",
  "status": "active",
  "identifiers": {
    "email": { "value": "jane@example.com", "verified": true },
    "phone": { "value": "+256772123456", "verified": false }
  },
  "profile": { "first_name": "Jane" },
  "roles": ["user"],
  "permissions": ["visits.view"],
  "last_login_at": "2026-10-08T09:12:00+03:00",
  "created_at": "2026-09-30T14:02:11+03:00"
}
```

`profile` holds your `$userAllowedFields`. `permissions` are filtered through the current token's abilities, so the client sees exactly what this token can do. To return a different shape, implement `UserTransformerInterface` (section 17).

### Verification during login

```json
{
  "status": 403,
  "error": "verification_required",
  "message": "Please verify your phone number before signing in.",
  "identifier_type": "phone",
  "destination": "+2567•••••456",
  "code_sent": true,
  "resend_in": 60
}
```

A code has already been sent. The app then calls `verify/confirm` with `{ "login": "0772123456", "code": "482913" }` and, on 200, repeats the login with the password it still holds. To resend without a token, call `verify/send` with `login` and `password`.

### Registration outcomes

| Situation | Status | Body |
| --- | --- | --- |
| Account usable now | 201 | `token` + `user` |
| Verification required | 201 | `user` + `verification` (type, masked destination, `code_sent`) |
| Account created as pending | 201 | `user`, message about activation |

### Password reset

```http
POST /api/auth/password/forgot   { "login": "0772123456" }                                   → 202 (always)
POST /api/auth/password/reset    { "login": "0772123456", "code": "482913", "password": "..." } → 200
```

Forgot always returns the same 202, whether or not the account exists. A successful reset revokes every token, so the app should send the user to sign in again.

Set `$apiResetLink` (for example `fieldtracker://reset-password?s={selector}&c={code}`) to include a deep link in reset emails; the app then posts `selector`, `code` and `password` to `password/reset`.

## 11. Password reset, verification and code delivery

Password reset and email/phone verification both send a short numeric code, by email or SMS, through notifiers you configure per channel. The web pages and API use these flows; call them directly for custom screens.

### How codes work

- 6 digits by default, valid 15 minutes, 5 wrong guesses allowed.
- Single use. Issuing a new code invalidates the previous one for the same identifier and purpose.
- A new code to the same identifier needs a 60-second gap (`$otpResendInterval`).
- Only a hash is stored. Each code also has a random 32-character selector used in email links.
- Typos (letters, wrong length) don't count as guesses; spaces and dashes are ignored.

### Configure delivery

```php
use Ephraitech\Auth\Notifications\AfricasTalkingNotifier;
use Ephraitech\Auth\Notifications\EmailNotifier;

public string $appName          = 'Field Tracker';
public string $emailFromAddress = 'no-reply@example.com';
public string $emailFromName    = 'Field Tracker';

public array $notifiers = [
    'email' => EmailNotifier::class,           // CodeIgniter Email, Config\Email settings
    'sms'   => AfricasTalkingNotifier::class,  // null disables SMS
];
```

| Notifier | Channels | Notes |
| --- | --- | --- |
| `EmailNotifier` | email | HTML + plain-text email through `Config\Email` |
| `AfricasTalkingNotifier` | sms | Needs username and API key; optional sender ID; sandbox mode |
| `LogNotifier` | both | Writes codes to `writable/logs/`; refuses to run in production |

Africa's Talking credentials belong in `.env`, never in committed config:

```
auth.africasTalkingUsername = yourusername
auth.africasTalkingApiKey   = atsk_xxxxxxxx
auth.africasTalkingSenderId = YOURBRAND
```

If the SMS notifier is enabled without credentials, the app fails at startup with a clear message.

### Password reset in code

```php
$reset = service('authPasswordReset');

// 1. Request: returns nothing, behaves identically whether or not the account exists
$reset->request($login, $ipAddress, fn ($selector, $code) => url_to('auth.reset') . "?s={$selector}&c={$code}");

// 2a. Reset with the code the user typed
$user = $reset->resetWithCode($login, $code, $newPassword);

// 2b. Or with the emailed link
$user = $reset->resetWithLink($selector, $code, $newPassword);

$reset->linkIsUsable($selector);   // show the form or an "expired" page
```

- `request()` silently skips unknown accounts, suspended or inactive accounts, cooldowns and delivery failures. Failures are logged. Always show "If an account matches, we've sent a code."
- A username is delivered to that user's email, or their phone if there is no email.
- `WeakPasswordException` from a reset leaves the code usable, so the user can choose a better password.
- `InvalidCodeException` has one generic message for wrong, expired, used and unknown.
- A successful reset revokes every token, signs out every browser, invalidates other reset codes, and marks the identifier that received the code as verified.

### Verification in code

```php
$verify = service('authVerification');

$verify->send($user, 'phone', $ipAddress);              // may throw ResendTooSoonException, NotificationException
$user = $verify->confirm($user, 'phone', $code);        // known user
$user = $verify->confirmByIdentifier($login, $code);    // API clients not signed in
$user = $verify->confirmWithLink($selector, $code);     // emailed link

$verify->secondsUntilResend($user, 'phone');            // for a resend countdown
$verify->requiredFor($user);                            // first identifier that must be verified, or null
```

Unlike reset, verification reports problems honestly, because the user is signed in or has just proven their password.

### Require verification

```php
// Must verify email before signing in:
public array $requireVerifiedToLogin = ['email' => true, 'username' => false, 'phone' => false];

// Verify-before-use signups: register as pending, activate on verification
public string $defaultUserStatus      = 'pending';
public bool   $activateOnVerification = true;
```

Leave `$activateOnVerification` off when `pending` means "awaiting admin approval".

### Write your own notifier

For another SMS gateway, WhatsApp or a queue, implement one method. The constructor receives the auth config.

```php
namespace App\Notifications;

use Ephraitech\Auth\Config\Auth;
use Ephraitech\Auth\Exceptions\NotificationException;
use Ephraitech\Auth\Notifications\NotifierInterface;
use Ephraitech\Auth\Notifications\OneTimeCodeMessage;

final class YoUgandaSmsNotifier implements NotifierInterface
{
    public function __construct(private readonly Auth $config)
    {
    }

    public function send(OneTimeCodeMessage $message): void
    {
        // $message->destination  E.164 number or email
        // $message->text()       ready-made wording, including the code
        // $message->code, ->purpose, ->channel, ->link, ->expiresInMinutes, ->user

        $ok = $this->postToGateway($message->destination, $message->text());

        if (! $ok) {
            throw NotificationException::deliveryFailed($message->channel, 'gateway rejected the message');
        }
    }

    private function postToGateway(string $to, string $text): bool
    {
        // call your provider's HTTP API here and return whether it accepted the message
        return service('curlrequest')->post('https://gateway.example.com/send', [
            'form_params' => ['to' => $to, 'message' => $text],
            'http_errors' => false,
        ])->getStatusCode() < 300;
    }
}
```

```php
public array $notifiers = ['email' => EmailNotifier::class, 'sms' => \App\Notifications\YoUgandaSmsNotifier::class];
```

A notifier needing other constructor dependencies can be registered as an instance at runtime: `service('authNotifiers')->register('sms', $instance)`. Always throw `NotificationException` on failure, so the flows can tell users the code wasn't sent.

## 12. Authorization

Define roles and permissions in config, run `php spark auth:sync`, then check permissions with filters, helpers or the authorizer. Check permissions, not role names: permissions survive reorganising roles.

### Define roles and permissions

```php
public array $permissions = [
    'visits.view'    => 'View visits',
    'visits.create'  => 'Record visits',
    'visits.delete'  => 'Delete visits',
    'reports.view'   => 'View reports',
    'reports.export' => 'Export reports',
    'users.view'     => 'View users',
    'users.create'   => 'Create users',
];

public array $roles = [
    'superadmin' => ['title' => 'Super Admin', 'description' => 'Unrestricted access.'],
    'manager'    => ['title' => 'Manager', 'description' => 'Runs a field team.'],
    'agent'      => ['title' => 'Field agent', 'description' => 'Records visits.'],
];

public array $matrix = [
    'superadmin' => ['*'],
    'manager'    => ['visits.*', 'reports.*', 'users.view'],
    'agent'      => ['visits.view', 'visits.create'],
];

public array $defaultRoles = ['agent'];
```

Rules enforced at startup: permission names are dotted lowercase (`area.action`), every role in the matrix and in `$defaultRoles` must exist, and a wildcard must match at least one permission.

### Sync to the database

```bash
php spark auth:sync            # add and update
php spark auth:sync --prune    # also delete system roles/permissions removed from config
```

- Config entries are created or updated and flagged as system rows.
- Roles listed in `$matrix` get exactly the expanded permission set; wildcards are expanded at sync time, so request-time checks are plain lookups.
- Roles and permissions created at runtime (for example from an admin screen) and roles not listed in `$matrix` are never touched.
- The sync runs in one transaction; a failure changes nothing.

Run it after every deployment that changes these arrays.

### Check permissions

In routes:

```php
$routes->get('visits', 'Visits::index', ['filter' => 'can:visits.view']);
$routes->post('visits', 'Visits::store', ['filter' => 'can:visits.view,visits.create']);   // all
$routes->get('reports', 'Reports::index', ['filter' => 'can:any,reports.view,reports.export']);
```

In controllers and views:

```php
can('visits.create');                       // one permission
can(['visits.view', 'visits.create']);      // all of them
can_any(['reports.view', 'reports.export']);
has_role('manager');                        // any of the given roles

auth()->can('visits.delete');               // same as can(), on the AuthManager
```

These apply the current token's abilities and tenant automatically.

### Assign roles and grants

```php
$authz = service('authAuthorizer');

$authz->assignRole($user, 'manager');            // idempotent
$authz->removeRole($user, 'manager');
$authz->syncRoles($user, ['agent', 'manager']);  // replace roles in this tenant scope

$authz->grantPermission($user, 'reports.export');  // direct grant, no role needed
$authz->revokePermission($user, 'reports.export');

$authz->rolesFor($user);
$authz->permissionsFor($user);    // the super role receives every permission
$authz->isSuper($user);
$authz->usersWithRole('manager'); // list of user IDs
```

Every method accepts a `User` entity or a user ID, plus an optional tenant ID (section 13). Unknown role or permission names throw `AuthException` with a hint to define them and run `auth:sync`.

### Checking another user, or with a token's abilities

```php
$authz->can($otherUser, 'visits.view');
$authz->can($user, 'users.delete', null, ['users.view']);   // false: abilities are a ceiling
$authz->canAny($user, [...]);
$authz->canAll($user, [...]);
```

### Performance

A user's roles and permissions are loaded with three queries the first time they are checked in a request, then cached. Ten checks in a view cost the same as one. Any assignment change for that user clears their cache immediately.

## 13. Multi-tenancy

With `$tenancy = 'multi'`, one installation serves many tenants (schools, branches, client companies): a person has one account, and their roles and grants differ per tenant.

```php
public string $tenancy      = 'multi';
public string $tenantHeader = 'X-Tenant-ID';
```

### Scoping rules

- Identifiers (email, phone, username) are unique across all tenants: one person, one account.
- Role assignments, direct grants and tokens carry a tenant ID: an integer or a UUID string, up to 64 characters.
- An empty tenant ID (`''`) means **global**. Global assignments apply in every tenant.
- A check inside tenant X considers global assignments plus tenant X assignments, never another tenant's.
- When no tenant is passed, the active tenant (set by the `tenant` filter) is used, falling back to global.

```php
$authz = service('authAuthorizer');

$authz->assignRole($teacher, 'admin', 'school-12');   // admin only in school 12
$authz->assignRole($owner, 'superadmin', '');          // superadmin everywhere

$authz->can($teacher, 'users.view', 'school-12');      // true
$authz->can($teacher, 'users.view', 'school-40');      // false
$authz->can($owner, 'users.view', 'school-40');        // true
```

During a tenant request, an assignment made without a tenant argument lands in that tenant, never globally. Pass `''` explicitly to create a global assignment.

### The tenant filter

```php
$routes->group('api/school', ['filter' => ['auth:token', 'tenant:required']], static function ($routes) {
    $routes->get('students', 'Api\Students::index', ['filter' => 'can:students.view']);
});
```

Order matters: `auth` first, then `tenant`, then `can` or `role`.

| Situation | Result |
| --- | --- |
| Header present, user has roles or grants there (global counts) | Tenant set, request continues |
| Header names a tenant the user has no access to | 403 "You do not have access to this tenant." |
| Token bound to tenant A, header names tenant B | 403 |
| Token bound to a tenant, no header | That tenant is used |
| No header with `tenant:required` | 400 |
| Single-tenant mode | Filter does nothing |

### Tenant-bound tokens

```php
// API login with "tenant": "school-12" in the body, or in code:
service('authTokens')->issueSessionToken($user->id, 'Teacher tablet', null, 'school-12');
```

A bound token can only be used in its tenant. At API login, a user without access to the requested tenant is refused before any token exists.

### Resolving tenants another way

If your app identifies tenants by subdomain or by a choice stored in the session, skip the `tenant` filter and set the tenant in your own filter:

```php
service('authTenant')->set($tenantId);
```

All permission checks for the rest of the request then use that tenant.

## 14. Route filters and helpers reference

Four filter aliases and seven helper functions are registered automatically when the package is installed.

### Filters

| Filter | Arguments | Passes when | Fails with |
| --- | --- | --- | --- |
| `auth` | none, `session`, `token`, or `session,token` | A user is signed in through an allowed guard | 401 JSON or redirect to login |
| `can` | permissions, optionally `any` first | The user holds all (or any) of them, within token abilities and tenant | 403 JSON or redirect to `forbidden` |
| `role` | role names | The user holds any of them in the tenant scope | 403 JSON or redirect |
| `tenant` | none or `required` | See section 13 | 400 or 403 |

```php
'filter' => 'auth'                              // either guard
'filter' => 'auth:token'                        // bearer tokens only
'filter' => 'can:users.view,users.update'       // all
'filter' => 'can:any,reports.view,reports.export'
'filter' => 'role:admin,manager'
'filter' => ['auth:token', 'tenant:required', 'can:orders.view']
```

Multiple filters per route need CodeIgniter 4.5 or newer, the package minimum.

**JSON or redirect?** A filter answers with JSON when the request carries a bearer token, is an AJAX request, or sends `Accept: application/json`. Otherwise it redirects with a flash message. A 401 includes `WWW-Authenticate: Bearer`.

**Mistakes fail loudly.** `can` with no permission or `auth:sesion` throws an exception, so a mistyped filter can never silently let everyone through.

**Watch the forbidden redirect.** If `$redirects['forbidden']` points at a page that is itself permission-protected, a forbidden user loops. Point it at a page every signed-in user can see.

### Helpers

| Function | Returns | Notes |
| --- | --- | --- |
| `auth()` | `AuthManager` | `auth()->user()`, `auth()->session()`, `auth()->token()`, `auth()->can()` |
| `user()` | `?User` | Signed-in user from the active guard |
| `user_id()` | `?int` |  |
| `can($permission)` / `can([...])` | `bool` | One permission, or all in the array |
| `can_any([...])` | `bool` | Any of them |
| `has_role($role)` / `has_role([...])` | `bool` | Any of the roles |
| `auth_intended_url(?$default)` | `string` | Page the user wanted before signing in |

All accept an optional tenant ID as the last argument where it applies. Each helper is skipped if your app already defines a function with the same name; in that case use the `auth()` methods.

### The AuthManager

```php
$auth = auth();   // or service('auth')

$auth->check();  $auth->user();  $auth->id();  $auth->logout();
$auth->can($p);  $auth->canAny([...]);  $auth->canAll([...]);  $auth->hasRole($r);

$auth->session();          // SessionGuard
$auth->token();            // TokenGuard
$auth->guard('token');     // by name
$auth->shouldUse('token'); // force a guard for the rest of the request

$auth->authorizer();       // Authorizer
$auth->tenant();           // TenantContext
$auth->config();           // Config\Auth

$auth->routes($routes, except: [], prefix: '');
$auth->apiRoutes($routes, except: [], prefix: 'api/auth');
```

## 15. Events

The package triggers CodeIgniter events so your app can react (send a welcome SMS, write an audit log, alert on lockouts) without changing package code. Every event fires only after the related database work has committed.

```php
// app/Config/Events.php
use CodeIgniter\Events\Events;
use Ephraitech\Auth\AuthEvents;
use Ephraitech\Auth\Entities\User;

Events::on(AuthEvents::REGISTERED, static function (User $user): void {
    log_message('info', 'New account {uuid}', ['uuid' => $user->uuid]);
});

Events::on(AuthEvents::LOCKED_OUT, static function (?string $type, string $identifier, string $ip): void {
    // alert the security channel
});
```

| Constant | Fires when | Payload |
| --- | --- | --- |
| `REGISTERED` | An account is created | `User $user` |
| `LOGIN` | A user signs in (web or API) | `User $user`, `string $guard` (`session` or `token`) |
| `LOGIN_FAILED` | A login attempt fails | `?string $identifierType`, `string $identifier`, `string $reason` |
| `LOCKED_OUT` | An identifier+IP reaches the failure limit | `?string $identifierType`, `string $identifier`, `string $ipAddress` |
| `LOGOUT` | A user signs out | `User $user`, `string $guard` |
| `PASSWORD_CHANGED` | A password is changed or reset | `User $user` |
| `IDENTIFIER_VERIFIED` | An email or phone is verified | `User $user`, `string $identifierType` |
| `TOKEN_ISSUED` | A session token or API key is issued | `int $userId`, `int $tokenId`, `string $type` |
| `TOKENS_REVOKED` | One or more tokens are revoked | `int $userId`, `list<int> $tokenIds` |

`LOGIN_FAILED` reasons include `unknown_identifier`, `invalid_password`, `undetectable`, `identifier_not_allowed`, `account_suspended`, `account_pending`, `account_inactive` and `unverified_email` / `unverified_phone`. The identifier is the normalized value that was tried.

## 16. CLI commands

Six `spark` commands cover setup, user and role administration, API keys and maintenance. They appear under "Ephraitech Auth" in `php spark list`.

Wherever a command takes a user, you may pass an ID, a UUID, an email, a username or a phone number in any local format. Purely numeric input is treated as an ID, so type phone numbers with a leading `0` or `+`.

| Command | Purpose |
| --- | --- |
| `auth:publish [--views] [--force]` | Create `app/Config/Auth.php`, or copy the page views to `app/Views/auth/` |
| `auth:sync [--prune]` | Sync roles, permissions and the matrix from config |
| `auth:user:create` | Create a user, prompting for anything not given |
| `auth:role list\|assign\|remove <user> [role]` | Manage a user's roles |
| `auth:token issue\|list\|revoke\|revoke-all` | Manage API keys and tokens |
| `auth:prune [--tokens-days=7]` | Delete stale tokens, old login attempts and expired codes |

### auth:user:create

```bash
php spark auth:user:create --email=admin@example.com --role=superadmin --tenant=global --verified
php spark auth:user:create --phone=0772123456 --generate --no-interaction
```

| Option | Effect |
| --- | --- |
| `--email`, `--username`, `--phone` | Identifiers; missing required ones are prompted for |
| `--password` | Password (warns: may be saved in shell history) |
| `--generate` | Generate a policy-compliant password and print it once |
| `--role=a,b` | Roles; default `$defaultRoles` |
| `--tenant=<id>` or `--tenant=global` | Tenant for the roles |
| `--verified` | Mark the given identifiers verified |
| `--skip-policy` | Skip password rules (trusted setups only) |
| `--no-interaction` | Never prompt; fail if input is missing |

Without `--password` or `--generate`, the password is asked for twice with hidden input on Linux and macOS.

### auth:role

```bash
php spark auth:role list admin@example.com
php spark auth:role assign 0772123456 manager
php spark auth:role remove 12 manager --tenant=school-12
```

`list` prints roles and effective permissions, and notes when the super role grants everything.

### auth:token

```bash
php spark auth:token issue admin@example.com "Reports integration" --abilities=reports.* --days=90
php spark auth:token list 12 --type=api_key
php spark auth:token revoke 57
php spark auth:token revoke-all 12 --type=session
```

Issued keys are printed once with a warning to store them; `list` never shows key material.

### auth:prune

Run daily from cron:

```
15 2 * * * cd /var/www/project && php spark auth:prune >> /dev/null 2>&1
```

It deletes tokens revoked or expired more than `--tokens-days` ago, login attempts older than `$loginAttemptRetentionDays`, and codes older than `$otpRetentionDays`.

## 17. Services and extension points

Every part of the package is available as a shared CodeIgniter service, and five extension points let a project change behaviour without forking. Service names are prefixed with `auth` to avoid clashing with other packages.

### Services

| Service | Class | Use it for |
| --- | --- | --- |
| `auth` | `AuthManager` | Current user, guards, checks, route registration |
| `authAuthorizer` | `Authorizer` | Roles, permissions, grants |
| `authTenant` | `TenantContext` | The active tenant |
| `authRegistrar` | `UserRegistrar` | Creating accounts |
| `authCredentials` | `CredentialVerifier` | Checking login + password without signing in |
| `authThrottle` | `LoginThrottle` | Lockout status, pruning attempts |
| `authPasswords` | `PasswordManager` | Setting, verifying and checking passwords |
| `authPasswordChanger` | `PasswordChanger` | `change()` and `reset()`, revoking tokens |
| `authTokens` | `TokenManager` | Issuing, validating, listing, revoking tokens |
| `authOneTimeCodes` | `OneTimeCodeManager` | Low-level code issuing and checking |
| `authNotifiers` | `NotifierRegistry` | Delivery per channel; register instances |
| `authPasswordReset` | `PasswordResetFlow` | Forgot/reset password |
| `authVerification` | `VerificationFlow` | Email/phone verification |

```php
service('authPasswords')->check($userId, $candidate);     // list of policy errors, nothing saved
service('authPasswordChanger')->change($user, $current, $new, keepTokenId: $tokenId);
service('authThrottle')->availableIn($identifier, $ip);   // seconds until another attempt is allowed
```

### Extension points

| Extension point | How | Section |
| --- | --- | --- |
| User model and entity | Extend the package classes, set `$userModel` | 5 |
| Delivery of codes | Implement `NotifierInterface`, set `$notifiers` | 11 |
| API user shape | Implement `UserTransformerInterface`, set `$apiUserTransformer` | below |
| Page design | `$viewLayout`, `$views`, `auth:publish --views` | 9 |
| Reacting to activity | Listen to `AuthEvents` | 15 |

### Custom API user shape

```php
namespace App\Auth;

use Ephraitech\Auth\Api\UserTransformerInterface;
use Ephraitech\Auth\Config\Auth;
use Ephraitech\Auth\Entities\AccessToken;
use Ephraitech\Auth\Entities\User;

final class FieldTrackerUserTransformer implements UserTransformerInterface
{
    public function __construct(private readonly Auth $config)
    {
    }

    public function transform(User $user, ?AccessToken $token = null): array
    {
        return [
            'id'         => $user->uuid,
            'name'       => trim($user->first_name . ' ' . $user->last_name),
            'phone'      => $user->phone,
            'can_export' => service('authAuthorizer')->can($user, 'reports.export', $token?->tenant(), $token?->abilityList()),
        ];
    }
}
```

```php
public string $apiUserTransformer = \App\Auth\FieldTrackerUserTransformer::class;
```

Every endpoint that returns a user then uses your shape.

### Building your own controllers

The built-in controllers are thin wrappers over the services above, so your own controllers can do the same with different screens or response formats. Use `auth()->session()` or `auth()->token()` for sign-in, `service('authRegistrar')` for signup, and the two flow services for reset and verification. Map exceptions to responses the way section 10 does.

## 18. Security model and production checklist

The package defends against the common attacks on sign-in systems by default; a production app still needs HTTPS, CSRF, rate limiting on public forms and a daily prune.

### What the package protects against

| Threat | Protection |
| --- | --- |
| Discovering which accounts exist | Same error for wrong password and unknown user; unknown users still spend hashing time; forgot password always gives the same answer |
| Password guessing | Lockout per identifier and IP after 5 failures; attempts while locked are not counted, so they don't extend the lock |
| Locking real users out | Lockout is keyed on identifier **and** IP, so an attacker only locks themselves |
| Stolen database | Passwords hashed (bcrypt or Argon2id, rehashed on login when settings change); tokens and codes stored as hashes only |
| Stolen device or leaked token | Instant revocation; password change or reset revokes tokens and ends other web sessions |
| Over-privileged integrations | Token abilities act as a ceiling, even for superadmins |
| Session fixation | New session ID on login and logout |
| Passwords leaking into sessions | Failed forms re-display only safe fields |
| Open redirects after login | Intended URLs are same-site only |
| Code guessing | Codes expire in 15 minutes, burn after 5 wrong guesses, single use, only the newest works |
| Codes leaking from URLs | `Referrer-Policy: no-referrer` on pages carrying codes |
| Cross-tenant access | Tenant filter rejects non-members and tokens bound to another tenant |
| Accidental misconfiguration | Config is validated at startup; mistyped filters throw instead of passing |

### Production checklist

- [ ] Serve everything over HTTPS; tokens and session cookies are credentials.
- [ ] Enable CSRF globally and exclude only the API prefix.
- [ ] Add CodeIgniter's `Throttler` to `login`, `register`, `forgot-password`, `verify/resend` and the matching API routes, for per-IP limits against credential stuffing and SMS abuse.
- [ ] Schedule `php spark auth:prune` daily.
- [ ] Keep Africa's Talking and other credentials in `.env`, never in Git.
- [ ] Replace `LogNotifier` with real notifiers (it refuses to run in production anyway).
- [ ] Set `$emailFromAddress` and `$appName`, and send a test reset to yourself.
- [ ] Run `php spark auth:sync` after deployments that change roles or permissions.
- [ ] Point `$redirects['forbidden']` at a page every signed-in user can see.
- [ ] Confirm the filters are registered: `php spark filter:check get /api/auth/me`.
- [ ] Consider `$sessionIdleTimeout` and `$sessionTokenIdleTimeout` for sensitive systems.

### Known limits

- A 6-digit code has a million combinations, so its hash would not resist someone holding a stolen database. The short expiry and guess limit are what protect codes.
- The built-in throttle is per identifier and IP. Spraying one password across many accounts from one IP needs the per-IP `Throttler` above.
- "This email address is already in use" on registration reveals that the account exists, as on nearly every signup form. For high-sensitivity apps, catch `RegistrationException` and show a generic message instead.

## 19. Testing apps that use the package

Your app's tests can create users, sign them in and read delivered codes with CodeIgniter's own testing tools; three habits avoid the common surprises.

### A base test case

```php
namespace Tests\Support;

use CodeIgniter\Test\CIUnitTestCase;
use CodeIgniter\Test\DatabaseTestTrait;
use Ephraitech\Auth\Authorization\RbacSynchronizer;
use Ephraitech\Auth\Config\Auth;

abstract class AppTestCase extends CIUnitTestCase
{
    use DatabaseTestTrait;

    protected $migrate   = true;
    protected $refresh   = true;
    protected $namespace = null;   // run every namespace's migrations, including the package

    protected Auth $authConfig;

    protected function setUp(): void
    {
        $this->resetServices();   // habit 1: fresh services per test
        parent::setUp();

        $this->authConfig = config(Auth::class);
        $this->authConfig->hashOptions = ['cost' => 4];   // habit 3: fast hashing
        $this->authConfig->notifiers   = ['email' => CapturingNotifier::class, 'sms' => CapturingNotifier::class];

        CapturingNotifier::reset();
        RbacSynchronizer::create($this->authConfig)->sync();
    }
}
```

**Habit 1: reset services before each test.** Services such as `auth` and `authTokens` are shared and hold the config and request they were built with. Without a reset, a test that changes config or headers talks to a service from the previous test.

**Habit 2: in feature tests, reset `auth` before each request.** `service('auth')` remembers the request it was created for, so call `\Config\Services::resetSingle('auth')` before every `get()`/`post()` in a test that makes several requests.

**Habit 3: lower the bcrypt cost.** Hashing is deliberately slow; `cost => 4` keeps behaviour identical and makes the suite many times faster.

### Read codes instead of sending them

```php
namespace Tests\Support;

use Ephraitech\Auth\Config\Auth;
use Ephraitech\Auth\Notifications\NotifierInterface;
use Ephraitech\Auth\Notifications\OneTimeCodeMessage;

final class CapturingNotifier implements NotifierInterface
{
    /** @var list<OneTimeCodeMessage> */
    public static array $messages = [];

    public function __construct(Auth $config)
    {
    }

    public function send(OneTimeCodeMessage $message): void
    {
        self::$messages[] = $message;
    }

    public static function reset(): void
    {
        self::$messages = [];
    }

    public static function last(): ?OneTimeCodeMessage
    {
        return self::$messages === [] ? null : self::$messages[array_key_last(self::$messages)];
    }
}
```

### Examples

```php
public function testManagerCanExportReports(): void
{
    $user = service('authRegistrar')->register(['email' => 'm@example.com'], 'Correct-Horse-42', [], ['roles' => ['manager']]);

    $this->assertTrue(service('authAuthorizer')->can($user, 'reports.export'));
}

public function testApiRequiresToken(): void
{
    $user  = service('authRegistrar')->register(['email' => 'a@example.com'], 'Correct-Horse-42');
    $token = service('authTokens')->issueSessionToken($user->id, 'Test device')->plaintext;

    \Config\Services::resetSingle('auth');
    $this->withHeaders(['Authorization' => 'Bearer ' . $token])->get('api/visits')->assertStatus(200);
}

public function testPasswordReset(): void
{
    service('authRegistrar')->register(['email' => 'r@example.com'], 'Correct-Horse-42');

    service('authPasswordReset')->request('r@example.com');
    service('authPasswordReset')->resetWithCode('r@example.com', CapturingNotifier::last()->code, 'Brand-New-Pass-99');

    $this->assertTrue(service('authPasswords')->verify(1, 'Brand-New-Pass-99'));
}
```

To change config for one test, modify `$this->authConfig` before the first `service()` call in that test.

## 20. Upgrading and versioning

The package follows semantic versioning; while it is below 1.0, each minor version (0.9 to 0.10) may change behaviour, so upgrades are an explicit choice.

### Upgrading

```bash
composer require ephraitech/ci4-auth:^0.10
php spark migrate -n "Ephraitech\Auth"
php spark auth:sync
```

Then read the release's entry in `CHANGELOG.md` for anything to adjust. Migrations are additive and never edited after release, so `migrate` is always safe to run.

New options, table names, redirects and view keys added in a release fall back to package defaults when your `app/Config/Auth.php` doesn't mention them, so existing overrides keep working.

### Release history

| Version | Date | Highlights |
| --- | --- | --- |
| 0.10.0 | 2026-10-08 | Built-in web pages and JSON API, one-time codes, password reset, email/phone verification, notifiers (email, Africa's Talking, log); fixes the empty filter Registrar from 0.9.x |
| 0.9.1 | 2026-10-08 | Minimum PHP raised to 8.2 |
| 0.9.0 | 2026-10-07 | First release: users and identities, guards, tokens, RBAC, multi-tenancy, throttling, filters, helpers, CLI, events |

### What counts as a breaking change

From 1.0.0 onward, these only change in a major version:

- Removing or renaming a config option, service, filter alias, helper, route name, event name or exception class.
- Changing a public method signature, an event payload or the API response shape.
- A migration that alters or drops existing columns.

New features, new options with safe defaults and new tables arrive in minor versions; fixes in patch versions.

### Upgrading from 0.9.x to 0.10.0

- Run `php spark migrate -n "Ephraitech\Auth"` to add `auth_one_time_codes`.
- The `auth`, `can`, `role` and `tenant` filter aliases now register automatically. If you added them to `app/Config/Filters.php` by hand as a workaround, you can remove them.
- Email delivery is enabled by default; set `$emailFromAddress` (or `Config\Email::$fromEmail`) before using password reset.

## 21. Troubleshooting and FAQ

Most problems come from configuration order, CSRF, or files saved with stray characters; the table below maps each symptom to its fix.

| Symptom | Cause | Fix |
| --- | --- | --- |
| `"auth" filter must have a matching alias defined` | Filter aliases not registered | Run `composer update ephraitech/ci4-auth` (0.9.x shipped an empty Registrar); check `Config\Modules::$discoverInComposer` is `true`; confirm with `php spark filter:check` |
| `service('auth')` returns `null` | Package services not discovered | Same `Config\Modules` check; run `composer dump-autoload` |
| `Ephraitech Auth config: ...` exception at startup | Invalid config combination | The message names the option; fix it in `app/Config/Auth.php` |
| Migration fails: table `users` already exists | Existing app already has a `users` table | Set `$tables['users']` to another name before migrating |
| 403 "The action you requested is not allowed" on API calls | CSRF applied to the API | Exclude the API prefix from the `csrf` filter |
| Every API call returns 401 | Missing ` Bearer  ` prefix, a revoked or expired token, or a proxy dropping the `Authorization` header | Send `Authorization: Bearer eph_...`; on Apache add `CGIPassAuth On` or the equivalent rewrite rule |
| Signed out after changing password | Your own controller didn't re-stamp the session | Call `auth()->session()->refresh()` after `change()` (the built-in page does this) |
| Users redirected in a loop | `$redirects['forbidden']` points at a protected page | Point it at a page every signed-in user can see |
| No reset emails arrive | No sender address, or SMTP settings | Set `$emailFromAddress` or `Config\Email::$fromEmail`; check `writable/logs/` for the delivery error |
| SMS not sent, 503 `delivery_failed` | Africa's Talking credentials, sender ID or balance | Check `.env` values, try `$africasTalkingSandbox = true` with username `sandbox`, read the logged reason |
| `NotificationException`: no notifier for 'sms' | SMS channel disabled | Set `$notifiers['sms']`, or don't make phone verification required |
| `strict_types declaration must be the very first statement` | A BOM or space before `<?php` in a file you edited | Save as UTF-8 without BOM; remove anything before `<?php` |
| A new role or permission "unknown" | Not synced to the database | Run `php spark auth:sync` |
| Tests see old config or requests | Shared services reused between tests | See section 19, habits 1 and 2 |

### FAQ

**Can I use an existing users table?** Not directly. The package expects its base columns (`uuid`, `status`, ...) and keeps credentials in `auth_identities`. For an existing app, point `$tables['users']` at a new table and migrate your accounts into it with a script that calls `service('authRegistrar')` (or sets identities and password hashes directly).

**Can users log in with either email or phone?** Yes: `$loginIdentifiers = ['email', 'phone']`. One field accepts both and detects which was typed.

**Can one email have two accounts in different tenants?** No. Identifiers are unique globally; one person has one account and different roles per tenant.

**Does it support JWT?** No, by design. Opaque tokens can be revoked instantly, which JWTs cannot without extra infrastructure.

**Can I disable registration?** Yes: `$allowRegistration = false` removes the page and makes the API endpoint return 404. Create accounts with `auth:user:create` or the registrar.

**How do I sign users in after my own OTP or social login?** Verify them your way, then call `auth()->session()->login($user)` (web) or `auth()->token()->issueFor($user, $deviceName)` (API).

**Where do I report bugs?** On [GitHub issues](https://github.com/etus-ephraitech/ci4-auth/issues), with the package version (`composer show ephraitech/ci4-auth`), PHP and CodeIgniter versions, and the relevant config.
