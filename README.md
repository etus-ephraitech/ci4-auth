# Ephraitech CI4 Auth

[![Tests](https://github.com/etus-ephraitech/ci4-auth/actions/workflows/tests.yml/badge.svg)](https://github.com/etus-ephraitech/ci4-auth/actions/workflows/tests.yml)

Authentication and authorization for CodeIgniter 4: web sessions, API tokens,
roles and permissions, and optional multi-tenancy, in one package.

## Features

- **Flexible identifiers:** sign in with email, username, phone, or any combination, all sharing one password. Phone numbers are normalized (`0772 123 456` and `+256772123456` are the same account).
- **Two guards, one API:** cookie sessions for web apps and bearer tokens for APIs and mobile apps. `service('auth')` picks the right one automatically.
- **Tokens done safely:** only SHA-256 hashes are stored. Abilities, expiry, idle timeout, per-user device cap and instant revocation are built in.
- **Roles and permissions:** wildcards (`users.*`), a super role, direct grants, and config-driven sync.
- **Multi-tenancy:** roles, grants and tokens can be scoped per tenant, with global roles for platform admins.
- **Secure by default:** timing-safe login failures, login throttling, session-fixation protection, password-change logout across devices, and open-redirect protection.
- **Ready-made flows:** login, registration, forgot/reset password, email/phone verification and change password, as Bootstrap 5 pages and as JSON endpoints, both optional and replaceable.

## Requirements

- PHP 8.2+ with `mbstring` and `intl`
- CodeIgniter 4.5+
- MySQL 5.7.7+ / MariaDB 10.2.2+ (or SQLite / PostgreSQL)

## Installation

```bash
composer require ephraitech/ci4-auth
php spark auth:publish                    # creates app/Config/Auth.php
php spark migrate -n "Ephraitech\Auth"
php spark auth:sync                       # roles and permissions from config
php spark auth:user:create --role=superadmin --tenant=global --verified
```

Services, filters, commands and helpers are discovered automatically.

## Configuration

`app/Config/Auth.php` extends the package config, so only the settings you declare are overridden. Every option is documented in `vendor/ephraitech/ci4-auth/src/Config/Auth.php`. Invalid combinations throw a clear error at startup.

### Identifiers

```php
public array $identifiers         = ['email', 'phone'];  // types that exist
public array $loginIdentifiers    = ['email', 'phone'];  // usable to sign in
public array $requiredIdentifiers = ['phone'];           // required at registration
public string $phoneDefaultCountryCode = '256';
```

A single `login` field is auto-detected: `@` means email, digits mean phone, anything else means username.

### Extending the users table

Add your own columns with a normal migration, then allow them:

```php
public array $userAllowedFields = ['first_name', 'last_name', 'avatar'];
```

For relationships or custom methods, extend `Ephraitech\Auth\Models\UserModel` (and `Entities\User`) and set `public string $userModel = \App\Models\UserModel::class;`.

## Registration

```php
use Ephraitech\Auth\Exceptions\RegistrationException;

try {
    $user = service('authRegistrar')->register(
        ['email' => $email, 'phone' => $phone],
        $password,
        ['first_name' => $firstName],
        ['status' => 'pending'],
    );
} catch (RegistrationException $e) {
    return redirect()->back()->withInput()->with('errors', $e->getFirstErrors());
}
```

The user, identities, password and default roles are created in one transaction. Errors are keyed by field.

## Web login

```php
try {
    auth()->session()->attempt($this->request->getPost('login'), $this->request->getPost('password'));
} catch (\Ephraitech\Auth\Exceptions\AuthException $e) {
    return redirect()->back()->withInput()->with('error', $e->getMessage());
}

return redirect()->to(auth_intended_url());
```

## API login

```php
$new = auth()->token()->attempt($login, $password, deviceName: 'Tecno Spark 20');

return $this->response->setJSON($new->toArray());   // token shown once
```

Clients then send `Authorization: Bearer eph_...`. Logout with `auth()->token()->logout()` or `logoutEverywhere()`.

## Protecting routes

```php
$routes->group('admin', ['filter' => 'auth:session'], static function ($routes) {
    $routes->get('users', 'Admin\Users::index', ['filter' => 'can:users.view']);
    $routes->get('reports', 'Admin\Reports::index', ['filter' => 'can:any,reports.view,reports.export']);
});

$routes->group('api', ['filter' => ['auth:token', 'tenant']], static function ($routes) {
    $routes->get('visits', 'Api\Visits::index', ['filter' => 'can:visits.view']);
});
```

## Built-in pages and endpoints

Register either or both in `app/Config/Routes.php`:

```php
service('auth')->routes($routes);       // web pages: /login, /register, /forgot-password, ...
service('auth')->apiRoutes($routes);    // JSON: /api/auth/login, /api/auth/me, ...

// Options:
service('auth')->routes($routes, except: ['register'], prefix: 'account');
service('auth')->apiRoutes($routes, prefix: 'v1/auth');
```

Exclude API routes from CSRF in `app/Config/Filters.php`:

```php
'csrf' => ['except' => ['api/*']],
```

### Web pages

| Page | Route name |
|---|---|
| Sign in | `auth.login` |
| Sign out (POST) | `auth.logout` |
| Create account | `auth.register` |
| Forgot / reset password | `auth.forgot`, `auth.reset` |
| Verify email or phone | `auth.verify` |
| Change password | `auth.password` |

Render them inside your own layout, and override any single page:

```php
public string $viewLayout  = 'layouts/main';   // must render the section below
public string $viewSection = 'content';
public array  $views       = ['login' => 'pages/custom_login'];
public array  $registrationFields = ['first_name' => 'First name'];
```

`php spark auth:publish --views` copies every page into `app/Views/auth/` for full control.

### API endpoints

| Method | Path | Auth |
|---|---|---|
| POST | `login` | |
| POST | `logout`, `logout-all` | token |
| GET | `me` | token |
| POST | `register` | |
| POST | `password/forgot`, `password/reset` | |
| POST | `password/change` | token |
| POST | `verify/send`, `verify/confirm` | |

Errors share one shape:

```json
{ "status": 422, "error": "validation_failed", "message": "...", "errors": { "password": "..." } }
```

A login that needs verification returns `403` with `"error": "verification_required"`, the identifier type, a masked destination and whether a code was sent. The client confirms with `verify/confirm` (login + code), then logs in again.

To match a project's response conventions, implement `UserTransformerInterface` and set `$apiUserTransformer`.

## Codes by email and SMS

Password reset and verification send short-lived numeric codes. Configure delivery per channel:

```php
use Ephraitech\Auth\Notifications\AfricasTalkingNotifier;
use Ephraitech\Auth\Notifications\EmailNotifier;

public string $appName = 'Field Tracker';
public string $emailFromAddress = 'no-reply@example.com';

public array $notifiers = [
    'email' => EmailNotifier::class,           // uses Config\Email
    'sms'   => AfricasTalkingNotifier::class,  // or null to disable
];
```

Africa's Talking credentials belong in `.env`:

```
auth.africasTalkingUsername = yourusername
auth.africasTalkingApiKey   = atsk_...
auth.africasTalkingSenderId = YOURBRAND
```

Use `LogNotifier::class` during development to write codes to `writable/logs/` instead of sending them. It refuses to run in production. For another SMS gateway, implement `NotifierInterface` (a single `send()` method).

To require verification before sign-in, or to activate pending accounts on verification:

```php
public array $requireVerifiedToLogin = ['email' => true, 'phone' => false, 'username' => false];
public bool  $activateOnVerification = true;   // with registration status 'pending'
```

| Filter | Meaning |
|---|---|
| `auth`, `auth:session`, `auth:token` | Signed in (either guard, or a specific one) |
| `can:a,b` / `can:any,a,b` | All / any of the permissions |
| `role:admin,manager` | Any of the roles |
| `tenant` / `tenant:required` | Set the tenant from `X-Tenant-ID` |

Browsers are redirected; API and AJAX clients get JSON 401/403 responses.

## Authorization

Define roles and permissions in config, then run `php spark auth:sync`:

```php
public array $permissions = [
    'visits.view'   => 'View visits',
    'visits.create' => 'Record visits',
];

public array $matrix = [
    'admin' => ['visits.*'],
    'user'  => ['visits.view'],
];
```

Check them anywhere:

```php
if (can('visits.create')) { ... }

auth()->authorizer()->assignRole($user, 'admin');
auth()->authorizer()->grantPermission($user, 'visits.create');
```

Token abilities act as a ceiling: a key issued with `['reports.view']` can only view reports, even for an admin.

## Multi-tenancy

Set `public string $tenancy = 'multi';`. Assign roles per tenant, or globally with `''`:

```php
auth()->authorizer()->assignRole($user, 'admin', 'school-12');
auth()->authorizer()->assignRole($owner, 'superadmin', '');   // every tenant
```

The `tenant` filter rejects users without access to the requested tenant, and tokens bound to a different tenant.

## Passwords

```php
service('authPasswordChanger')->change($user, $current, $new, keepTokenId: $currentTokenId);
service('authPasswordChanger')->reset($user, $new);   // after your reset-code check
```

Both revoke the user's other tokens and sign out their other browsers.

## Events

```php
use CodeIgniter\Events\Events;
use Ephraitech\Auth\AuthEvents;

Events::on(AuthEvents::REGISTERED, static function ($user) {
    // send a verification SMS or email
});
```

Available events: `REGISTERED`, `LOGIN`, `LOGIN_FAILED`, `LOCKED_OUT`, `LOGOUT`, `PASSWORD_CHANGED`, `TOKEN_ISSUED`, `TOKENS_REVOKED`. All fire after the related database work commits.


## CLI

| Command | Purpose |
|---|---|
| `auth:publish` | Create `app/Config/Auth.php` |
| `auth:sync [--prune]` | Sync roles and permissions from config |
| `auth:user:create` | Create a user (prompts for missing input) |
| `auth:role list\|assign\|remove <user> [role]` | Manage roles |
| `auth:token issue\|list\|revoke\|revoke-all` | Manage API keys and tokens |
| `auth:prune` | Delete stale tokens and old login attempts (run daily) |

Users can be referenced by ID, UUID, email, username or phone.

## Security notes

- Add CodeIgniter's `Throttler` filter to login routes for per-IP rate limiting. The built-in throttle works per identifier and IP.
- Use HTTPS: bearer tokens and session cookies are credentials.
- Run `php spark auth:prune` daily from cron.
- Add CodeIgniter's `Throttler` to `register`, `forgot-password`, `verify/resend` and their API equivalents, so your forms can't be used to spam inboxes or spend SMS credit.

## Testing

```bash
composer install
composer test
```

## License

MIT. See [LICENSE](LICENSE).