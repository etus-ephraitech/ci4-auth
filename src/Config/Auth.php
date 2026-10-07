<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Config;

use CodeIgniter\Config\BaseConfig;
use Ephraitech\Auth\Models\UserModel;
use LogicException;

/**
 * Ephraitech Auth configuration.
 *
 * Host applications override any setting by creating app/Config/Auth.php:
 *
 *     namespace Config;
 *
 *     class Auth extends \Ephraitech\Auth\Config\Auth
 *     {
 *         public array $identifiers         = ['email', 'phone'];
 *         public array $loginIdentifiers    = ['email', 'phone'];
 *         public array $requiredIdentifiers = ['phone'];
 *     }
 *
 * The package always resolves config(\Ephraitech\Auth\Config\Auth::class);
 * CodeIgniter's config factory returns the host's Config\Auth when it exists.
 */
class Auth extends BaseConfig
{
    // ------------------------------------------------------------------
    // Constants
    // ------------------------------------------------------------------

    public const IDENTIFIER_EMAIL    = 'email';
    public const IDENTIFIER_USERNAME = 'username';
    public const IDENTIFIER_PHONE    = 'phone';
    public const CREDENTIAL_PASSWORD = 'password';

    public const SUPPORTED_IDENTIFIERS = [
        self::IDENTIFIER_EMAIL,
        self::IDENTIFIER_USERNAME,
        self::IDENTIFIER_PHONE,
    ];

    public const TENANCY_SINGLE = 'single';
    public const TENANCY_MULTI  = 'multi';

    public const TOKEN_TYPE_SESSION = 'session';
    public const TOKEN_TYPE_API_KEY = 'api_key';

    public const USER_STATUSES = ['active', 'inactive', 'suspended', 'pending'];

    private const REQUIRED_TABLE_KEYS = [
        'users',
        'identities',
        'access_tokens',
        'roles',
        'permissions',
        'role_permissions',
        'user_roles',
        'user_permissions',
        'login_attempts',
    ];

    // ------------------------------------------------------------------
    // Database
    // ------------------------------------------------------------------

    /**
     * Database connection group. NULL uses the host's default group.
     */
    public ?string $DBGroup = null;

    /**
     * Table names. Rename to avoid collisions with existing tables.
     *
     * @var array<string, string>
     */
    public array $tables = [
        'users'            => 'users',
        'identities'       => 'auth_identities',
        'access_tokens'    => 'auth_access_tokens',
        'roles'            => 'auth_roles',
        'permissions'      => 'auth_permissions',
        'role_permissions' => 'auth_role_permissions',
        'user_roles'       => 'auth_user_roles',
        'user_permissions' => 'auth_user_permissions',
        'login_attempts'   => 'auth_login_attempts',
    ];

    // ------------------------------------------------------------------
    // Users
    // ------------------------------------------------------------------

    /**
     * Model class used for users. Must extend Ephraitech\Auth\Models\UserModel.
     *
     * @var class-string<UserModel>
     */
    public string $userModel = UserModel::class;

    /**
     * Extra columns the host app added to the users table via its own
     * migration. Merged into the user model's allowedFields.
     *
     * @var list<string>
     */
    public array $userAllowedFields = [];

    /**
     * Generate a UUID for every user, for use as a public identifier in
     * URLs and API responses instead of the auto-increment id.
     */
    public bool $useUuid = true;

    /**
     * Status assigned to newly registered users.
     */
    public string $defaultUserStatus = 'active';

    // ------------------------------------------------------------------
    // Identifiers
    // ------------------------------------------------------------------

    /**
     * Identifier types enabled in this application.
     *
     * @var list<string>
     */
    public array $identifiers = [self::IDENTIFIER_EMAIL];

    /**
     * Identifier types that may be used to log in. Subset of $identifiers.
     *
     * @var list<string>
     */
    public array $loginIdentifiers = [self::IDENTIFIER_EMAIL];

    /**
     * Identifier types that must be supplied at registration.
     * Subset of $identifiers, and must include at least one login identifier.
     *
     * @var list<string>
     */
    public array $requiredIdentifiers = [self::IDENTIFIER_EMAIL];

    /**
     * Detect the identifier type from a single "login" input
     * ('@' => email, digits => phone, otherwise username).
     * When false, callers must state the type explicitly.
     */
    public bool $detectLoginIdentifier = true;

    /**
     * Whether an identifier must be verified before it can be used to log in.
     *
     * @var array<string, bool>
     */
    public array $requireVerifiedToLogin = [
        self::IDENTIFIER_EMAIL    => false,
        self::IDENTIFIER_USERNAME => false,
        self::IDENTIFIER_PHONE    => false,
    ];

    public int $emailMaxLength = 254;

    public int $usernameMinLength = 3;

    public int $usernameMaxLength = 30;

    /**
     * Applied after the username is lowercased. Default: letters, digits,
     * dot, underscore and hyphen; must start and end with a letter or digit.
     */
    public string $usernamePattern = '/^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$/';

    /**
     * Usernames that can never be registered (compared lowercased).
     *
     * @var list<string>
     */
    public array $reservedUsernames = [
        'root',
        'system',
        'administrator',
        'api',
        'null',
        'undefined',
    ];

    /**
     * Country calling code applied to local-format phone numbers
     * (e.g. 0772123456 => +256772123456). Digits only.
     */
    public string $phoneDefaultCountryCode = '256';

    /**
     * Digit count limits for a normalized phone number, country code included.
     * E.164 allows at most 15 digits.
     */
    public int $phoneMinDigits = 8;

    public int $phoneMaxDigits = 15;

    // ------------------------------------------------------------------
    // Passwords
    // ------------------------------------------------------------------

    /**
     * Algorithm passed to password_hash(). Switch to PASSWORD_ARGON2ID in the
     * host config when the server's PHP build supports it, and raise
     * $passwordMaxLength accordingly.
     */
    public string|int|null $hashAlgorithm = PASSWORD_DEFAULT;

    /**
     * Options passed to password_hash() (e.g. ['cost' => 12] for bcrypt).
     *
     * @var array<string, int>
     */
    public array $hashOptions = [];

    public int $passwordMinLength = 8;

    /**
     * Bcrypt silently truncates input beyond 72 bytes, so the default caps
     * passwords there rather than accepting characters that are ignored.
     */
    public int $passwordMaxLength = 72;

    public bool $passwordRequireUppercase = false;

    public bool $passwordRequireLowercase = false;

    public bool $passwordRequireNumber = true;

    public bool $passwordRequireSymbol = false;

    /**
     * Reject passwords that contain the user's username, email local part,
     * or phone number.
     */
    public bool $passwordDisallowIdentifiers = true;

    // ------------------------------------------------------------------
    // Session guard (web applications)
    // ------------------------------------------------------------------

    /**
     * Session key under which the authenticated user's state is stored.
     */
    public string $sessionKey = 'ephraitech_auth';

    /**
     * Log out web users after this many seconds of inactivity. 0 disables.
     */
    public int $sessionIdleTimeout = 0;

    /**
     * Regenerate the session ID on login to prevent session fixation.
     */
    public bool $regenerateSessionOnLogin = true;

    // ------------------------------------------------------------------
    // Token guard (APIs, mobile apps, integrations)
    // ------------------------------------------------------------------

    /**
     * Prefix on issued tokens, to make them recognisable in logs and
     * secret scanners. Only the SHA-256 hash of the full token is stored.
     */
    public string $tokenPrefix = 'eph_';

    /**
     * Random bytes per token (before encoding). Minimum 16.
     */
    public int $tokenBytes = 32;

    /**
     * Request header carrying the "Bearer <token>" value.
     */
    public string $tokenHeader = 'Authorization';

    /**
     * Absolute lifetime of user session tokens, in seconds (default 30 days).
     */
    public int $sessionTokenLifetime = 2_592_000;

    /**
     * Expire session tokens unused for this many seconds. 0 disables.
     */
    public int $sessionTokenIdleTimeout = 0;

    /**
     * Lifetime of integration API keys in seconds. NULL = no expiry
     * (revocation remains instant).
     */
    public ?int $apiKeyLifetime = null;

    /**
     * Minimum seconds between last_used_at writes for the same token,
     * to avoid a database write on every request.
     */
    public int $tokenLastUsedUpdateInterval = 60;

    /**
     * Maximum active session tokens per user; the oldest is revoked when
     * exceeded. 0 = unlimited. Does not apply to API keys.
     */
    public int $maxSessionTokensPerUser = 10;

    /**
     * Abilities granted to a token when none are specified. '*' means the
     * token may do anything its user is permitted to do.
     *
     * @var list<string>
     */
    public array $defaultTokenAbilities = ['*'];

    // ------------------------------------------------------------------
    // Login throttling
    // ------------------------------------------------------------------

    /**
     * Failed attempts allowed per identifier+IP within $loginAttemptWindow.
     */
    public int $maxLoginAttempts = 5;

    public int $loginAttemptWindow = 900;

    public int $lockoutDuration = 900;

    /**
     * Also record successful logins in the attempts table (audit trail).
     */
    public bool $recordSuccessfulLogins = true;

    /**
     * Days to keep login attempt rows before the prune command removes them.
     */
    public int $loginAttemptRetentionDays = 90;

    // ------------------------------------------------------------------
    // Tenancy
    // ------------------------------------------------------------------

    /**
     * 'single': tenant_id columns are ignored.
     * 'multi':  roles, direct permissions and tokens are scoped by tenant_id.
     */
    public string $tenancy = self::TENANCY_SINGLE;

    /**
     * Request header used to select the active tenant in multi-tenant mode.
     */
    public string $tenantHeader = 'X-Tenant-ID';

    // ------------------------------------------------------------------
    // Authorization
    // ------------------------------------------------------------------

    /**
     * Role that bypasses every permission check. NULL disables the bypass.
     */
    public ?string $superRole = 'superadmin';

    /**
     * Roles assigned automatically to newly registered users.
     *
     * @var list<string>
     */
    public array $defaultRoles = ['user'];

    /**
     * Roles synced into the database by the auth:sync command.
     *
     * @var array<string, array{title: string, description: string}>
     */
    public array $roles = [
        'superadmin' => [
            'title'       => 'Super Admin',
            'description' => 'Unrestricted access to everything.',
        ],
        'admin' => [
            'title'       => 'Administrator',
            'description' => 'Manages users, roles and access tokens.',
        ],
        'user' => [
            'title'       => 'User',
            'description' => 'Standard authenticated user.',
        ],
    ];

    /**
     * Permissions synced into the database by the auth:sync command.
     *
     * @var array<string, string>
     */
    public array $permissions = [
        'users.view'    => 'View users',
        'users.create'  => 'Create users',
        'users.update'  => 'Update users',
        'users.delete'  => 'Delete users',
        'roles.manage'  => 'Manage roles and permissions',
        'tokens.manage' => 'Manage access tokens and API keys',
    ];

    /**
     * Role => permissions. Supports '*' (all) and 'prefix.*' wildcards.
     *
     * @var array<string, list<string>>
     */
    public array $matrix = [
        'superadmin' => ['*'],
        'admin'      => ['users.*', 'roles.manage', 'tokens.manage'],
        'user'       => [],
    ];

    // ------------------------------------------------------------------
    // Web redirects (session guard and filters)
    // ------------------------------------------------------------------

    /**
     * @var array{login: string, afterLogin: string, afterLogout: string, forbidden: string}
     */
    public array $redirects = [
        'login'       => '/login',
        'afterLogin'  => '/',
        'afterLogout' => '/login',
        'forbidden'   => '/',
    ];

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    /**
     * Resolve a configured table name by key.
     */
    public function table(string $key): string
    {
        if (! isset($this->tables[$key]) || $this->tables[$key] === '') {
            throw new LogicException("Ephraitech Auth: no table configured for key '{$key}'.");
        }

        return $this->tables[$key];
    }

    public function isIdentifierEnabled(string $type): bool
    {
        return in_array($type, $this->identifiers, true);
    }

    public function canLoginWith(string $type): bool
    {
        return in_array($type, $this->loginIdentifiers, true);
    }

    public function isIdentifierRequired(string $type): bool
    {
        return in_array($type, $this->requiredIdentifiers, true);
    }

    public function mustBeVerifiedToLogin(string $type): bool
    {
        return (bool) ($this->requireVerifiedToLogin[$type] ?? false);
    }

    public function isMultiTenant(): bool
    {
        return $this->tenancy === self::TENANCY_MULTI;
    }

    /**
     * Validate the configuration. Called once when the auth services boot,
     * so misconfiguration fails loudly at startup instead of mid-request.
     *
     * @throws LogicException
     */
    public function assertValid(): void
    {
        $this->assertTables();
        $this->assertUserSettings();
        $this->assertIdentifiers();
        $this->assertPasswordPolicy();
        $this->assertTokens();
        $this->assertThrottling();
        $this->assertTenancy();
        $this->assertAuthorization();
    }

    private function assertTables(): void
    {
        foreach (self::REQUIRED_TABLE_KEYS as $key) {
            $this->table($key);
        }

        $names = array_values($this->tables);

        if (count($names) !== count(array_unique($names))) {
            $this->fail('$tables contains duplicate table names.');
        }
    }

    private function assertUserSettings(): void
    {
        if (! class_exists($this->userModel)) {
            $this->fail("\$userModel class '{$this->userModel}' does not exist.");
        }

        if (
            $this->userModel !== UserModel::class
            && ! is_subclass_of($this->userModel, UserModel::class)
        ) {
            $this->fail('$userModel must extend ' . UserModel::class . '.');
        }

        if (! in_array($this->defaultUserStatus, self::USER_STATUSES, true)) {
            $this->fail('$defaultUserStatus must be one of: ' . implode(', ', self::USER_STATUSES) . '.');
        }

        foreach ($this->userAllowedFields as $field) {
            if (! is_string($field) || preg_match('/^[A-Za-z_][A-Za-z0-9_]*$/', $field) !== 1) {
                $this->fail('$userAllowedFields contains an invalid column name.');
            }
        }
    }

    private function assertIdentifiers(): void
    {
        if ($this->identifiers === []) {
            $this->fail('$identifiers must enable at least one identifier type.');
        }

        if (count($this->identifiers) !== count(array_unique($this->identifiers))) {
            $this->fail('$identifiers contains duplicates.');
        }

        foreach ($this->identifiers as $type) {
            if (! in_array($type, self::SUPPORTED_IDENTIFIERS, true)) {
                $this->fail(
                    "Unsupported identifier '{$type}'. Supported: "
                        . implode(', ', self::SUPPORTED_IDENTIFIERS) . '.'
                );
            }
        }

        if ($this->loginIdentifiers === []) {
            $this->fail('$loginIdentifiers must contain at least one identifier type.');
        }

        foreach ($this->loginIdentifiers as $type) {
            if (! $this->isIdentifierEnabled($type)) {
                $this->fail("Login identifier '{$type}' is not enabled in \$identifiers.");
            }
        }

        if ($this->requiredIdentifiers === []) {
            $this->fail('$requiredIdentifiers must contain at least one identifier type.');
        }

        foreach ($this->requiredIdentifiers as $type) {
            if (! $this->isIdentifierEnabled($type)) {
                $this->fail("Required identifier '{$type}' is not enabled in \$identifiers.");
            }
        }

        if (array_intersect($this->requiredIdentifiers, $this->loginIdentifiers) === []) {
            $this->fail(
                '$requiredIdentifiers must include at least one of $loginIdentifiers, '
                    . 'otherwise users could register without a way to log in.'
            );
        }

        if ($this->emailMaxLength < 6 || $this->emailMaxLength > 254) {
            $this->fail('$emailMaxLength must be between 6 and 254.');
        }

        if ($this->usernameMinLength < 1 || $this->usernameMinLength > $this->usernameMaxLength) {
            $this->fail('$usernameMinLength must be at least 1 and not exceed $usernameMaxLength.');
        }

        if ($this->usernameMaxLength > 191) {
            $this->fail('$usernameMaxLength cannot exceed 191 (indexed column limit).');
        }

        if (@preg_match($this->usernamePattern, '') === false) {
            $this->fail('$usernamePattern is not a valid regular expression.');
        }

        if (preg_match('/^\d{1,4}$/', $this->phoneDefaultCountryCode) !== 1) {
            $this->fail('$phoneDefaultCountryCode must be 1 to 4 digits, without "+".');
        }

        if ($this->phoneMinDigits < 4 || $this->phoneMinDigits > $this->phoneMaxDigits || $this->phoneMaxDigits > 15) {
            $this->fail('Phone digit limits must satisfy 4 <= $phoneMinDigits <= $phoneMaxDigits <= 15.');
        }
    }

    private function assertPasswordPolicy(): void
    {
        if ($this->passwordMinLength < 6) {
            $this->fail('$passwordMinLength must be at least 6.');
        }

        if ($this->passwordMinLength > $this->passwordMaxLength) {
            $this->fail('$passwordMinLength cannot exceed $passwordMaxLength.');
        }

        $isBcrypt = $this->hashAlgorithm === PASSWORD_BCRYPT || $this->hashAlgorithm === PASSWORD_DEFAULT;

        if ($isBcrypt && $this->passwordMaxLength > 72) {
            $this->fail('Bcrypt ignores input beyond 72 bytes; keep $passwordMaxLength <= 72 or switch algorithm.');
        }

        if (! in_array($this->hashAlgorithm, password_algos(), true) && $this->hashAlgorithm !== PASSWORD_DEFAULT) {
            $this->fail('$hashAlgorithm is not supported by this PHP build.');
        }
    }

    private function assertTokens(): void
    {
        if (preg_match('/^[A-Za-z0-9_]{0,16}$/', $this->tokenPrefix) !== 1) {
            $this->fail('$tokenPrefix may contain only letters, digits and underscores (max 16).');
        }

        if ($this->tokenBytes < 16 || $this->tokenBytes > 128) {
            $this->fail('$tokenBytes must be between 16 and 128.');
        }

        if ($this->tokenHeader === '') {
            $this->fail('$tokenHeader cannot be empty.');
        }

        if ($this->sessionTokenLifetime < 60) {
            $this->fail('$sessionTokenLifetime must be at least 60 seconds.');
        }

        if ($this->sessionTokenIdleTimeout < 0 || $this->sessionIdleTimeout < 0) {
            $this->fail('Idle timeouts cannot be negative (use 0 to disable).');
        }

        if ($this->apiKeyLifetime !== null && $this->apiKeyLifetime < 60) {
            $this->fail('$apiKeyLifetime must be NULL (no expiry) or at least 60 seconds.');
        }

        if ($this->tokenLastUsedUpdateInterval < 0 || $this->maxSessionTokensPerUser < 0) {
            $this->fail('$tokenLastUsedUpdateInterval and $maxSessionTokensPerUser cannot be negative.');
        }

        foreach ($this->defaultTokenAbilities as $ability) {
            if (! is_string($ability) || $ability === '') {
                $this->fail('$defaultTokenAbilities must contain non-empty strings.');
            }
        }
    }

    private function assertThrottling(): void
    {
        if ($this->maxLoginAttempts < 1) {
            $this->fail('$maxLoginAttempts must be at least 1.');
        }

        if ($this->loginAttemptWindow < 1 || $this->lockoutDuration < 1) {
            $this->fail('$loginAttemptWindow and $lockoutDuration must be positive.');
        }

        if ($this->loginAttemptRetentionDays < 1) {
            $this->fail('$loginAttemptRetentionDays must be at least 1.');
        }
    }

    private function assertTenancy(): void
    {
        if (! in_array($this->tenancy, [self::TENANCY_SINGLE, self::TENANCY_MULTI], true)) {
            $this->fail("\$tenancy must be '" . self::TENANCY_SINGLE . "' or '" . self::TENANCY_MULTI . "'.");
        }

        if ($this->isMultiTenant() && $this->tenantHeader === '') {
            $this->fail('$tenantHeader cannot be empty in multi-tenant mode.');
        }
    }

    private function assertAuthorization(): void
    {
        $roleNames = array_keys($this->roles);

        foreach ($this->roles as $name => $role) {
            if (! is_string($name) || preg_match('/^[a-z0-9][a-z0-9_-]*$/', $name) !== 1) {
                $this->fail("Role name '{$name}' must be lowercase letters, digits, '_' or '-'.");
            }

            if (! isset($role['title']) || ! is_string($role['title']) || $role['title'] === '') {
                $this->fail("Role '{$name}' needs a non-empty 'title'.");
            }
        }

        if ($this->superRole !== null && ! in_array($this->superRole, $roleNames, true)) {
            $this->fail("\$superRole '{$this->superRole}' is not defined in \$roles.");
        }

        foreach ($this->defaultRoles as $role) {
            if (! in_array($role, $roleNames, true)) {
                $this->fail("Default role '{$role}' is not defined in \$roles.");
            }
        }

        foreach (array_keys($this->permissions) as $permission) {
            if (preg_match('/^[a-z0-9_-]+(\.[a-z0-9_-]+)+$/', (string) $permission) !== 1) {
                $this->fail("Permission '{$permission}' must use dotted lowercase form, e.g. 'users.create'.");
            }
        }

        foreach ($this->matrix as $role => $grants) {
            if (! in_array($role, $roleNames, true)) {
                $this->fail("\$matrix references undefined role '{$role}'.");
            }

            foreach ($grants as $grant) {
                if ($grant === '*') {
                    continue;
                }

                if (str_ends_with($grant, '.*')) {
                    $prefix  = substr($grant, 0, -1);
                    $matches = array_filter(
                        array_keys($this->permissions),
                        static fn(string $p): bool => str_starts_with($p, $prefix)
                    );

                    if ($matches === []) {
                        $this->fail("Wildcard '{$grant}' for role '{$role}' matches no defined permission.");
                    }

                    continue;
                }

                if (! array_key_exists($grant, $this->permissions)) {
                    $this->fail("\$matrix grants undefined permission '{$grant}' to role '{$role}'.");
                }
            }
        }
    }

    /**
     * @throws LogicException
     */
    private function fail(string $message): never
    {
        throw new LogicException('Ephraitech Auth config: ' . $message);
    }
}
