<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Config;

use CodeIgniter\Config\BaseService;
use CodeIgniter\Config\Factories;
use Ephraitech\Auth\Authentication\AuthManager;
use Ephraitech\Auth\Authentication\CredentialVerifier;
use Ephraitech\Auth\Authentication\Guards\SessionGuard;
use Ephraitech\Auth\Authentication\Guards\TokenGuard;
use Ephraitech\Auth\Authentication\LoginThrottle;
use Ephraitech\Auth\Authorization\Authorizer;
use Ephraitech\Auth\Authorization\TenantContext;
use Ephraitech\Auth\Models\IdentityModel;
use Ephraitech\Auth\Models\LoginAttemptModel;
use Ephraitech\Auth\Models\PermissionModel;
use Ephraitech\Auth\Models\RoleModel;
use Ephraitech\Auth\Models\UserModel;
use Ephraitech\Auth\Passwords\PasswordChanger;
use Ephraitech\Auth\Passwords\PasswordHasher;
use Ephraitech\Auth\Passwords\PasswordManager;
use Ephraitech\Auth\Passwords\PasswordPolicy;
use Ephraitech\Auth\Models\AccessTokenModel;
use Ephraitech\Auth\Registration\UserRegistrar;
use Ephraitech\Auth\Tokens\TokenManager;
use Ephraitech\Auth\Models\OneTimeCodeModel;
use Ephraitech\Auth\Notifications\NotifierRegistry;
use Ephraitech\Auth\OneTimeCodes\OneTimeCodeManager;
use Ephraitech\Auth\Flows\DeliveryTargetResolver;
use Ephraitech\Auth\Flows\PasswordResetFlow;
use Ephraitech\Auth\Flows\VerificationFlow;

/**
 * Service definitions, auto-discovered by CodeIgniter (Config\Modules
 * with 'services' in $aliases and $discoverInComposer = true, the defaults).
 *
 *   service('auth')                 AuthManager (guards + checks)
 *   service('authTenant')           TenantContext
 *   service('authAuthorizer')       Authorizer
 *   service('authTokens')           TokenManager
 *   service('authPasswords')        PasswordManager
 *   service('authPasswordChanger')  PasswordChanger
 *   service('authCredentials')      CredentialVerifier
 *   service('authThrottle')         LoginThrottle
 *   service('authRegistrar')        UserRegistrar
 *   service('authPasswordReset')    PasswordResetFlow
 *   service('authVerification')     VerificationFlow
 *
 * All names are prefixed to avoid colliding with other packages.
 * 
 *  service('authOneTimeCodes')     OneTimeCodeManager
 *  service('authNotifiers')        NotifierRegistry
 */
class Services extends BaseService
{
    private static bool $configValidated = false;

    public static function auth(bool $getShared = true): AuthManager
    {
        if ($getShared) {
            return static::getSharedInstance('auth');
        }

        $config = self::authConfig();

        return new AuthManager(
            $config,
            service('authAuthorizer'),
            service('authTenant'),
            service('request'),
            [
                SessionGuard::NAME => static fn(): SessionGuard => new SessionGuard(
                    $config,
                    service('authCredentials'),
                    self::userModel($config),
                    self::packageModel(IdentityModel::class),
                    service('session'),
                    service('request'),
                ),
                TokenGuard::NAME => static fn(): TokenGuard => new TokenGuard(
                    $config,
                    service('authTokens'),
                    self::userModel($config),
                    service('authCredentials'),
                    service('request'),
                ),
            ],
        );
    }

    public static function authTenant(bool $getShared = true): TenantContext
    {
        if ($getShared) {
            return static::getSharedInstance('authTenant');
        }

        return new TenantContext();
    }

    public static function authAuthorizer(bool $getShared = true): Authorizer
    {
        if ($getShared) {
            return static::getSharedInstance('authAuthorizer');
        }

        return new Authorizer(
            self::authConfig(),
            self::packageModel(RoleModel::class),
            self::packageModel(PermissionModel::class),
            service('authTenant'),
        );
    }

    public static function authTokens(bool $getShared = true): TokenManager
    {
        if ($getShared) {
            return static::getSharedInstance('authTokens');
        }

        return new TokenManager(self::authConfig(), self::packageModel(AccessTokenModel::class));
    }

    public static function authPasswords(bool $getShared = true): PasswordManager
    {
        if ($getShared) {
            return static::getSharedInstance('authPasswords');
        }

        $config = self::authConfig();

        return new PasswordManager(
            $config,
            new PasswordHasher($config),
            new PasswordPolicy($config),
            self::packageModel(IdentityModel::class),
        );
    }

    public static function authPasswordChanger(bool $getShared = true): PasswordChanger
    {
        if ($getShared) {
            return static::getSharedInstance('authPasswordChanger');
        }

        $config = self::authConfig();

        return new PasswordChanger(
            $config,
            self::userModel($config),
            service('authPasswords'),
            service('authTokens'),
        );
    }

    public static function authThrottle(bool $getShared = true): LoginThrottle
    {
        if ($getShared) {
            return static::getSharedInstance('authThrottle');
        }

        return new LoginThrottle(self::authConfig(), self::packageModel(LoginAttemptModel::class));
    }

    public static function authCredentials(bool $getShared = true): CredentialVerifier
    {
        if ($getShared) {
            return static::getSharedInstance('authCredentials');
        }

        $config = self::authConfig();

        return new CredentialVerifier(
            $config,
            self::userModel($config),
            self::packageModel(IdentityModel::class),
            service('authPasswords'),
            service('authThrottle'),
        );
    }

    public static function authRegistrar(bool $getShared = true): UserRegistrar
    {
        if ($getShared) {
            return static::getSharedInstance('authRegistrar');
        }

        $config = self::authConfig();

        return new UserRegistrar(
            $config,
            self::userModel($config),
            self::packageModel(IdentityModel::class),
            service('authPasswords'),
            service('authAuthorizer'),
        );
    }


    public static function authOneTimeCodes(bool $getShared = true): OneTimeCodeManager
    {
        if ($getShared) {
            return static::getSharedInstance('authOneTimeCodes');
        }

        return new OneTimeCodeManager(self::authConfig(), self::packageModel(OneTimeCodeModel::class));
    }

    public static function authNotifiers(bool $getShared = true): NotifierRegistry
    {
        if ($getShared) {
            return static::getSharedInstance('authNotifiers');
        }

        return new NotifierRegistry(self::authConfig());
    }

    public static function authPasswordReset(bool $getShared = true): PasswordResetFlow
    {
        if ($getShared) {
            return static::getSharedInstance('authPasswordReset');
        }

        $config     = self::authConfig();
        $users      = self::userModel($config);
        $identities = self::packageModel(IdentityModel::class);

        return new PasswordResetFlow(
            $config,
            $users,
            $identities,
            new DeliveryTargetResolver($config, $users, $identities),
            service('authOneTimeCodes'),
            service('authNotifiers'),
            service('authPasswords'),
            service('authPasswordChanger'),
        );
    }

    public static function authVerification(bool $getShared = true): VerificationFlow
    {
        if ($getShared) {
            return static::getSharedInstance('authVerification');
        }

        $config     = self::authConfig();
        $users      = self::userModel($config);
        $identities = self::packageModel(IdentityModel::class);

        return new VerificationFlow(
            $config,
            $users,
            $identities,
            new DeliveryTargetResolver($config, $users, $identities),
            service('authOneTimeCodes'),
            service('authNotifiers'),
        );
    }

    // ------------------------------------------------------------------

    /**
     * Resolve config (host override preferred) and validate it once per process.
     */
    private static function authConfig(): Auth
    {
        /** @var Auth $config */
        $config = config(Auth::class);

        if (! self::$configValidated) {
            $config->assertValid();
            self::$configValidated = true;
        }

        return $config;
    }

    private static function userModel(Auth $config): UserModel
    {
        /** @var UserModel $model */
        $model = Factories::models($config->userModel, ['preferApp' => false]);

        return $model;
    }

    /**
     * @template T of object
     *
     * @param class-string<T> $class
     *
     * @return T
     */
    private static function packageModel(string $class): object
    {
        return Factories::models($class, ['preferApp' => false]);
    }
}
