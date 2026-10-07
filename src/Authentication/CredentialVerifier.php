<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Authentication;

use CodeIgniter\Config\Factories;
use CodeIgniter\Events\Events;
use Ephraitech\Auth\AuthEvents;
use Ephraitech\Auth\Config\Auth;
use Ephraitech\Auth\Entities\Identity;
use Ephraitech\Auth\Entities\User;
use Ephraitech\Auth\Exceptions\AccountNotActiveException;
use Ephraitech\Auth\Exceptions\AuthException;
use Ephraitech\Auth\Exceptions\IdentifierNotVerifiedException;
use Ephraitech\Auth\Exceptions\InvalidCredentialsException;
use Ephraitech\Auth\Exceptions\InvalidIdentifierException;
use Ephraitech\Auth\Exceptions\LockedOutException;
use Ephraitech\Auth\Models\IdentityModel;
use Ephraitech\Auth\Models\UserModel;
use Ephraitech\Auth\Passwords\PasswordManager;

/**
 * Turns "login + password" into a verified User, shared by both guards.
 *
 * Order matters for security:
 *   1. Detect type and normalize (never reveals validity).
 *   2. Throttle check, before any password work.
 *   3. Look up identity; unknown => dummy hash (equal timing).
 *   4. Verify password.
 *   5. Only now reveal account status or verification problems.
 */
final class CredentialVerifier
{
    public function __construct(
        private readonly Auth $config,
        private readonly UserModel $users,
        private readonly IdentityModel $identities,
        private readonly PasswordManager $passwords,
        private readonly LoginThrottle $throttle,
    ) {}

    public static function create(?Auth $config = null): self
    {
        /** @var Auth $config */
        $config ??= config(Auth::class);

        /** @var UserModel $users */
        $users = Factories::models($config->userModel, ['preferApp' => false]);

        /** @var IdentityModel $identities */
        $identities = Factories::models(IdentityModel::class, ['preferApp' => false]);

        return new self($config, $users, $identities, PasswordManager::create($config), LoginThrottle::create($config));
    }

    /**
     * @param string|null $type Identifier type, or NULL to detect from $login.
     *
     * @throws LockedOutException
     * @throws InvalidCredentialsException
     * @throws AccountNotActiveException
     * @throws IdentifierNotVerifiedException
     * @throws AuthException                  Misconfiguration.
     */
    public function verify(
        string $login,
        string $password,
        ?string $type = null,
        string $ipAddress = '0.0.0.0',
        ?string $userAgent = null,
    ): User {
        $login = trim($login);
        $type  = $this->resolveType($login, $type);

        $normalized = null;

        if ($type !== null && $this->config->canLoginWith($type)) {
            $normalized = $this->identities->normalizer()->tryNormalize($type, $login);
        }

        $key = $normalized ?? mb_strtolower(mb_substr($login, 0, 255, 'UTF-8'), 'UTF-8');

        $this->throttle->check($key, $ipAddress);

        if ($type === null) {
            $this->failWithDummy($password, null, $key, null, $ipAddress, $userAgent, 'undetectable');
        }

        if (! $this->config->canLoginWith($type)) {
            $this->failWithDummy($password, $type, $key, null, $ipAddress, $userAgent, 'identifier_not_allowed');
        }

        $identity = $normalized !== null ? $this->identities->findByIdentifier($type, $normalized) : null;
        $user     = $identity instanceof Identity ? $this->users->find($identity->user_id) : null;

        if (! $identity instanceof Identity || ! $user instanceof User) {
            $this->failWithDummy($password, $type, $key, null, $ipAddress, $userAgent, 'unknown_identifier');
        }

        $userId = (int) $user->id;

        if (! $this->passwords->verify($userId, $password)) {
            $this->fail($type, $key, $userId, $ipAddress, $userAgent, 'invalid_password');
        }

        if (! $user->isActive()) {
            $status = (string) $user->status;

            $this->record($type, $key, $userId, $ipAddress, $userAgent, 'account_' . $status);

            throw new AccountNotActiveException($status, $user->status_reason);
        }

        if ($this->config->mustBeVerifiedToLogin($type) && ! $identity->isVerified()) {
            $this->record($type, $key, $userId, $ipAddress, $userAgent, 'unverified_' . $type);

            throw new IdentifierNotVerifiedException($type, $userId);
        }

        $this->throttle->recordSuccess($type, $key, $userId, $ipAddress, $userAgent);
        $this->identities->touchLastUsed((int) $identity->id);

        return $user;
    }

    /**
     * @throws AuthException
     */
    private function resolveType(string $login, ?string $type): ?string
    {
        if ($type !== null) {
            return $type;
        }

        if ($this->config->detectLoginIdentifier) {
            try {
                return $this->identities->normalizer()->detectLoginType($login);
            } catch (InvalidIdentifierException) {
                return null;
            }
        }

        if (count($this->config->loginIdentifiers) === 1) {
            return $this->config->loginIdentifiers[0];
        }

        throw new AuthException(
            'The identifier type must be passed to verify() when detectLoginIdentifier is disabled '
                . 'and more than one login identifier is enabled.'
        );
    }

    /**
     * @throws InvalidCredentialsException
     */
    private function failWithDummy(
        string $password,
        ?string $type,
        string $key,
        ?int $userId,
        string $ipAddress,
        ?string $userAgent,
        string $reason,
    ): never {
        $this->passwords->hasher()->verifyDummy($password);

        $this->fail($type, $key, $userId, $ipAddress, $userAgent, $reason);
    }

    /**
     * @throws InvalidCredentialsException
     */
    private function fail(
        ?string $type,
        string $key,
        ?int $userId,
        string $ipAddress,
        ?string $userAgent,
        string $reason,
    ): never {
        $this->record($type, $key, $userId, $ipAddress, $userAgent, $reason);

        throw new InvalidCredentialsException();
    }

    private function record(
        ?string $type,
        string $key,
        ?int $userId,
        string $ipAddress,
        ?string $userAgent,
        string $reason,
    ): void {
        $this->throttle->recordFailure($type, $key, $userId, $ipAddress, $userAgent, $reason);

        Events::trigger(AuthEvents::LOGIN_FAILED, $type, $key, $reason);
    }
}
