<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Passwords;

use CodeIgniter\Config\Factories;
use Ephraitech\Auth\Config\Auth;
use Ephraitech\Auth\Entities\Identity;
use Ephraitech\Auth\Exceptions\AuthException;
use Ephraitech\Auth\Exceptions\WeakPasswordException;
use Ephraitech\Auth\Models\IdentityModel;
use Throwable;

/**
 * Sets and verifies a user's password, stored as the 'password' row in
 * auth_identities. Handles policy enforcement and transparent rehashing.
 */
final class PasswordManager
{
    public function __construct(
        private readonly Auth $config,
        private readonly PasswordHasher $hasher,
        private readonly PasswordPolicy $policy,
        private readonly IdentityModel $identities,
    ) {}

    public static function create(?Auth $config = null): self
    {
        /** @var Auth $config */
        $config ??= config(Auth::class);

        /** @var IdentityModel $identities */
        $identities = Factories::models(IdentityModel::class, ['preferApp' => false]);

        return new self($config, new PasswordHasher($config), new PasswordPolicy($config), $identities);
    }

    /**
     * Validate, hash and store a password for a user.
     *
     * $enforcePolicy = false is for trusted paths only (seeders, CLI
     * admin creation); even then, empty passwords and NUL bytes are refused.
     *
     * Callers changing an existing password should also revoke the user's
     * tokens/sessions (the token service provides this).
     *
     * @throws WeakPasswordException
     * @throws AuthException
     */
    public function setPassword(int $userId, string $password, bool $enforcePolicy = true): void
    {
        if ($password === '' || str_contains($password, "\0")) {
            throw new WeakPasswordException(['The password cannot be empty or contain invalid characters.']);
        }

        if ($enforcePolicy) {
            $this->policy->assert($password, $this->identifierValues($userId));
        }

        $this->identities->setPasswordHash($userId, $this->hasher->hash($password));
    }

    /**
     * Verify a password for a user. On success, upgrades the stored hash
     * if the algorithm/cost config has changed, and records last use.
     *
     * Always spends hashing time, even when the user has no password row.
     */
    public function verify(int $userId, string $password): bool
    {
        $identity = $this->identities->findPassword($userId);

        if (! $identity instanceof Identity || empty($identity->secret)) {
            $this->hasher->verifyDummy($password);

            return false;
        }

        $hash = (string) $identity->secret;

        if (! $this->hasher->verify($password, $hash)) {
            return false;
        }

        if ($this->hasher->needsRehash($hash)) {
            try {
                $this->identities->setPasswordHash($userId, $this->hasher->hash($password));
            } catch (Throwable $e) {
                // A failed upgrade must never block a valid login.
                log_message('error', 'Ephraitech Auth: password rehash failed for user {id}: {message}', [
                    'id'      => $userId,
                    'message' => $e->getMessage(),
                ]);
            }
        }

        $this->identities->touchLastUsed((int) $identity->id);

        return true;
    }

    public function hasPassword(int $userId): bool
    {
        return $this->identities->findPassword($userId) instanceof Identity;
    }

    /**
     * Validate a candidate password for a user without saving it, e.g. to
     * show errors on a "change password" form before submission.
     *
     * @return list<string>
     */
    public function check(int $userId, string $password): array
    {
        return $this->policy->errors($password, $this->identifierValues($userId));
    }

    public function hasher(): PasswordHasher
    {
        return $this->hasher;
    }

    public function policy(): PasswordPolicy
    {
        return $this->policy;
    }

    /**
     * @return array<string, string|null>
     */
    private function identifierValues(int $userId): array
    {
        $values = [];

        foreach ($this->identities->findIdentifiersForUser($userId) as $type => $identity) {
            $values[$type] = $identity->identifier;
        }

        return $values;
    }
}
