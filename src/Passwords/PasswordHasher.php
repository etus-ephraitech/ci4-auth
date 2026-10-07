<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Passwords;

use Ephraitech\Auth\Config\Auth;
use Ephraitech\Auth\Exceptions\AuthException;
use ValueError;

/**
 * Thin, config-driven wrapper over PHP's password_* functions.
 */
final class PasswordHasher
{
    public function __construct(private readonly Auth $config) {}

    /**
     * @throws AuthException
     */
    public function hash(string $password): string
    {
        try {
            return password_hash($password, $this->config->hashAlgorithm, $this->config->hashOptions);
        } catch (ValueError $e) {
            throw new AuthException('The password could not be hashed: ' . $e->getMessage(), 0, $e);
        }
    }

    public function verify(string $password, string $hash): bool
    {
        if ($hash === '') {
            return false;
        }

        return password_verify($password, $hash);
    }

    /**
     * True when the stored hash was made with an older algorithm or cost
     * than the current config, so it should be upgraded on next login.
     */
    public function needsRehash(string $hash): bool
    {
        return password_needs_rehash($hash, $this->config->hashAlgorithm, $this->config->hashOptions);
    }

    /**
     * Spend the same time a real verification would, for login attempts
     * against identifiers that don't exist. Without this, "unknown user"
     * responds measurably faster than "wrong password", which lets an
     * attacker enumerate registered emails and phone numbers.
     */
    public function verifyDummy(string $password): void
    {
        try {
            $this->hash($password);
        } catch (AuthException) {
            // Timing equalization only; the outcome is already a failure.
        }
    }
}
