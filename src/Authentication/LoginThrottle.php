<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Authentication;

use CodeIgniter\Config\Factories;
use CodeIgniter\Events\Events;
use CodeIgniter\I18n\Time;
use Ephraitech\Auth\AuthEvents;
use Ephraitech\Auth\Config\Auth;
use Ephraitech\Auth\Exceptions\LockedOutException;
use Ephraitech\Auth\Models\LoginAttemptModel;

/**
 * Locks an identifier+IP pair after $maxLoginAttempts failures within
 * $loginAttemptWindow, for $lockoutDuration after the latest failure.
 *
 * Keyed on identifier+IP (not identifier alone) so an attacker cannot
 * lock a real user out by spamming their email from elsewhere. Pair this
 * with CodeIgniter's Throttler filter on the login route for per-IP
 * limits against credential stuffing across many identifiers.
 */
final class LoginThrottle
{
    public function __construct(
        private readonly Auth $config,
        private readonly LoginAttemptModel $attempts,
    ) {}

    public static function create(?Auth $config = null): self
    {
        /** @var Auth $config */
        $config ??= config(Auth::class);

        /** @var LoginAttemptModel $attempts */
        $attempts = Factories::models(LoginAttemptModel::class, ['preferApp' => false]);

        return new self($config, $attempts);
    }

    /**
     * @throws LockedOutException
     */
    public function check(string $identifierKey, string $ipAddress): void
    {
        $wait = $this->availableIn($identifierKey, $ipAddress);

        if ($wait > 0) {
            throw new LockedOutException($wait);
        }
    }

    /**
     * Seconds until the next attempt is allowed; 0 when allowed now.
     */
    public function availableIn(string $identifierKey, string $ipAddress): int
    {
        $windowStart = Time::now()->subSeconds($this->config->loginAttemptWindow);
        $failures    = $this->attempts->failuresSince($identifierKey, $ipAddress, $windowStart);

        if ($failures['count'] < $this->config->maxLoginAttempts || $failures['latest'] === null) {
            return 0;
        }

        $until = Time::parse($failures['latest'])->getTimestamp() + $this->config->lockoutDuration;

        return max(0, $until - Time::now()->getTimestamp());
    }

    public function recordFailure(
        ?string $type,
        string $identifierKey,
        ?int $userId,
        string $ipAddress,
        ?string $userAgent,
        string $reason,
    ): void {
        $this->attempts->record($type, $identifierKey, $userId, $ipAddress, $userAgent, false, $reason);

        $windowStart = Time::now()->subSeconds($this->config->loginAttemptWindow);
        $count       = $this->attempts->failuresSince($identifierKey, $ipAddress, $windowStart)['count'];

        if ($count === $this->config->maxLoginAttempts) {
            Events::trigger(AuthEvents::LOCKED_OUT, $type, $identifierKey, $ipAddress);
        }
    }

    public function recordSuccess(
        ?string $type,
        string $identifierKey,
        int $userId,
        string $ipAddress,
        ?string $userAgent,
    ): void {
        if ($this->config->recordSuccessfulLogins) {
            $this->attempts->record($type, $identifierKey, $userId, $ipAddress, $userAgent, true, null);

            return;
        }

        $this->attempts->clearFailures($identifierKey, $ipAddress);
    }

    /**
     * Delete attempts older than $loginAttemptRetentionDays (prune command).
     */
    public function prune(): int
    {
        return $this->attempts->deleteOlderThan(
            Time::now()->subDays($this->config->loginAttemptRetentionDays)
        );
    }
}
