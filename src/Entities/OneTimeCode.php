<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Entities;

use CodeIgniter\Entity\Entity;
use CodeIgniter\I18n\Time;

/**
 * A single-use code sent to one identity for one purpose.
 *
 * @property int|null    $id
 * @property int|null    $user_id
 * @property int|null    $identity_id
 * @property string|null $purpose
 * @property string|null $channel
 * @property string|null $selector
 * @property string|null $code_hash
 * @property int         $attempts
 * @property string|null $ip_address
 * @property Time|null   $expires_at
 * @property Time|null   $consumed_at
 * @property Time|null   $created_at
 */
class OneTimeCode extends Entity
{
    public const PURPOSE_PASSWORD_RESET    = 'password_reset';
    public const PURPOSE_VERIFY_IDENTIFIER = 'verify_identifier';

    public const PURPOSES = [
        self::PURPOSE_PASSWORD_RESET,
        self::PURPOSE_VERIFY_IDENTIFIER,
    ];

    public const CHANNEL_EMAIL = 'email';
    public const CHANNEL_SMS   = 'sms';

    protected $dates = ['expires_at', 'consumed_at', 'created_at'];

    protected $casts = [
        'id'          => '?integer',
        'user_id'     => '?integer',
        'identity_id' => '?integer',
        'attempts'    => 'integer',
    ];

    public function isConsumed(): bool
    {
        return ! empty($this->attributes['consumed_at']);
    }

    public function isExpired(): bool
    {
        $expiresAt = $this->expires_at;

        return ! $expiresAt instanceof Time || $expiresAt->getTimestamp() <= Time::now()->getTimestamp();
    }

    public function attemptsExhausted(int $maxAttempts): bool
    {
        return $this->attempts >= $maxAttempts;
    }

    /**
     * Usable = not consumed, not expired, guesses remaining.
     */
    public function isUsable(int $maxAttempts): bool
    {
        return ! $this->isConsumed() && ! $this->isExpired() && ! $this->attemptsExhausted($maxAttempts);
    }

    /**
     * Seconds until expiry (0 when expired).
     */
    public function secondsRemaining(): int
    {
        $expiresAt = $this->expires_at;

        if (! $expiresAt instanceof Time) {
            return 0;
        }

        return max(0, $expiresAt->getTimestamp() - Time::now()->getTimestamp());
    }

    /**
     * The hash is never included in array/JSON output.
     */
    public function toArray(bool $onlyChanged = false, bool $cast = true, bool $recursive = false): array
    {
        $data = parent::toArray($onlyChanged, $cast, $recursive);

        unset($data['code_hash']);

        return $data;
    }
}
