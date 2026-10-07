<?php

declare(strict_types=1);

namespace Ephraitech\Auth\OneTimeCodes;

use CodeIgniter\Config\Factories;
use CodeIgniter\I18n\Time;
use Ephraitech\Auth\Config\Auth;
use Ephraitech\Auth\Entities\Identity;
use Ephraitech\Auth\Entities\OneTimeCode;
use Ephraitech\Auth\Entities\User;
use Ephraitech\Auth\Exceptions\AuthException;
use Ephraitech\Auth\Exceptions\ResendTooSoonException;
use Ephraitech\Auth\Models\OneTimeCodeModel;

/**
 * Issues and verifies short-lived, single-use numeric codes.
 *
 * Verification is two-step on purpose: check() confirms the code without
 * using it up, and consume() burns it once the action (e.g. setting a new
 * password) has actually succeeded. A user whose new password fails the
 * policy can therefore retry without requesting a fresh code.
 */
final class OneTimeCodeManager
{
    private const CHANNELS = [
        Auth::IDENTIFIER_EMAIL => OneTimeCode::CHANNEL_EMAIL,
        Auth::IDENTIFIER_PHONE => OneTimeCode::CHANNEL_SMS,
    ];

    public function __construct(
        private readonly Auth $config,
        private readonly OneTimeCodeModel $codes,
    ) {}

    public static function create(?Auth $config = null): self
    {
        /** @var Auth $config */
        $config ??= config(Auth::class);

        /** @var OneTimeCodeModel $codes */
        $codes = Factories::models(OneTimeCodeModel::class, ['preferApp' => false]);

        return new self($config, $codes);
    }

    /**
     * Delivery channel for an identifier type, or NULL when it can't
     * receive codes (usernames).
     */
    public function channelFor(string $identifierType): ?string
    {
        return self::CHANNELS[$identifierType] ?? null;
    }

    /**
     * Seconds before another code may be issued (0 = now).
     */
    public function secondsUntilResend(Identity $identity, string $purpose): int
    {
        $interval = $this->config->otpResendInterval;

        if ($interval === 0 || $identity->id === null) {
            return 0;
        }

        $last = $this->codes->lastIssuedAt((int) $identity->id, $purpose);

        if ($last === null) {
            return 0;
        }

        return max(0, $last->getTimestamp() + $interval - Time::now()->getTimestamp());
    }

    /**
     * Issue a new code, invalidating older outstanding ones for the same
     * identity and purpose.
     *
     * @throws ResendTooSoonException
     * @throws AuthException
     */
    public function issue(User $user, Identity $identity, string $purpose, ?string $ipAddress = null): IssuedCode
    {
        $this->assertPurpose($purpose);

        if ($user->id === null || $identity->id === null || (int) $identity->user_id !== (int) $user->id) {
            throw new AuthException('The identity does not belong to the user.');
        }

        $channel = $this->channelFor((string) $identity->type);

        if ($channel === null || empty($identity->identifier)) {
            throw new AuthException("Codes cannot be sent to a '{$identity->type}' identifier.");
        }

        $wait = $this->secondsUntilResend($identity, $purpose);

        if ($wait > 0) {
            throw new ResendTooSoonException($wait);
        }

        $this->codes->consumeOutstanding((int) $identity->id, $purpose);

        $code     = $this->generate();
        $selector = bin2hex(random_bytes(16));

        $id = $this->codes->insert([
            'user_id'     => (int) $user->id,
            'identity_id' => (int) $identity->id,
            'purpose'     => $purpose,
            'channel'     => $channel,
            'selector'    => $selector,
            'code_hash'   => $this->hash($selector, $code),
            'attempts'    => 0,
            'ip_address'  => $ipAddress !== null && $ipAddress !== '' ? substr($ipAddress, 0, 45) : null,
            'expires_at'  => Time::now()->addSeconds($this->config->otpLifetime)->toDateTimeString(),
        ], true);

        if ($id === false) {
            throw new AuthException('Failed to issue the code.');
        }

        $record = $this->codes->find($id);

        if (! $record instanceof OneTimeCode) {
            throw new AuthException("Code {$id} could not be loaded after issuing.");
        }

        return new IssuedCode($record, $code, $channel, (string) $identity->identifier);
    }

    /**
     * Find a code by the selector from a link, restricted to one purpose.
     */
    public function findBySelector(string $selector, string $purpose): ?OneTimeCode
    {
        $record = $this->codes->findBySelector(strtolower(trim($selector)));

        return $record !== null && $record->purpose === $purpose ? $record : null;
    }

    /**
     * The current code for an identity, for typed-in (SMS) verification.
     */
    public function latestFor(Identity $identity, string $purpose): ?OneTimeCode
    {
        return $identity->id === null ? null : $this->codes->latestActive((int) $identity->id, $purpose);
    }

    /**
     * Whether $code matches. A wrong code counts as an attempt; malformed
     * input (wrong length, letters) does not, since it isn't a real guess.
     * Does NOT consume the code; call consume() after the action succeeds.
     */
    public function check(OneTimeCode $record, string $code): bool
    {
        if (! $record->isUsable($this->config->otpMaxAttempts)) {
            return false;
        }

        $code = preg_replace('/[\s-]+/', '', $code) ?? '';

        if (preg_match('/^\d{' . $this->config->otpLength . '}$/', $code) !== 1) {
            return false;
        }

        if (hash_equals((string) $record->code_hash, $this->hash((string) $record->selector, $code))) {
            return true;
        }

        $this->codes->incrementAttempts((int) $record->id);

        return false;
    }

    /**
     * Burn a code. False when it was already used (lost a race).
     */
    public function consume(OneTimeCode $record): bool
    {
        return $this->codes->markConsumed((int) $record->id);
    }

    /**
     * Invalidate all outstanding codes of a purpose for a user, e.g. every
     * reset code once the password has been changed.
     */
    public function invalidateForUser(int $userId, string $purpose): int
    {
        $this->assertPurpose($purpose);

        return $this->codes->consumeOutstandingForUser($userId, $purpose);
    }

    /**
     * Delete codes older than $otpRetentionDays (auth:prune).
     */
    public function prune(): int
    {
        return $this->codes->deleteStale(Time::now()->subDays($this->config->otpRetentionDays));
    }

    // ------------------------------------------------------------------

    private function generate(): string
    {
        $length = $this->config->otpLength;

        return str_pad((string) random_int(0, (10 ** $length) - 1), $length, '0', STR_PAD_LEFT);
    }

    private function hash(string $selector, string $code): string
    {
        return hash('sha256', $selector . ':' . $code);
    }

    /**
     * @throws AuthException
     */
    private function assertPurpose(string $purpose): void
    {
        if (! in_array($purpose, OneTimeCode::PURPOSES, true)) {
            throw new AuthException("Unknown code purpose '{$purpose}'.");
        }
    }
}
