<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Notifications;

use Ephraitech\Auth\Entities\OneTimeCode;
use Ephraitech\Auth\OneTimeCodes\IssuedCode;
use Ephraitech\Auth\Entities\User;

/**
 * Everything a notifier needs to deliver a code, with ready-made wording.
 * Custom notifiers may use subject()/text() or build their own content.
 */
final class OneTimeCodeMessage
{
    public function __construct(
        public readonly User $user,
        public readonly string $channel,
        public readonly string $destination,
        public readonly string $purpose,
        public readonly string $code,
        public readonly ?string $link,
        public readonly int $expiresInMinutes,
        public readonly string $appName,
    ) {}

    public function subject(): string
    {
        $prefix = $this->appName !== '' ? $this->appName . ': ' : '';

        return $prefix . match ($this->purpose) {
            OneTimeCode::PURPOSE_PASSWORD_RESET => 'Reset your password',
            default                             => 'Verify your ' . ($this->channel === OneTimeCode::CHANNEL_SMS ? 'phone number' : 'email address'),
        };
    }

    /**
     * Plain text, short enough for a single SMS when there is no link.
     */
    public function text(): string
    {
        $prefix  = $this->appName !== '' ? $this->appName . ': ' : '';
        $minutes = $this->expiresInMinutes . ' minute' . ($this->expiresInMinutes === 1 ? '' : 's');

        $body = match ($this->purpose) {
            OneTimeCode::PURPOSE_PASSWORD_RESET => "{$prefix}your password reset code is {$this->code}. It expires in {$minutes}.",
            default                             => "{$prefix}your verification code is {$this->code}. It expires in {$minutes}.",
        };

        if ($this->link !== null && $this->link !== '') {
            $body .= "\n\nOr open this link: {$this->link}";
        }

        return $body . "\n\nIf you didn't request this, ignore this message.";
    }

    /**
     * Build the message for a freshly issued code.
     */
    public static function fromIssued(User $user, IssuedCode $issued, ?string $link, string $appName): self
    {
        return new self(
            $user,
            $issued->channel,
            $issued->destination,
            (string) $issued->record->purpose,
            $issued->code,
            $link,
            $issued->expiresInMinutes(),
            $appName,
        );
    }
}
