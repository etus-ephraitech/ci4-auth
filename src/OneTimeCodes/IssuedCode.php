<?php

declare(strict_types=1);

namespace Ephraitech\Auth\OneTimeCodes;

use Ephraitech\Auth\Entities\OneTimeCode;

/**
 * Returned once, at issue time: the only moment the plain code exists.
 */
final class IssuedCode
{
    public function __construct(
        public readonly OneTimeCode $record,
        public readonly string $code,
        public readonly string $channel,
        public readonly string $destination,
    ) {}

    public function selector(): string
    {
        return (string) $this->record->selector;
    }

    public function expiresInMinutes(): int
    {
        return max(1, (int) ceil($this->record->secondsRemaining() / 60));
    }
}
