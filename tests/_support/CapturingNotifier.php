<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Tests\Support;

use Ephraitech\Auth\Config\Auth;
use Ephraitech\Auth\Exceptions\NotificationException;
use Ephraitech\Auth\Notifications\NotifierInterface;
use Ephraitech\Auth\Notifications\OneTimeCodeMessage;

/**
 * Records messages instead of sending them, so tests can read the codes.
 * Set $fail = true to simulate a delivery failure.
 */
final class CapturingNotifier implements NotifierInterface
{
    /**
     * @var list<OneTimeCodeMessage>
     */
    public static array $messages = [];

    public static bool $fail = false;

    public function __construct(Auth $config) {}

    public function send(OneTimeCodeMessage $message): void
    {
        if (self::$fail) {
            throw NotificationException::deliveryFailed($message->channel, 'simulated failure');
        }

        self::$messages[] = $message;
    }

    public static function reset(): void
    {
        self::$messages = [];
        self::$fail     = false;
    }

    public static function last(): ?OneTimeCodeMessage
    {
        return self::$messages === [] ? null : self::$messages[array_key_last(self::$messages)];
    }
}
