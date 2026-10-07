<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Exceptions;

/**
 * A code could not be delivered. Messages are written for developers and
 * logs; show users a generic "we couldn't send the code" instead.
 */
final class NotificationException extends AuthException
{
    public static function channelDisabled(string $channel): self
    {
        return new self(
            "No notifier is configured for the '{$channel}' channel. Set Config\\Auth::\$notifiers['{$channel}']."
        );
    }

    public static function unsupportedChannel(string $notifier, string $channel): self
    {
        return new self("{$notifier} cannot deliver over the '{$channel}' channel.");
    }

    public static function deliveryFailed(string $channel, string $reason): self
    {
        return new self("Delivery over '{$channel}' failed: {$reason}");
    }

    public static function misconfigured(string $notifier, string $reason): self
    {
        return new self("{$notifier} is not configured: {$reason}");
    }
}
