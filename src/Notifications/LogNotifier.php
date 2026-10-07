<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Notifications;

use Ephraitech\Auth\Config\Auth;
use Ephraitech\Auth\Exceptions\NotificationException;

/**
 * Development notifier: writes the message to writable/logs instead of
 * sending it, for both channels. Refuses to run in production, where it
 * would silently leave users without their codes.
 */
final class LogNotifier implements NotifierInterface
{
    public function __construct(private readonly Auth $config) {}

    public function send(OneTimeCodeMessage $message): void
    {
        if (ENVIRONMENT === 'production') {
            throw NotificationException::misconfigured(
                self::class,
                'LogNotifier must not be used in production; configure a real notifier.'
            );
        }

        log_message('notice', 'Ephraitech Auth [{channel}] to {to}: {text}', [
            'channel' => $message->channel,
            'to'      => $message->destination,
            'text'    => $message->text(),
        ]);
    }
}
