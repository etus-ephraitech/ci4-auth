<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Notifications;

use Ephraitech\Auth\Exceptions\NotificationException;

/**
 * Delivers one-time codes. Implementations are built by NotifierRegistry
 * as `new YourNotifier(Ephraitech\Auth\Config\Auth $config)`, so their
 * constructor must accept the auth config as its only required argument.
 */
interface NotifierInterface
{
    /**
     * @throws NotificationException When the message cannot be delivered.
     */
    public function send(OneTimeCodeMessage $message): void;
}
