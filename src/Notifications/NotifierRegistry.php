<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Notifications;

use Ephraitech\Auth\Config\Auth;
use Ephraitech\Auth\Exceptions\NotificationException;

/**
 * Resolves the notifier for each channel from Config\Auth::$notifiers.
 * Apps needing constructor dependencies can register instances directly:
 *
 *     service('authNotifiers')->register('sms', new MySmsNotifier($client));
 */
final class NotifierRegistry
{
    /**
     * @var array<string, NotifierInterface>
     */
    private array $instances = [];

    public function __construct(private readonly Auth $config) {}

    public function register(string $channel, NotifierInterface $notifier): void
    {
        $this->instances[$channel] = $notifier;
    }

    public function supports(string $channel): bool
    {
        return isset($this->instances[$channel]) || ! empty($this->config->notifiers[$channel]);
    }

    /**
     * @throws NotificationException
     */
    public function for(string $channel): NotifierInterface
    {
        if (isset($this->instances[$channel])) {
            return $this->instances[$channel];
        }

        $class = $this->config->notifiers[$channel] ?? null;

        if ($class === null || $class === '') {
            throw NotificationException::channelDisabled($channel);
        }

        $notifier = new $class($this->config);

        if (! $notifier instanceof NotifierInterface) {
            throw NotificationException::misconfigured($class, 'it does not implement ' . NotifierInterface::class);
        }

        return $this->instances[$channel] = $notifier;
    }

    /**
     * @throws NotificationException
     */
    public function send(OneTimeCodeMessage $message): void
    {
        $this->for($message->channel)->send($message);
    }
}
