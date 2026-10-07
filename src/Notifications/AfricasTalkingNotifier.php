<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Notifications;

use Ephraitech\Auth\Config\Auth;
use Ephraitech\Auth\Entities\OneTimeCode;
use Ephraitech\Auth\Exceptions\NotificationException;
use Throwable;

/**
 * Sends SMS codes through Africa's Talking.
 *
 *   .env:
 *     auth.africasTalkingUsername = yourusername
 *     auth.africasTalkingApiKey   = atsk_...
 *     auth.africasTalkingSenderId = EPHRAITECH   (optional, must be registered)
 *
 *   app/Config/Auth.php:
 *     public array $notifiers = ['email' => EmailNotifier::class, 'sms' => AfricasTalkingNotifier::class];
 */
final class AfricasTalkingNotifier implements NotifierInterface
{
    private const LIVE_URL    = 'https://api.africastalking.com/version1/messaging';
    private const SANDBOX_URL = 'https://api.sandbox.africastalking.com/version1/messaging';

    /**
     * Africa's Talking per-recipient status code for an accepted message.
     */
    private const STATUS_SUCCESS = 101;

    public function __construct(private readonly Auth $config) {}

    public function send(OneTimeCodeMessage $message): void
    {
        if ($message->channel !== OneTimeCode::CHANNEL_SMS) {
            throw NotificationException::unsupportedChannel(self::class, $message->channel);
        }

        if ($this->config->africasTalkingUsername === '' || $this->config->africasTalkingApiKey === '') {
            throw NotificationException::misconfigured(self::class, "Africa's Talking username and API key are required.");
        }

        $form = [
            'username' => $this->config->africasTalkingUsername,
            'to'       => $message->destination,
            'message'  => $message->text(),
        ];

        if ($this->config->africasTalkingSenderId !== '') {
            $form['from'] = $this->config->africasTalkingSenderId;
        }

        try {
            $client   = service('curlrequest', ['timeout' => 15, 'http_errors' => false], null, null, false);
            $response = $client->post($this->config->africasTalkingSandbox ? self::SANDBOX_URL : self::LIVE_URL, [
                'headers' => [
                    'apiKey' => $this->config->africasTalkingApiKey,
                    'Accept' => 'application/json',
                ],
                'form_params' => $form,
            ]);
        } catch (Throwable $e) {
            throw NotificationException::deliveryFailed(OneTimeCode::CHANNEL_SMS, 'request error: ' . $e->getMessage());
        }

        $status = $response->getStatusCode();
        $body   = json_decode((string) $response->getBody(), true);

        if ($status < 200 || $status >= 300 || ! is_array($body)) {
            throw NotificationException::deliveryFailed(OneTimeCode::CHANNEL_SMS, "HTTP {$status} from Africa's Talking.");
        }

        $recipient = $body['SMSMessageData']['Recipients'][0] ?? null;

        if (! is_array($recipient) || (int) ($recipient['statusCode'] ?? 0) !== self::STATUS_SUCCESS) {
            $reason = is_array($recipient)
                ? (string) ($recipient['status'] ?? 'unknown status')
                : (string) ($body['SMSMessageData']['Message'] ?? 'no recipients accepted');

            throw NotificationException::deliveryFailed(OneTimeCode::CHANNEL_SMS, $reason);
        }
    }
}
