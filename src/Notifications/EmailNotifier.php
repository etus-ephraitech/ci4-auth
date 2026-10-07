<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Notifications;

use Config\Email as EmailConfig;
use Ephraitech\Auth\Config\Auth;
use Ephraitech\Auth\Entities\OneTimeCode;
use Ephraitech\Auth\Exceptions\NotificationException;

/**
 * Sends codes with CodeIgniter's Email library, using the SMTP/sendmail
 * settings in Config\Email.
 */
final class EmailNotifier implements NotifierInterface
{
    public function __construct(private readonly Auth $config) {}

    public function send(OneTimeCodeMessage $message): void
    {
        if ($message->channel !== OneTimeCode::CHANNEL_EMAIL) {
            throw NotificationException::unsupportedChannel(self::class, $message->channel);
        }

        /** @var EmailConfig $emailConfig */
        $emailConfig = config(EmailConfig::class);

        $fromAddress = $this->config->emailFromAddress !== '' ? $this->config->emailFromAddress : $emailConfig->fromEmail;
        $fromName    = $this->config->emailFromName !== '' ? $this->config->emailFromName : $emailConfig->fromName;

        if ($fromAddress === '') {
            throw NotificationException::misconfigured(
                self::class,
                'set Config\Auth::$emailFromAddress or Config\Email::$fromEmail.'
            );
        }

        $email = service('email', null, false);

        $email->setFrom($fromAddress, $fromName);
        $email->setTo($message->destination);
        $email->setSubject($message->subject());
        $email->setMailType('html');
        $email->setMessage($this->html($message));
        $email->setAltMessage($message->text());

        if (! $email->send(false)) {
            log_message('error', 'Ephraitech Auth: email to {to} failed: {debug}', [
                'to'    => $message->destination,
                'debug' => $email->printDebugger(['headers']),
            ]);

            throw NotificationException::deliveryFailed(OneTimeCode::CHANNEL_EMAIL, 'the mail server rejected the message (see logs).');
        }
    }

    private function html(OneTimeCodeMessage $message): string
    {
        $title   = esc($message->subject());
        $code    = esc($message->code);
        $minutes = $message->expiresInMinutes . ' minute' . ($message->expiresInMinutes === 1 ? '' : 's');
        $intro   = $message->purpose === OneTimeCode::PURPOSE_PASSWORD_RESET
            ? 'Use this code to reset your password:'
            : 'Use this code to verify your email address:';

        $button = '';

        if ($message->link !== null && $message->link !== '') {
            $href   = esc($message->link, 'attr');
            $button = <<<HTML
                <p style="margin:24px 0">
                  <a href="{$href}" style="background:#0d6efd;color:#ffffff;padding:12px 20px;border-radius:6px;text-decoration:none;display:inline-block">Continue</a>
                </p>
                <p style="color:#6c757d;font-size:13px">If the button doesn't work, copy this link into your browser:<br>{$href}</p>
                HTML;
        }

        return <<<HTML
            <!DOCTYPE html>
            <html lang="en">
            <head><meta charset="utf-8"><title>{$title}</title></head>
            <body style="font-family:Arial,Helvetica,sans-serif;background:#f8f9fa;margin:0;padding:24px">
              <div style="max-width:480px;margin:0 auto;background:#ffffff;border-radius:8px;padding:32px">
                <h1 style="font-size:20px;margin:0 0 16px">{$title}</h1>
                <p>{$intro}</p>
                <p style="font-size:32px;letter-spacing:6px;font-weight:bold;margin:16px 0">{$code}</p>
                <p style="color:#6c757d">This code expires in {$minutes}.</p>
                {$button}
                <p style="color:#6c757d;font-size:13px;margin-top:32px">If you didn't request this, you can safely ignore this email.</p>
              </div>
            </body>
            </html>
            HTML;
    }
}
