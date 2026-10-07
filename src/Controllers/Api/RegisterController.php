<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Controllers\Api;

use CodeIgniter\HTTP\ResponseInterface;
use Ephraitech\Auth\Exceptions\AuthException;
use Ephraitech\Auth\Exceptions\NotificationException;
use Ephraitech\Auth\Exceptions\RegistrationException;
use Ephraitech\Auth\Exceptions\ResendTooSoonException;
use Ephraitech\Auth\Support\Mask;

final class RegisterController extends BaseApiController
{
    /**
     * POST register
     * Body: enabled identifiers (email/username/phone), password,
     *       $registrationFields columns, device_name?
     *
     * 201 with a token when the account is usable right away; 201 with
     * verification details when a code must be confirmed first.
     */
    public function register(): ResponseInterface
    {
        if (! $this->authConfig->allowRegistration) {
            return $this->fail(404, 'not_found', 'Registration is not available.');
        }

        if ($this->str('password') === '') {
            return $this->validationFailed(['password' => 'The password field is required.']);
        }

        $identifiers = [];

        foreach ($this->authConfig->identifiers as $type) {
            $identifiers[$type] = $this->str($type);
        }

        $attributes = [];

        foreach (array_keys($this->authConfig->registrationFields) as $column) {
            $attributes[$column] = $this->str($column);
        }

        try {
            $user = service('authRegistrar')->register($identifiers, $this->str('password'), $attributes);
        } catch (RegistrationException $e) {
            return $this->validationFailed($e->getFirstErrors());
        }

        $flow       = service('authVerification');
        $verifyType = $flow->requiredFor($user);

        if ($verifyType !== null) {
            $codeSent = false;

            try {
                $flow->send($user, $verifyType, $this->ip(), $this->linkBuilder($this->authConfig->apiVerifyLink));
                $codeSent = true;
            } catch (ResendTooSoonException) {
                $codeSent = true;
            } catch (NotificationException $e) {
                log_message('error', 'Ephraitech Auth: verification code not sent: {message}', ['message' => $e->getMessage()]);
            } catch (AuthException) {
                // reported through code_sent = false
            }

            $identity = $user->refreshIdentities()->getIdentity($verifyType);

            return $this->respond([
                'user'         => $this->transform($user),
                'verification' => [
                    'required'        => true,
                    'identifier_type' => $verifyType,
                    'destination'     => $identity !== null ? Mask::identifier($verifyType, (string) $identity->identifier) : null,
                    'code_sent'       => $codeSent,
                ],
            ], 201, 'Account created. Please verify it with the code we sent.');
        }

        if (! $user->isActive()) {
            return $this->respond(['user' => $this->transform($user)], 201, 'Account created and awaiting activation.');
        }

        try {
            $new = $this->tokenGuard()->issueFor($user, $this->deviceName());
        } catch (AuthException $e) {
            return $this->respond(['user' => $this->transform($user)], 201, 'Account created. Please sign in.');
        }

        return $this->respond([
            'token' => $new->toArray(),
            'user'  => $this->transform($user),
        ], 201, 'Account created.');
    }
}
