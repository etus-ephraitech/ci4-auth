<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Controllers\Api;

use CodeIgniter\HTTP\ResponseInterface;
use Ephraitech\Auth\Entities\User;
use Ephraitech\Auth\Exceptions\AuthException;
use Ephraitech\Auth\Exceptions\IdentifierNotVerifiedException;
use Ephraitech\Auth\Exceptions\InvalidCodeException;
use Ephraitech\Auth\Exceptions\InvalidIdentifierException;
use Ephraitech\Auth\Exceptions\NotificationException;
use Ephraitech\Auth\Exceptions\ResendTooSoonException;
use Ephraitech\Auth\Support\Mask;

/**
 * Works for two kinds of client:
 *   signed in (Bearer token):  body type? (email|phone)
 *   not signed in:             send needs login + password (proves the
 *                              account); confirm needs login + code
 *                              (the code itself proves the identifier).
 */
final class VerifyController extends BaseApiController
{
    /**
     * POST verify/send
     */
    public function send(): ResponseInterface
    {
        $current = $this->tokenGuard()->user();

        if ($current !== null) {
            $user = $current;
            $type = $this->requestedType() ?? $this->firstUnverified($user);
        } else {
            $errors = $this->missing(['login' => 'login', 'password' => 'password']);

            if ($errors !== []) {
                return $this->validationFailed($errors);
            }

            try {
                service('authCredentials')->verify(
                    $this->str('login'),
                    $this->str('password'),
                    null,
                    $this->ip(),
                    $this->request->getUserAgent()->getAgentString()
                );

                return $this->fail(409, 'already_verified', 'Nothing needs verifying. Please sign in.');
            } catch (IdentifierNotVerifiedException $e) {
                $user = $this->users()->find($e->getUserId());
                $type = $e->getIdentifierType();
            } catch (AuthException $e) {
                return $this->credentialFailure($e);
            }

            if (! $user instanceof User) {
                return $this->fail(401, 'invalid_credentials', 'The credentials provided are incorrect.');
            }
        }

        if ($type === null) {
            return $this->fail(409, 'already_verified', 'Your account is already verified.');
        }

        try {
            service('authVerification')->send($user, $type, $this->ip(), $this->linkBuilder($this->authConfig->apiVerifyLink));
        } catch (ResendTooSoonException $e) {
            return $this->fail(
                429,
                'resend_too_soon',
                $e->getMessage(),
                [],
                ['retry_after' => $e->getRetryAfter()],
                ['Retry-After' => (string) $e->getRetryAfter()]
            );
        } catch (NotificationException $e) {
            log_message('error', 'Ephraitech Auth: verification code not sent: {message}', ['message' => $e->getMessage()]);

            return $this->fail(503, 'delivery_failed', 'We could not send a code right now. Please try again shortly.');
        } catch (AuthException $e) {
            return $this->fail(422, 'invalid_request', $e->getMessage());
        }

        $identity = $user->refreshIdentities()->getIdentity($type);

        return $this->respond([
            'identifier_type' => $type,
            'destination'     => $identity !== null ? Mask::identifier($type, (string) $identity->identifier) : null,
            'expires_in'      => $this->authConfig->otpLifetime,
        ], 202, 'We sent you a verification code.');
    }

    /**
     * POST verify/confirm
     * Signed in: code, type?    Not signed in: login, code
     */
    public function confirm(): ResponseInterface
    {
        $current = $this->tokenGuard()->user();
        $errors  = $this->missing($current !== null ? ['code' => 'code'] : ['login' => 'login', 'code' => 'code']);

        if ($errors !== []) {
            return $this->validationFailed($errors);
        }

        $flow = service('authVerification');

        try {
            if ($current !== null) {
                $type = $this->requestedType() ?? $this->firstUnverified($current);

                if ($type === null) {
                    return $this->fail(409, 'already_verified', 'Your account is already verified.');
                }

                $user = $flow->confirm($current, $type, $this->str('code'));
            } else {
                $user = $flow->confirmByIdentifier($this->str('login'), $this->str('code'));
            }
        } catch (InvalidCodeException $e) {
            return $this->fail(422, 'invalid_code', $e->getMessage());
        }

        return $this->respond(
            ['user' => $this->transform($user)],
            200,
            $current !== null ? 'Verified.' : 'Verified. You can now sign in.'
        );
    }

    private function requestedType(): ?string
    {
        $type = $this->str('type');

        if ($type === '') {
            return null;
        }

        return in_array($type, self::DELIVERABLE, true) ? $type : null;
    }
}
