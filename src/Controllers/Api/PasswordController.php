<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Controllers\Api;

use CodeIgniter\HTTP\ResponseInterface;
use Ephraitech\Auth\Exceptions\InvalidCodeException;
use Ephraitech\Auth\Exceptions\InvalidCredentialsException;
use Ephraitech\Auth\Exceptions\WeakPasswordException;

final class PasswordController extends BaseApiController
{
    /**
     * POST password/forgot
     * Body: login
     * Always 202 with the same message, whether or not the account exists.
     */
    public function forgot(): ResponseInterface
    {
        $errors = $this->missing(['login' => 'login']);

        if ($errors !== []) {
            return $this->validationFailed($errors);
        }

        service('authPasswordReset')->request(
            $this->str('login'),
            $this->ip(),
            $this->linkBuilder($this->authConfig->apiResetLink)
        );

        return $this->respond([], 202, 'If an account matches, we have sent a password reset code.');
    }

    /**
     * POST password/reset
     * Body: password + either (login, code) or (selector, code)
     */
    public function reset(): ResponseInterface
    {
        $byLink = $this->str('selector') !== '';
        $errors = $this->missing(
            $byLink
                ? ['code' => 'code', 'password' => 'password']
                : ['login' => 'login', 'code' => 'code', 'password' => 'password']
        );

        if ($errors !== []) {
            return $this->validationFailed($errors);
        }

        $flow = service('authPasswordReset');

        try {
            if ($byLink) {
                $flow->resetWithLink($this->str('selector'), $this->str('code'), $this->str('password'));
            } else {
                $flow->resetWithCode($this->str('login'), $this->str('code'), $this->str('password'));
            }
        } catch (WeakPasswordException $e) {
            return $this->validationFailed(['password' => implode(' ', $e->getErrors())]);
        } catch (InvalidCodeException $e) {
            return $this->fail(422, 'invalid_code', $e->getMessage());
        }

        return $this->respond([], 200, 'Your password has been reset. Please sign in with your new password.');
    }

    /**
     * POST password/change (auth:token)
     * Body: current_password, password
     * Keeps the current token; every other token and browser session ends.
     */
    public function change(): ResponseInterface
    {
        $errors = $this->missing(['current_password' => 'current password', 'password' => 'password']);

        if ($errors !== []) {
            return $this->validationFailed($errors);
        }

        $user  = $this->tokenGuard()->user();
        $token = $this->tokenGuard()->token();

        if ($user === null) {
            return $this->fail(401, 'unauthenticated', 'Authentication is required to access this resource.');
        }

        try {
            service('authPasswordChanger')->change(
                $user,
                $this->str('current_password'),
                $this->str('password'),
                $token !== null ? (int) $token->id : null
            );
        } catch (InvalidCredentialsException $e) {
            return $this->validationFailed(['current_password' => $e->getMessage()]);
        } catch (WeakPasswordException $e) {
            return $this->validationFailed(['password' => implode(' ', $e->getErrors())]);
        }

        return $this->respond([], 200, 'Your password has been changed. Other devices have been signed out.');
    }
}
