<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Controllers;

use CodeIgniter\HTTP\RedirectResponse;
use Ephraitech\Auth\Exceptions\InvalidCodeException;
use Ephraitech\Auth\Exceptions\WeakPasswordException;

/**
 * Two modes:
 *   link: /reset-password?s=<selector>&c=<code> from the email
 *   code: identifier + typed code (SMS, or email without clicking)
 */
final class ResetPasswordController extends BaseAuthController
{
    public function show(): string
    {
        // The code may be in the URL; never leak it to other sites via Referer.
        $this->response->setHeader('Referrer-Policy', 'no-referrer');

        $selector = $this->query('s');
        $code     = $this->query('c');
        $common   = [
            'loginLabel'    => $this->loginLabel(),
            'codeLength'    => $this->authConfig->otpLength,
            'passwordRules' => service('authPasswords')->policy()->describe(),
        ];

        if ($selector === '') {
            return $this->render('reset', 'Reset password', $common + ['mode' => 'code']);
        }

        if (! service('authPasswordReset')->linkIsUsable($selector)) {
            return $this->render('reset', 'Link expired', $common + ['mode' => 'expired']);
        }

        return $this->render('reset', 'Choose a new password', $common + [
            'mode'     => 'link',
            'selector' => $selector,
            'code'     => $code,
        ]);
    }

    public function update(): RedirectResponse
    {
        $selector = trim($this->post('s'));
        $login    = trim($this->post('login'));
        $old      = ['login' => $login];

        $rules = [
            'password'         => ['label' => 'New password', 'rules' => 'required'],
            'password_confirm' => ['label' => 'Password confirmation', 'rules' => 'required|matches[password]'],
        ];

        if ($selector === '') {
            $rules['login'] = ['label' => $this->loginLabel(), 'rules' => 'required'];
            $rules['code']  = ['label' => 'Code', 'rules' => 'required'];
        }

        if (! $this->validatePost($rules)) {
            return $this->backWithErrors($this->validationErrors(), $old);
        }

        $flow     = service('authPasswordReset');
        $password = $this->post('password');

        try {
            if ($selector !== '') {
                $flow->resetWithLink($selector, $this->post('c'), $password);
            } else {
                $flow->resetWithCode($login, $this->post('code'), $password);
            }
        } catch (WeakPasswordException $e) {
            return $this->backWithErrors(['password' => implode(' ', $e->getErrors())], $old);
        } catch (InvalidCodeException $e) {
            return $this->backWithError($e->getMessage(), $old);
        }

        return redirect()->route('auth.login')
            ->with('message', 'Your password has been reset. Please sign in with your new password.')
            ->with('old', ['login' => $login]);
    }
}
