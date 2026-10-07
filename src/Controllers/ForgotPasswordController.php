<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Controllers;

use CodeIgniter\HTTP\RedirectResponse;

final class ForgotPasswordController extends BaseAuthController
{
    public function show(): string
    {
        return $this->render('forgot', 'Forgot password', ['loginLabel' => $this->loginLabel()]);
    }

    /**
     * Same response whether or not the account exists.
     */
    public function send(): RedirectResponse
    {
        $login = trim($this->post('login'));

        if (! $this->validatePost([
            'login' => ['label' => $this->loginLabel(), 'rules' => 'required'],
        ])) {
            return $this->backWithErrors($this->validationErrors(), ['login' => $login]);
        }

        service('authPasswordReset')->request($login, $this->ip(), $this->resetLinkBuilder());

        return redirect()->route('auth.reset')
            ->with('message', 'If an account matches what you entered, we have sent a reset code. Enter it below, or use the link in the email.')
            ->with('old', ['login' => $login]);
    }
}
