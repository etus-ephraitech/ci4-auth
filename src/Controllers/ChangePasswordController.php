<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Controllers;

use CodeIgniter\HTTP\RedirectResponse;
use Ephraitech\Auth\Exceptions\InvalidCredentialsException;
use Ephraitech\Auth\Exceptions\WeakPasswordException;

/**
 * Signed-in password change (routes carry the auth:session filter).
 * Signs out every other device; this browser stays signed in.
 */
final class ChangePasswordController extends BaseAuthController
{
    public function show(): string
    {
        return $this->render('change_password', 'Change password', [
            'passwordRules' => service('authPasswords')->policy()->describe(),
        ]);
    }

    public function update(): RedirectResponse
    {
        if (! $this->validatePost([
            'current_password' => ['label' => 'Current password', 'rules' => 'required'],
            'password'         => ['label' => 'New password', 'rules' => 'required'],
            'password_confirm' => ['label' => 'Password confirmation', 'rules' => 'required|matches[password]'],
        ])) {
            return $this->backWithErrors($this->validationErrors());
        }

        $user = $this->sessionGuard()->user();

        if ($user === null) {
            return redirect()->route('auth.login');
        }

        try {
            service('authPasswordChanger')->change($user, $this->post('current_password'), $this->post('password'));
        } catch (InvalidCredentialsException $e) {
            return $this->backWithErrors(['current_password' => $e->getMessage()]);
        } catch (WeakPasswordException $e) {
            return $this->backWithErrors(['password' => implode(' ', $e->getErrors())]);
        }

        $this->sessionGuard()->refresh();

        return redirect()->route('auth.password')
            ->with('message', 'Your password has been changed. Other devices have been signed out.');
    }
}
