<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Controllers;

use CodeIgniter\HTTP\RedirectResponse;
use Ephraitech\Auth\Exceptions\AccountNotActiveException;
use Ephraitech\Auth\Exceptions\IdentifierNotVerifiedException;
use Ephraitech\Auth\Exceptions\InvalidCredentialsException;
use Ephraitech\Auth\Exceptions\LockedOutException;

final class LoginController extends BaseAuthController
{
    public function show(): RedirectResponse|string
    {
        if ($this->sessionGuard()->check()) {
            return redirect()->to($this->authConfig->redirect('afterLogin'));
        }

        return $this->render('login', 'Sign in', ['loginLabel' => $this->loginLabel()]);
    }

    public function attempt(): RedirectResponse
    {
        $login = trim($this->post('login'));
        $old   = ['login' => $login];

        if (! $this->validatePost([
            'login'    => ['label' => $this->loginLabel(), 'rules' => 'required'],
            'password' => ['label' => 'Password', 'rules' => 'required'],
        ])) {
            return $this->backWithErrors($this->validationErrors(), $old);
        }

        try {
            $this->sessionGuard()->attempt($login, $this->post('password'));
        } catch (IdentifierNotVerifiedException $e) {
            return $this->startVerification($e->getUserId(), $e->getIdentifierType());
        } catch (InvalidCredentialsException | LockedOutException | AccountNotActiveException $e) {
            return $this->backWithError($e->getMessage(), $old);
        }

        return redirect()->to(auth_intended_url());
    }
}
