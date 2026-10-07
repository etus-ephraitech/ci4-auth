<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Controllers;

use CodeIgniter\HTTP\RedirectResponse;

/**
 * POST only (with CSRF), so a link or image on another site can't sign
 * your users out.
 */
final class LogoutController extends BaseAuthController
{
    public function logout(): RedirectResponse
    {
        $this->sessionGuard()->logout();

        return redirect()->to($this->authConfig->redirect('afterLogout'))
            ->with('message', 'You have been signed out.');
    }
}
