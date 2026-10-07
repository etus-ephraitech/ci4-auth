<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Controllers;

use CodeIgniter\HTTP\RedirectResponse;
use Ephraitech\Auth\Config\Auth;
use Ephraitech\Auth\Entities\User;
use Ephraitech\Auth\Exceptions\AccountNotActiveException;
use Ephraitech\Auth\Exceptions\AuthException;
use Ephraitech\Auth\Exceptions\InvalidCodeException;
use Ephraitech\Auth\Exceptions\NotificationException;
use Ephraitech\Auth\Exceptions\ResendTooSoonException;
use Ephraitech\Auth\Support\Mask;
use Ephraitech\Auth\Support\PendingVerification;

/**
 * Verifies the email or phone of either the signed-in user (?type=phone)
 * or a user parked by login/registration (PendingVerification).
 */
final class VerifyController extends BaseAuthController
{
    private const DELIVERABLE = [Auth::IDENTIFIER_EMAIL, Auth::IDENTIFIER_PHONE];

    public function show(): RedirectResponse|string
    {
        [$user, $type] = $this->target();

        if ($user === null || $type === null) {
            return $this->noTarget();
        }

        $identity = $user->getIdentity($type);

        if ($identity === null || $identity->isVerified()) {
            PendingVerification::clear();

            return redirect()->to($this->authConfig->redirect('afterLogin'));
        }

        return $this->render('verify', 'Verify your account', [
            'type'        => $type,
            'destination' => Mask::identifier($type, (string) $identity->identifier),
            'codeLength'  => $this->authConfig->otpLength,
            'resendIn'    => service('authVerification')->secondsUntilResend($user, $type),
        ]);
    }

    public function confirm(): RedirectResponse
    {
        [$user, $type, $pending] = $this->target();

        if ($user === null || $type === null) {
            return $this->noTarget();
        }

        if (! $this->validatePost(['code' => ['label' => 'Code', 'rules' => 'required']])) {
            return $this->backWithErrors($this->validationErrors());
        }

        try {
            $verified = service('authVerification')->confirm($user, $type, $this->post('code'));
        } catch (InvalidCodeException $e) {
            return $this->backWithError($e->getMessage());
        }

        return $this->finish($verified, $type, $pending);
    }

    public function resend(): RedirectResponse
    {
        [$user, $type] = $this->target();

        if ($user === null || $type === null) {
            return $this->noTarget();
        }

        try {
            service('authVerification')->send($user, $type, $this->ip(), $this->verifyLinkBuilder());
        } catch (ResendTooSoonException $e) {
            return $this->backWithError($e->getMessage());
        } catch (NotificationException $e) {
            log_message('error', 'Ephraitech Auth: verification code not sent: {message}', ['message' => $e->getMessage()]);

            return $this->backWithError('We could not send a code right now. Please try again shortly.');
        } catch (AuthException $e) {
            return $this->backWithError($e->getMessage());
        }

        return redirect()->back()->with('message', 'We sent you a new code.');
    }

    /**
     * Emailed link. Signs in only when this browser holds the matching
     * pending login (the password was proven here); otherwise asks the
     * user to sign in, since links can be opened on any device.
     */
    public function link(): RedirectResponse
    {
        $this->response->setHeader('Referrer-Policy', 'no-referrer');

        try {
            $user = service('authVerification')->confirmWithLink($this->query('s'), $this->query('c'));
        } catch (InvalidCodeException $e) {
            return redirect()->route('auth.login')->with('error', $e->getMessage());
        }

        $pending = PendingVerification::get();

        if ($pending !== null && $pending['user_id'] === (int) $user->id) {
            return $this->finish($user, $pending['type'], true);
        }

        $current = $this->sessionGuard()->user();

        if ($current !== null && $current->id === $user->id) {
            return $this->finish($user, Auth::IDENTIFIER_EMAIL, false);
        }

        return redirect()->route('auth.login')
            ->with('message', 'Your email address is verified. Please sign in.');
    }

    // ------------------------------------------------------------------

    private function finish(User $user, string $type, bool $pending): RedirectResponse
    {
        $label = $type === Auth::IDENTIFIER_PHONE ? 'phone number' : 'email address';

        if (! $pending) {
            return redirect()->to($this->authConfig->redirect('afterLogin'))
                ->with('message', "Your {$label} is verified.");
        }

        PendingVerification::clear();

        if (! $user->isActive()) {
            return redirect()->route('auth.login')
                ->with('message', "Your {$label} is verified. Your account is awaiting activation.");
        }

        try {
            $this->sessionGuard()->login($user);
        } catch (AccountNotActiveException $e) {
            return redirect()->route('auth.login')->with('error', $e->getMessage());
        }

        return redirect()->to(auth_intended_url())->with('message', "Your {$label} is verified. Welcome!");
    }

    /**
     * @return array{0: User|null, 1: string|null, 2: bool} user, type, pending
     */
    private function target(): array
    {
        $requested = $this->query('type') !== '' ? $this->query('type') : $this->post('type');
        $requested = in_array($requested, self::DELIVERABLE, true) ? $requested : null;

        $current = $this->sessionGuard()->user();

        if ($current !== null) {
            return [$current, $requested ?? $this->firstUnverified($current), false];
        }

        $pending = PendingVerification::get();

        if ($pending === null) {
            return [null, null, false];
        }

        $user = $this->users()->find($pending['user_id']);

        return $user instanceof User ? [$user, $pending['type'], true] : [null, null, false];
    }

    private function firstUnverified(User $user): ?string
    {
        foreach (self::DELIVERABLE as $type) {
            $identity = $user->getIdentity($type);

            if ($identity !== null && ! $identity->isVerified()) {
                return $type;
            }
        }

        return null;
    }

    private function noTarget(): RedirectResponse
    {
        if ($this->sessionGuard()->check()) {
            return redirect()->to($this->authConfig->redirect('afterLogin'))
                ->with('message', 'Your account is already verified.');
        }

        return redirect()->route('auth.login')->with('error', 'Please sign in to continue.');
    }
}
