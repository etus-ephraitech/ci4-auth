<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Controllers;

use CodeIgniter\Exceptions\PageNotFoundException;
use CodeIgniter\HTTP\RedirectResponse;
use Ephraitech\Auth\Config\Auth;
use Ephraitech\Auth\Exceptions\RegistrationException;

final class RegisterController extends BaseAuthController
{
    private const FIELD_META = [
        Auth::IDENTIFIER_EMAIL    => ['label' => 'Email address', 'input' => 'email', 'autocomplete' => 'email'],
        Auth::IDENTIFIER_USERNAME => ['label' => 'Username', 'input' => 'text', 'autocomplete' => 'username'],
        Auth::IDENTIFIER_PHONE    => ['label' => 'Phone number', 'input' => 'tel', 'autocomplete' => 'tel'],
    ];

    public function show(): RedirectResponse|string
    {
        $this->assertEnabled();

        if ($this->sessionGuard()->check()) {
            return redirect()->to($this->authConfig->redirect('afterLogin'));
        }

        $identifierFields = [];

        foreach ($this->authConfig->identifiers as $type) {
            $identifierFields[$type] = self::FIELD_META[$type] + [
                'required' => $this->authConfig->isIdentifierRequired($type),
            ];
        }

        return $this->render('register', 'Create account', [
            'identifierFields'   => $identifierFields,
            'registrationFields' => $this->authConfig->registrationFields,
            'passwordRules'      => service('authPasswords')->policy()->describe(),
        ]);
    }

    public function store(): RedirectResponse
    {
        $this->assertEnabled();

        $identifiers = [];

        foreach ($this->authConfig->identifiers as $type) {
            $identifiers[$type] = trim($this->post($type));
        }

        $attributes = [];

        foreach (array_keys($this->authConfig->registrationFields) as $column) {
            $attributes[$column] = trim($this->post($column));
        }

        $old = array_merge($identifiers, $attributes);

        if (! $this->validatePost([
            'password'         => ['label' => 'Password', 'rules' => 'required'],
            'password_confirm' => ['label' => 'Password confirmation', 'rules' => 'required|matches[password]'],
        ])) {
            return $this->backWithErrors($this->validationErrors(), $old);
        }

        try {
            $user = service('authRegistrar')->register($identifiers, $this->post('password'), $attributes);
        } catch (RegistrationException $e) {
            return $this->backWithErrors($e->getFirstErrors(), $old);
        }

        $verifyType = service('authVerification')->requiredFor($user);

        if ($verifyType !== null) {
            return $this->startVerification((int) $user->id, $verifyType);
        }

        if ($user->isActive()) {
            $this->sessionGuard()->login($user);

            return redirect()->to($this->authConfig->redirect('afterRegister'))
                ->with('message', 'Welcome! Your account is ready.');
        }

        return redirect()->route('auth.login')
            ->with('message', 'Your account has been created and is awaiting activation.');
    }

    private function assertEnabled(): void
    {
        if (! $this->authConfig->allowRegistration) {
            throw PageNotFoundException::forPageNotFound();
        }
    }
}
