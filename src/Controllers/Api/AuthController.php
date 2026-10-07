<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Controllers\Api;

use CodeIgniter\HTTP\ResponseInterface;
use Ephraitech\Auth\Exceptions\AuthException;
use Ephraitech\Auth\Exceptions\IdentifierNotVerifiedException;

final class AuthController extends BaseApiController
{
    /**
     * POST login
     * Body: login, password, device_name?, abilities? (list), tenant? (multi-tenant)
     */
    public function login(): ResponseInterface
    {
        $errors = $this->missing(['login' => 'login', 'password' => 'password']);

        if ($errors !== []) {
            return $this->validationFailed($errors);
        }

        $abilities = null;

        if (array_key_exists('abilities', $this->input())) {
            $requested = $this->input()['abilities'];

            if (! is_array($requested) || $requested === [] || array_filter($requested, static fn($a): bool => ! is_string($a)) !== []) {
                return $this->validationFailed(['abilities' => 'Abilities must be a non-empty list of strings.']);
            }

            $abilities = array_values($requested);
        }

        try {
            $user = service('authCredentials')->verify(
                $this->str('login'),
                $this->str('password'),
                null,
                $this->ip(),
                $this->request->getUserAgent()->getAgentString()
            );
        } catch (IdentifierNotVerifiedException $e) {
            return $this->verificationRequired($e->getUserId(), $e->getIdentifierType());
        } catch (AuthException $e) {
            return $this->credentialFailure($e);
        }

        $tenant = null;

        if ($this->authConfig->isMultiTenant() && $this->str('tenant') !== '') {
            $tenant     = $this->str('tenant');
            $authorizer = service('authAuthorizer');

            if ($authorizer->rolesFor($user, $tenant) === [] && $authorizer->permissionsFor($user, $tenant) === []) {
                return $this->fail(403, 'no_tenant_access', 'You do not have access to this tenant.');
            }
        }

        try {
            $new = $this->tokenGuard()->issueFor($user, $this->deviceName(), $abilities, $tenant);
        } catch (AuthException $e) {
            return $this->fail(422, 'invalid_request', $e->getMessage());
        }

        return $this->respond([
            'token' => $new->toArray(),
            'user'  => $this->transform($user),
        ]);
    }

    /**
     * POST logout: revoke the token used for this request.
     */
    public function logout(): ResponseInterface
    {
        $this->tokenGuard()->logout();

        return $this->respond([], 200, 'Signed out.');
    }

    /**
     * POST logout-all: revoke every session token of this user (all devices).
     */
    public function logoutAll(): ResponseInterface
    {
        $this->tokenGuard()->logoutEverywhere();

        return $this->respond([], 200, 'Signed out of all devices.');
    }

    /**
     * GET me
     */
    public function me(): ResponseInterface
    {
        $user = $this->tokenGuard()->user();

        if ($user === null) {
            return $this->fail(401, 'unauthenticated', 'Authentication is required to access this resource.');
        }

        return $this->respond(['user' => $this->transform($user)]);
    }
}
