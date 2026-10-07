<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Filters;

use CodeIgniter\Filters\FilterInterface;
use CodeIgniter\HTTP\RequestInterface;
use CodeIgniter\HTTP\ResponseInterface;
use Ephraitech\Auth\Exceptions\AuthException;
use Ephraitech\Auth\Filters\Concerns\HandlesAuthFailures;

/**
 * Requires ANY of the listed roles in the active tenant scope.
 *
 *   'role:admin'
 *   'role:admin,manager'
 *
 * Prefer the 'can' filter where possible: permissions survive role
 * reorganisation, role names baked into routes do not.
 */
final class RoleFilter implements FilterInterface
{
    use HandlesAuthFailures;

    /**
     * @param array<int, string>|null $arguments
     */
    public function before(RequestInterface $request, $arguments = null)
    {
        $roles = $this->normalizeArguments($arguments);

        if ($roles === []) {
            throw new AuthException("The 'role' filter needs at least one role, e.g. role:admin");
        }

        $auth = service('auth');

        if (! $auth->check()) {
            return $this->unauthenticated($request, $auth);
        }

        if (! $auth->hasRole($roles)) {
            return $this->forbidden($request, $auth);
        }

        return null;
    }

    /**
     * @param array<int, string>|null $arguments
     */
    public function after(RequestInterface $request, ResponseInterface $response, $arguments = null)
    {
        return null;
    }
}
