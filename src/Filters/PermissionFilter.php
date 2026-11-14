<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Filters;

use CodeIgniter\Filters\FilterInterface;
use CodeIgniter\HTTP\RequestInterface;
use CodeIgniter\HTTP\ResponseInterface;
use Ephraitech\Auth\Exceptions\AuthException;
use Ephraitech\Auth\Filters\Concerns\HandlesAuthFailures;

/**
 * Requires permissions (respecting token abilities and the active tenant).
 * Implies sign-in: a signed-out visitor is redirected to the login page
 * (401 JSON for API clients), so no separate 'auth' filter is needed.
 *
 *   'can:users.view'                         one permission
 *   'can:users.view,users.update'            ALL listed
 *   'can:reports.view|reports.export'        ANY listed
 *   'can:any,reports.view,reports.export'    ANY listed (older form)
 *   'can:session,users.view'                 also pin the guard (session|token)
 */
final class PermissionFilter implements FilterInterface
{
    use HandlesAuthFailures;

    /**
     * @param array<int, string>|null $arguments
     */
    public function before(RequestInterface $request, $arguments = null)
    {
        $auth        = service('auth');
        $permissions = $this->pinGuard($this->normalizeArguments($arguments), $auth);
        $mode        = 'all';

        if (($permissions[0] ?? null) === 'any') {
            $mode = 'any';
            array_shift($permissions);
        }

        if ($permissions === []) {
            throw new AuthException("The 'can' filter needs at least one permission, e.g. can:users.view");
        }

        if (! $auth->check()) {
            return $this->unauthenticated($request, $auth);
        }

        $allowed = $mode === 'any'
            ? $auth->canAny($permissions)
            : $auth->canAll($permissions);

        if (! $allowed) {
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
