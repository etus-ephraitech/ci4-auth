<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Filters;

use CodeIgniter\Filters\FilterInterface;
use CodeIgniter\HTTP\RequestInterface;
use CodeIgniter\HTTP\ResponseInterface;
use Ephraitech\Auth\Authentication\Guards\SessionGuard;
use Ephraitech\Auth\Authentication\Guards\TokenGuard;
use Ephraitech\Auth\Exceptions\AuthException;
use Ephraitech\Auth\Filters\Concerns\HandlesAuthFailures;

/**
 * Requires an authenticated user.
 *
 *   'auth'               either guard (token if a bearer token is sent, else session)
 *   'auth:session'       web session only
 *   'auth:token'         bearer token only
 *   'auth:session,token' same as plain 'auth'
 */
final class AuthFilter implements FilterInterface
{
    use HandlesAuthFailures;

    private const GUARDS = [SessionGuard::NAME, TokenGuard::NAME];

    /**
     * @param array<int, string>|null $arguments
     */
    public function before(RequestInterface $request, $arguments = null)
    {
        $auth    = service('auth');
        $allowed = $this->normalizeArguments($arguments);

        foreach ($allowed as $guard) {
            if (! in_array($guard, self::GUARDS, true)) {
                throw new AuthException(
                    "Unknown guard '{$guard}' in auth filter. Use: " . implode(', ', self::GUARDS) . '.'
                );
            }
        }

        if (count($allowed) === 1) {
            $auth->shouldUse($allowed[0]);
        }

        if (! $auth->check()) {
            return $this->unauthenticated($request, $auth);
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
