<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Filters;

use CodeIgniter\Filters\FilterInterface;
use CodeIgniter\HTTP\IncomingRequest;
use CodeIgniter\HTTP\RequestInterface;
use CodeIgniter\HTTP\ResponseInterface;
use Ephraitech\Auth\Authentication\Guards\TokenGuard;
use Ephraitech\Auth\Exceptions\AuthException;
use Ephraitech\Auth\Filters\Concerns\HandlesAuthFailures;

/**
 * Sets the active tenant from the tenant header (default X-Tenant-ID).
 * No-op in single-tenant mode.
 *
 *   'tenant'           header optional
 *   'tenant:required'  400 when no tenant can be determined
 *
 * Rules:
 *   - A token bound to a tenant implies that tenant when no header is sent,
 *     and is rejected (403) if the header names a different tenant.
 *   - An authenticated user with no roles or grants in the tenant
 *     (including global ones) is rejected (403), so a header cannot be
 *     used to peek into tenants the user doesn't belong to.
 *
 * Place it after 'auth' and before 'can'/'role':
 *   'filter' => ['auth:token', 'tenant:required', 'can:orders.view']
 *
 * Apps resolving tenants another way (subdomain, session) can skip this
 * filter and call service('authTenant')->set($id) in their own filter.
 */
final class TenantFilter implements FilterInterface
{
    use HandlesAuthFailures;

    /**
     * @param array<int, string>|null $arguments
     */
    public function before(RequestInterface $request, $arguments = null)
    {
        $auth   = service('auth');
        $config = $auth->config();

        if (! $config->isMultiTenant()) {
            return null;
        }

        $required = in_array('required', $this->normalizeArguments($arguments), true);
        $tenantId = $request instanceof IncomingRequest
            ? trim($request->getHeaderLine($config->tenantHeader))
            : '';

        $guard = $auth->guard();
        $bound = $guard instanceof TokenGuard ? $guard->token()?->tenant() : null;

        if ($tenantId === '' && $bound !== null) {
            $tenantId = $bound;
        }

        if ($bound !== null && $tenantId !== $bound) {
            return $this->forbidden($request, $auth, 'This token is not valid for the requested tenant.');
        }

        if ($tenantId === '') {
            return $required
                ? $this->badRequest($request, $auth, "The {$config->tenantHeader} header is required.")
                : null;
        }

        try {
            $auth->tenant()->set($tenantId);
        } catch (AuthException $e) {
            return $this->badRequest($request, $auth, $e->getMessage());
        }

        $user = $auth->user();

        if ($user !== null) {
            $authorizer = $auth->authorizer();

            if ($authorizer->rolesFor($user, $tenantId) === [] && $authorizer->permissionsFor($user, $tenantId) === []) {
                $auth->tenant()->clear();

                return $this->forbidden($request, $auth, 'You do not have access to this tenant.');
            }
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
