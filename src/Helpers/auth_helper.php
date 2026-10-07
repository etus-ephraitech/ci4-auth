<?php

declare(strict_types=1);

use Ephraitech\Auth\Authentication\AuthManager;
use Ephraitech\Auth\Entities\User;
use Ephraitech\Auth\Support\IntendedUrl;

/*
 * Global helpers, autoloaded through composer.json "files".
 * Each is skipped if the host app already defines a function of that name.
 */

if (! function_exists('auth')) {
    /**
     * The AuthManager: auth()->user(), auth()->session()->attempt(...), etc.
     */
    function auth(): AuthManager
    {
        return service('auth');
    }
}

if (! function_exists('user')) {
    /**
     * The authenticated user from the active guard, or NULL.
     */
    function user(): ?User
    {
        return service('auth')->user();
    }
}

if (! function_exists('user_id')) {
    function user_id(): ?int
    {
        return service('auth')->id();
    }
}

if (! function_exists('can')) {
    /**
     * One permission, or ALL permissions when an array is given.
     *
     * @param list<string>|string $permissions
     */
    function can(array|string $permissions, ?string $tenantId = null): bool
    {
        $auth = service('auth');

        return is_array($permissions)
            ? $auth->canAll($permissions, $tenantId)
            : $auth->can($permissions, $tenantId);
    }
}

if (! function_exists('can_any')) {
    /**
     * @param list<string> $permissions
     */
    function can_any(array $permissions, ?string $tenantId = null): bool
    {
        return service('auth')->canAny($permissions, $tenantId);
    }
}

if (! function_exists('has_role')) {
    /**
     * @param list<string>|string $roles ANY of these.
     */
    function has_role(array|string $roles, ?string $tenantId = null): bool
    {
        return service('auth')->hasRole($roles, $tenantId);
    }
}

if (! function_exists('auth_intended_url')) {
    /**
     * Where to send a user after login: the page they originally wanted
     * (same-site only), or $default (falls back to redirects['afterLogin']).
     */
    function auth_intended_url(?string $default = null): string
    {
        return IntendedUrl::pull($default ?? service('auth')->config()->redirects['afterLogin']);
    }
}
