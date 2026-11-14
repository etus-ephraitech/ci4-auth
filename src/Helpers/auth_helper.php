<?php

declare(strict_types=1);

use Ephraitech\Auth\Authentication\AuthManager;
use Ephraitech\Auth\Authorization\Authorizer;
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
     * Checks the SIGNED-IN user (session or bearer token). In services,
     * commands, seeders and queued jobs, where nobody is signed in, use
     * can_user() instead.
     *
     *   can('documents.view')                     one permission
     *   can('documents.view|documents.approve')   any of them
     *   can(['documents.view', 'documents.sign']) all of them
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
     * Any of the permissions, as a list or as 'a|b'.
     *
     * @param list<string>|string $permissions
     */
    function can_any(array|string $permissions, ?string $tenantId = null): bool
    {
        $list = is_array($permissions) ? $permissions : Authorizer::splitAny($permissions);

        return service('auth')->canAny($list, $tenantId);
    }
}

if (! function_exists('can_user')) {
    /**
     * Checks a GIVEN user, regardless of who (if anyone) is signed in.
     * Safe in services, commands, seeders and queued jobs. Same forms as
     * can(): 'a', 'a|b' (any) or ['a', 'b'] (all). No token abilities apply.
     *
     * @param list<string>|string $permissions
     */
    function can_user(User|int $user, array|string $permissions, ?string $tenantId = null): bool
    {
        $authorizer = service('authAuthorizer');

        return is_array($permissions)
            ? $authorizer->canAll($user, $permissions, $tenantId)
            : $authorizer->can($user, $permissions, $tenantId);
    }
}

if (! function_exists('has_role')) {
    /**
     * Signed-in user holds ANY of these: 'admin', 'admin|manager' or a list.
     *
     * @param list<string>|string $roles
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
        return IntendedUrl::pull($default ?? service('auth')->config()->redirect('afterLogin'));
    }
}
