<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Tests\Support\Config;

use Ephraitech\Auth\Config\Auth;

/**
 * Stands in for a host app's Config\Auth: it adds a role, a permission and
 * a user column that the package defaults don't have.
 */
class AppAuth extends Auth
{
    public array $userAllowedFields = ['first_name'];

    public array $roles = [
        'superadmin' => ['title' => 'Super Admin', 'description' => 'Unrestricted access to everything.'],
        'admin'      => ['title' => 'Administrator', 'description' => 'Manages users, roles and access tokens.'],
        'user'       => ['title' => 'User', 'description' => 'Standard authenticated user.'],
        'manager'    => ['title' => 'Manager', 'description' => 'Runs a field team.'],
    ];

    public array $permissions = [
        'users.view'    => 'View users',
        'users.create'  => 'Create users',
        'users.update'  => 'Update users',
        'users.delete'  => 'Delete users',
        'roles.manage'  => 'Manage roles and permissions',
        'tokens.manage' => 'Manage access tokens and API keys',
        'visits.view'   => 'View visits',
    ];

    public array $matrix = [
        'superadmin' => ['*'],
        'admin'      => ['users.*', 'roles.manage', 'tokens.manage'],
        'user'       => [],
        'manager'    => ['visits.view', 'users.view'],
    ];
}
