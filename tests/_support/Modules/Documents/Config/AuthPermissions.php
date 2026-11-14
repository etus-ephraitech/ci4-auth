<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Tests\Support\Modules\Documents\Config;

use Ephraitech\Auth\Config\AuthPermissions as BasePermissions;

/**
 * A module declaring its own permissions, as a host app's module would.
 * Only discovered when a test registers this folder as a namespace.
 */
class AuthPermissions extends BasePermissions
{
    public array $permissions = [
        'documents.view' => 'View documents',
        'documents.sign' => 'Sign documents',
        'users.view'     => 'Module wording that must NOT override the app',
    ];

    public array $roles = [
        'signatory' => ['title' => 'Signatory', 'description' => 'Signs contracts.'],
    ];

    public array $matrix = [
        'admin'     => ['documents.*'],
        'signatory' => ['documents.view', 'documents.sign'],
    ];
}
