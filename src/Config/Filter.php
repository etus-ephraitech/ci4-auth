<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Config;

use Ephraitech\Auth\Filters\AuthFilter;
use Ephraitech\Auth\Filters\PermissionFilter;
use Ephraitech\Auth\Filters\RoleFilter;
use Ephraitech\Auth\Filters\TenantFilter;

/**
 * Auto-discovered by CodeIgniter (Config\Modules with 'registrars' in
 * $aliases, the default). Merges these aliases into Config\Filters.
 */
class Registrar
{
    /**
     * @return array{aliases: array<string, class-string>}
     */
    public static function Filters(): array
    {
        return [
            'aliases' => [
                'auth'   => AuthFilter::class,
                'can'    => PermissionFilter::class,
                'role'   => RoleFilter::class,
                'tenant' => TenantFilter::class,
            ],
        ];
    }
}
