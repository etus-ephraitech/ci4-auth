<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Config;

/**
 * Base class for permissions a module declares itself.
 *
 * Put a class named AuthPermissions in the module's Config folder, in any
 * namespace CodeIgniter knows (app/, a Composer package, a module path in
 * Config\Autoload):
 *
 *     namespace Modules\Documents\Config;
 *
 *     class AuthPermissions extends \Ephraitech\Auth\Config\AuthPermissions
 *     {
 *         public array $permissions = [
 *             'documents.view' => 'View documents',
 *             'documents.sign' => 'Sign documents',
 *         ];
 *
 *         public array $matrix = [
 *             'manager' => ['documents.*'],
 *             'staff'   => ['documents.view'],
 *         ];
 *     }
 *
 * Every module's lists are merged into the app's Config\Auth when it is
 * first resolved, so auth:sync, the authorizer and config validation all
 * see them. On a clash the app's Config\Auth wins. Turn discovery off with
 * Config\Auth::$discoverModulePermissions = false.
 */
abstract class AuthPermissions
{
    /**
     * Permission name => description.
     *
     * @var array<string, string>
     */
    public array $permissions = [];

    /**
     * Role name => title and description. Usually empty: modules grant to
     * roles the app already defines.
     *
     * @var array<string, array{title: string, description?: string}>
     */
    public array $roles = [];

    /**
     * Role => permissions to ADD to that role (wildcards allowed). Merged
     * with the app's matrix, never replacing it.
     *
     * @var array<string, list<string>>
     */
    public array $matrix = [];
}
