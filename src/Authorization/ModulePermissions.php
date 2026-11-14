<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Authorization;

use Ephraitech\Auth\Config\Auth;
use Ephraitech\Auth\Config\AuthPermissions;
use ReflectionClass;

/**
 * Finds every Config/AuthPermissions.php that modules provide and merges
 * their permissions, roles and matrix grants into the auth config.
 */
final class ModulePermissions
{
    /**
     * Classes extending AuthPermissions in Config/AuthPermissions.php of
     * every namespace CodeIgniter's autoloader knows, sorted by name.
     *
     * @return list<class-string<AuthPermissions>>
     */
    public static function discover(): array
    {
        $locator = service('locator');
        $classes = [];

        foreach ($locator->search('Config/AuthPermissions') as $file) {
            $class = $locator->getClassname($file);

            if ($class === '' || ! class_exists($class) || ! is_subclass_of($class, AuthPermissions::class)) {
                continue;
            }

            if ((new ReflectionClass($class))->isAbstract()) {
                continue;
            }

            $classes[$class] = true;
        }

        $names = array_keys($classes);
        sort($names);

        return $names;
    }

    /**
     * Merge module definitions into the config. Existing entries win;
     * matrix grants are added to the role's grants, never replacing them.
     *
     * @param iterable<AuthPermissions> $modules
     *
     * @return list<array{class: string, permissions: int, roles: int, grants: int}>
     *         What each module contributed (entries the config already had are not counted).
     */
    public static function apply(Auth $config, iterable $modules): array
    {
        $summary = [];

        foreach ($modules as $module) {
            $newPermissions = array_diff_key($module->permissions, $config->permissions);
            $newRoles       = array_diff_key($module->roles, $config->roles);
            $grants         = 0;

            $config->permissions += $module->permissions;
            $config->roles       += $module->roles;

            foreach ($module->matrix as $role => $roleGrants) {
                $existing = $config->matrix[$role] ?? [];
                $merged   = array_values(array_unique(array_merge($existing, $roleGrants)));
                $grants  += count($merged) - count($existing);

                $config->matrix[$role] = $merged;
            }

            $summary[] = [
                'class'       => $module::class,
                'permissions' => count($newPermissions),
                'roles'       => count($newRoles),
                'grants'      => $grants,
            ];
        }

        return $summary;
    }
}
