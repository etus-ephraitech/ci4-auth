<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Authorization;

use CodeIgniter\Config\Factories;
use CodeIgniter\Database\BaseConnection;
use CodeIgniter\I18n\Time;
use Config\Database;
use Ephraitech\Auth\Config\Auth;
use Ephraitech\Auth\Entities\Permission;
use Ephraitech\Auth\Entities\Role;
use Ephraitech\Auth\Exceptions\AuthException;
use Ephraitech\Auth\Models\PermissionModel;
use Ephraitech\Auth\Models\RoleModel;
use Throwable;

/**
 * Makes the database match Config\Auth's $permissions, $roles and $matrix.
 *
 *   - Config entries are upserted and flagged is_system = 1.
 *   - Roles listed in $matrix get EXACTLY the expanded permission set
 *     (config is the source of truth for them).
 *   - Roles and permissions created at runtime (is_system = 0), and roles
 *     not listed in $matrix, are never touched.
 *   - With $prune, system rows no longer in config are deleted.
 *
 * Runs in one transaction; any failure leaves the database unchanged.
 */
final class RbacSynchronizer
{
    private BaseConnection $db;

    public function __construct(
        private readonly Auth $config,
        private readonly RoleModel $roles,
        private readonly PermissionModel $permissions,
    ) {
        $this->db = Database::connect($config->DBGroup);
    }

    public static function create(?Auth $config = null): self
    {
        /** @var Auth $config */
        $config ??= config(Auth::class);

        /** @var RoleModel $roles */
        $roles = Factories::models(RoleModel::class, ['preferApp' => false]);

        /** @var PermissionModel $permissions */
        $permissions = Factories::models(PermissionModel::class, ['preferApp' => false]);

        return new self($config, $roles, $permissions);
    }

    /**
     * @return array<string, int> Counts of what changed.
     *
     * @throws AuthException
     */
    public function sync(bool $prune = false): array
    {
        $this->config->assertValid();

        $report = [
            'permissions_created'   => 0,
            'permissions_updated'   => 0,
            'permissions_pruned'    => 0,
            'roles_created'         => 0,
            'roles_updated'         => 0,
            'roles_pruned'          => 0,
            'role_permission_links' => 0,
        ];

        $this->db->transBegin();

        try {
            $this->syncPermissions($report, $prune);
            $this->syncRoles($report, $prune);
            $this->syncMatrix($report);

            if ($this->db->transStatus() === false) {
                throw new AuthException('RBAC sync failed; all changes were rolled back.');
            }

            $this->db->transCommit();
        } catch (Throwable $e) {
            $this->db->transRollback();

            throw $e;
        }

        return $report;
    }

    /**
     * @param array<string, int> $report
     */
    private function syncPermissions(array &$report, bool $prune): void
    {
        /** @var array<string, Permission> $existing */
        $existing = [];

        foreach ($this->permissions->findAll() as $permission) {
            $existing[(string) $permission->name] = $permission;
        }

        foreach ($this->config->permissions as $name => $description) {
            $current = $existing[$name] ?? null;

            if ($current === null) {
                $this->must($this->permissions->insert([
                    'name'        => $name,
                    'description' => $description,
                    'is_system'   => 1,
                ]), "create permission '{$name}'");

                $report['permissions_created']++;

                continue;
            }

            if ($current->description !== $description || ! $current->is_system) {
                $this->must($this->permissions->update($current->id, [
                    'description' => $description,
                    'is_system'   => 1,
                ]), "update permission '{$name}'");

                $report['permissions_updated']++;
            }
        }

        if (! $prune) {
            return;
        }

        foreach ($existing as $name => $permission) {
            if ($permission->is_system && ! array_key_exists($name, $this->config->permissions)) {
                $this->must($this->permissions->delete($permission->id), "prune permission '{$name}'");
                $report['permissions_pruned']++;
            }
        }
    }

    /**
     * @param array<string, int> $report
     */
    private function syncRoles(array &$report, bool $prune): void
    {
        /** @var array<string, Role> $existing */
        $existing = [];

        foreach ($this->roles->findAll() as $role) {
            $existing[(string) $role->name] = $role;
        }

        foreach ($this->config->roles as $name => $definition) {
            $title       = $definition['title'];
            $description = $definition['description'] ?? null;
            $current     = $existing[$name] ?? null;

            if ($current === null) {
                $this->must($this->roles->insert([
                    'name'        => $name,
                    'title'       => $title,
                    'description' => $description,
                    'is_system'   => 1,
                ]), "create role '{$name}'");

                $report['roles_created']++;

                continue;
            }

            if ($current->title !== $title || $current->description !== $description || ! $current->is_system) {
                $this->must($this->roles->update($current->id, [
                    'title'       => $title,
                    'description' => $description,
                    'is_system'   => 1,
                ]), "update role '{$name}'");

                $report['roles_updated']++;
            }
        }

        if (! $prune) {
            return;
        }

        foreach ($existing as $name => $role) {
            if ($role->is_system && ! array_key_exists($name, $this->config->roles)) {
                $this->must($this->roles->delete($role->id), "prune role '{$name}'");
                $report['roles_pruned']++;
            }
        }
    }

    /**
     * @param array<string, int> $report
     */
    private function syncMatrix(array &$report): void
    {
        $permissionIds = $this->permissions->idsByName();
        $roleIds       = $this->roles->idsByName();
        $knownNames    = array_keys($permissionIds);
        $table         = $this->config->table('role_permissions');
        $now           = Time::now()->toDateTimeString();

        foreach ($this->config->matrix as $role => $grants) {
            if (! isset($roleIds[$role])) {
                throw new AuthException("Role '{$role}' is missing after sync.");
            }

            $roleId = $roleIds[$role];
            $names  = PermissionMatcher::expand($grants, $knownNames);

            $this->db->table($table)->where('role_id', $roleId)->delete();

            if ($names === []) {
                continue;
            }

            $this->db->table($table)->insertBatch(array_map(
                static fn(string $name): array => [
                    'role_id'       => $roleId,
                    'permission_id' => $permissionIds[$name],
                    'created_at'    => $now,
                ],
                $names
            ));

            $report['role_permission_links'] += count($names);
        }
    }

    /**
     * @throws AuthException
     */
    private function must(mixed $result, string $action): void
    {
        if ($result === false) {
            throw new AuthException("RBAC sync could not {$action}.");
        }
    }
}
