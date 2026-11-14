<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Authorization;

use CodeIgniter\Config\Factories;
use CodeIgniter\Database\BaseConnection;
use CodeIgniter\I18n\Time;
use Config\Database;
use Ephraitech\Auth\Config\Auth;
use Ephraitech\Auth\Config\ConfigResolver;
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
 *     (config is the source of truth for them). Only the difference is
 *     written, so an unchanged config produces an empty report.
 *   - Roles and permissions created at runtime (is_system = 0), and roles
 *     not listed in $matrix, are never touched.
 *   - With $prune, system rows no longer in config are deleted.
 *   - With $dryRun, every change is computed inside the transaction and
 *     then rolled back, so the report shows exactly what a real run would do.
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
        $config ??= ConfigResolver::resolve();

        /** @var RoleModel $roles */
        $roles = Factories::models(RoleModel::class, ['preferApp' => false]);

        /** @var PermissionModel $permissions */
        $permissions = Factories::models(PermissionModel::class, ['preferApp' => false]);

        return new self($config, $roles, $permissions);
    }

    /**
     * Sync and report every change by name.
     *
     * @throws AuthException
     */
    public function run(bool $prune = false, bool $dryRun = false): SyncReport
    {
        $this->config->assertValid();

        $report = new SyncReport(
            $this->config::class,
            count($this->config->roles),
            count($this->config->permissions),
            $dryRun,
            $prune,
        );

        $this->db->transBegin();

        try {
            $this->syncPermissions($report, $prune);
            $this->syncRoles($report, $prune);
            $this->syncMatrix($report);

            if ($this->db->transStatus() === false) {
                throw new AuthException('RBAC sync failed; all changes were rolled back.');
            }

            if ($dryRun) {
                $this->db->transRollback();
            } else {
                $this->db->transCommit();
            }
        } catch (Throwable $e) {
            $this->db->transRollback();

            throw $e;
        }

        return $report;
    }

    /**
     * Sync and return change counts (the pre-0.10.3 API).
     *
     * @return array<string, int>
     *
     * @throws AuthException
     */
    public function sync(bool $prune = false): array
    {
        return $this->run($prune)->counts();
    }

    private function syncPermissions(SyncReport $report, bool $prune): void
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

                $report->permissionsCreated[] = $name;

                continue;
            }

            if ((string) $current->description !== (string) $description || ! $current->is_system) {
                $this->must($this->permissions->update($current->id, [
                    'description' => $description,
                    'is_system'   => 1,
                ]), "update permission '{$name}'");

                $report->permissionsUpdated[] = $name;
            }
        }

        if (! $prune) {
            return;
        }

        foreach ($existing as $name => $permission) {
            if ($permission->is_system && ! array_key_exists($name, $this->config->permissions)) {
                $this->must($this->permissions->delete($permission->id), "prune permission '{$name}'");
                $report->permissionsPruned[] = $name;
            }
        }
    }

    private function syncRoles(SyncReport $report, bool $prune): void
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

                $report->rolesCreated[] = $name;

                continue;
            }

            if (
                $current->title !== $title
                || (string) $current->description !== (string) $description
                || ! $current->is_system
            ) {
                $this->must($this->roles->update($current->id, [
                    'title'       => $title,
                    'description' => $description,
                    'is_system'   => 1,
                ]), "update role '{$name}'");

                $report->rolesUpdated[] = $name;
            }
        }

        if (! $prune) {
            return;
        }

        foreach ($existing as $name => $role) {
            if ($role->is_system && ! array_key_exists($name, $this->config->roles)) {
                $this->must($this->roles->delete($role->id), "prune role '{$name}'");
                $report->rolesPruned[] = $name;
            }
        }
    }

    /**
     * Link each matrix role to exactly its expanded permissions, writing
     * only the links that are missing or no longer wanted.
     */
    private function syncMatrix(SyncReport $report): void
    {
        $permissionIds   = $this->permissions->idsByName();
        $permissionNames = array_flip($permissionIds);
        $roleIds         = $this->roles->idsByName();
        $knownNames      = array_keys($permissionIds);
        $table           = $this->config->table('role_permissions');
        $now             = Time::now()->toDateTimeString();

        foreach ($this->config->matrix as $role => $grants) {
            if (! isset($roleIds[$role])) {
                throw new AuthException("Role '{$role}' is missing after sync.");
            }

            $roleId = $roleIds[$role];

            $wanted = [];

            foreach (PermissionMatcher::expand($grants, $knownNames) as $name) {
                $wanted[$permissionIds[$name]] = $name;
            }

            $rows = $this->db->table($table)
                ->select('permission_id')
                ->where('role_id', $roleId)
                ->get()
                ->getResultArray();

            $current = [];

            foreach ($rows as $row) {
                $id           = (int) $row['permission_id'];
                $current[$id] = $permissionNames[$id] ?? (string) $id;
            }

            $toAdd    = array_diff_key($wanted, $current);
            $toRemove = array_diff_key($current, $wanted);

            if ($toRemove !== []) {
                $this->db->table($table)
                    ->where('role_id', $roleId)
                    ->whereIn('permission_id', array_keys($toRemove))
                    ->delete();
            }

            if ($toAdd !== []) {
                $this->db->table($table)->insertBatch(array_map(
                    static fn (int $permissionId): array => [
                        'role_id'       => $roleId,
                        'permission_id' => $permissionId,
                        'created_at'    => $now,
                    ],
                    array_keys($toAdd)
                ));
            }

            $added   = array_values($toAdd);
            $removed = array_values($toRemove);
            sort($added);
            sort($removed);

            $report->recordLinks($role, $added, $removed);
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
