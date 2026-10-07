<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Authorization;

use CodeIgniter\Config\Factories;
use CodeIgniter\Database\BaseBuilder;
use CodeIgniter\Database\BaseConnection;
use CodeIgniter\Database\Exceptions\DatabaseException;
use CodeIgniter\I18n\Time;
use Config\Database;
use Ephraitech\Auth\Config\Auth;
use Ephraitech\Auth\Entities\User;
use Ephraitech\Auth\Exceptions\AuthException;
use Ephraitech\Auth\Models\PermissionModel;
use Ephraitech\Auth\Models\RoleModel;
use Throwable;

/**
 * Role/permission checks and assignments.
 *
 * Tenant rules (multi-tenant mode):
 *   - Every method takes an optional $tenantId. NULL means "the tenant in
 *     TenantContext", falling back to global when none is set.
 *   - Pass '' explicitly to target global assignments.
 *   - Global assignments (tenant '') apply in every tenant, so a platform
 *     superadmin is assigned once, globally.
 *   - Checks in tenant X consider global + X assignments only.
 * In single-tenant mode the tenant argument is ignored.
 *
 * Token abilities act as a ceiling: when $abilities is given, a permission
 * must be allowed by BOTH the user's grants and the token's abilities.
 * This applies to the super role too, so a scoped key stays scoped.
 */
final class Authorizer
{
    private BaseConnection $db;

    /**
     * @var array<int, array<string, array{roles: list<string>, permissions: array<string, true>, super: bool}>>
     */
    private array $cache = [];

    /**
     * @var array<string, int>|null
     */
    private ?array $roleIds = null;

    /**
     * @var array<string, int>|null
     */
    private ?array $permissionIds = null;

    public function __construct(
        private readonly Auth $config,
        private readonly RoleModel $roles,
        private readonly PermissionModel $permissions,
        private readonly TenantContext $tenant,
    ) {
        $this->db = Database::connect($config->DBGroup);
    }

    public static function create(?Auth $config = null, ?TenantContext $tenant = null): self
    {
        /** @var Auth $config */
        $config ??= config(Auth::class);

        /** @var RoleModel $roles */
        $roles = Factories::models(RoleModel::class, ['preferApp' => false]);

        /** @var PermissionModel $permissions */
        $permissions = Factories::models(PermissionModel::class, ['preferApp' => false]);

        return new self($config, $roles, $permissions, $tenant ?? new TenantContext());
    }

    // ------------------------------------------------------------------
    // Checks
    // ------------------------------------------------------------------

    /**
     * @param list<string>|null $abilities Token abilities, or NULL for a session/user check.
     */
    public function can(User|int $user, string $permission, ?string $tenantId = null, ?array $abilities = null): bool
    {
        if ($abilities !== null && ! PermissionMatcher::anyMatches($abilities, $permission)) {
            return false;
        }

        $state = $this->load($this->userId($user), $this->tenantKey($tenantId));

        return $state['super'] || isset($state['permissions'][$permission]);
    }

    /**
     * @param list<string>      $permissions
     * @param list<string>|null $abilities
     */
    public function canAny(User|int $user, array $permissions, ?string $tenantId = null, ?array $abilities = null): bool
    {
        foreach ($permissions as $permission) {
            if ($this->can($user, $permission, $tenantId, $abilities)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param list<string>      $permissions
     * @param list<string>|null $abilities
     */
    public function canAll(User|int $user, array $permissions, ?string $tenantId = null, ?array $abilities = null): bool
    {
        if ($permissions === []) {
            return false;
        }

        foreach ($permissions as $permission) {
            if (! $this->can($user, $permission, $tenantId, $abilities)) {
                return false;
            }
        }

        return true;
    }

    /**
     * True when the user holds ANY of the given roles.
     *
     * @param list<string>|string $roles
     */
    public function hasRole(User|int $user, array|string $roles, ?string $tenantId = null): bool
    {
        $held = $this->load($this->userId($user), $this->tenantKey($tenantId))['roles'];

        return array_intersect((array) $roles, $held) !== [];
    }

    public function isSuper(User|int $user, ?string $tenantId = null): bool
    {
        return $this->load($this->userId($user), $this->tenantKey($tenantId))['super'];
    }

    /**
     * @return list<string>
     */
    public function rolesFor(User|int $user, ?string $tenantId = null): array
    {
        return $this->load($this->userId($user), $this->tenantKey($tenantId))['roles'];
    }

    /**
     * Effective permission names. The super role receives every permission
     * defined in the database.
     *
     * @return list<string>
     */
    public function permissionsFor(User|int $user, ?string $tenantId = null): array
    {
        $state = $this->load($this->userId($user), $this->tenantKey($tenantId));

        if ($state['super']) {
            return $this->permissions->allNames();
        }

        $names = array_keys($state['permissions']);
        sort($names);

        return $names;
    }

    /**
     * IDs of users holding a role in the given tenant scope.
     *
     * @return list<int>
     */
    public function usersWithRole(string $role, ?string $tenantId = null): array
    {
        $rows = $this->userRoles()
            ->select('user_id')
            ->distinct()
            ->where('role_id', $this->roleId($role))
            ->whereIn('tenant_id', $this->tenantScope($this->tenantKey($tenantId)))
            ->get()
            ->getResultArray();

        return array_map(static fn(array $row): int => (int) $row['user_id'], $rows);
    }

    // ------------------------------------------------------------------
    // Role assignments
    // ------------------------------------------------------------------

    /**
     * Idempotent: assigning a role the user already holds is a no-op.
     *
     * @throws AuthException
     */
    public function assignRole(User|int $user, string $role, ?string $tenantId = null): void
    {
        $userId    = $this->userId($user);
        $roleId    = $this->roleId($role);
        $tenantKey = $this->tenantKey($tenantId);

        $this->insertIgnoringDuplicate(
            fn(): BaseBuilder => $this->userRoles()
                ->where('user_id', $userId)
                ->where('role_id', $roleId)
                ->where('tenant_id', $tenantKey),
            fn(): bool => (bool) $this->userRoles()->insert([
                'user_id'    => $userId,
                'role_id'    => $roleId,
                'tenant_id'  => $tenantKey,
                'created_at' => Time::now()->toDateTimeString(),
            ])
        );

        $this->flush($userId);
    }

    public function removeRole(User|int $user, string $role, ?string $tenantId = null): void
    {
        $userId = $this->userId($user);

        $this->userRoles()
            ->where('user_id', $userId)
            ->where('role_id', $this->roleId($role))
            ->where('tenant_id', $this->tenantKey($tenantId))
            ->delete();

        $this->flush($userId);
    }

    /**
     * Replace the user's roles in exactly one tenant scope (global
     * assignments are untouched when syncing a specific tenant).
     *
     * @param list<string> $roles
     *
     * @throws AuthException
     */
    public function syncRoles(User|int $user, array $roles, ?string $tenantId = null): void
    {
        $userId    = $this->userId($user);
        $tenantKey = $this->tenantKey($tenantId);
        $roleIds   = array_values(array_unique(array_map(fn(string $r): int => $this->roleId($r), $roles)));
        $now       = Time::now()->toDateTimeString();

        $this->transaction(function () use ($userId, $tenantKey, $roleIds, $now): void {
            $this->userRoles()
                ->where('user_id', $userId)
                ->where('tenant_id', $tenantKey)
                ->delete();

            if ($roleIds !== []) {
                $this->userRoles()->insertBatch(array_map(
                    static fn(int $roleId): array => [
                        'user_id'    => $userId,
                        'role_id'    => $roleId,
                        'tenant_id'  => $tenantKey,
                        'created_at' => $now,
                    ],
                    $roleIds
                ));
            }
        });

        $this->flush($userId);
    }

    // ------------------------------------------------------------------
    // Direct permission grants
    // ------------------------------------------------------------------

    /**
     * @throws AuthException
     */
    public function grantPermission(User|int $user, string $permission, ?string $tenantId = null): void
    {
        $userId       = $this->userId($user);
        $permissionId = $this->permissionId($permission);
        $tenantKey    = $this->tenantKey($tenantId);

        $this->insertIgnoringDuplicate(
            fn(): BaseBuilder => $this->userPermissions()
                ->where('user_id', $userId)
                ->where('permission_id', $permissionId)
                ->where('tenant_id', $tenantKey),
            fn(): bool => (bool) $this->userPermissions()->insert([
                'user_id'       => $userId,
                'permission_id' => $permissionId,
                'tenant_id'     => $tenantKey,
                'created_at'    => Time::now()->toDateTimeString(),
            ])
        );

        $this->flush($userId);
    }

    public function revokePermission(User|int $user, string $permission, ?string $tenantId = null): void
    {
        $userId = $this->userId($user);

        $this->userPermissions()
            ->where('user_id', $userId)
            ->where('permission_id', $this->permissionId($permission))
            ->where('tenant_id', $this->tenantKey($tenantId))
            ->delete();

        $this->flush($userId);
    }

    // ------------------------------------------------------------------
    // Cache
    // ------------------------------------------------------------------

    /**
     * Drop cached roles/permissions for one user, or everything.
     */
    public function flush(?int $userId = null): void
    {
        if ($userId === null) {
            $this->cache         = [];
            $this->roleIds       = null;
            $this->permissionIds = null;

            return;
        }

        unset($this->cache[$userId]);
    }

    public function tenant(): TenantContext
    {
        return $this->tenant;
    }

    // ------------------------------------------------------------------
    // Internals
    // ------------------------------------------------------------------

    /**
     * @return array{roles: list<string>, permissions: array<string, true>, super: bool}
     */
    private function load(int $userId, string $tenantKey): array
    {
        if (isset($this->cache[$userId][$tenantKey])) {
            return $this->cache[$userId][$tenantKey];
        }

        $scope = $this->tenantScope($tenantKey);

        $roleRows = $this->db->table($this->config->table('user_roles') . ' ur')
            ->select('r.id, r.name')
            ->join($this->config->table('roles') . ' r', 'r.id = ur.role_id')
            ->where('ur.user_id', $userId)
            ->whereIn('ur.tenant_id', $scope)
            ->get()
            ->getResultArray();

        $roleNames = array_values(array_unique(array_map(
            static fn(array $row): string => (string) $row['name'],
            $roleRows
        )));

        $roleIds = array_values(array_unique(array_map(
            static fn(array $row): int => (int) $row['id'],
            $roleRows
        )));

        $super = $this->config->superRole !== null
            && in_array($this->config->superRole, $roleNames, true);

        $permissions = [];

        if (! $super) {
            if ($roleIds !== []) {
                $rows = $this->db->table($this->config->table('role_permissions') . ' rp')
                    ->select('p.name')
                    ->join($this->config->table('permissions') . ' p', 'p.id = rp.permission_id')
                    ->whereIn('rp.role_id', $roleIds)
                    ->get()
                    ->getResultArray();

                foreach ($rows as $row) {
                    $permissions[(string) $row['name']] = true;
                }
            }

            $rows = $this->db->table($this->config->table('user_permissions') . ' up')
                ->select('p.name')
                ->join($this->config->table('permissions') . ' p', 'p.id = up.permission_id')
                ->where('up.user_id', $userId)
                ->whereIn('up.tenant_id', $scope)
                ->get()
                ->getResultArray();

            foreach ($rows as $row) {
                $permissions[(string) $row['name']] = true;
            }
        }

        sort($roleNames);

        return $this->cache[$userId][$tenantKey] = [
            'roles'       => $roleNames,
            'permissions' => $permissions,
            'super'       => $super,
        ];
    }

    /**
     * @throws AuthException
     */
    private function tenantKey(?string $tenantId): string
    {
        if (! $this->config->isMultiTenant()) {
            return '';
        }

        $key = trim($tenantId ?? $this->tenant->get() ?? '');

        if (strlen($key) > TenantContext::MAX_LENGTH) {
            throw new AuthException('Tenant identifier cannot exceed ' . TenantContext::MAX_LENGTH . ' characters.');
        }

        return $key;
    }

    /**
     * @return list<string>
     */
    private function tenantScope(string $tenantKey): array
    {
        return $tenantKey === '' ? [''] : ['', $tenantKey];
    }

    /**
     * @throws AuthException
     */
    private function userId(User|int $user): int
    {
        $id = $user instanceof User ? $user->id : $user;

        if ($id === null || $id < 1) {
            throw new AuthException('A saved user is required for authorization checks.');
        }

        return (int) $id;
    }

    /**
     * @throws AuthException
     */
    private function roleId(string $name): int
    {
        $this->roleIds ??= $this->roles->idsByName();

        if (! isset($this->roleIds[$name])) {
            $this->roleIds = $this->roles->idsByName();
        }

        if (! isset($this->roleIds[$name])) {
            throw new AuthException(
                "Unknown role '{$name}'. Define it in Config\\Auth::\$roles and run the auth sync command."
            );
        }

        return $this->roleIds[$name];
    }

    /**
     * @throws AuthException
     */
    private function permissionId(string $name): int
    {
        $this->permissionIds ??= $this->permissions->idsByName();

        if (! isset($this->permissionIds[$name])) {
            $this->permissionIds = $this->permissions->idsByName();
        }

        if (! isset($this->permissionIds[$name])) {
            throw new AuthException(
                "Unknown permission '{$name}'. Define it in Config\\Auth::\$permissions and run the auth sync command."
            );
        }

        return $this->permissionIds[$name];
    }

    private function userRoles(): BaseBuilder
    {
        return $this->db->table($this->config->table('user_roles'));
    }

    private function userPermissions(): BaseBuilder
    {
        return $this->db->table($this->config->table('user_permissions'));
    }

    /**
     * Insert unless the row exists; tolerate a concurrent insert of the
     * same row hitting the unique index.
     *
     * @param callable(): BaseBuilder $existsQuery
     * @param callable(): bool        $insert
     */
    private function insertIgnoringDuplicate(callable $existsQuery, callable $insert): void
    {
        if ($existsQuery()->countAllResults() > 0) {
            return;
        }

        try {
            if ($insert()) {
                return;
            }
        } catch (DatabaseException $e) {
            if ($existsQuery()->countAllResults() > 0) {
                return;
            }

            throw new AuthException('Failed to save the assignment.', 0, $e);
        }

        if ($existsQuery()->countAllResults() === 0) {
            throw new AuthException('Failed to save the assignment.');
        }
    }

    /**
     * @param callable(): void $work
     */
    private function transaction(callable $work): void
    {
        $this->db->transBegin();

        try {
            $work();

            if ($this->db->transStatus() === false) {
                throw new AuthException('Database transaction failed.');
            }

            $this->db->transCommit();
        } catch (Throwable $e) {
            $this->db->transRollback();

            throw $e;
        }
    }
}
