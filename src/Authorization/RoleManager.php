<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Authorization;

use CodeIgniter\Config\Factories;
use CodeIgniter\Database\BaseConnection;
use CodeIgniter\I18n\Time;
use Config\Database;
use Ephraitech\Auth\Config\Auth;
use Ephraitech\Auth\Config\ConfigResolver;
use Ephraitech\Auth\Entities\Role;
use Ephraitech\Auth\Exceptions\AuthException;
use Ephraitech\Auth\Models\PermissionModel;
use Ephraitech\Auth\Models\RoleModel;
use Throwable;

/**
 * Creates and edits roles from inside the app (an admin "Roles" screen).
 *
 * Any role created or edited here is marked app-managed, so auth:sync
 * leaves its title, description and permissions alone and never prunes
 * it. release() hands a role defined in Config\Auth back to config; the
 * next auth:sync then restores the config version.
 *
 * Every change clears the authorizer's cache, so checks in the same
 * request already see it.
 *
 * Requires the 2020-01-01-000003 migration (app_managed column).
 */
final class RoleManager
{
    private const NAME_PATTERN = '/^[a-z0-9][a-z0-9_-]*$/';

    private BaseConnection $db;

    public function __construct(
        private readonly Auth $config,
        private readonly RoleModel $roles,
        private readonly PermissionModel $permissions,
        private readonly Authorizer $authorizer,
    ) {
        $this->db = Database::connect($config->DBGroup);
    }

    public static function create(?Auth $config = null, ?Authorizer $authorizer = null): self
    {
        $config ??= ConfigResolver::resolve();

        /** @var RoleModel $roles */
        $roles = Factories::models(RoleModel::class, ['preferApp' => false]);

        /** @var PermissionModel $permissions */
        $permissions = Factories::models(PermissionModel::class, ['preferApp' => false]);

        return new self($config, $roles, $permissions, $authorizer ?? Authorizer::create($config));
    }

    // ------------------------------------------------------------------
    // Reading
    // ------------------------------------------------------------------

    /**
     * Every role in the database, by name.
     *
     * @return list<Role>
     */
    public function all(): array
    {
        return $this->roles->orderBy('name', 'ASC')->findAll();
    }

    public function find(string $name): ?Role
    {
        return $this->roles->findByName($name);
    }

    /**
     * Permission names currently linked to a role.
     *
     * @return list<string>
     *
     * @throws AuthException
     */
    public function permissionsOf(string $name): array
    {
        $role = $this->mustFind($name);

        $rows = $this->db->table($this->config->table('role_permissions') . ' rp')
            ->select('p.name')
            ->join($this->config->table('permissions') . ' p', 'p.id = rp.permission_id')
            ->where('rp.role_id', $role->id)
            ->orderBy('p.name', 'ASC')
            ->get()
            ->getResultArray();

        return array_map(static fn (array $row): string => (string) $row['name'], $rows);
    }

    /**
     * Whether the role is defined in Config\Auth (or a module's permissions).
     */
    public function isInConfig(string $name): bool
    {
        return array_key_exists($name, $this->config->roles);
    }

    // ------------------------------------------------------------------
    // Writing
    // ------------------------------------------------------------------

    /**
     * Create a role in the app.
     *
     * @param list<string> $permissions Permission names; 'area.*' and '*' wildcards allowed.
     *
     * @throws AuthException Invalid or taken name, unknown permissions.
     */
    public function createRole(string $name, string $title, ?string $description = null, array $permissions = []): Role
    {
        $name  = trim($name);
        $title = trim($title);

        if (preg_match(self::NAME_PATTERN, $name) !== 1) {
            throw new AuthException("Role name '{$name}' must be lowercase letters, digits, '_' or '-', starting with a letter or digit.");
        }

        if ($title === '') {
            throw new AuthException('A role needs a title.');
        }

        if ($this->roles->findByName($name) !== null) {
            throw new AuthException("A role named '{$name}' already exists; use updateRole() to change it.");
        }

        $ids = $this->resolvePermissions($permissions);

        $this->transaction(function () use ($name, $title, $description, $ids): void {
            $this->must($this->roles->insert([
                'name'        => $name,
                'title'       => $title,
                'description' => $description,
                'is_system'   => $this->isInConfig($name) ? 1 : 0,
                'app_managed' => 1,
            ]), "create role '{$name}'");

            $this->writeLinks($this->mustFind($name), $ids);
        });

        $this->authorizer->flush();

        return $this->mustFind($name);
    }

    /**
     * Change a role's title and/or description. Marks it app-managed.
     *
     * @throws AuthException
     */
    public function updateRole(string $name, ?string $title = null, ?string $description = null): Role
    {
        $role    = $this->mustFind($name);
        $changes = ['app_managed' => 1];

        if ($title !== null) {
            $title = trim($title);

            if ($title === '') {
                throw new AuthException('A role needs a title.');
            }

            $changes['title'] = $title;
        }

        if ($description !== null) {
            $changes['description'] = $description;
        }

        $this->must($this->roles->update($role->id, $changes), "update role '{$name}'");
        $this->authorizer->flush();

        return $this->mustFind($name);
    }

    /**
     * Replace a role's permissions. Marks it app-managed.
     *
     * @param list<string> $permissions Permission names; wildcards allowed.
     *
     * @return array{added: list<string>, removed: list<string>}
     *
     * @throws AuthException The super role, unknown permissions.
     */
    public function setPermissions(string $name, array $permissions): array
    {
        $role = $this->mustFind($name);

        if ($this->config->superRole !== null && $name === $this->config->superRole) {
            throw new AuthException("'{$name}' is the super role and passes every check; its permissions cannot be edited.");
        }

        $ids    = $this->resolvePermissions($permissions);
        $change = ['added' => [], 'removed' => []];

        $this->transaction(function () use ($role, $ids, &$change): void {
            $change = $this->writeLinks($role, $ids);

            $this->must($this->roles->update($role->id, ['app_managed' => 1]), "mark role '{$role->name}' as app-managed");
        });

        $this->authorizer->flush();

        return $change;
    }

    /**
     * Hand a config role back to Config\Auth: the next auth:sync restores
     * its config title, description and permissions.
     *
     * @throws AuthException The role is not defined in config.
     */
    public function release(string $name): void
    {
        $role = $this->mustFind($name);

        if (! $this->isInConfig($name)) {
            throw new AuthException("Role '{$name}' was created in the app and is not defined in Config\\Auth, so there is no config version to return to.");
        }

        $this->must($this->roles->update($role->id, ['app_managed' => 0]), "release role '{$name}'");
    }

    /**
     * Delete a role created in the app. Users lose it immediately.
     *
     * @throws AuthException The super role, or a role defined in config.
     */
    public function deleteRole(string $name): void
    {
        $role = $this->mustFind($name);

        if ($this->config->superRole !== null && $name === $this->config->superRole) {
            throw new AuthException("'{$name}' is the super role and cannot be deleted.");
        }

        if ($this->isInConfig($name)) {
            throw new AuthException(
                "Role '{$name}' is defined in Config\\Auth. Remove it there and run \"php spark auth:sync --prune\" instead; "
                    . 'deleting it here would be undone by the next sync.'
            );
        }

        $this->must($this->roles->delete($role->id), "delete role '{$name}'");
        $this->authorizer->flush();
    }

    // ------------------------------------------------------------------
    // Internals
    // ------------------------------------------------------------------

    /**
     * @param list<string> $patterns
     *
     * @return array<int, string> permission id => name
     *
     * @throws AuthException
     */
    private function resolvePermissions(array $patterns): array
    {
        $known   = $this->permissions->idsByName();
        $unknown = [];

        foreach ($patterns as $pattern) {
            if (PermissionMatcher::expand([$pattern], array_keys($known)) === []) {
                $unknown[] = $pattern;
            }
        }

        if ($unknown !== []) {
            throw new AuthException(
                'Unknown permission(s): ' . implode(', ', $unknown)
                    . '. Define them in Config\\Auth::$permissions (or a module\'s AuthPermissions) and run "php spark auth:sync".'
            );
        }

        $ids = [];

        foreach (PermissionMatcher::expand($patterns, array_keys($known)) as $permission) {
            $ids[$known[$permission]] = $permission;
        }

        return $ids;
    }

    /**
     * Make the role's links exactly $wanted, writing only the difference.
     *
     * @param array<int, string> $wanted
     *
     * @return array{added: list<string>, removed: list<string>}
     */
    private function writeLinks(Role $role, array $wanted): array
    {
        $table   = $this->config->table('role_permissions');
        $names   = array_flip($this->permissions->idsByName());
        $current = [];

        foreach ($this->db->table($table)->select('permission_id')->where('role_id', $role->id)->get()->getResultArray() as $row) {
            $id           = (int) $row['permission_id'];
            $current[$id] = $names[$id] ?? (string) $id;
        }

        $toAdd    = array_diff_key($wanted, $current);
        $toRemove = array_diff_key($current, $wanted);

        if ($toRemove !== []) {
            $this->db->table($table)->where('role_id', $role->id)->whereIn('permission_id', array_keys($toRemove))->delete();
        }

        if ($toAdd !== []) {
            $now = Time::now()->toDateTimeString();

            $this->db->table($table)->insertBatch(array_map(
                static fn (int $id): array => ['role_id' => $role->id, 'permission_id' => $id, 'created_at' => $now],
                array_keys($toAdd)
            ));
        }

        $added   = array_values($toAdd);
        $removed = array_values($toRemove);
        sort($added);
        sort($removed);

        return ['added' => $added, 'removed' => $removed];
    }

    /**
     * @throws AuthException
     */
    private function mustFind(string $name): Role
    {
        $role = $this->roles->findByName($name);

        if (! $role instanceof Role) {
            throw new AuthException("Unknown role '{$name}'.");
        }

        return $role;
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

    /**
     * @throws AuthException
     */
    private function must(mixed $result, string $action): void
    {
        if ($result === false) {
            throw new AuthException("Could not {$action}.");
        }
    }
}
