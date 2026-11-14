<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Authorization;

/**
 * What one RBAC sync changed (or, in a dry run, would change), by name.
 */
final class SyncReport
{
    /** @var list<string> */
    public array $permissionsCreated = [];

    /** @var list<string> */
    public array $permissionsUpdated = [];

    /** @var list<string> */
    public array $permissionsPruned = [];

    /** @var list<string> */
    public array $rolesCreated = [];

    /** @var list<string> */
    public array $rolesUpdated = [];

    /** @var list<string> */
    public array $rolesPruned = [];

    /**
     * Role => permissions linked and unlinked. Only roles with changes appear.
     *
     * @var array<string, array{added: list<string>, removed: list<string>}>
     */
    public array $links = [];

    /**
     * @param class-string $configClass The config class that was synced.
     */
    public function __construct(
        public readonly string $configClass,
        public readonly int $configRoleCount,
        public readonly int $configPermissionCount,
        public readonly bool $dryRun,
        public readonly bool $prune,
    ) {
    }

    /**
     * @param list<string> $added
     * @param list<string> $removed
     */
    public function recordLinks(string $role, array $added, array $removed): void
    {
        if ($added === [] && $removed === []) {
            return;
        }

        $this->links[$role] = ['added' => $added, 'removed' => $removed];
    }

    public function hasChanges(): bool
    {
        return $this->permissionsCreated !== []
            || $this->permissionsUpdated !== []
            || $this->permissionsPruned !== []
            || $this->rolesCreated !== []
            || $this->rolesUpdated !== []
            || $this->rolesPruned !== []
            || $this->links !== [];
    }

    public function linksAdded(): int
    {
        return array_sum(array_map(static fn (array $change): int => count($change['added']), $this->links));
    }

    public function linksRemoved(): int
    {
        return array_sum(array_map(static fn (array $change): int => count($change['removed']), $this->links));
    }

    /**
     * Counts in the shape RbacSynchronizer::sync() has always returned.
     * 'role_permission_links' now counts links added, not links rewritten.
     *
     * @return array<string, int>
     */
    public function counts(): array
    {
        return [
            'permissions_created'           => count($this->permissionsCreated),
            'permissions_updated'           => count($this->permissionsUpdated),
            'permissions_pruned'            => count($this->permissionsPruned),
            'roles_created'                 => count($this->rolesCreated),
            'roles_updated'                 => count($this->rolesUpdated),
            'roles_pruned'                  => count($this->rolesPruned),
            'role_permission_links'         => $this->linksAdded(),
            'role_permission_links_removed' => $this->linksRemoved(),
        ];
    }
}
