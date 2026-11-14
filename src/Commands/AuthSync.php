<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Commands;

use CodeIgniter\CLI\BaseCommand;
use CodeIgniter\CLI\CLI;
use Ephraitech\Auth\Authorization\RbacSynchronizer;
use Ephraitech\Auth\Authorization\SyncReport;
use Ephraitech\Auth\Commands\Concerns\InteractsWithAuth;
use Ephraitech\Auth\Config\ConfigResolver;
use ReflectionClass;
use Throwable;

class AuthSync extends BaseCommand
{
    use InteractsWithAuth;

    protected $group       = 'Ephraitech Auth';
    protected $name        = 'auth:sync';
    protected $description = 'Syncs roles, permissions and the role matrix from Config\Auth into the database.';
    protected $usage       = 'auth:sync [--prune] [--dry-run]';
    protected $options     = [
        '--prune'   => 'Delete system roles/permissions that were removed from config.',
        '--dry-run' => 'Show what would change without writing anything.',
    ];

    /**
     * @param array<int|string, string|null> $params
     */
    public function run(array $params)
    {
        $prune  = $this->hasOption($params, 'prune');
        $dryRun = $this->hasOption($params, 'dry-run');

        $ignored = ConfigResolver::ignoredAppClassReason();

        if ($ignored !== null) {
            CLI::write('Warning: ' . $ignored, 'yellow');
            CLI::newLine();
        }

        try {
            $report = RbacSynchronizer::create()->run($prune, $dryRun);
        } catch (Throwable $e) {
            CLI::error('Sync failed, nothing was changed: ' . $e->getMessage());

            return EXIT_ERROR;
        }

        $this->printSource($report);

        if (! $report->hasChanges()) {
            CLI::write(
                $dryRun ? 'Dry run: nothing would change. The database already matches the config.'
                        : 'Nothing to change. The database already matches the config.',
                'green'
            );

            return EXIT_SUCCESS;
        }

        $this->printChanges($report);

        CLI::newLine();

        if ($dryRun) {
            CLI::write('Dry run: nothing was written. Run without --dry-run to apply these changes.', 'yellow');
        } else {
            CLI::write('RBAC is in sync with config' . ($prune ? ' (pruned).' : '.'), 'green');
        }

        return EXIT_SUCCESS;
    }

    private function printSource(SyncReport $report): void
    {
        CLI::write('Config:  ' . $report->configClass . ' (' . $this->configFile($report->configClass) . ')');
        CLI::write("Defines: {$report->configRoleCount} role(s), {$report->configPermissionCount} permission(s)");
        CLI::newLine();
    }

    private function printChanges(SyncReport $report): void
    {
        $verb = $report->dryRun ? 'would be ' : '';

        $sections = [
            "Permissions {$verb}created" => [$report->permissionsCreated, 'green'],
            "Permissions {$verb}updated" => [$report->permissionsUpdated, 'yellow'],
            "Permissions {$verb}pruned"  => [$report->permissionsPruned, 'red'],
            "Roles {$verb}created"       => [$report->rolesCreated, 'green'],
            "Roles {$verb}updated"       => [$report->rolesUpdated, 'yellow'],
            "Roles {$verb}pruned"        => [$report->rolesPruned, 'red'],
        ];

        foreach ($sections as $title => [$names, $colour]) {
            if ($names === []) {
                continue;
            }

            CLI::write($title . ' (' . count($names) . '):', $colour);

            foreach ($names as $name) {
                CLI::write('  ' . $name);
            }
        }

        if ($report->links === []) {
            return;
        }

        CLI::write(
            "Role permissions {$verb}changed (+{$report->linksAdded()} / -{$report->linksRemoved()}):",
            'yellow'
        );

        foreach ($report->links as $role => $change) {
            $parts = array_merge(
                array_map(static fn (string $p): string => '+' . $p, $change['added']),
                array_map(static fn (string $p): string => '-' . $p, $change['removed']),
            );

            CLI::write('  ' . $role . ': ' . implode(', ', $parts));
        }
    }

    /**
     * The config's file, relative to the project root when possible.
     *
     * @param class-string $class
     */
    private function configFile(string $class): string
    {
        $file = (new ReflectionClass($class))->getFileName();

        if ($file === false) {
            return 'unknown file';
        }

        if (defined('ROOTPATH') && str_starts_with($file, ROOTPATH)) {
            return substr($file, strlen(ROOTPATH));
        }

        return $file;
    }
}
