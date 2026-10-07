<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Commands;

use CodeIgniter\CLI\BaseCommand;
use CodeIgniter\CLI\CLI;
use Ephraitech\Auth\Authorization\RbacSynchronizer;
use Ephraitech\Auth\Commands\Concerns\InteractsWithAuth;
use Throwable;

class AuthSync extends BaseCommand
{
    use InteractsWithAuth;

    protected $group       = 'Ephraitech Auth';
    protected $name        = 'auth:sync';
    protected $description = 'Syncs roles, permissions and the role matrix from Config\Auth into the database.';
    protected $usage       = 'auth:sync [--prune]';
    protected $options     = [
        '--prune' => 'Delete system roles/permissions that were removed from config.',
    ];

    /**
     * @param array<int|string, string|null> $params
     */
    public function run(array $params)
    {
        $prune = $this->hasOption($params, 'prune');

        try {
            $report = RbacSynchronizer::create()->sync($prune);
        } catch (Throwable $e) {
            CLI::error('Sync failed, nothing was changed: ' . $e->getMessage());

            return EXIT_ERROR;
        }

        $rows = [];

        foreach ($report as $key => $count) {
            $rows[] = [str_replace('_', ' ', $key), (string) $count];
        }

        CLI::table($rows, ['Change', 'Count']);
        CLI::write('RBAC is in sync with config' . ($prune ? ' (pruned).' : '.'), 'green');

        return EXIT_SUCCESS;
    }
}
