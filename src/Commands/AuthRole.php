<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Commands;

use CodeIgniter\CLI\BaseCommand;
use CodeIgniter\CLI\CLI;
use Ephraitech\Auth\Commands\Concerns\InteractsWithAuth;
use Ephraitech\Auth\Exceptions\AuthException;

class AuthRole extends BaseCommand
{
    use InteractsWithAuth;

    private const ACTIONS = ['list', 'assign', 'remove'];

    protected $group       = 'Ephraitech Auth';
    protected $name        = 'auth:role';
    protected $description = "Lists, assigns or removes a user's roles.";
    protected $usage       = 'auth:role <list|assign|remove> <user> [role] [--tenant=]';
    protected $arguments   = [
        'action' => 'list, assign or remove.',
        'user'   => 'User ID, UUID, email, username or phone.',
        'role'   => 'Role name (assign/remove).',
    ];
    protected $options = [
        '--tenant' => 'Tenant scope; "global" for all tenants (multi-tenant mode).',
    ];

    /**
     * @param array<int|string, string|null> $params
     */
    public function run(array $params)
    {
        $action = $params[0] ?? null;

        if (! in_array($action, self::ACTIONS, true)) {
            CLI::error('Action must be one of: ' . implode(', ', self::ACTIONS) . '.');
            CLI::write('Usage: ' . $this->usage);

            return EXIT_ERROR;
        }

        $user = $this->resolveUser($params[1] ?? null);

        if ($user === null) {
            CLI::error('User not found: ' . ($params[1] ?? '(none given)'));

            return EXIT_ERROR;
        }

        $authorizer = service('authAuthorizer');
        $tenant     = $this->tenantOption($params);

        try {
            if ($action === 'list') {
                $roles       = $authorizer->rolesFor($user, $tenant);
                $permissions = $authorizer->permissionsFor($user, $tenant);

                CLI::write('User:  ' . $this->describeUser($user), 'yellow');
                CLI::write('Roles: ' . ($roles === [] ? '(none)' : implode(', ', $roles)));

                if ($authorizer->isSuper($user, $tenant)) {
                    CLI::write('Super role: all permissions granted.', 'green');
                }

                CLI::write('Effective permissions (' . count($permissions) . '):');

                foreach ($permissions as $permission) {
                    CLI::write('  - ' . $permission);
                }

                return EXIT_SUCCESS;
            }

            $role = trim((string) ($params[2] ?? ''));

            if ($role === '') {
                CLI::error("A role name is required for '{$action}'.");

                return EXIT_ERROR;
            }

            if ($action === 'assign') {
                $authorizer->assignRole($user, $role, $tenant);
                CLI::write("Assigned '{$role}' to " . $this->describeUser($user) . '.', 'green');
            } else {
                $authorizer->removeRole($user, $role, $tenant);
                CLI::write("Removed '{$role}' from " . $this->describeUser($user) . '.', 'green');
            }
        } catch (AuthException $e) {
            CLI::error($e->getMessage());

            return EXIT_ERROR;
        }

        return EXIT_SUCCESS;
    }
}
