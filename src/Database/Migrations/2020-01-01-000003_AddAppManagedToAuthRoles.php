<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Database\Migrations;

use CodeIgniter\Database\Forge;
use CodeIgniter\Database\Migration;
use Ephraitech\Auth\Config\Auth;
use Ephraitech\Auth\Config\ConfigResolver;

/**
 * Adds auth_roles.app_managed (v0.11.0).
 *
 * 1 = the role is edited in the app (RoleManager): auth:sync leaves its
 * title, description and permissions alone and never prunes it.
 * 0 = config is the source of truth (the default, unchanged behaviour).
 */
class AddAppManagedToAuthRoles extends Migration
{
    private Auth $config;

    public function __construct(?Forge $forge = null)
    {
        $config       = ConfigResolver::resolve();
        $this->config = $config;

        if ($config->DBGroup !== null) {
            $this->DBGroup = $config->DBGroup;
        }

        parent::__construct($forge);
    }

    public function up(): void
    {
        $this->forge->addColumn($this->config->table('roles'), [
            'app_managed' => [
                'type'       => 'TINYINT',
                'constraint' => 1,
                'default'    => 0,
                'after'      => 'is_system',
            ],
        ]);
    }

    public function down(): void
    {
        $this->forge->dropColumn($this->config->table('roles'), 'app_managed');
    }
}
