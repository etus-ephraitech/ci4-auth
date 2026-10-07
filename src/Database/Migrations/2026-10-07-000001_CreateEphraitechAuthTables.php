<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Database\Migrations;

use CodeIgniter\Database\Forge;
use CodeIgniter\Database\Migration;
use Ephraitech\Auth\Config\Auth;

/**
 * Creates every table used by Ephraitech Auth.
 *
 * Table names and the database group come from Ephraitech\Auth\Config\Auth
 * (or the host's Config\Auth override), so set those BEFORE migrating.
 *
 * Requires MySQL 5.7.7+ / MariaDB 10.2.2+ (InnoDB large index prefixes)
 * when using MySQLi, for the utf8mb4 composite unique indexes.
 */
class CreateEphraitechAuthTables extends Migration
{
    private Auth $config;

    /**
     * @var array<string, string>
     */
    private array $attributes = [];

    public function __construct(?Forge $forge = null)
    {
        /** @var Auth $config */
        $config       = config(Auth::class);
        $this->config = $config;

        if ($config->DBGroup !== null) {
            $this->DBGroup = $config->DBGroup;
        }

        parent::__construct($forge);

        if ($this->db->DBDriver === 'MySQLi') {
            $this->attributes = ['ENGINE' => 'InnoDB'];
        }
    }

    public function up(): void
    {
        $this->createUsersTable();
        $this->createIdentitiesTable();
        $this->createAccessTokensTable();
        $this->createRolesTable();
        $this->createPermissionsTable();
        $this->createRolePermissionsTable();
        $this->createUserRolesTable();
        $this->createUserPermissionsTable();
        $this->createLoginAttemptsTable();
    }

    public function down(): void
    {
        $this->db->disableForeignKeyChecks();

        foreach (
            [
                'login_attempts',
                'user_permissions',
                'user_roles',
                'role_permissions',
                'permissions',
                'roles',
                'access_tokens',
                'identities',
                'users',
            ] as $key
        ) {
            $this->forge->dropTable($this->config->table($key), true);
        }

        $this->db->enableForeignKeyChecks();
    }

    // ------------------------------------------------------------------
    // Tables
    // ------------------------------------------------------------------

    /**
     * The person. Deliberately lean: host apps add their own profile
     * columns through their own migrations (see $userAllowedFields).
     */
    private function createUsersTable(): void
    {
        $this->forge->addField([
            'id'             => $this->bigIncrements(),
            'uuid'           => ['type' => 'CHAR', 'constraint' => 36, 'null' => true],
            'status'         => ['type' => 'VARCHAR', 'constraint' => 20, 'default' => $this->config->defaultUserStatus],
            'status_reason'  => ['type' => 'VARCHAR', 'constraint' => 255, 'null' => true],
            'last_login_at'  => $this->nullableDatetime(),
            'last_active_at' => $this->nullableDatetime(),
            'created_at'     => $this->nullableDatetime(),
            'updated_at'     => $this->nullableDatetime(),
            'deleted_at'     => $this->nullableDatetime(),
        ]);

        $this->forge->addPrimaryKey('id');
        $this->forge->addUniqueKey('uuid');
        $this->forge->addKey('status');
        $this->forge->addKey('deleted_at');

        $this->forge->createTable($this->config->table('users'), false, $this->attributes);
    }

    /**
     * One row per credential: email, username, phone (identifier set,
     * secret NULL) and password (secret = hash, identifier NULL).
     *
     * (type, identifier) unique => an email/username/phone belongs to one
     *                              account globally; NULL identifiers on
     *                              password rows never collide.
     * (user_id, type) unique    => one of each type per user.
     */
    private function createIdentitiesTable(): void
    {
        $this->forge->addField([
            'id'           => $this->bigIncrements(),
            'user_id'      => $this->bigForeignId(),
            'type'         => ['type' => 'VARCHAR', 'constraint' => 32],
            'identifier'   => ['type' => 'VARCHAR', 'constraint' => 255, 'null' => true],
            'secret'       => ['type' => 'VARCHAR', 'constraint' => 255, 'null' => true],
            'verified_at'  => $this->nullableDatetime(),
            'last_used_at' => $this->nullableDatetime(),
            'created_at'   => $this->nullableDatetime(),
            'updated_at'   => $this->nullableDatetime(),
        ]);

        $this->forge->addPrimaryKey('id');
        $this->forge->addUniqueKey(['type', 'identifier']);
        $this->forge->addUniqueKey(['user_id', 'type']);
        $this->forge->addForeignKey('user_id', $this->config->table('users'), 'id', 'CASCADE', 'CASCADE');

        $this->forge->createTable($this->config->table('identities'), false, $this->attributes);
    }

    /**
     * Unified token table: user session tokens and integration API keys.
     * Only the SHA-256 hash of a token is stored.
     */
    private function createAccessTokensTable(): void
    {
        $this->forge->addField([
            'id'           => $this->bigIncrements(),
            'user_id'      => $this->bigForeignId(),
            'tenant_id'    => $this->tenantId(),
            'type'         => ['type' => 'VARCHAR', 'constraint' => 20],
            'name'         => ['type' => 'VARCHAR', 'constraint' => 100],
            'token_hash'   => ['type' => 'CHAR', 'constraint' => 64],
            'abilities'    => ['type' => 'TEXT', 'null' => true],
            'ip_address'   => ['type' => 'VARCHAR', 'constraint' => 45, 'null' => true],
            'user_agent'   => ['type' => 'VARCHAR', 'constraint' => 255, 'null' => true],
            'last_used_at' => $this->nullableDatetime(),
            'expires_at'   => $this->nullableDatetime(),
            'revoked_at'   => $this->nullableDatetime(),
            'created_at'   => $this->nullableDatetime(),
            'updated_at'   => $this->nullableDatetime(),
        ]);

        $this->forge->addPrimaryKey('id');
        $this->forge->addUniqueKey('token_hash');
        $this->forge->addKey(['user_id', 'type', 'revoked_at']);
        $this->forge->addKey('tenant_id');
        $this->forge->addKey('expires_at');
        $this->forge->addForeignKey('user_id', $this->config->table('users'), 'id', 'CASCADE', 'CASCADE');

        $this->forge->createTable($this->config->table('access_tokens'), false, $this->attributes);
    }

    private function createRolesTable(): void
    {
        $this->forge->addField([
            'id'          => $this->increments(),
            'name'        => ['type' => 'VARCHAR', 'constraint' => 64],
            'title'       => ['type' => 'VARCHAR', 'constraint' => 100],
            'description' => ['type' => 'VARCHAR', 'constraint' => 255, 'null' => true],
            'is_system'   => ['type' => 'TINYINT', 'constraint' => 1, 'default' => 0],
            'created_at'  => $this->nullableDatetime(),
            'updated_at'  => $this->nullableDatetime(),
        ]);

        $this->forge->addPrimaryKey('id');
        $this->forge->addUniqueKey('name');

        $this->forge->createTable($this->config->table('roles'), false, $this->attributes);
    }

    private function createPermissionsTable(): void
    {
        $this->forge->addField([
            'id'          => $this->increments(),
            'name'        => ['type' => 'VARCHAR', 'constraint' => 150],
            'description' => ['type' => 'VARCHAR', 'constraint' => 255, 'null' => true],
            'is_system'   => ['type' => 'TINYINT', 'constraint' => 1, 'default' => 0],
            'created_at'  => $this->nullableDatetime(),
            'updated_at'  => $this->nullableDatetime(),
        ]);

        $this->forge->addPrimaryKey('id');
        $this->forge->addUniqueKey('name');

        $this->forge->createTable($this->config->table('permissions'), false, $this->attributes);
    }

    private function createRolePermissionsTable(): void
    {
        $this->forge->addField([
            'role_id'       => $this->foreignId(),
            'permission_id' => $this->foreignId(),
            'created_at'    => $this->nullableDatetime(),
        ]);

        $this->forge->addPrimaryKey(['role_id', 'permission_id']);
        $this->forge->addKey('permission_id');
        $this->forge->addForeignKey('role_id', $this->config->table('roles'), 'id', 'CASCADE', 'CASCADE');
        $this->forge->addForeignKey('permission_id', $this->config->table('permissions'), 'id', 'CASCADE', 'CASCADE');

        $this->forge->createTable($this->config->table('role_permissions'), false, $this->attributes);
    }

    /**
     * tenant_id is NOT NULL DEFAULT '' (empty = no tenant) rather than NULL,
     * because unique indexes treat NULLs as distinct and would allow the
     * same role to be assigned twice in single-tenant mode.
     */
    private function createUserRolesTable(): void
    {
        $this->forge->addField([
            'id'         => $this->bigIncrements(),
            'user_id'    => $this->bigForeignId(),
            'role_id'    => $this->foreignId(),
            'tenant_id'  => $this->tenantId(),
            'created_at' => $this->nullableDatetime(),
        ]);

        $this->forge->addPrimaryKey('id');
        $this->forge->addUniqueKey(['user_id', 'role_id', 'tenant_id']);
        $this->forge->addKey('role_id');
        $this->forge->addKey('tenant_id');
        $this->forge->addForeignKey('user_id', $this->config->table('users'), 'id', 'CASCADE', 'CASCADE');
        $this->forge->addForeignKey('role_id', $this->config->table('roles'), 'id', 'CASCADE', 'CASCADE');

        $this->forge->createTable($this->config->table('user_roles'), false, $this->attributes);
    }

    /**
     * Direct grants to a user, on top of their roles.
     */
    private function createUserPermissionsTable(): void
    {
        $this->forge->addField([
            'id'            => $this->bigIncrements(),
            'user_id'       => $this->bigForeignId(),
            'permission_id' => $this->foreignId(),
            'tenant_id'     => $this->tenantId(),
            'created_at'    => $this->nullableDatetime(),
        ]);

        $this->forge->addPrimaryKey('id');
        $this->forge->addUniqueKey(['user_id', 'permission_id', 'tenant_id']);
        $this->forge->addKey('permission_id');
        $this->forge->addKey('tenant_id');
        $this->forge->addForeignKey('user_id', $this->config->table('users'), 'id', 'CASCADE', 'CASCADE');
        $this->forge->addForeignKey('permission_id', $this->config->table('permissions'), 'id', 'CASCADE', 'CASCADE');

        $this->forge->createTable($this->config->table('user_permissions'), false, $this->attributes);
    }

    /**
     * Throttling + audit trail. user_id is SET NULL on user deletion so
     * the security history survives the account.
     */
    private function createLoginAttemptsTable(): void
    {
        $this->forge->addField([
            'id'         => $this->bigIncrements(),
            'type'       => ['type' => 'VARCHAR', 'constraint' => 32, 'null' => true],
            'identifier' => ['type' => 'VARCHAR', 'constraint' => 255, 'null' => true],
            'user_id'    => array_merge($this->bigForeignId(), ['null' => true]),
            'ip_address' => ['type' => 'VARCHAR', 'constraint' => 45],
            'user_agent' => ['type' => 'VARCHAR', 'constraint' => 255, 'null' => true],
            'success'    => ['type' => 'TINYINT', 'constraint' => 1, 'default' => 0],
            'reason'     => ['type' => 'VARCHAR', 'constraint' => 50, 'null' => true],
            'created_at' => ['type' => 'DATETIME'],
        ]);

        $this->forge->addPrimaryKey('id');
        $this->forge->addKey(['identifier', 'ip_address', 'created_at']);
        $this->forge->addKey(['ip_address', 'created_at']);
        $this->forge->addKey('user_id');
        $this->forge->addKey('created_at');
        $this->forge->addForeignKey('user_id', $this->config->table('users'), 'id', 'CASCADE', 'SET NULL');

        $this->forge->createTable($this->config->table('login_attempts'), false, $this->attributes);
    }

    // ------------------------------------------------------------------
    // Column definitions
    // ------------------------------------------------------------------

    /**
     * @return array<string, mixed>
     */
    private function bigIncrements(): array
    {
        return ['type' => 'BIGINT', 'unsigned' => true, 'auto_increment' => true];
    }

    /**
     * @return array<string, mixed>
     */
    private function increments(): array
    {
        return ['type' => 'INT', 'unsigned' => true, 'auto_increment' => true];
    }

    /**
     * @return array<string, mixed>
     */
    private function bigForeignId(): array
    {
        return ['type' => 'BIGINT', 'unsigned' => true];
    }

    /**
     * @return array<string, mixed>
     */
    private function foreignId(): array
    {
        return ['type' => 'INT', 'unsigned' => true];
    }

    /**
     * VARCHAR so host apps can use integer or UUID tenant keys.
     *
     * @return array<string, mixed>
     */
    private function tenantId(): array
    {
        return ['type' => 'VARCHAR', 'constraint' => 64, 'default' => ''];
    }

    /**
     * @return array<string, mixed>
     */
    private function nullableDatetime(): array
    {
        return ['type' => 'DATETIME', 'null' => true];
    }
}
