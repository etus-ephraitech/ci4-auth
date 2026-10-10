<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Database\Migrations;

use CodeIgniter\Database\Forge;
use CodeIgniter\Database\Migration;
use Ephraitech\Auth\Config\Auth;

/**
 * Adds auth_one_time_codes (v0.10.0): short-lived, single-use codes for
 * password reset and email/phone verification.
 *
 * Each code has a random public selector (for links) and a hashed secret
 * code (typed by the user or embedded in the link).
 */
class CreateAuthOneTimeCodesTable extends Migration
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
        $this->forge->addField([
            'id'          => ['type' => 'BIGINT', 'unsigned' => true, 'auto_increment' => true],
            'user_id'     => ['type' => 'BIGINT', 'unsigned' => true],
            'identity_id' => ['type' => 'BIGINT', 'unsigned' => true],
            'purpose'     => ['type' => 'VARCHAR', 'constraint' => 32],
            'channel'     => ['type' => 'VARCHAR', 'constraint' => 20],
            'selector'    => ['type' => 'CHAR', 'constraint' => 32],
            'code_hash'   => ['type' => 'CHAR', 'constraint' => 64],
            'attempts'    => ['type' => 'INT', 'unsigned' => true, 'default' => 0],
            'ip_address'  => ['type' => 'VARCHAR', 'constraint' => 45, 'null' => true],
            'expires_at'  => ['type' => 'DATETIME'],
            'consumed_at' => ['type' => 'DATETIME', 'null' => true],
            'created_at'  => ['type' => 'DATETIME', 'null' => true],
        ]);

        $this->forge->addPrimaryKey('id');
        $this->forge->addUniqueKey('selector');
        $this->forge->addKey(['identity_id', 'purpose', 'consumed_at']);
        $this->forge->addKey(['user_id', 'purpose']);
        $this->forge->addKey('expires_at');
        $this->forge->addForeignKey('user_id', $this->config->table('users'), 'id', 'CASCADE', 'CASCADE');
        $this->forge->addForeignKey('identity_id', $this->config->table('identities'), 'id', 'CASCADE', 'CASCADE');

        $this->forge->createTable($this->config->table('one_time_codes'), false, $this->attributes);
    }

    public function down(): void
    {
        $this->forge->dropTable($this->config->table('one_time_codes'), true);
    }
}
