<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Models;

use CodeIgniter\Database\ConnectionInterface;
use CodeIgniter\Model;
use CodeIgniter\Validation\ValidationInterface;
use Ephraitech\Auth\Config\Auth;
use Ephraitech\Auth\Entities\Role;

class RoleModel extends Model
{
    protected $primaryKey     = 'id';
    protected $returnType     = Role::class;
    protected $useSoftDeletes = false;
    protected $useTimestamps  = true;
    protected $dateFormat     = 'datetime';
    protected $createdField   = 'created_at';
    protected $updatedField   = 'updated_at';
    protected $allowedFields  = ['name', 'title', 'description', 'is_system'];

    public function __construct(?ConnectionInterface $db = null, ?ValidationInterface $validation = null)
    {
        /** @var Auth $config */
        $config      = config(Auth::class);
        $this->table = $config->table('roles');

        if ($config->DBGroup !== null) {
            $this->DBGroup = $config->DBGroup;
        }

        parent::__construct($db, $validation);
    }

    public function findByName(string $name): ?Role
    {
        $role = $this->where('name', $name)->first();

        return $role instanceof Role ? $role : null;
    }

    /**
     * @return array<string, int> name => id
     */
    public function idsByName(): array
    {
        $rows = $this->builder()->select('id, name')->get()->getResultArray();

        $map = [];

        foreach ($rows as $row) {
            $map[(string) $row['name']] = (int) $row['id'];
        }

        return $map;
    }
}
