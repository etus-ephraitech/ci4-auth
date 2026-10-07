<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Models;

use CodeIgniter\Database\ConnectionInterface;
use CodeIgniter\Model;
use CodeIgniter\Validation\ValidationInterface;
use Ephraitech\Auth\Config\Auth;
use Ephraitech\Auth\Entities\Permission;

class PermissionModel extends Model
{
    protected $primaryKey     = 'id';
    protected $returnType     = Permission::class;
    protected $useSoftDeletes = false;
    protected $useTimestamps  = true;
    protected $dateFormat     = 'datetime';
    protected $createdField   = 'created_at';
    protected $updatedField   = 'updated_at';
    protected $allowedFields  = ['name', 'description', 'is_system'];

    public function __construct(?ConnectionInterface $db = null, ?ValidationInterface $validation = null)
    {
        /** @var Auth $config */
        $config      = config(Auth::class);
        $this->table = $config->table('permissions');

        if ($config->DBGroup !== null) {
            $this->DBGroup = $config->DBGroup;
        }

        parent::__construct($db, $validation);
    }

    public function findByName(string $name): ?Permission
    {
        $permission = $this->where('name', $name)->first();

        return $permission instanceof Permission ? $permission : null;
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

    /**
     * @return list<string>
     */
    public function allNames(): array
    {
        $rows = $this->builder()->select('name')->orderBy('name', 'ASC')->get()->getResultArray();

        return array_map(static fn(array $row): string => (string) $row['name'], $rows);
    }
}
