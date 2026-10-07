<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Entities;

use CodeIgniter\Entity\Entity;

/**
 * @property int|null                       $id
 * @property string|null                    $name
 * @property string|null                    $description
 * @property bool                           $is_system
 * @property \CodeIgniter\I18n\Time|null    $created_at
 * @property \CodeIgniter\I18n\Time|null    $updated_at
 */
class Permission extends Entity
{
    protected $dates = ['created_at', 'updated_at'];

    protected $casts = [
        'id'        => '?integer',
        'is_system' => 'boolean',
    ];
}
