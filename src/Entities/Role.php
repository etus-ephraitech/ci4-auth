<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Entities;

use CodeIgniter\Entity\Entity;

/**
 * @property int|null                       $id
 * @property string|null                    $name
 * @property string|null                    $title
 * @property string|null                    $description
 * @property bool                           $is_system
 * @property bool                           $app_managed  Edited in the app; auth:sync leaves it alone.
 * @property \CodeIgniter\I18n\Time|null    $created_at
 * @property \CodeIgniter\I18n\Time|null    $updated_at
 */
class Role extends Entity
{
    protected $dates = ['created_at', 'updated_at'];

    protected $casts = [
        'id'        => '?integer',
        'is_system'   => 'boolean',
        'app_managed' => 'boolean',
    ];

    public function isAppManaged(): bool
    {
        return ! empty($this->attributes['app_managed']);
    }
}
