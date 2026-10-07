<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Entities;

use CodeIgniter\Entity\Entity;
use Ephraitech\Auth\Config\Auth;

/**
 * A single credential row: email, username, phone or password.
 *
 * @property int|null                       $id
 * @property int|null                       $user_id
 * @property string|null                    $type
 * @property string|null                    $identifier
 * @property string|null                    $secret
 * @property \CodeIgniter\I18n\Time|null    $verified_at
 * @property \CodeIgniter\I18n\Time|null    $last_used_at
 * @property \CodeIgniter\I18n\Time|null    $created_at
 * @property \CodeIgniter\I18n\Time|null    $updated_at
 */
class Identity extends Entity
{
    protected $dates = ['verified_at', 'last_used_at', 'created_at', 'updated_at'];

    protected $casts = [
        'id'      => '?integer',
        'user_id' => '?integer',
    ];

    public function isPassword(): bool
    {
        return ($this->attributes['type'] ?? null) === Auth::CREDENTIAL_PASSWORD;
    }

    public function isVerified(): bool
    {
        return ! empty($this->attributes['verified_at']);
    }

    /**
     * The password hash is never included in array/JSON output.
     */
    public function toArray(bool $onlyChanged = false, bool $cast = true, bool $recursive = false): array
    {
        $data = parent::toArray($onlyChanged, $cast, $recursive);

        unset($data['secret']);

        return $data;
    }
}
