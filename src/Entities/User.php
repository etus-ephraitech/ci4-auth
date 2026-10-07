<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Entities;

use CodeIgniter\Config\Factories;
use CodeIgniter\Entity\Entity;
use Ephraitech\Auth\Config\Auth;
use Ephraitech\Auth\Models\IdentityModel;

/**
 * Base user entity. Host apps may extend it (and point a custom UserModel's
 * $returnType at the subclass) to add accessors for their own columns.
 *
 * Identifier accessors read from auth_identities, loaded once per entity:
 *   $user->email, $user->username, $user->phone
 *
 * @property int|null                       $id
 * @property string|null                    $uuid
 * @property string|null                    $status
 * @property string|null                    $status_reason
 * @property \CodeIgniter\I18n\Time|null    $last_login_at
 * @property \CodeIgniter\I18n\Time|null    $last_active_at
 * @property \CodeIgniter\I18n\Time|null    $created_at
 * @property \CodeIgniter\I18n\Time|null    $updated_at
 * @property \CodeIgniter\I18n\Time|null    $deleted_at
 */
class User extends Entity
{
    protected $dates = ['last_login_at', 'last_active_at', 'created_at', 'updated_at', 'deleted_at'];

    protected $casts = [
        'id' => '?integer',
    ];

    /**
     * Identities keyed by type (password row excluded). NULL = not loaded.
     *
     * @var array<string, Identity>|null
     */
    private ?array $identityCache = null;

    // ------------------------------------------------------------------
    // Status
    // ------------------------------------------------------------------

    public function isActive(): bool
    {
        return ($this->attributes['status'] ?? null) === 'active';
    }

    public function isSuspended(): bool
    {
        return ($this->attributes['status'] ?? null) === 'suspended';
    }

    public function isPending(): bool
    {
        return ($this->attributes['status'] ?? null) === 'pending';
    }

    public function isInactive(): bool
    {
        return ($this->attributes['status'] ?? null) === 'inactive';
    }

    // ------------------------------------------------------------------
    // Identities
    // ------------------------------------------------------------------

    /**
     * @return array<string, Identity>
     */
    public function getIdentities(): array
    {
        if ($this->identityCache !== null) {
            return $this->identityCache;
        }

        $id = $this->attributes['id'] ?? null;

        if ($id === null) {
            return [];
        }

        /** @var IdentityModel $model */
        $model = Factories::models(IdentityModel::class, ['preferApp' => false]);

        $this->identityCache = $model->findIdentifiersForUser((int) $id);

        return $this->identityCache;
    }

    public function getIdentity(string $type): ?Identity
    {
        return $this->getIdentities()[$type] ?? null;
    }

    public function getEmail(): ?string
    {
        return $this->getIdentity(Auth::IDENTIFIER_EMAIL)?->identifier;
    }

    public function getUsername(): ?string
    {
        return $this->getIdentity(Auth::IDENTIFIER_USERNAME)?->identifier;
    }

    public function getPhone(): ?string
    {
        return $this->getIdentity(Auth::IDENTIFIER_PHONE)?->identifier;
    }

    public function hasVerified(string $type): bool
    {
        return $this->getIdentity($type)?->isVerified() ?? false;
    }

    /**
     * Discard cached identities, e.g. after changing an email or phone.
     */
    public function refreshIdentities(): static
    {
        $this->identityCache = null;

        return $this;
    }
}
