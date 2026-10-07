<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Entities;

use CodeIgniter\Entity\Entity;
use CodeIgniter\I18n\Time;
use Ephraitech\Auth\Authorization\PermissionMatcher;
use Ephraitech\Auth\Config\Auth;

/**
 * A stored token (session token or API key). The plaintext is never
 * stored or recoverable; only its SHA-256 hash.
 *
 * @property int|null           $id
 * @property int|null           $user_id
 * @property string|null        $tenant_id
 * @property string|null        $type
 * @property string|null        $name
 * @property string|null        $token_hash
 * @property list<string>|null  $abilities
 * @property string|null        $ip_address
 * @property string|null        $user_agent
 * @property Time|null          $last_used_at
 * @property Time|null          $expires_at
 * @property Time|null          $revoked_at
 * @property Time|null          $created_at
 * @property Time|null          $updated_at
 */
class AccessToken extends Entity
{
    protected $dates = ['last_used_at', 'expires_at', 'revoked_at', 'created_at', 'updated_at'];

    protected $casts = [
        'id'        => '?integer',
        'user_id'   => '?integer',
        'abilities' => '?json-array',
    ];

    public function isSession(): bool
    {
        return ($this->attributes['type'] ?? null) === Auth::TOKEN_TYPE_SESSION;
    }

    public function isApiKey(): bool
    {
        return ($this->attributes['type'] ?? null) === Auth::TOKEN_TYPE_API_KEY;
    }

    public function isRevoked(): bool
    {
        return ! empty($this->attributes['revoked_at']);
    }

    public function isExpired(): bool
    {
        $expiresAt = $this->expires_at;

        return $expiresAt instanceof Time && $expiresAt->getTimestamp() <= Time::now()->getTimestamp();
    }

    /**
     * True when unused for longer than $timeoutSeconds (0 disables).
     */
    public function isIdle(int $timeoutSeconds): bool
    {
        if ($timeoutSeconds <= 0) {
            return false;
        }

        $reference = $this->last_used_at ?? $this->created_at;

        return $reference instanceof Time
            && $reference->getTimestamp() + $timeoutSeconds <= Time::now()->getTimestamp();
    }

    /**
     * @return list<string>
     */
    public function abilityList(): array
    {
        $abilities = $this->abilities;

        return is_array($abilities)
            ? array_values(array_filter($abilities, 'is_string'))
            : [];
    }

    /**
     * Whether this token's abilities cover a permission. This is only the
     * token ceiling; the user must still hold the permission (Authorizer).
     */
    public function allows(string $permission): bool
    {
        return PermissionMatcher::anyMatches($this->abilityList(), $permission);
    }

    /**
     * Tenant the token is bound to, or NULL for none/global.
     */
    public function tenant(): ?string
    {
        $tenant = (string) ($this->attributes['tenant_id'] ?? '');

        return $tenant === '' ? null : $tenant;
    }

    /**
     * The hash is never included in array/JSON output.
     */
    public function toArray(bool $onlyChanged = false, bool $cast = true, bool $recursive = false): array
    {
        $data = parent::toArray($onlyChanged, $cast, $recursive);

        unset($data['token_hash']);

        return $data;
    }
}
