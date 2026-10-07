<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Models;

use CodeIgniter\Config\Factories;
use CodeIgniter\Database\ConnectionInterface;
use CodeIgniter\I18n\Time;
use CodeIgniter\Model;
use CodeIgniter\Validation\ValidationInterface;
use Ephraitech\Auth\Config\Auth;
use Ephraitech\Auth\Entities\User;
use Ephraitech\Auth\Exceptions\AuthException;

/**
 * Base user model. Host apps may extend it and set Config\Auth::$userModel.
 *
 * Subclasses may declare their own $allowedFields and $returnType: the base
 * columns and Config\Auth::$userAllowedFields are always merged in, so a
 * subclass can never accidentally lock out status/uuid writes.
 */
class UserModel extends Model
{
    /**
     * Columns created by the package migration that the model may write.
     */
    public const BASE_ALLOWED_FIELDS = [
        'uuid',
        'status',
        'status_reason',
        'last_login_at',
        'last_active_at',
    ];

    protected $primaryKey          = 'id';
    protected $returnType          = User::class;
    protected $useSoftDeletes      = true;
    protected $useTimestamps       = true;
    protected $dateFormat          = 'datetime';
    protected $createdField        = 'created_at';
    protected $updatedField        = 'updated_at';
    protected $deletedField        = 'deleted_at';
    protected $allowedFields       = [];
    protected $beforeInsert        = ['prepareNewUser'];
    protected $beforeInsertBatch   = ['prepareNewUsers'];

    protected Auth $authConfig;

    public function __construct(?ConnectionInterface $db = null, ?ValidationInterface $validation = null)
    {
        /** @var Auth $config */
        $config = config(Auth::class);

        $this->authConfig = $config;
        $this->table      = $config->table('users');

        if ($config->DBGroup !== null) {
            $this->DBGroup = $config->DBGroup;
        }

        $this->allowedFields = array_values(array_unique(array_merge(
            self::BASE_ALLOWED_FIELDS,
            $this->allowedFields,
            $config->userAllowedFields
        )));

        parent::__construct($db, $validation);
    }

    // ------------------------------------------------------------------
    // Lookups
    // ------------------------------------------------------------------

    public function findByUuid(string $uuid): ?User
    {
        $user = $this->where('uuid', strtolower(trim($uuid)))->first();

        return $user instanceof User ? $user : null;
    }

    /**
     * Find an active (non-deleted) user by email, username or phone.
     * Accepts raw input; returns NULL for unknown or invalid values.
     */
    public function findByIdentifier(string $type, string $value): ?User
    {
        $identity = $this->identities()->findByIdentifier($type, $value);

        if ($identity === null) {
            return null;
        }

        $user = $this->find($identity->user_id);

        return $user instanceof User ? $user : null;
    }

    // ------------------------------------------------------------------
    // State changes (bypass updated_at: these are activity, not edits)
    // ------------------------------------------------------------------

    public function touchLastLogin(int $userId): void
    {
        $now = Time::now()->toDateTimeString();

        $this->builder()
            ->where($this->primaryKey, $userId)
            ->update(['last_login_at' => $now, 'last_active_at' => $now]);
    }

    public function touchLastActive(int $userId): void
    {
        $this->builder()
            ->where($this->primaryKey, $userId)
            ->update(['last_active_at' => Time::now()->toDateTimeString()]);
    }

    /**
     * @throws AuthException
     */
    public function setStatus(int $userId, string $status, ?string $reason = null): bool
    {
        if (! in_array($status, Auth::USER_STATUSES, true)) {
            throw new AuthException(
                "Invalid user status '{$status}'. Allowed: " . implode(', ', Auth::USER_STATUSES) . '.'
            );
        }

        return $this->update($userId, [
            'status'        => $status,
            'status_reason' => $status === 'active' ? null : $reason,
        ]);
    }

    // ------------------------------------------------------------------
    // Callbacks
    // ------------------------------------------------------------------

    /**
     * @param array{data: array<string, mixed>} $data
     *
     * @return array{data: array<string, mixed>}
     */
    protected function prepareNewUser(array $data): array
    {
        $data['data'] = $this->applyInsertDefaults($data['data']);

        return $data;
    }

    /**
     * @param array{data: list<array<string, mixed>>} $data
     *
     * @return array{data: list<array<string, mixed>>}
     */
    protected function prepareNewUsers(array $data): array
    {
        foreach ($data['data'] as $index => $row) {
            $data['data'][$index] = $this->applyInsertDefaults($row);
        }

        return $data;
    }

    /**
     * @param array<string, mixed> $row
     *
     * @return array<string, mixed>
     */
    private function applyInsertDefaults(array $row): array
    {
        if ($this->authConfig->useUuid && empty($row['uuid'])) {
            $row['uuid'] = self::generateUuid();
        }

        if (empty($row['status'])) {
            $row['status'] = $this->authConfig->defaultUserStatus;
        }

        return $row;
    }

    /**
     * RFC 4122 version 4 UUID.
     */
    public static function generateUuid(): string
    {
        $bytes    = random_bytes(16);
        $bytes[6] = chr((ord($bytes[6]) & 0x0F) | 0x40);
        $bytes[8] = chr((ord($bytes[8]) & 0x3F) | 0x80);

        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($bytes), 4));
    }

    protected function identities(): IdentityModel
    {
        /** @var IdentityModel $model */
        $model = Factories::models(IdentityModel::class, ['preferApp' => false]);

        return $model;
    }

    /**
     * Columns callers may set on a user beyond the package-managed base
     * columns: the subclass's own $allowedFields plus $userAllowedFields.
     *
     * @return list<string>
     */
    public function profileFields(): array
    {
        return array_values(array_diff($this->allowedFields, self::BASE_ALLOWED_FIELDS));
    }
}
