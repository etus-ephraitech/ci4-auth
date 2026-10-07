<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Models;

use CodeIgniter\Database\ConnectionInterface;
use CodeIgniter\I18n\Time;
use CodeIgniter\Model;
use CodeIgniter\Validation\ValidationInterface;
use Ephraitech\Auth\Config\Auth;
use Ephraitech\Auth\Entities\AccessToken;

class AccessTokenModel extends Model
{
    protected $primaryKey     = 'id';
    protected $returnType     = AccessToken::class;
    protected $useSoftDeletes = false;
    protected $useTimestamps  = true;
    protected $dateFormat     = 'datetime';
    protected $createdField   = 'created_at';
    protected $updatedField   = 'updated_at';
    protected $allowedFields  = [
        'user_id',
        'tenant_id',
        'type',
        'name',
        'token_hash',
        'abilities',
        'ip_address',
        'user_agent',
        'last_used_at',
        'expires_at',
        'revoked_at',
    ];

    public function __construct(?ConnectionInterface $db = null, ?ValidationInterface $validation = null)
    {
        /** @var Auth $config */
        $config      = config(Auth::class);
        $this->table = $config->table('access_tokens');

        if ($config->DBGroup !== null) {
            $this->DBGroup = $config->DBGroup;
        }

        parent::__construct($db, $validation);
    }

    public function findByHash(string $hash): ?AccessToken
    {
        $token = $this->where('token_hash', $hash)->first();

        return $token instanceof AccessToken ? $token : null;
    }

    /**
     * Non-revoked, non-expired tokens for a user, newest first.
     *
     * @return list<AccessToken>
     */
    public function activeForUser(int $userId, ?string $type = null): array
    {
        $now = Time::now()->toDateTimeString();

        $this->where('user_id', $userId)
            ->where('revoked_at', null)
            ->groupStart()
            ->where('expires_at', null)
            ->orWhere('expires_at >', $now)
            ->groupEnd();

        if ($type !== null) {
            $this->where('type', $type);
        }

        return $this->orderBy('created_at', 'DESC')
            ->orderBy('id', 'DESC')
            ->findAll();
    }

    /**
     * Record use without touching updated_at.
     */
    public function touchLastUsed(int $tokenId, ?string $ipAddress = null): void
    {
        $data = ['last_used_at' => Time::now()->toDateTimeString()];

        if ($ipAddress !== null && $ipAddress !== '') {
            $data['ip_address'] = substr($ipAddress, 0, 45);
        }

        $this->builder()->where($this->primaryKey, $tokenId)->update($data);
    }

    /**
     * Revoke the given tokens if not already revoked.
     *
     * @param list<int> $ids
     *
     * @return int Number of tokens revoked by this call.
     */
    public function markRevoked(array $ids): int
    {
        if ($ids === []) {
            return 0;
        }

        $this->builder()
            ->whereIn($this->primaryKey, $ids)
            ->where('revoked_at', null)
            ->update(['revoked_at' => Time::now()->toDateTimeString()]);

        return $this->db->affectedRows();
    }

    /**
     * Delete tokens revoked or expired before the cutoff.
     */
    public function deleteStale(Time $cutoff): int
    {
        $cutoffString = $cutoff->toDateTimeString();

        $this->builder()
            ->groupStart()
            ->where('revoked_at <', $cutoffString)
            ->orWhere('expires_at <', $cutoffString)
            ->groupEnd()
            ->delete();

        return $this->db->affectedRows();
    }
}
