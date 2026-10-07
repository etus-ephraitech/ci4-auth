<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Models;

use CodeIgniter\Database\ConnectionInterface;
use CodeIgniter\I18n\Time;
use CodeIgniter\Model;
use CodeIgniter\Validation\ValidationInterface;
use Ephraitech\Auth\Config\Auth;
use Ephraitech\Auth\Entities\OneTimeCode;

class OneTimeCodeModel extends Model
{
    protected $primaryKey     = 'id';
    protected $returnType     = OneTimeCode::class;
    protected $useSoftDeletes = false;
    protected $useTimestamps  = true;
    protected $dateFormat     = 'datetime';
    protected $createdField   = 'created_at';
    protected $updatedField   = '';
    protected $allowedFields  = [
        'user_id',
        'identity_id',
        'purpose',
        'channel',
        'selector',
        'code_hash',
        'attempts',
        'ip_address',
        'expires_at',
        'consumed_at',
    ];

    public function __construct(?ConnectionInterface $db = null, ?ValidationInterface $validation = null)
    {
        /** @var Auth $config */
        $config      = config(Auth::class);
        $this->table = $config->table('one_time_codes');

        if ($config->DBGroup !== null) {
            $this->DBGroup = $config->DBGroup;
        }

        parent::__construct($db, $validation);
    }

    public function findBySelector(string $selector): ?OneTimeCode
    {
        if (preg_match('/^[0-9a-f]{32}$/', $selector) !== 1) {
            return null;
        }

        $code = $this->where('selector', $selector)->first();

        return $code instanceof OneTimeCode ? $code : null;
    }

    /**
     * Newest unconsumed, unexpired code for an identity and purpose.
     */
    public function latestActive(int $identityId, string $purpose): ?OneTimeCode
    {
        $code = $this->where('identity_id', $identityId)
            ->where('purpose', $purpose)
            ->where('consumed_at', null)
            ->where('expires_at >', Time::now()->toDateTimeString())
            ->orderBy('id', 'DESC')
            ->first();

        return $code instanceof OneTimeCode ? $code : null;
    }

    /**
     * When the last code for this identity and purpose was issued.
     */
    public function lastIssuedAt(int $identityId, string $purpose): ?Time
    {
        $row = $this->builder()
            ->selectMax('created_at', 'last_issued')
            ->where('identity_id', $identityId)
            ->where('purpose', $purpose)
            ->get()
            ->getRowArray();

        $last = $row['last_issued'] ?? null;

        return is_string($last) && $last !== '' ? Time::parse($last) : null;
    }

    /**
     * Count a wrong guess. Done in SQL so concurrent guesses can't race
     * past the limit.
     */
    public function incrementAttempts(int $codeId): void
    {
        $this->builder()
            ->set('attempts', 'attempts + 1', false)
            ->where($this->primaryKey, $codeId)
            ->update();
    }

    /**
     * Mark a code used. Returns false if it was already consumed, so two
     * simultaneous submissions of the same code can't both succeed.
     */
    public function markConsumed(int $codeId): bool
    {
        $this->builder()
            ->where($this->primaryKey, $codeId)
            ->where('consumed_at', null)
            ->update(['consumed_at' => Time::now()->toDateTimeString()]);

        return $this->db->affectedRows() === 1;
    }

    /**
     * Invalidate every outstanding code for an identity and purpose,
     * e.g. when a fresh code is issued, so only the newest one works.
     */
    public function consumeOutstanding(int $identityId, string $purpose): int
    {
        $this->builder()
            ->where('identity_id', $identityId)
            ->where('purpose', $purpose)
            ->where('consumed_at', null)
            ->update(['consumed_at' => Time::now()->toDateTimeString()]);

        return $this->db->affectedRows();
    }

    /**
     * Invalidate every outstanding code of a purpose for a user, across all
     * identities (e.g. all reset codes once the password has been changed).
     */
    public function consumeOutstandingForUser(int $userId, string $purpose): int
    {
        $this->builder()
            ->where('user_id', $userId)
            ->where('purpose', $purpose)
            ->where('consumed_at', null)
            ->update(['consumed_at' => Time::now()->toDateTimeString()]);

        return $this->db->affectedRows();
    }

    /**
     * Delete codes that expired or were used before the cutoff.
     */
    public function deleteStale(Time $cutoff): int
    {
        $cutoffString = $cutoff->toDateTimeString();

        $this->builder()
            ->groupStart()
            ->where('expires_at <', $cutoffString)
            ->orWhere('consumed_at <', $cutoffString)
            ->groupEnd()
            ->delete();

        return $this->db->affectedRows();
    }
}
