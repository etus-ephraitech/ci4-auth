<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Models;

use CodeIgniter\Database\ConnectionInterface;
use CodeIgniter\I18n\Time;
use CodeIgniter\Model;
use CodeIgniter\Validation\ValidationInterface;
use Ephraitech\Auth\Config\Auth;

class LoginAttemptModel extends Model
{
    protected $primaryKey     = 'id';
    protected $returnType     = 'array';
    protected $useSoftDeletes = false;
    protected $useTimestamps  = false;
    protected $allowedFields  = [
        'type',
        'identifier',
        'user_id',
        'ip_address',
        'user_agent',
        'success',
        'reason',
        'created_at',
    ];

    public function __construct(?ConnectionInterface $db = null, ?ValidationInterface $validation = null)
    {
        /** @var Auth $config */
        $config      = config(Auth::class);
        $this->table = $config->table('login_attempts');

        if ($config->DBGroup !== null) {
            $this->DBGroup = $config->DBGroup;
        }

        parent::__construct($db, $validation);
    }

    public function record(
        ?string $type,
        ?string $identifier,
        ?int $userId,
        string $ipAddress,
        ?string $userAgent,
        bool $success,
        ?string $reason,
    ): void {
        $this->builder()->insert([
            'type'       => $type,
            'identifier' => $identifier !== null ? mb_substr($identifier, 0, 255, 'UTF-8') : null,
            'user_id'    => $userId,
            'ip_address' => substr($ipAddress, 0, 45),
            'user_agent' => $userAgent !== null ? mb_substr($userAgent, 0, 255, 'UTF-8') : null,
            'success'    => $success ? 1 : 0,
            'reason'     => $reason !== null ? substr($reason, 0, 50) : null,
            'created_at' => Time::now()->toDateTimeString(),
        ]);
    }

    /**
     * Failures for identifier+IP since $since, ignoring any before the
     * most recent success (a successful login resets the counter).
     *
     * @return array{count: int, latest: string|null}
     */
    public function failuresSince(string $identifier, string $ipAddress, Time $since): array
    {
        $lastSuccess = $this->builder()
            ->selectMax('created_at', 'last_success')
            ->where('identifier', $identifier)
            ->where('ip_address', $ipAddress)
            ->where('success', 1)
            ->get()
            ->getRowArray()['last_success'] ?? null;

        $from = $since->toDateTimeString();

        if ($lastSuccess !== null && $lastSuccess > $from) {
            $from = $lastSuccess;
        }

        $row = $this->builder()
            ->select('COUNT(*) AS attempts, MAX(created_at) AS latest', false)
            ->where('identifier', $identifier)
            ->where('ip_address', $ipAddress)
            ->where('success', 0)
            ->where('created_at >', $from)
            ->get()
            ->getRowArray();

        return [
            'count'  => (int) ($row['attempts'] ?? 0),
            'latest' => $row['latest'] ?? null,
        ];
    }

    public function clearFailures(string $identifier, string $ipAddress): void
    {
        $this->builder()
            ->where('identifier', $identifier)
            ->where('ip_address', $ipAddress)
            ->where('success', 0)
            ->delete();
    }

    public function deleteOlderThan(Time $cutoff): int
    {
        $this->builder()->where('created_at <', $cutoff->toDateTimeString())->delete();

        return $this->db->affectedRows();
    }
}
