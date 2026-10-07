<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Models;

use CodeIgniter\Database\ConnectionInterface;
use CodeIgniter\Database\Exceptions\DatabaseException;
use CodeIgniter\I18n\Time;
use CodeIgniter\Model;
use CodeIgniter\Validation\ValidationInterface;
use Ephraitech\Auth\Config\Auth;
use Ephraitech\Auth\Entities\Identity;
use Ephraitech\Auth\Exceptions\AuthException;
use Ephraitech\Auth\Exceptions\IdentifierTakenException;
use Ephraitech\Auth\Exceptions\InvalidIdentifierException;
use Ephraitech\Auth\Support\IdentifierNormalizer;

/**
 * Persistence for auth_identities. Every identifier passed in is normalized
 * here, so callers may pass raw user input.
 */
class IdentityModel extends Model
{
    protected $primaryKey     = 'id';
    protected $returnType     = Identity::class;
    protected $useSoftDeletes = false;
    protected $useTimestamps  = true;
    protected $dateFormat     = 'datetime';
    protected $createdField   = 'created_at';
    protected $updatedField   = 'updated_at';
    protected $allowedFields  = [
        'user_id',
        'type',
        'identifier',
        'secret',
        'verified_at',
        'last_used_at',
    ];

    protected Auth $authConfig;

    protected IdentifierNormalizer $normalizer;

    public function __construct(?ConnectionInterface $db = null, ?ValidationInterface $validation = null)
    {
        /** @var Auth $config */
        $config = config(Auth::class);

        $this->authConfig = $config;
        $this->normalizer = new IdentifierNormalizer($config);
        $this->table      = $config->table('identities');

        if ($config->DBGroup !== null) {
            $this->DBGroup = $config->DBGroup;
        }

        parent::__construct($db, $validation);
    }

    public function normalizer(): IdentifierNormalizer
    {
        return $this->normalizer;
    }

    // ------------------------------------------------------------------
    // Lookups
    // ------------------------------------------------------------------

    /**
     * Find an identifier row by raw or normalized value.
     * Returns NULL for unknown or invalid input.
     */
    public function findByIdentifier(string $type, string $value): ?Identity
    {
        $normalized = $this->normalizer->tryNormalize($type, $value);

        if ($normalized === null) {
            return null;
        }

        $identity = $this->where('type', $type)
            ->where('identifier', $normalized)
            ->first();

        return $identity instanceof Identity ? $identity : null;
    }

    /**
     * All identifier rows for a user, keyed by type. Password row excluded.
     *
     * @return array<string, Identity>
     */
    public function findIdentifiersForUser(int $userId): array
    {
        $rows = $this->where('user_id', $userId)
            ->where('type !=', Auth::CREDENTIAL_PASSWORD)
            ->findAll();

        $keyed = [];

        foreach ($rows as $row) {
            $keyed[(string) $row->type] = $row;
        }

        return $keyed;
    }

    public function findPassword(int $userId): ?Identity
    {
        $identity = $this->where('user_id', $userId)
            ->where('type', Auth::CREDENTIAL_PASSWORD)
            ->first();

        return $identity instanceof Identity ? $identity : null;
    }

    /**
     * Whether a (raw or normalized) identifier belongs to any account,
     * optionally ignoring one user (for profile updates).
     */
    public function identifierExists(string $type, string $value, ?int $exceptUserId = null): bool
    {
        $normalized = $this->normalizer->tryNormalize($type, $value);

        if ($normalized === null) {
            return false;
        }

        $builder = $this->builder()
            ->where('type', $type)
            ->where('identifier', $normalized);

        if ($exceptUserId !== null) {
            $builder->where('user_id !=', $exceptUserId);
        }

        return $builder->countAllResults() > 0;
    }

    // ------------------------------------------------------------------
    // Writes
    // ------------------------------------------------------------------

    /**
     * Create or replace a user's email/username/phone.
     * Changing the value clears verification unless $verified is true.
     *
     * @throws InvalidIdentifierException
     * @throws IdentifierTakenException
     * @throws AuthException
     */
    public function setIdentifier(int $userId, string $type, string $value, bool $verified = false): Identity
    {
        $normalized = $this->normalizer->normalize($type, $value);
        $now        = Time::now()->toDateTimeString();

        $owner = $this->where('type', $type)->where('identifier', $normalized)->first();

        if ($owner instanceof Identity && (int) $owner->user_id !== $userId) {
            throw IdentifierTakenException::forType($type);
        }

        $existing = $this->where('user_id', $userId)->where('type', $type)->first();

        if (! $existing instanceof Identity) {
            $id = $this->safeWrite(
                fn() => $this->insert([
                    'user_id'     => $userId,
                    'type'        => $type,
                    'identifier'  => $normalized,
                    'verified_at' => $verified ? $now : null,
                ], true),
                $type,
                $normalized,
                $userId
            );

            return $this->findOrFail((int) $id);
        }

        $changes = [];

        if ($existing->identifier !== $normalized) {
            $changes['identifier']  = $normalized;
            $changes['verified_at'] = $verified ? $now : null;
        } elseif ($verified && ! $existing->isVerified()) {
            $changes['verified_at'] = $now;
        }

        if ($changes !== []) {
            $this->safeWrite(
                fn() => $this->update($existing->id, $changes),
                $type,
                $normalized,
                $userId
            );
        }

        return $this->findOrFail((int) $existing->id);
    }

    /**
     * Create or replace the user's password hash. Hashing happens in the
     * password service; this method stores an already-computed hash.
     */
    public function setPasswordHash(int $userId, string $hash): void
    {
        if ($hash === '' || password_get_info($hash)['algo'] === null) {
            throw new AuthException('Refusing to store a value that is not a password hash.');
        }

        $existing = $this->findPassword($userId);

        $result = $existing instanceof Identity
            ? $this->update($existing->id, ['secret' => $hash])
            : $this->insert([
                'user_id'    => $userId,
                'type'       => Auth::CREDENTIAL_PASSWORD,
                'identifier' => null,
                'secret'     => $hash,
            ]);

        if ($result === false) {
            throw new AuthException('Failed to save the password.');
        }
    }

    public function markVerified(int $userId, string $type): bool
    {
        return $this->builder()
            ->where('user_id', $userId)
            ->where('type', $type)
            ->where('verified_at', null)
            ->update(['verified_at' => Time::now()->toDateTimeString()]);
    }

    public function removeIdentifier(int $userId, string $type): bool
    {
        if ($type === Auth::CREDENTIAL_PASSWORD) {
            throw new AuthException('Use the password service to manage passwords.');
        }

        return (bool) $this->where('user_id', $userId)->where('type', $type)->delete();
    }

    /**
     * Record use without touching updated_at.
     */
    public function touchLastUsed(int $identityId): void
    {
        $this->builder()
            ->where($this->primaryKey, $identityId)
            ->update(['last_used_at' => Time::now()->toDateTimeString()]);
    }

    // ------------------------------------------------------------------

    /**
     * Run a write, converting unique-index races (two requests claiming the
     * same identifier at once) into IdentifierTakenException.
     *
     * @param callable(): (bool|int|string) $write
     */
    private function safeWrite(callable $write, string $type, string $normalized, int $userId): bool|int|string
    {
        try {
            $result = $write();
        } catch (DatabaseException $e) {
            $result = false;
            $error  = $e;
        }

        if ($result !== false) {
            return $result;
        }

        if ($this->identifierExists($type, $normalized, $userId)) {
            throw IdentifierTakenException::forType($type);
        }

        throw new AuthException(
            'Failed to save the ' . InvalidIdentifierException::label($type) . '.',
            0,
            $error ?? null
        );
    }

    private function findOrFail(int $id): Identity
    {
        $identity = $this->find($id);

        if (! $identity instanceof Identity) {
            throw new AuthException("Identity {$id} could not be loaded after saving.");
        }

        return $identity;
    }
}
