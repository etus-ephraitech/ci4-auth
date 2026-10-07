<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Support;

/**
 * Remembers, in this browser's session, a user who proved their password
 * (or just registered) but must verify an identifier before signing in.
 * Expires after 30 minutes.
 */
final class PendingVerification
{
    public const SESSION_KEY = 'ephraitech_auth_pending_verification';

    private const TTL = 1800;

    public static function put(int $userId, string $type): void
    {
        session()->set(self::SESSION_KEY, [
            'user_id' => $userId,
            'type'    => $type,
            'at'      => time(),
        ]);
    }

    /**
     * @return array{user_id: int, type: string}|null
     */
    public static function get(): ?array
    {
        $data = session()->get(self::SESSION_KEY);

        if (! is_array($data) || ! isset($data['user_id'], $data['type'], $data['at'])) {
            return null;
        }

        if (time() - (int) $data['at'] > self::TTL) {
            self::clear();

            return null;
        }

        return ['user_id' => (int) $data['user_id'], 'type' => (string) $data['type']];
    }

    public static function clear(): void
    {
        session()->remove(self::SESSION_KEY);
    }
}
