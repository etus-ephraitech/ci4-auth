<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Authorization;

use Ephraitech\Auth\Exceptions\AuthException;

/**
 * Holds the active tenant for the current request. Set by the tenant
 * filter (or the host app) once per request; read by the Authorizer
 * whenever a tenant is not passed explicitly.
 */
final class TenantContext
{
    public const MAX_LENGTH = 64;

    private ?string $tenantId = null;

    /**
     * @throws AuthException
     */
    public function set(int|string|null $tenantId): void
    {
        if ($tenantId === null) {
            $this->tenantId = null;

            return;
        }

        $tenantId = trim((string) $tenantId);

        if ($tenantId === '') {
            $this->tenantId = null;

            return;
        }

        if (strlen($tenantId) > self::MAX_LENGTH) {
            throw new AuthException('Tenant identifier cannot exceed ' . self::MAX_LENGTH . ' characters.');
        }

        $this->tenantId = $tenantId;
    }

    public function get(): ?string
    {
        return $this->tenantId;
    }

    public function has(): bool
    {
        return $this->tenantId !== null;
    }

    public function clear(): void
    {
        $this->tenantId = null;
    }
}
