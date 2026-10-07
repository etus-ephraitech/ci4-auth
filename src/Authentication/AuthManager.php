<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Authentication;

use Closure;
use CodeIgniter\HTTP\RequestInterface;
use Ephraitech\Auth\Authentication\Guards\GuardInterface;
use Ephraitech\Auth\Authentication\Guards\SessionGuard;
use Ephraitech\Auth\Authentication\Guards\TokenGuard;
use Ephraitech\Auth\Authorization\Authorizer;
use Ephraitech\Auth\Authorization\TenantContext;
use Ephraitech\Auth\Config\Auth;
use Ephraitech\Auth\Entities\User;
use Ephraitech\Auth\Exceptions\AuthException;

/**
 * The single entry point apps use: service('auth').
 *
 * Guard selection: whatever a filter forced via shouldUse(), otherwise
 * 'token' when the request carries a bearer token, otherwise 'session'.
 * Guards are built lazily, so API requests never start a PHP session.
 *
 * Permission checks through this class automatically apply the current
 * token's abilities and bound tenant.
 */
final class AuthManager
{
    /**
     * @var array<string, GuardInterface>
     */
    private array $resolved = [];

    private ?string $forced = null;

    /**
     * @param array<string, Closure(): GuardInterface> $guards
     */
    public function __construct(
        private readonly Auth $config,
        private readonly Authorizer $authorizer,
        private readonly TenantContext $tenant,
        private readonly RequestInterface $request,
        private readonly array $guards,
    ) {}

    // ------------------------------------------------------------------
    // Guards
    // ------------------------------------------------------------------

    /**
     * @throws AuthException
     */
    public function guard(?string $name = null): GuardInterface
    {
        $name ??= $this->defaultGuardName();

        if (isset($this->resolved[$name])) {
            return $this->resolved[$name];
        }

        if (! isset($this->guards[$name])) {
            throw new AuthException("Unknown auth guard '{$name}'.");
        }

        return $this->resolved[$name] = ($this->guards[$name])();
    }

    /**
     * Force a guard for the rest of the request (used by filters).
     *
     * @throws AuthException
     */
    public function shouldUse(string $name): void
    {
        if (! isset($this->guards[$name])) {
            throw new AuthException("Unknown auth guard '{$name}'.");
        }

        $this->forced = $name;
    }

    public function session(): SessionGuard
    {
        $guard = $this->guard(SessionGuard::NAME);

        if (! $guard instanceof SessionGuard) {
            throw new AuthException('The session guard is misconfigured.');
        }

        return $guard;
    }

    public function token(): TokenGuard
    {
        $guard = $this->guard(TokenGuard::NAME);

        if (! $guard instanceof TokenGuard) {
            throw new AuthException('The token guard is misconfigured.');
        }

        return $guard;
    }

    // ------------------------------------------------------------------
    // Current user
    // ------------------------------------------------------------------

    public function check(): bool
    {
        return $this->guard()->check();
    }

    public function user(): ?User
    {
        return $this->guard()->user();
    }

    public function id(): ?int
    {
        return $this->guard()->id();
    }

    public function logout(): void
    {
        $this->guard()->logout();
    }

    // ------------------------------------------------------------------
    // Authorization for the current user
    // ------------------------------------------------------------------

    public function can(string $permission, ?string $tenantId = null): bool
    {
        $user = $this->user();

        if ($user === null) {
            return false;
        }

        [$abilities, $tenant] = $this->tokenScope($tenantId);

        return $this->authorizer->can($user, $permission, $tenant, $abilities);
    }

    /**
     * @param list<string> $permissions
     */
    public function canAny(array $permissions, ?string $tenantId = null): bool
    {
        $user = $this->user();

        if ($user === null) {
            return false;
        }

        [$abilities, $tenant] = $this->tokenScope($tenantId);

        return $this->authorizer->canAny($user, $permissions, $tenant, $abilities);
    }

    /**
     * @param list<string> $permissions
     */
    public function canAll(array $permissions, ?string $tenantId = null): bool
    {
        $user = $this->user();

        if ($user === null) {
            return false;
        }

        [$abilities, $tenant] = $this->tokenScope($tenantId);

        return $this->authorizer->canAll($user, $permissions, $tenant, $abilities);
    }

    /**
     * @param list<string>|string $roles
     */
    public function hasRole(array|string $roles, ?string $tenantId = null): bool
    {
        $user = $this->user();

        if ($user === null) {
            return false;
        }

        return $this->authorizer->hasRole($user, $roles, $this->tokenScope($tenantId)[1]);
    }

    public function authorizer(): Authorizer
    {
        return $this->authorizer;
    }

    public function tenant(): TenantContext
    {
        return $this->tenant;
    }

    public function config(): Auth
    {
        return $this->config;
    }

    // ------------------------------------------------------------------

    private function defaultGuardName(): string
    {
        if ($this->forced !== null) {
            return $this->forced;
        }

        return TokenGuard::extractFromRequest($this->config, $this->request) !== null
            ? TokenGuard::NAME
            : SessionGuard::NAME;
    }

    /**
     * Abilities and tenant implied by the current token, if authenticated by one.
     *
     * @return array{0: list<string>|null, 1: string|null}
     */
    private function tokenScope(?string $tenantId): array
    {
        $guard = $this->guard();

        if ($guard instanceof TokenGuard) {
            $token = $guard->token();

            if ($token !== null) {
                return [$token->abilityList(), $tenantId ?? $token->tenant()];
            }
        }

        return [null, $tenantId];
    }
}
