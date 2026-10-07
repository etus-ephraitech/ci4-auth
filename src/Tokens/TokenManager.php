<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Tokens;

use CodeIgniter\Config\Factories;
use CodeIgniter\Events\Events;
use CodeIgniter\I18n\Time;
use Ephraitech\Auth\AuthEvents;
use Ephraitech\Auth\Authorization\TenantContext;
use Ephraitech\Auth\Config\Auth;
use Ephraitech\Auth\Entities\AccessToken;
use Ephraitech\Auth\Exceptions\AuthException;
use Ephraitech\Auth\Models\AccessTokenModel;
use JsonException;

/**
 * Issues, validates and revokes opaque bearer tokens.
 *
 * Token format: <prefix><base64url(random bytes)>, e.g. eph_Q2x...
 * Storage:      SHA-256 hex of the full token; plaintext returned once.
 *
 * Session tokens: user logins from apps; absolute lifetime, optional idle
 *                 timeout, capped per user (oldest revoked first).
 * API keys:       integrations; optional expiry, never idle-expired,
 *                 not counted toward the session cap.
 */
final class TokenManager
{
    private const MAX_TOKEN_LENGTH = 255;

    private const MAX_NAME_LENGTH = 100;

    private const ABILITY_PATTERN = '/^(\*|[a-z0-9_-]+(\.[a-z0-9_-]+)*(\.\*)?)$/';

    public function __construct(
        private readonly Auth $config,
        private readonly AccessTokenModel $tokens,
    ) {}

    public static function create(?Auth $config = null): self
    {
        /** @var Auth $config */
        $config ??= config(Auth::class);

        /** @var AccessTokenModel $tokens */
        $tokens = Factories::models(AccessTokenModel::class, ['preferApp' => false]);

        return new self($config, $tokens);
    }

    // ------------------------------------------------------------------
    // Issuing
    // ------------------------------------------------------------------

    /**
     * Issue a login token for a user (mobile app, SPA, API client login).
     *
     * @param list<string>|null $abilities NULL = $defaultTokenAbilities.
     *
     * @throws AuthException
     */
    public function issueSessionToken(
        int $userId,
        string $name,
        ?array $abilities = null,
        ?string $tenantId = null,
        ?string $ipAddress = null,
        ?string $userAgent = null,
    ): NewAccessToken {
        $expiresAt = Time::now()->addSeconds($this->config->sessionTokenLifetime);

        $new = $this->issue(
            $userId,
            Auth::TOKEN_TYPE_SESSION,
            $name,
            $abilities,
            $tenantId,
            $expiresAt,
            $ipAddress,
            $userAgent
        );

        $this->enforceSessionCap($userId);

        return $new;
    }

    /**
     * Issue an integration API key.
     *
     * @param list<string>|null $abilities       NULL = $defaultTokenAbilities.
     * @param int|null          $lifetimeSeconds NULL = $apiKeyLifetime (which may itself be NULL = no expiry).
     *
     * @throws AuthException
     */
    public function issueApiKey(
        int $userId,
        string $name,
        ?array $abilities = null,
        ?string $tenantId = null,
        ?int $lifetimeSeconds = null,
    ): NewAccessToken {
        $lifetime = $lifetimeSeconds ?? $this->config->apiKeyLifetime;

        if ($lifetime !== null && $lifetime < 60) {
            throw new AuthException('API key lifetime must be at least 60 seconds.');
        }

        $expiresAt = $lifetime !== null ? Time::now()->addSeconds($lifetime) : null;

        return $this->issue($userId, Auth::TOKEN_TYPE_API_KEY, $name, $abilities, $tenantId, $expiresAt, null, null);
    }

    // ------------------------------------------------------------------
    // Validation
    // ------------------------------------------------------------------

    /**
     * Resolve a plaintext token to a usable AccessToken, or NULL when it is
     * unknown, revoked, expired or idle. Updates last_used_at (throttled).
     *
     * User status is NOT checked here; the token guard checks the owner.
     */
    public function validate(string $plaintext, ?string $ipAddress = null): ?AccessToken
    {
        $plaintext = trim($plaintext);

        if ($plaintext === '' || strlen($plaintext) > self::MAX_TOKEN_LENGTH) {
            return null;
        }

        $prefix = $this->config->tokenPrefix;

        if ($prefix !== '' && ! str_starts_with($plaintext, $prefix)) {
            return null;
        }

        $token = $this->tokens->findByHash($this->hash($plaintext));

        if (! $token instanceof AccessToken || $token->isRevoked() || $token->isExpired()) {
            return null;
        }

        if ($token->isSession() && $token->isIdle($this->config->sessionTokenIdleTimeout)) {
            return null;
        }

        $this->touch($token, $ipAddress);

        return $token;
    }

    /**
     * Extract the token from an "Authorization: Bearer <token>" header value.
     */
    public static function extractBearer(?string $headerValue): ?string
    {
        if ($headerValue === null || preg_match('/^\s*Bearer\s+(\S+)\s*$/i', $headerValue, $matches) !== 1) {
            return null;
        }

        return $matches[1];
    }

    // ------------------------------------------------------------------
    // Listing
    // ------------------------------------------------------------------

    /**
     * Active tokens for a user, newest first (for "your devices" / "API keys" screens).
     *
     * @return list<AccessToken>
     */
    public function listForUser(int $userId, ?string $type = null): array
    {
        if ($type !== null) {
            $this->assertType($type);
        }

        return $this->tokens->activeForUser($userId, $type);
    }

    // ------------------------------------------------------------------
    // Revocation (takes effect on the very next request)
    // ------------------------------------------------------------------

    /**
     * Revoke one token. When $userId is given, the token must belong to
     * that user, so users can only revoke their own devices/keys.
     */
    public function revoke(int $tokenId, ?int $userId = null): bool
    {
        $token = $this->tokens->find($tokenId);

        if (! $token instanceof AccessToken || $token->isRevoked()) {
            return false;
        }

        if ($userId !== null && $token->user_id !== $userId) {
            return false;
        }

        return $this->revokeIds((int) $token->user_id, [(int) $token->id]) === [(int) $token->id];
    }

    /**
     * Revoke the token presented by the client (logout).
     */
    public function revokePlaintext(string $plaintext): bool
    {
        $token = $this->tokens->findByHash($this->hash(trim($plaintext)));

        if (! $token instanceof AccessToken || $token->isRevoked()) {
            return false;
        }

        return $this->revokeIds((int) $token->user_id, [(int) $token->id]) !== [];
    }

    /**
     * Revoke all of a user's active tokens, optionally of one type and
     * optionally keeping one (e.g. the device that changed the password).
     *
     * $dispatchEvent = false lets a caller running inside its own
     * transaction fire TOKENS_REVOKED itself after commit.
     *
     * @return list<int> IDs revoked by this call.
     */
    public function revokeAllForUser(
        int $userId,
        ?string $type = null,
        ?int $exceptTokenId = null,
        bool $dispatchEvent = true,
    ): array {
        if ($type !== null) {
            $this->assertType($type);
        }

        $ids = [];

        foreach ($this->tokens->activeForUser($userId, $type) as $token) {
            if ($exceptTokenId === null || (int) $token->id !== $exceptTokenId) {
                $ids[] = (int) $token->id;
            }
        }

        return $this->revokeIds($userId, $ids, $dispatchEvent);
    }

    /**
     * Delete revoked/expired tokens older than the given age (prune command).
     */
    public function pruneStale(int $olderThanDays = 7): int
    {
        if ($olderThanDays < 0) {
            throw new AuthException('Prune age cannot be negative.');
        }

        return $this->tokens->deleteStale(Time::now()->subDays($olderThanDays));
    }

    public function hash(string $plaintext): string
    {
        return hash('sha256', $plaintext);
    }

    // ------------------------------------------------------------------
    // Internals
    // ------------------------------------------------------------------

    /**
     * @param list<string>|null $abilities
     *
     * @throws AuthException
     */
    private function issue(
        int $userId,
        string $type,
        string $name,
        ?array $abilities,
        ?string $tenantId,
        ?Time $expiresAt,
        ?string $ipAddress,
        ?string $userAgent,
    ): NewAccessToken {
        if ($userId < 1) {
            throw new AuthException('Tokens can only be issued to a saved user.');
        }

        $plaintext = $this->generate();

        try {
            $encodedAbilities = json_encode(
                $this->cleanAbilities($abilities ?? $this->config->defaultTokenAbilities),
                JSON_THROW_ON_ERROR
            );
        } catch (JsonException $e) {
            throw new AuthException('Token abilities could not be encoded.', 0, $e);
        }

        $id = $this->tokens->insert([
            'user_id'    => $userId,
            'tenant_id'  => $this->cleanTenant($tenantId),
            'type'       => $type,
            'name'       => $this->cleanName($name),
            'token_hash' => $this->hash($plaintext),
            'abilities'  => $encodedAbilities,
            'ip_address' => $ipAddress !== null && $ipAddress !== '' ? substr($ipAddress, 0, 45) : null,
            'user_agent' => $userAgent !== null && $userAgent !== '' ? mb_substr($userAgent, 0, 255, 'UTF-8') : null,
            'expires_at' => $expiresAt?->toDateTimeString(),
        ], true);

        if ($id === false) {
            throw new AuthException('Failed to issue the token.');
        }

        $token = $this->tokens->find($id);

        if (! $token instanceof AccessToken) {
            throw new AuthException("Token {$id} could not be loaded after issuing.");
        }

        Events::trigger(AuthEvents::TOKEN_ISSUED, $userId, (int) $id, $type);

        return new NewAccessToken($token, $plaintext);
    }

    private function generate(): string
    {
        $random = rtrim(strtr(base64_encode(random_bytes($this->config->tokenBytes)), '+/', '-_'), '=');

        return $this->config->tokenPrefix . $random;
    }

    private function touch(AccessToken $token, ?string $ipAddress): void
    {
        $lastUsed = $token->last_used_at;
        $now      = Time::now();

        if (
            $lastUsed instanceof Time
            && $now->getTimestamp() - $lastUsed->getTimestamp() < $this->config->tokenLastUsedUpdateInterval
        ) {
            return;
        }

        $this->tokens->touchLastUsed((int) $token->id, $ipAddress);

        $token->last_used_at = $now;
    }

    private function enforceSessionCap(int $userId): void
    {
        $max = $this->config->maxSessionTokensPerUser;

        if ($max <= 0) {
            return;
        }

        $active = $this->tokens->activeForUser($userId, Auth::TOKEN_TYPE_SESSION);

        if (count($active) <= $max) {
            return;
        }

        $this->revokeIds(
            $userId,
            array_map(static fn(AccessToken $t): int => (int) $t->id, array_slice($active, $max))
        );
    }

    /**
     * @param list<int> $ids
     *
     * @return list<int>
     */
    private function revokeIds(int $userId, array $ids, bool $dispatchEvent = true): array
    {
        if ($ids === [] || $this->tokens->markRevoked($ids) === 0) {
            return [];
        }

        if ($dispatchEvent) {
            Events::trigger(AuthEvents::TOKENS_REVOKED, $userId, $ids);
        }

        return $ids;
    }

    /**
     * @param list<mixed> $abilities
     *
     * @return list<string>
     *
     * @throws AuthException
     */
    private function cleanAbilities(array $abilities): array
    {
        if ($abilities === []) {
            throw new AuthException('A token needs at least one ability; use ["*"] for full user access.');
        }

        $clean = [];

        foreach ($abilities as $ability) {
            if (! is_string($ability) || preg_match(self::ABILITY_PATTERN, $ability) !== 1) {
                throw new AuthException(
                    'Invalid token ability ' . var_export($ability, true)
                        . ". Use '*', a permission like 'users.view', or a wildcard like 'users.*'."
                );
            }

            $clean[$ability] = true;
        }

        return array_keys($clean);
    }

    /**
     * @throws AuthException
     */
    private function cleanName(string $name): string
    {
        $name = trim($name);

        if ($name === '' || mb_strlen($name, 'UTF-8') > self::MAX_NAME_LENGTH) {
            throw new AuthException('Token name must be between 1 and ' . self::MAX_NAME_LENGTH . ' characters.');
        }

        return $name;
    }

    /**
     * @throws AuthException
     */
    private function cleanTenant(?string $tenantId): string
    {
        if (! $this->config->isMultiTenant() || $tenantId === null) {
            return '';
        }

        $tenantId = trim($tenantId);

        if (strlen($tenantId) > TenantContext::MAX_LENGTH) {
            throw new AuthException('Tenant identifier cannot exceed ' . TenantContext::MAX_LENGTH . ' characters.');
        }

        return $tenantId;
    }

    /**
     * @throws AuthException
     */
    private function assertType(string $type): void
    {
        if (! in_array($type, [Auth::TOKEN_TYPE_SESSION, Auth::TOKEN_TYPE_API_KEY], true)) {
            throw new AuthException("Unknown token type '{$type}'.");
        }
    }
}
