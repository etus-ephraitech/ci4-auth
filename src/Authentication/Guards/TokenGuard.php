<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Authentication\Guards;

use CodeIgniter\Events\Events;
use CodeIgniter\HTTP\IncomingRequest;
use CodeIgniter\HTTP\RequestInterface;
use Ephraitech\Auth\AuthEvents;
use Ephraitech\Auth\Authentication\CredentialVerifier;
use Ephraitech\Auth\Config\Auth;
use Ephraitech\Auth\Entities\AccessToken;
use Ephraitech\Auth\Entities\User;
use Ephraitech\Auth\Exceptions\AccountNotActiveException;
use Ephraitech\Auth\Exceptions\AuthException;
use Ephraitech\Auth\Models\UserModel;
use Ephraitech\Auth\Tokens\NewAccessToken;
use Ephraitech\Auth\Tokens\TokenManager;

/**
 * Bearer-token authentication for APIs, mobile apps and integrations.
 * Stateless: every request is authenticated from its own header.
 */
final class TokenGuard implements GuardInterface
{
    public const NAME = 'token';

    private ?User $user = null;

    private ?AccessToken $token = null;

    private bool $resolved = false;

    public function __construct(
        private readonly Auth $config,
        private readonly TokenManager $tokens,
        private readonly UserModel $users,
        private readonly CredentialVerifier $verifier,
        private readonly RequestInterface $request,
    ) {}

    /**
     * Read the presented token from the request, if any.
     * "Authorization: Bearer <token>", or the raw value of a custom header.
     */
    public static function extractFromRequest(Auth $config, RequestInterface $request): ?string
    {
        if (! $request instanceof IncomingRequest) {
            return null;
        }

        $header = $request->getHeaderLine($config->tokenHeader);

        if ($header === '') {
            return null;
        }

        if (strcasecmp($config->tokenHeader, 'Authorization') === 0) {
            return TokenManager::extractBearer($header);
        }

        return TokenManager::extractBearer($header) ?? trim($header);
    }

    public function name(): string
    {
        return self::NAME;
    }

    /**
     * API login: verify credentials and issue a session token.
     *
     * @param string            $deviceName e.g. "Tecno Spark 20" or "Field Tracker Android".
     * @param list<string>|null $abilities  NULL = $defaultTokenAbilities.
     *
     * @throws \Ephraitech\Auth\Exceptions\LockedOutException
     * @throws \Ephraitech\Auth\Exceptions\InvalidCredentialsException
     * @throws AccountNotActiveException
     * @throws \Ephraitech\Auth\Exceptions\IdentifierNotVerifiedException
     */
    public function attempt(
        string $login,
        string $password,
        string $deviceName,
        ?array $abilities = null,
        ?string $tenantId = null,
        ?string $type = null,
    ): NewAccessToken {
        $user = $this->verifier->verify($login, $password, $type, $this->ipAddress(), $this->userAgent());

        return $this->issueFor($user, $deviceName, $abilities, $tenantId);
    }

    /**
     * Issue a session token for an already-verified user
     * (after OTP, social login, or right after registration).
     *
     * @param list<string>|null $abilities
     *
     * @throws AccountNotActiveException
     * @throws AuthException
     */
    public function issueFor(User $user, string $deviceName, ?array $abilities = null, ?string $tenantId = null): NewAccessToken
    {
        if ($user->id === null) {
            throw new AuthException('Cannot issue a token for an unsaved user.');
        }

        if (! $user->isActive()) {
            throw new AccountNotActiveException((string) $user->status, $user->status_reason);
        }

        $new = $this->tokens->issueSessionToken(
            (int) $user->id,
            $deviceName,
            $abilities,
            $tenantId,
            $this->ipAddress(),
            $this->userAgent()
        );

        $this->users->touchLastLogin((int) $user->id);

        $this->user     = $user;
        $this->token    = $new->token;
        $this->resolved = true;

        Events::trigger(AuthEvents::LOGIN, $user, self::NAME);

        return $new;
    }

    public function check(): bool
    {
        return $this->user() !== null;
    }

    public function user(): ?User
    {
        $this->resolve();

        return $this->user;
    }

    public function id(): ?int
    {
        return $this->user()?->id;
    }

    /**
     * The token authenticating this request.
     */
    public function token(): ?AccessToken
    {
        $this->resolve();

        return $this->token;
    }

    /**
     * Revoke the current token (logout from this device).
     */
    public function logout(): void
    {
        $this->resolve();

        $user  = $this->user;
        $token = $this->token;

        if ($token !== null) {
            $this->tokens->revoke((int) $token->id);
        }

        $this->user  = null;
        $this->token = null;

        if ($user !== null) {
            Events::trigger(AuthEvents::LOGOUT, $user, self::NAME);
        }
    }

    /**
     * Revoke every session token of the current user ("log out all devices").
     * API keys are left alone; revoke those explicitly via TokenManager.
     */
    public function logoutEverywhere(): void
    {
        $this->resolve();

        $user = $this->user;

        if ($user === null) {
            return;
        }

        $this->tokens->revokeAllForUser((int) $user->id, Auth::TOKEN_TYPE_SESSION);

        $this->user  = null;
        $this->token = null;

        Events::trigger(AuthEvents::LOGOUT, $user, self::NAME);
    }

    // ------------------------------------------------------------------

    private function resolve(): void
    {
        if ($this->resolved) {
            return;
        }

        $this->resolved = true;

        $plaintext = self::extractFromRequest($this->config, $this->request);

        if ($plaintext === null) {
            return;
        }

        $token = $this->tokens->validate($plaintext, $this->ipAddress());

        if ($token === null) {
            return;
        }

        $user = $this->users->find($token->user_id);

        if (! $user instanceof User || ! $user->isActive()) {
            return;
        }

        $this->user  = $user;
        $this->token = $token;
    }

    private function ipAddress(): string
    {
        return $this->request->getIPAddress();
    }

    private function userAgent(): ?string
    {
        return $this->request instanceof IncomingRequest
            ? $this->request->getUserAgent()->getAgentString()
            : null;
    }
}
