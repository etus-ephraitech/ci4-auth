<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Authentication\Guards;

use CodeIgniter\Events\Events;
use CodeIgniter\HTTP\IncomingRequest;
use CodeIgniter\HTTP\RequestInterface;
use CodeIgniter\Session\SessionInterface;
use Ephraitech\Auth\AuthEvents;
use Ephraitech\Auth\Authentication\CredentialVerifier;
use Ephraitech\Auth\Config\Auth;
use Ephraitech\Auth\Entities\User;
use Ephraitech\Auth\Exceptions\AccountNotActiveException;
use Ephraitech\Auth\Exceptions\AuthException;
use Ephraitech\Auth\Models\IdentityModel;
use Ephraitech\Auth\Models\UserModel;

/**
 * Cookie-session authentication for server-rendered web apps.
 *
 * On every request the stored login is re-checked: the user must still
 * exist and be active, the idle timeout must not have passed, and the
 * password must not have changed since login. A password change or reset
 * therefore signs out every other browser.
 */
final class SessionGuard implements GuardInterface
{
    public const NAME = 'session';

    /**
     * Seconds between activity writes (session + last_active_at).
     */
    private const ACTIVITY_WRITE_INTERVAL = 60;

    private ?User $user = null;

    private bool $resolved = false;

    public function __construct(
        private readonly Auth $config,
        private readonly CredentialVerifier $verifier,
        private readonly UserModel $users,
        private readonly IdentityModel $identities,
        private readonly SessionInterface $session,
        private readonly RequestInterface $request,
    ) {}

    public function name(): string
    {
        return self::NAME;
    }

    /**
     * Verify credentials and sign the user in.
     *
     * @throws \Ephraitech\Auth\Exceptions\LockedOutException
     * @throws \Ephraitech\Auth\Exceptions\InvalidCredentialsException
     * @throws AccountNotActiveException
     * @throws \Ephraitech\Auth\Exceptions\IdentifierNotVerifiedException
     */
    public function attempt(string $login, string $password, ?string $type = null): User
    {
        $user = $this->verifier->verify($login, $password, $type, $this->ipAddress(), $this->userAgent());

        $this->login($user);

        return $user;
    }

    /**
     * Sign in an already-verified user (after OTP, magic link, registration).
     *
     * @throws AccountNotActiveException
     * @throws AuthException
     */
    public function login(User $user): void
    {
        if ($user->id === null) {
            throw new AuthException('Cannot log in an unsaved user.');
        }

        if (! $user->isActive()) {
            throw new AccountNotActiveException((string) $user->status, $user->status_reason);
        }

        if ($this->config->regenerateSessionOnLogin) {
            $this->session->regenerate(true);
        }

        $userId = (int) $user->id;
        $now    = time();

        $this->session->set($this->config->sessionKey, [
            'user_id'              => $userId,
            'login_at'             => $now,
            'last_activity'        => $now,
            'password_fingerprint' => $this->fingerprint($userId),
        ]);

        $this->users->touchLastLogin($userId);

        $this->user     = $user;
        $this->resolved = true;

        Events::trigger(AuthEvents::LOGIN, $user, self::NAME);
    }

    public function check(): bool
    {
        return $this->user() !== null;
    }

    public function user(): ?User
    {
        if ($this->resolved) {
            return $this->user;
        }

        $this->resolved = true;
        $this->user     = $this->resolveFromSession();

        return $this->user;
    }

    public function id(): ?int
    {
        return $this->user()?->id;
    }

    /**
     * Unix time of the current login, for "re-enter password after N
     * minutes" checks on sensitive pages.
     */
    public function loggedInAt(): ?int
    {
        if (! $this->check()) {
            return null;
        }

        $data = $this->session->get($this->config->sessionKey);

        return is_array($data) && isset($data['login_at']) ? (int) $data['login_at'] : null;
    }

    public function logout(): void
    {
        $user = $this->user();

        $this->clear();

        if ($this->config->regenerateSessionOnLogin) {
            $this->session->regenerate(true);
        }

        if ($user !== null) {
            Events::trigger(AuthEvents::LOGOUT, $user, self::NAME);
        }
    }

    /**
     * Re-stamp the current session after the user changed their own
     * password, so this browser stays signed in while every other session
     * (with the old fingerprint) is signed out. Regenerates the session ID.
     */
    public function refresh(): void
    {
        $user = $this->user();

        if ($user === null) {
            return;
        }

        $data = $this->session->get($this->config->sessionKey);

        if (! is_array($data)) {
            return;
        }

        $this->session->regenerate(true);

        $data['password_fingerprint'] = $this->fingerprint((int) $user->id);
        $data['last_activity']        = time();

        $this->session->set($this->config->sessionKey, $data);
    }

    // ------------------------------------------------------------------

    private function resolveFromSession(): ?User
    {
        $data = $this->session->get($this->config->sessionKey);

        if (! is_array($data) || empty($data['user_id'])) {
            return null;
        }

        $now     = time();
        $idle    = $this->config->sessionIdleTimeout;
        $lastHit = (int) ($data['last_activity'] ?? 0);

        if ($idle > 0 && $now - $lastHit > $idle) {
            $this->clear();

            return null;
        }

        $userId = (int) $data['user_id'];
        $user   = $this->users->find($userId);

        if (! $user instanceof User || ! $user->isActive()) {
            $this->clear();

            return null;
        }

        if (! hash_equals((string) ($data['password_fingerprint'] ?? ''), $this->fingerprint($userId))) {
            $this->clear();

            return null;
        }

        if ($now - $lastHit >= self::ACTIVITY_WRITE_INTERVAL) {
            $data['last_activity'] = $now;
            $this->session->set($this->config->sessionKey, $data);
            $this->users->touchLastActive($userId);
        }

        return $user;
    }

    /**
     * Changes whenever the password hash changes (including rehashes,
     * which only happen at login anyway).
     */
    private function fingerprint(int $userId): string
    {
        $secret = $this->identities->findPassword($userId)?->secret;

        return $secret === null ? '' : substr(hash('sha256', (string) $secret), 0, 32);
    }

    private function clear(): void
    {
        $this->session->remove($this->config->sessionKey);
        $this->user     = null;
        $this->resolved = true;
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
