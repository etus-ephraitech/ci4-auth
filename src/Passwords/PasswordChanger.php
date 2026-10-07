<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Passwords;

use CodeIgniter\Config\Factories;
use CodeIgniter\Database\BaseConnection;
use CodeIgniter\Events\Events;
use Config\Database;
use Ephraitech\Auth\AuthEvents;
use Ephraitech\Auth\Config\Auth;
use Ephraitech\Auth\Entities\User;
use Ephraitech\Auth\Exceptions\AuthException;
use Ephraitech\Auth\Exceptions\InvalidCredentialsException;
use Ephraitech\Auth\Exceptions\WeakPasswordException;
use Ephraitech\Auth\Models\UserModel;
use Ephraitech\Auth\Tokens\TokenManager;
use Throwable;

/**
 * Changing or resetting a password ends every existing token, so a
 * stolen device or leaked key loses access immediately. Web sessions
 * are invalidated by the session guard (Step 9), which detects that the
 * password changed since the session began.
 */
final class PasswordChanger
{
    private BaseConnection $db;

    public function __construct(
        private readonly Auth $config,
        private readonly UserModel $users,
        private readonly PasswordManager $passwords,
        private readonly TokenManager $tokens,
    ) {
        $this->db = Database::connect($config->DBGroup);
    }

    public static function create(?Auth $config = null): self
    {
        /** @var Auth $config */
        $config ??= config(Auth::class);

        /** @var UserModel $users */
        $users = Factories::models($config->userModel, ['preferApp' => false]);

        return new self($config, $users, PasswordManager::create($config), TokenManager::create($config));
    }

    /**
     * User-initiated change: requires the current password.
     *
     * @param int|null $keepTokenId Token of the device making the change,
     *                              so it stays signed in. NULL revokes all.
     *
     * @throws InvalidCredentialsException
     * @throws WeakPasswordException
     * @throws AuthException
     */
    public function change(User|int $user, string $currentPassword, string $newPassword, ?int $keepTokenId = null): void
    {
        $entity = $this->resolveUser($user);
        $userId = (int) $entity->id;

        if (! $this->passwords->verify($userId, $currentPassword)) {
            throw new InvalidCredentialsException('The current password is incorrect.');
        }

        if (hash_equals($currentPassword, $newPassword)) {
            throw new WeakPasswordException(['The new password must be different from the current password.']);
        }

        $this->apply($entity, $newPassword, $keepTokenId);
    }

    /**
     * Reset without the current password: forgot-password flows (after the
     * host verifies the reset code/link) and admin resets. Revokes all tokens.
     *
     * @throws WeakPasswordException
     * @throws AuthException
     */
    public function reset(User|int $user, string $newPassword): void
    {
        $this->apply($this->resolveUser($user), $newPassword, null);
    }

    private function apply(User $user, string $newPassword, ?int $keepTokenId): void
    {
        $userId = (int) $user->id;
        $errors = $this->passwords->check($userId, $newPassword);

        if ($errors !== []) {
            throw new WeakPasswordException($errors);
        }

        $this->db->transBegin();

        try {
            $this->passwords->setPassword($userId, $newPassword, false);

            $revoked = $this->tokens->revokeAllForUser($userId, null, $keepTokenId, false);

            if ($this->db->transStatus() === false) {
                throw new AuthException('Database transaction failed while changing the password.');
            }

            $this->db->transCommit();
        } catch (Throwable $e) {
            $this->db->transRollback();

            throw $e;
        }

        if ($revoked !== []) {
            Events::trigger(AuthEvents::TOKENS_REVOKED, $userId, $revoked);
        }

        Events::trigger(AuthEvents::PASSWORD_CHANGED, $user);
    }

    /**
     * @throws AuthException
     */
    private function resolveUser(User|int $user): User
    {
        if ($user instanceof User) {
            if ($user->id === null) {
                throw new AuthException('A saved user is required.');
            }

            return $user;
        }

        $entity = $this->users->find($user);

        if (! $entity instanceof User) {
            throw new AuthException("User {$user} not found.");
        }

        return $entity;
    }
}
