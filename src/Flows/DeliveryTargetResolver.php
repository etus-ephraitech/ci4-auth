<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Flows;

use Ephraitech\Auth\Config\Auth;
use Ephraitech\Auth\Entities\Identity;
use Ephraitech\Auth\Entities\User;
use Ephraitech\Auth\Models\IdentityModel;
use Ephraitech\Auth\Models\UserModel;

/**
 * Turns what a person typed ("jane@x.com", "0772 123 456", "jane") into
 * the user and the identity a code should be delivered to.
 *
 * Unlike login detection, this considers every enabled identifier, not
 * only $loginIdentifiers: someone may sign in by username but reset by email.
 */
final class DeliveryTargetResolver
{
    private const MIN_PHONE_DIGITS = 7;

    public function __construct(
        private readonly Auth $config,
        private readonly UserModel $users,
        private readonly IdentityModel $identities,
    ) {}

    /**
     * Password reset: email, phone, or username. A username is delivered
     * to that user's email, falling back to their phone.
     *
     * @return array{0: User, 1: Identity}|null
     */
    public function forPasswordReset(string $login): ?array
    {
        $login = trim($login);

        if ($login === '') {
            return null;
        }

        $type = $this->detect($login);

        if ($type !== Auth::IDENTIFIER_USERNAME) {
            return $this->byIdentifier($type, $login);
        }

        $user = $this->users->findByIdentifier(Auth::IDENTIFIER_USERNAME, $login);

        if ($user === null) {
            return null;
        }

        foreach ([Auth::IDENTIFIER_EMAIL, Auth::IDENTIFIER_PHONE] as $deliverable) {
            $identity = $user->getIdentity($deliverable);

            if ($identity !== null) {
                return [$user, $identity];
            }
        }

        return null;
    }

    /**
     * Verification by identifier: email or phone only (a username can't
     * receive a code).
     *
     * @return array{0: User, 1: Identity}|null
     */
    public function forIdentifier(string $login): ?array
    {
        $login = trim($login);

        if ($login === '') {
            return null;
        }

        $type = $this->detect($login);

        return $type === Auth::IDENTIFIER_USERNAME ? null : $this->byIdentifier($type, $login);
    }

    // ------------------------------------------------------------------

    private function detect(string $login): string
    {
        if (str_contains($login, '@')) {
            return Auth::IDENTIFIER_EMAIL;
        }

        if (
            preg_match('/^\+?[\d\s\-().]+$/', $login) === 1
            && preg_match_all('/\d/', $login) >= self::MIN_PHONE_DIGITS
            && $this->config->isIdentifierEnabled(Auth::IDENTIFIER_PHONE)
        ) {
            return Auth::IDENTIFIER_PHONE;
        }

        return Auth::IDENTIFIER_USERNAME;
    }

    /**
     * @return array{0: User, 1: Identity}|null
     */
    private function byIdentifier(string $type, string $login): ?array
    {
        $identity = $this->identities->findByIdentifier($type, $login);

        if ($identity === null) {
            return null;
        }

        $user = $this->users->find($identity->user_id);

        return $user instanceof User ? [$user, $identity] : null;
    }
}
