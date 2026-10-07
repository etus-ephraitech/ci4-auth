<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Flows;

use Closure;
use CodeIgniter\Config\Factories;
use CodeIgniter\Events\Events;
use Ephraitech\Auth\AuthEvents;
use Ephraitech\Auth\Config\Auth;
use Ephraitech\Auth\Entities\Identity;
use Ephraitech\Auth\Entities\OneTimeCode;
use Ephraitech\Auth\Entities\User;
use Ephraitech\Auth\Exceptions\AuthException;
use Ephraitech\Auth\Exceptions\InvalidCodeException;
use Ephraitech\Auth\Exceptions\InvalidIdentifierException;
use Ephraitech\Auth\Exceptions\NotificationException;
use Ephraitech\Auth\Exceptions\ResendTooSoonException;
use Ephraitech\Auth\Models\IdentityModel;
use Ephraitech\Auth\Models\UserModel;
use Ephraitech\Auth\Notifications\NotifierRegistry;
use Ephraitech\Auth\Notifications\OneTimeCodeMessage;
use Ephraitech\Auth\OneTimeCodes\OneTimeCodeManager;

/**
 * Email/phone verification, shared by web and API.
 *
 * Sending requires knowing which user it is: either they're signed in, or
 * login just failed with IdentifierNotVerifiedException (only thrown after
 * a correct password, so revealing details to them is safe). Unlike
 * password reset, errors here are reported honestly to the caller.
 *
 * Confirming needs only the code: possessing it proves control of the
 * identifier, so no password is required.
 */
final class VerificationFlow
{
    public function __construct(
        private readonly Auth $config,
        private readonly UserModel $users,
        private readonly IdentityModel $identities,
        private readonly DeliveryTargetResolver $resolver,
        private readonly OneTimeCodeManager $codes,
        private readonly NotifierRegistry $notifiers,
    ) {}

    public static function create(?Auth $config = null): self
    {
        /** @var Auth $config */
        $config ??= config(Auth::class);

        /** @var UserModel $users */
        $users = Factories::models($config->userModel, ['preferApp' => false]);

        /** @var IdentityModel $identities */
        $identities = Factories::models(IdentityModel::class, ['preferApp' => false]);

        return new self(
            $config,
            $users,
            $identities,
            new DeliveryTargetResolver($config, $users, $identities),
            OneTimeCodeManager::create($config),
            new NotifierRegistry($config),
        );
    }

    /**
     * Send a verification code to one of the user's identifiers.
     *
     * @param Closure(string $selector, string $code): string|null $linkBuilder
     *        Builds the verification URL for email delivery (web).
     *
     * @throws ResendTooSoonException
     * @throws NotificationException
     * @throws AuthException          No such identifier, already verified, or not deliverable.
     */
    public function send(User $user, string $type, ?string $ipAddress = null, ?Closure $linkBuilder = null): void
    {
        $identity = $user->getIdentity($type);

        if ($identity === null) {
            throw new AuthException('This account has no ' . InvalidIdentifierException::label($type) . '.');
        }

        if ($identity->isVerified()) {
            throw new AuthException('This ' . InvalidIdentifierException::label($type) . ' is already verified.');
        }

        $channel = $this->codes->channelFor($type);

        if ($channel === null) {
            throw new AuthException('A ' . InvalidIdentifierException::label($type) . ' cannot receive codes.');
        }

        if (! $this->notifiers->supports($channel)) {
            throw NotificationException::channelDisabled($channel);
        }

        $issued = $this->codes->issue($user, $identity, OneTimeCode::PURPOSE_VERIFY_IDENTIFIER, $ipAddress);

        $link = $linkBuilder !== null && $issued->channel === OneTimeCode::CHANNEL_EMAIL
            ? $linkBuilder($issued->selector(), $issued->code)
            : null;

        try {
            $this->notifiers->send(OneTimeCodeMessage::fromIssued($user, $issued, $link, $this->config->appName));
        } catch (NotificationException $e) {
            $this->codes->consume($issued->record);

            throw $e;
        }
    }

    /**
     * Seconds before send() may be called again for this identifier
     * (for disabling a "resend" button with a countdown).
     */
    public function secondsUntilResend(User $user, string $type): int
    {
        $identity = $user->getIdentity($type);

        return $identity === null
            ? 0
            : $this->codes->secondsUntilResend($identity, OneTimeCode::PURPOSE_VERIFY_IDENTIFIER);
    }

    /**
     * The first identifier this user must verify before using the account,
     * if a code can actually be delivered to it; NULL when none.
     */
    public function requiredFor(User $user): ?string
    {
        foreach ([Auth::IDENTIFIER_EMAIL, Auth::IDENTIFIER_PHONE] as $type) {
            $identity = $user->getIdentity($type);
            $channel  = $this->codes->channelFor($type);

            if ($identity === null || $identity->isVerified() || $channel === null || ! $this->notifiers->supports($channel)) {
                continue;
            }

            if (
                $this->config->mustBeVerifiedToLogin($type)
                || ($user->isPending() && $this->config->activateOnVerification)
            ) {
                return $type;
            }
        }

        return null;
    }

    /**
     * Confirm for a known user (signed in, or pending after login).
     *
     * @throws InvalidCodeException
     */
    public function confirm(User $user, string $type, string $code): User
    {
        $identity = $user->getIdentity($type);

        if ($identity === null) {
            throw new InvalidCodeException();
        }

        return $this->checkAndComplete(
            $this->codes->latestFor($identity, OneTimeCode::PURPOSE_VERIFY_IDENTIFIER),
            $code
        );
    }

    /**
     * Confirm with the identifier plus the code (API clients that aren't
     * signed in yet). Unknown identifiers fail like wrong codes.
     *
     * @throws InvalidCodeException
     */
    public function confirmByIdentifier(string $login, string $code): User
    {
        $target = $this->resolver->forIdentifier($login);

        if ($target === null) {
            throw new InvalidCodeException();
        }

        return $this->checkAndComplete(
            $this->codes->latestFor($target[1], OneTimeCode::PURPOSE_VERIFY_IDENTIFIER),
            $code
        );
    }

    /**
     * Confirm from an emailed link.
     *
     * @throws InvalidCodeException
     */
    public function confirmWithLink(string $selector, string $code): User
    {
        return $this->checkAndComplete(
            $this->codes->findBySelector($selector, OneTimeCode::PURPOSE_VERIFY_IDENTIFIER),
            $code
        );
    }

    // ------------------------------------------------------------------

    /**
     * @throws InvalidCodeException
     */
    private function checkAndComplete(?OneTimeCode $record, string $code): User
    {
        if ($record === null || ! $this->codes->check($record, $code) || ! $this->codes->consume($record)) {
            throw new InvalidCodeException();
        }

        $identity = $this->identities->find($record->identity_id);
        $user     = $this->users->find($record->user_id);

        if (! $identity instanceof Identity || ! $user instanceof User) {
            throw new InvalidCodeException();
        }

        $userId = (int) $user->id;
        $type   = (string) $identity->type;

        $this->identities->markVerified($userId, $type);

        if ($this->config->activateOnVerification && $user->isPending()) {
            $this->users->setStatus($userId, 'active');
        }

        $fresh = $this->users->find($userId);

        if (! $fresh instanceof User) {
            throw new InvalidCodeException();
        }

        Events::trigger(AuthEvents::IDENTIFIER_VERIFIED, $fresh, $type);

        return $fresh;
    }

}
