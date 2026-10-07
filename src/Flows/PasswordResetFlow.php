<?php
    declare(strict_types=1);

    namespace Ephraitech\Auth\Flows;

    use Closure;
    use CodeIgniter\Config\Factories;
    use Ephraitech\Auth\Config\Auth;
    use Ephraitech\Auth\Entities\Identity;
    use Ephraitech\Auth\Entities\OneTimeCode;
    use Ephraitech\Auth\Entities\User;
    use Ephraitech\Auth\Exceptions\AuthException;
    use Ephraitech\Auth\Exceptions\InvalidCodeException;
    use Ephraitech\Auth\Exceptions\NotificationException;
    use Ephraitech\Auth\Exceptions\ResendTooSoonException;
    use Ephraitech\Auth\Exceptions\WeakPasswordException;
    use Ephraitech\Auth\Models\IdentityModel;
    use Ephraitech\Auth\Models\UserModel;
    use Ephraitech\Auth\Notifications\NotifierRegistry;
    use Ephraitech\Auth\Notifications\OneTimeCodeMessage;
    use Ephraitech\Auth\OneTimeCodes\OneTimeCodeManager;
    use Ephraitech\Auth\Passwords\PasswordChanger;
    use Ephraitech\Auth\Passwords\PasswordManager;

    /**
     * Forgot-password, shared by web and API.
     *
     *   1. request()        always behaves the same whether or not the
     *                        account exists; the caller shows a generic
     *                        "if an account matches, we've sent a code".
     *   2. resetWithLink()  email link (selector + code), or
     *      resetWithCode()  identifier + typed code (SMS or email).
     *
     * A successful reset revokes every token, signs out every browser
     * (PasswordChanger), invalidates all other reset codes, and marks the
     * identity that received the code as verified.
     */
    final class PasswordResetFlow
    {
        /**
         * Statuses allowed to reset. Suspended/inactive accounts get nothing,
         * silently, so the response never reveals their state.
         */
        private const RESETTABLE_STATUSES = ['active', 'pending'];

        public function __construct(
            private readonly Auth $config,
            private readonly UserModel $users,
            private readonly IdentityModel $identities,
            private readonly DeliveryTargetResolver $resolver,
            private readonly OneTimeCodeManager $codes,
            private readonly NotifierRegistry $notifiers,
            private readonly PasswordManager $passwords,
            private readonly PasswordChanger $changer,
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
                PasswordManager::create($config),
                PasswordChanger::create($config),
            );
        }

        /**
         * Send a reset code if the account exists and can receive one.
         *
         * Returns nothing on purpose: unknown accounts, suspended accounts,
         * resend cooldowns and delivery failures all look identical to the
         * caller. Failures are logged for the developer instead.
         *
         * @param Closure(string $selector, string $code): string|null $linkBuilder
         *        Builds the reset URL for email delivery (web). NULL sends the
         *        code only (API clients, SMS).
         */
        public function request(string $login, ?string $ipAddress = null, ?Closure $linkBuilder = null): void
        {
            $target = $this->resolver->forPasswordReset($login);

            if ($target === null) {
                return;
            }

            [$user, $identity] = $target;

            if (! in_array((string) $user->status, self::RESETTABLE_STATUSES, true)) {
                return;
            }

            $channel = $this->codes->channelFor((string) $identity->type);

            if ($channel === null || ! $this->notifiers->supports($channel)) {
                log_message('warning', 'Ephraitech Auth: password reset for user {id} skipped, no notifier for {type}.', [
                    'id'   => $user->id,
                    'type' => $identity->type,
                ]);

                return;
            }

            try {
                $issued = $this->codes->issue($user, $identity, OneTimeCode::PURPOSE_PASSWORD_RESET, $ipAddress);
            } catch (ResendTooSoonException) {
                return;
            }

            $link = $linkBuilder !== null && $issued->channel === OneTimeCode::CHANNEL_EMAIL
                ? $linkBuilder($issued->selector(), $issued->code)
                : null;

            try {
                $this->notifiers->send(OneTimeCodeMessage::fromIssued($user, $issued, $link, $this->config->appName));
            } catch (NotificationException $e) {
                $this->codes->consume($issued->record);

                log_message('error', 'Ephraitech Auth: password reset code for user {id} not delivered: {message}', [
                    'id'      => $user->id,
                    'message' => $e->getMessage(),
                ]);
            }
        }

        /**
         * Reset from an emailed link.
         *
         * @throws InvalidCodeException
         * @throws WeakPasswordException The code stays valid; the user can retry.
         * @throws AuthException
         */
        public function resetWithLink(string $selector, string $code, string $newPassword): User
        {
            $record = $this->codes->findBySelector($selector, OneTimeCode::PURPOSE_PASSWORD_RESET);

            if ($record === null || ! $this->codes->check($record, $code)) {
                throw new InvalidCodeException();
            }

            return $this->complete($record, $newPassword);
        }

        /**
         * Reset with the identifier the user entered plus the code they received.
         *
         * @throws InvalidCodeException
         * @throws WeakPasswordException The code stays valid; the user can retry.
         * @throws AuthException
         */
        public function resetWithCode(string $login, string $code, string $newPassword): User
        {
            $target = $this->resolver->forPasswordReset($login);

            if ($target === null) {
                throw new InvalidCodeException();
            }

            $record = $this->codes->latestFor($target[1], OneTimeCode::PURPOSE_PASSWORD_RESET);

            if ($record === null || ! $this->codes->check($record, $code)) {
                throw new InvalidCodeException();
            }

            return $this->complete($record, $newPassword);
        }

        /**
         * Whether a link is still usable, for showing the "choose a new
         * password" form or an "expired link" page before the user types.
         * Does not count as a guess.
         */
        public function linkIsUsable(string $selector): bool
        {
            $record = $this->codes->findBySelector($selector, OneTimeCode::PURPOSE_PASSWORD_RESET);

            return $record !== null && $record->isUsable($this->config->otpMaxAttempts);
        }

    // ------------------------------------------------------------------

        /**
         * Order matters:
         *   1. policy check first, so a weak password doesn't burn the code;
         *   2. consume atomically, so two simultaneous submissions can't both win;
         *   3. only then change the password.
         */
        private function complete(OneTimeCode $record, string $newPassword): User
        {
            $user = $this->users->find($record->user_id);

            if (! $user instanceof User || ! in_array((string) $user->status, self::RESETTABLE_STATUSES, true)) {
                throw new InvalidCodeException();
            }

            $userId = (int) $user->id;
            $errors = $this->passwords->check($userId, $newPassword);

            if ($errors !== []) {
                throw new WeakPasswordException($errors);
            }

            if (! $this->codes->consume($record)) {
                throw new InvalidCodeException();
            }

            $this->changer->reset($user, $newPassword);
            $this->codes->invalidateForUser($userId, OneTimeCode::PURPOSE_PASSWORD_RESET);

            $identity = $this->identities->find($record->identity_id);

            if ($identity instanceof Identity) {
                // Receiving the code proves the person controls this identifier.
                $this->identities->markVerified($userId, (string) $identity->type);
            }

            return $user->refreshIdentities();
        }
    }
