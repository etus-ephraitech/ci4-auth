<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Passwords;

use Ephraitech\Auth\Config\Auth;
use Ephraitech\Auth\Exceptions\WeakPasswordException;

/**
 * Validates passwords against the rules in Config\Auth.
 */
final class PasswordPolicy
{
    /**
     * Identifier fragments shorter than this are not checked, to avoid
     * rejecting passwords for containing e.g. a 2-letter username.
     */
    private const MIN_FRAGMENT_LENGTH = 4;

    public function __construct(private readonly Auth $config) {}

    /**
     * Throw when the password breaks any rule.
     *
     * @param array<string, string|null> $identifiers type => value, e.g.
     *                                                ['email' => 'jane@x.com', 'phone' => '+256772123456']
     *
     * @throws WeakPasswordException
     */
    public function assert(string $password, array $identifiers = []): void
    {
        $errors = $this->errors($password, $identifiers);

        if ($errors !== []) {
            throw new WeakPasswordException($errors);
        }
    }

    /**
     * @param array<string, string|null> $identifiers
     *
     * @return list<string> Human-readable reasons; empty when acceptable.
     */
    public function errors(string $password, array $identifiers = []): array
    {
        if (str_contains($password, "\0")) {
            return ['The password contains an invalid character.'];
        }

        if (! mb_check_encoding($password, 'UTF-8')) {
            return ['The password contains invalid characters.'];
        }

        $errors = [];
        $min    = $this->config->passwordMinLength;
        $max    = $this->config->passwordMaxLength;

        if (mb_strlen($password, 'UTF-8') < $min) {
            $errors[] = "The password must be at least {$min} characters long.";
        }

        if ($this->usesBcrypt()) {
            if (strlen($password) > $max) {
                $errors[] = "The password cannot be longer than {$max} bytes "
                    . '(accented letters and emoji count as more than one).';
            }
        } elseif (mb_strlen($password, 'UTF-8') > $max) {
            $errors[] = "The password cannot be longer than {$max} characters.";
        }

        if ($this->config->passwordRequireUppercase && preg_match('/\p{Lu}/u', $password) !== 1) {
            $errors[] = 'The password must contain at least one uppercase letter.';
        }

        if ($this->config->passwordRequireLowercase && preg_match('/\p{Ll}/u', $password) !== 1) {
            $errors[] = 'The password must contain at least one lowercase letter.';
        }

        if ($this->config->passwordRequireNumber && preg_match('/\p{N}/u', $password) !== 1) {
            $errors[] = 'The password must contain at least one number.';
        }

        if ($this->config->passwordRequireSymbol && preg_match('/[^\p{L}\p{N}\s]/u', $password) !== 1) {
            $errors[] = 'The password must contain at least one symbol.';
        }

        if ($this->config->passwordDisallowIdentifiers) {
            $errors = array_merge($errors, $this->identifierErrors($password, $identifiers));
        }

        return $errors;
    }

    /**
     * Requirements in plain language, for showing beside password fields.
     *
     * @return list<string>
     */
    public function describe(): array
    {
        $rules = ["At least {$this->config->passwordMinLength} characters"];

        if ($this->config->passwordRequireUppercase) {
            $rules[] = 'An uppercase letter';
        }

        if ($this->config->passwordRequireLowercase) {
            $rules[] = 'A lowercase letter';
        }

        if ($this->config->passwordRequireNumber) {
            $rules[] = 'A number';
        }

        if ($this->config->passwordRequireSymbol) {
            $rules[] = 'A symbol';
        }

        if ($this->config->passwordDisallowIdentifiers) {
            $rules[] = 'Must not contain your username, email or phone number';
        }

        return $rules;
    }

    // ------------------------------------------------------------------

    /**
     * @param array<string, string|null> $identifiers
     *
     * @return list<string>
     */
    private function identifierErrors(string $password, array $identifiers): array
    {
        $haystack = mb_strtolower($password, 'UTF-8');
        $errors   = [];

        foreach ($identifiers as $type => $value) {
            if ($value === null || $value === '') {
                continue;
            }

            foreach ($this->fragmentsFor((string) $type, $value) as $fragment) {
                if (
                    mb_strlen($fragment, 'UTF-8') >= self::MIN_FRAGMENT_LENGTH
                    && str_contains($haystack, $fragment)
                ) {
                    $errors[] = match ($type) {
                        Auth::IDENTIFIER_EMAIL    => 'The password cannot contain your email address.',
                        Auth::IDENTIFIER_USERNAME => 'The password cannot contain your username.',
                        Auth::IDENTIFIER_PHONE    => 'The password cannot contain your phone number.',
                        default                   => 'The password cannot contain your personal identifiers.',
                    };

                    break;
                }
            }
        }

        return array_values(array_unique($errors));
    }

    /**
     * Lowercased substrings of an identifier that a password must not contain.
     *
     * @return list<string>
     */
    private function fragmentsFor(string $type, string $value): array
    {
        $value = mb_strtolower(trim($value), 'UTF-8');

        switch ($type) {
            case Auth::IDENTIFIER_EMAIL:
                $at = strrpos($value, '@');

                return $at === false ? [$value] : [substr($value, 0, $at)];

            case Auth::IDENTIFIER_PHONE:
                $digits = preg_replace('/\D/', '', $value) ?? '';
                $code   = $this->config->phoneDefaultCountryCode;

                $fragments = [$digits];

                if (str_starts_with($digits, $code)) {
                    // National significant number: 772123456 also catches 0772123456
                    $fragments[] = substr($digits, strlen($code));
                }

                return $fragments;

            default:
                return [$value];
        }
    }

    private function usesBcrypt(): bool
    {
        return in_array($this->config->hashAlgorithm, [PASSWORD_BCRYPT, PASSWORD_DEFAULT], true);
    }
}
