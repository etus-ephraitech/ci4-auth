<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Support;

use Ephraitech\Auth\Config\Auth;
use Ephraitech\Auth\Exceptions\InvalidIdentifierException;

/**
 * Converts raw identifier input into the canonical form stored in
 * auth_identities, and validates it against the configuration.
 *
 * Normalization is idempotent: normalizing an already-normalized value
 * returns it unchanged, so it is safe to apply on every read and write.
 *
 *   email    => trimmed, lowercased, RFC-validated
 *   username => trimmed, lowercased, length/pattern/reserved checked
 *   phone    => E.164 ("+256772123456"), local formats expanded using
 *               $phoneDefaultCountryCode
 */
final class IdentifierNormalizer
{
    private const PHONE_INPUT_PATTERN = '/^\+?[\d\s\-().]+$/';

    /**
     * A number this long after stripping a leading default country code
     * is treated as already international (e.g. "256772123456").
     */
    private const MIN_NATIONAL_DIGITS = 7;

    public function __construct(private readonly Auth $config) {}

    /**
     * @throws InvalidIdentifierException
     */
    public function normalize(string $type, string $value): string
    {
        if (! in_array($type, Auth::SUPPORTED_IDENTIFIERS, true)) {
            throw InvalidIdentifierException::unsupportedType($type);
        }

        if (! $this->config->isIdentifierEnabled($type)) {
            throw InvalidIdentifierException::notEnabled($type);
        }

        return match ($type) {
            Auth::IDENTIFIER_EMAIL    => $this->normalizeEmail($value),
            Auth::IDENTIFIER_USERNAME => $this->normalizeUsername($value),
            Auth::IDENTIFIER_PHONE    => $this->normalizePhone($value),
        };
    }

    /**
     * Normalize without throwing; returns NULL when the value is invalid.
     * Intended for lookups, where invalid input simply means "not found".
     */
    public function tryNormalize(string $type, string $value): ?string
    {
        try {
            return $this->normalize($type, $value);
        } catch (InvalidIdentifierException) {
            return null;
        }
    }

    /**
     * Determine which login identifier type a single "login" input refers to,
     * considering only the types enabled in $loginIdentifiers.
     *
     *   contains "@"                       => email
     *   digits/phone punctuation, 7+ digits => phone
     *   anything else                      => username
     *
     * @throws InvalidIdentifierException
     */
    public function detectLoginType(string $value): string
    {
        $value = trim($value);
        $login = $this->config->loginIdentifiers;

        if ($value === '') {
            throw InvalidIdentifierException::undetectable();
        }

        if (count($login) === 1) {
            return $login[0];
        }

        $emailEnabled    = in_array(Auth::IDENTIFIER_EMAIL, $login, true);
        $phoneEnabled    = in_array(Auth::IDENTIFIER_PHONE, $login, true);
        $usernameEnabled = in_array(Auth::IDENTIFIER_USERNAME, $login, true);

        if (str_contains($value, '@')) {
            if ($emailEnabled) {
                return Auth::IDENTIFIER_EMAIL;
            }

            throw InvalidIdentifierException::undetectable();
        }

        $phoneLike = preg_match(self::PHONE_INPUT_PATTERN, $value) === 1;

        if ($phoneLike && $phoneEnabled) {
            $digitCount = preg_match_all('/\d/', $value);

            if ($digitCount >= self::MIN_NATIONAL_DIGITS || ! $usernameEnabled) {
                return Auth::IDENTIFIER_PHONE;
            }
        }

        if ($usernameEnabled) {
            return Auth::IDENTIFIER_USERNAME;
        }

        throw InvalidIdentifierException::undetectable();
    }

    // ------------------------------------------------------------------

    private function normalizeEmail(string $value): string
    {
        $type  = Auth::IDENTIFIER_EMAIL;
        $email = mb_strtolower(trim($value), 'UTF-8');

        if ($email === '') {
            throw InvalidIdentifierException::empty($type);
        }

        if (strlen($email) > $this->config->emailMaxLength) {
            throw InvalidIdentifierException::invalid(
                $type,
                "cannot be longer than {$this->config->emailMaxLength} characters"
            );
        }

        if (filter_var($email, FILTER_VALIDATE_EMAIL, FILTER_FLAG_EMAIL_UNICODE) === false) {
            throw InvalidIdentifierException::invalid($type, 'is not valid');
        }

        return $email;
    }

    private function normalizeUsername(string $value): string
    {
        $type     = Auth::IDENTIFIER_USERNAME;
        $username = mb_strtolower(trim($value), 'UTF-8');

        if ($username === '') {
            throw InvalidIdentifierException::empty($type);
        }

        $length = mb_strlen($username, 'UTF-8');
        $min    = $this->config->usernameMinLength;
        $max    = $this->config->usernameMaxLength;

        if ($length < $min || $length > $max) {
            throw InvalidIdentifierException::invalid($type, "must be between {$min} and {$max} characters");
        }

        if (preg_match($this->config->usernamePattern, $username) !== 1) {
            throw InvalidIdentifierException::invalid(
                $type,
                'may contain only letters, numbers, dots, underscores and hyphens, '
                    . 'and must start and end with a letter or number'
            );
        }

        $reserved = array_map(
            static fn(string $name): string => mb_strtolower($name, 'UTF-8'),
            $this->config->reservedUsernames
        );

        if (in_array($username, $reserved, true)) {
            throw InvalidIdentifierException::reserved($type);
        }

        return $username;
    }

    private function normalizePhone(string $value): string
    {
        $type = Auth::IDENTIFIER_PHONE;
        $raw  = trim($value);

        if ($raw === '') {
            throw InvalidIdentifierException::empty($type);
        }

        if (preg_match(self::PHONE_INPUT_PATTERN, $raw) !== 1) {
            throw InvalidIdentifierException::invalid(
                $type,
                'may contain only digits, spaces, dashes, parentheses and a leading +'
            );
        }

        $hasPlus     = str_starts_with($raw, '+');
        $digits      = preg_replace('/\D/', '', $raw) ?? '';
        $countryCode = $this->config->phoneDefaultCountryCode;

        if ($digits === '') {
            throw InvalidIdentifierException::empty($type);
        }

        if (! $hasPlus) {
            if (str_starts_with($digits, '00')) {
                // International dialling prefix: 00256772123456
                $digits = substr($digits, 2);
            } elseif (str_starts_with($digits, '0')) {
                // National trunk prefix: 0772123456
                $digits = $countryCode . substr($digits, 1);
            } elseif (
                ! str_starts_with($digits, $countryCode)
                || strlen($digits) - strlen($countryCode) < self::MIN_NATIONAL_DIGITS
            ) {
                // National number without trunk prefix: 772123456
                $digits = $countryCode . $digits;
            }
        }

        $length = strlen($digits);
        $min    = $this->config->phoneMinDigits;
        $max    = $this->config->phoneMaxDigits;

        if ($length < $min || $length > $max) {
            throw InvalidIdentifierException::invalid(
                $type,
                "must have between {$min} and {$max} digits including the country code"
            );
        }

        if ($digits[0] === '0') {
            throw InvalidIdentifierException::invalid($type, 'has an invalid country code');
        }

        return '+' . $digits;
    }
}
