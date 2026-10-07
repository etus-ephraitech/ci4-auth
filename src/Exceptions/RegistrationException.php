<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Exceptions;

/**
 * Registration failed validation. Errors are keyed by form field
 * ('email', 'username', 'phone', 'password', or a profile column), so
 * controllers can map them straight back onto the form.
 */
final class RegistrationException extends AuthException
{
    /**
     * @param array<string, list<string>> $errors
     */
    public function __construct(private readonly array $errors)
    {
        $first = '';

        foreach ($errors as $messages) {
            if ($messages !== []) {
                $first = $messages[0];
                break;
            }
        }

        parent::__construct($first !== '' ? $first : 'Registration failed.');
    }

    /**
     * @return array<string, list<string>>
     */
    public function getErrors(): array
    {
        return $this->errors;
    }

    /**
     * First message per field, convenient for CI4 form helpers
     * and validation_show_error()-style views.
     *
     * @return array<string, string>
     */
    public function getFirstErrors(): array
    {
        $first = [];

        foreach ($this->errors as $field => $messages) {
            if ($messages !== []) {
                $first[$field] = $messages[0];
            }
        }

        return $first;
    }

    /**
     * @return list<string>
     */
    public function getFlatErrors(): array
    {
        return array_merge(...array_values($this->errors));
    }
}
