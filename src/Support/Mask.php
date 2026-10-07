<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Support;

use Ephraitech\Auth\Config\Auth;

/**
 * Partially hides identifiers for display: "j•••@example.com", "+2567•••••456".
 * Enough for the owner to recognise, not enough to harvest.
 */
final class Mask
{
    public static function identifier(string $type, string $value): string
    {
        if ($type === Auth::IDENTIFIER_EMAIL) {
            $at = strrpos($value, '@');

            if ($at === false || $at === 0) {
                return $value;
            }

            $local = substr($value, 0, $at);

            return mb_substr($local, 0, 1, 'UTF-8')
                . str_repeat('•', max(3, mb_strlen($local, 'UTF-8') - 1))
                . substr($value, $at);
        }

        if ($type === Auth::IDENTIFIER_PHONE) {
            $length = strlen($value);

            if ($length <= 8) {
                return $value;
            }

            return substr($value, 0, 5) . str_repeat('•', $length - 8) . substr($value, -3);
        }

        return $value;
    }
}
