<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Authorization;

/**
 * Pattern matching for permission grants and token abilities.
 *
 *   '*'          matches everything
 *   'users.*'    matches 'users.view', 'users.create', 'users.roles.assign'
 *   'users.view' matches only itself
 */
final class PermissionMatcher
{
    public static function matches(string $pattern, string $permission): bool
    {
        if ($pattern === '*' || $pattern === $permission) {
            return true;
        }

        if (str_ends_with($pattern, '.*')) {
            return str_starts_with($permission, substr($pattern, 0, -1));
        }

        return false;
    }

    /**
     * @param list<string> $patterns
     */
    public static function anyMatches(array $patterns, string $permission): bool
    {
        foreach ($patterns as $pattern) {
            if (self::matches((string) $pattern, $permission)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Expand patterns into the concrete permission names they cover.
     *
     * @param list<string> $patterns
     * @param list<string> $known
     *
     * @return list<string>
     */
    public static function expand(array $patterns, array $known): array
    {
        $result = [];

        foreach ($known as $permission) {
            if (self::anyMatches($patterns, $permission)) {
                $result[$permission] = true;
            }
        }

        $names = array_keys($result);
        sort($names);

        return $names;
    }
}
