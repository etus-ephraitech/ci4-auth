<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Support;

/**
 * Remembers the page a guest tried to open, so login can send them back.
 * Only same-site URLs are ever returned, preventing open redirects
 * (e.g. a crafted link bouncing users to a phishing site after login).
 */
final class IntendedUrl
{
    public const SESSION_KEY = 'ephraitech_auth_intended';

    public static function remember(string $url): void
    {
        if (self::isSafe($url)) {
            session()->set(self::SESSION_KEY, $url);
        }
    }

    /**
     * Return and forget the intended URL, or $default when none/unsafe.
     */
    public static function pull(string $default = '/'): string
    {
        $session = session();
        $url     = $session->get(self::SESSION_KEY);

        $session->remove(self::SESSION_KEY);

        return is_string($url) && $url !== '' && self::isSafe($url) ? $url : $default;
    }

    public static function forget(): void
    {
        session()->remove(self::SESSION_KEY);
    }

    private static function isSafe(string $url): bool
    {
        // Relative path, but not protocol-relative ("//evil.com") or "/\evil.com"
        if (str_starts_with($url, '/')) {
            return ! str_starts_with($url, '//') && ! str_starts_with($url, '/\\');
        }

        $target = parse_url($url);
        $site   = parse_url(base_url());

        if ($target === false || $site === false || ! isset($target['host'], $site['host'])) {
            return false;
        }

        return in_array(strtolower($target['scheme'] ?? ''), ['http', 'https'], true)
            && strcasecmp($target['host'], $site['host']) === 0;
    }
}
