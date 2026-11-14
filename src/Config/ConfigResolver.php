<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Config;

/**
 * Returns the auth config the host application actually defines.
 *
 * Since CodeIgniter 4.4, config(\Ephraitech\Auth\Config\Auth::class) returns
 * exactly that class: a fully qualified name skips the app's Config\Auth.
 * A project's roles, permissions and user columns were silently ignored.
 *
 * Every package class therefore asks this resolver instead. It returns the
 * app's Config\Auth when that class exists and extends the package config,
 * and the package defaults otherwise.
 */
final class ConfigResolver
{
    /**
     * The class host applications create in app/Config/Auth.php.
     */
    public const APP_CLASS = 'Config\Auth';

    /**
     * Replacement for APP_CLASS, used only by the package's own tests.
     */
    private static ?string $appClassOverride = null;

    /**
     * The shared config instance: the app's Config\Auth, or the package defaults.
     */
    public static function resolve(): Auth
    {
        /** @var Auth $config */
        $config = config(self::resolvedClass());

        return $config;
    }

    /**
     * Which class resolve() returns.
     *
     * @return class-string<Auth>
     */
    public static function resolvedClass(): string
    {
        $candidate = self::appClass();

        if (class_exists($candidate) && is_subclass_of($candidate, Auth::class)) {
            return $candidate;
        }

        return Auth::class;
    }

    /**
     * Why the app's config class was ignored, or NULL when it is used or
     * doesn't exist. Typical cause: an app/Config/Auth.php left over from
     * another auth library, which does not extend this package's config.
     */
    public static function ignoredAppClassReason(): ?string
    {
        $candidate = self::appClass();

        if (! class_exists($candidate) || is_subclass_of($candidate, Auth::class)) {
            return null;
        }

        return "{$candidate} exists but does not extend " . Auth::class
            . ', so Ephraitech Auth ignores it and uses its own defaults. '
            . 'Make it extend ' . Auth::class . ' (run "php spark auth:publish --force" to recreate it).';
    }

    /**
     * Point the resolver at another class. Package tests only.
     *
     * @internal
     */
    public static function useAppClass(?string $class): void
    {
        self::$appClassOverride = $class;
    }

    private static function appClass(): string
    {
        return self::$appClassOverride ?? self::APP_CLASS;
    }
}
