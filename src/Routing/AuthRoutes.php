<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Routing;

use CodeIgniter\Router\RouteCollection;
use Ephraitech\Auth\Config\Auth;
use Ephraitech\Auth\Exceptions\AuthException;

/**
 * Route definitions for the package's pages. Every route is named, so
 * links and redirects keep working under any prefix.
 *
 *   GET  login              auth.login          POST login              auth.login.attempt
 *   POST logout             auth.logout
 *   GET  register           auth.register       POST register           auth.register.store
 *   GET  forgot-password    auth.forgot         POST forgot-password    auth.forgot.send
 *   GET  reset-password     auth.reset          POST reset-password     auth.reset.update
 *   GET  verify             auth.verify         POST verify             auth.verify.confirm
 *   POST verify/resend      auth.verify.resend  GET  verify/link        auth.verify.link
 *   GET  account/password   auth.password       POST account/password   auth.password.update
 *   
 *   API (default prefix api/auth):
 *   POST login             api.auth.login
 *   POST logout            api.auth.logout            (auth:token)
 *   POST logout-all        api.auth.logout_all        (auth:token)
 *   GET  me                api.auth.me                (auth:token)
 *   POST register          api.auth.register
 *   POST password/forgot   api.auth.password.forgot
 *   POST password/reset    api.auth.password.reset
 *   POST password/change   api.auth.password.change   (auth:token)
 *   POST verify/send       api.auth.verify.send
 *   POST verify/confirm    api.auth.verify.confirm
 */
final class AuthRoutes
{
    public const WEB_GROUPS = ['login', 'logout', 'register', 'forgot', 'reset', 'verify', 'password'];

    private const CONTROLLERS = '\Ephraitech\Auth\Controllers\\';

    public const API_GROUPS = ['login', 'logout', 'me', 'register', 'password', 'change', 'verify'];

    private const API_CONTROLLERS = '\Ephraitech\Auth\Controllers\Api\\';

    /**
     * @param list<string> $except
     *
     * @throws AuthException
     */
    public static function web(RouteCollection $routes, Auth $config, array $except = [], string $prefix = ''): void
    {
        $unknown = array_diff($except, self::WEB_GROUPS);

        if ($unknown !== []) {
            throw new AuthException(
                'Unknown auth route group(s): ' . implode(', ', $unknown) . '. Use: ' . implode(', ', self::WEB_GROUPS) . '.'
            );
        }

        $skip = array_flip($except);

        if (! $config->allowRegistration) {
            $skip['register'] = true;
        }

        $c = self::CONTROLLERS;

        $define = static function (RouteCollection $r) use ($skip, $c): void {
            if (! isset($skip['login'])) {
                $r->get('login', $c . 'LoginController::show', ['as' => 'auth.login']);
                $r->post('login', $c . 'LoginController::attempt', ['as' => 'auth.login.attempt']);
            }

            if (! isset($skip['logout'])) {
                $r->post('logout', $c . 'LogoutController::logout', ['as' => 'auth.logout']);
            }

            if (! isset($skip['register'])) {
                $r->get('register', $c . 'RegisterController::show', ['as' => 'auth.register']);
                $r->post('register', $c . 'RegisterController::store', ['as' => 'auth.register.store']);
            }

            if (! isset($skip['forgot'])) {
                $r->get('forgot-password', $c . 'ForgotPasswordController::show', ['as' => 'auth.forgot']);
                $r->post('forgot-password', $c . 'ForgotPasswordController::send', ['as' => 'auth.forgot.send']);
            }

            if (! isset($skip['reset'])) {
                $r->get('reset-password', $c . 'ResetPasswordController::show', ['as' => 'auth.reset']);
                $r->post('reset-password', $c . 'ResetPasswordController::update', ['as' => 'auth.reset.update']);
            }

            if (! isset($skip['verify'])) {
                $r->get('verify', $c . 'VerifyController::show', ['as' => 'auth.verify']);
                $r->post('verify', $c . 'VerifyController::confirm', ['as' => 'auth.verify.confirm']);
                $r->post('verify/resend', $c . 'VerifyController::resend', ['as' => 'auth.verify.resend']);
                $r->get('verify/link', $c . 'VerifyController::link', ['as' => 'auth.verify.link']);
            }

            if (! isset($skip['password'])) {
                $r->get('account/password', $c . 'ChangePasswordController::show', [
                    'as'     => 'auth.password',
                    'filter' => 'auth:session',
                ]);
                $r->post('account/password', $c . 'ChangePasswordController::update', [
                    'as'     => 'auth.password.update',
                    'filter' => 'auth:session',
                ]);
            }
        };

        $prefix = trim($prefix, '/');

        if ($prefix === '') {
            $define($routes);

            return;
        }

        $routes->group($prefix, $define);
    }

    /**
     * @param list<string> $except
     *
     * @throws AuthException
     */
    public static function api(RouteCollection $routes, Auth $config, array $except = [], string $prefix = 'api/auth'): void
    {
        $unknown = array_diff($except, self::API_GROUPS);

        if ($unknown !== []) {
            throw new AuthException(
                'Unknown auth API route group(s): ' . implode(', ', $unknown) . '. Use: ' . implode(', ', self::API_GROUPS) . '.'
            );
        }

        $skip = array_flip($except);

        if (! $config->allowRegistration) {
            $skip['register'] = true;
        }

        $c = self::API_CONTROLLERS;

        $define = static function (RouteCollection $r) use ($skip, $c): void {
            $protected = static fn(string $name): array => ['as' => $name, 'filter' => 'auth:token'];

            if (! isset($skip['login'])) {
                $r->post('login', $c . 'AuthController::login', ['as' => 'api.auth.login']);
            }

            if (! isset($skip['logout'])) {
                $r->post('logout', $c . 'AuthController::logout', $protected('api.auth.logout'));
                $r->post('logout-all', $c . 'AuthController::logoutAll', $protected('api.auth.logout_all'));
            }

            if (! isset($skip['me'])) {
                $r->get('me', $c . 'AuthController::me', $protected('api.auth.me'));
            }

            if (! isset($skip['register'])) {
                $r->post('register', $c . 'RegisterController::register', ['as' => 'api.auth.register']);
            }

            if (! isset($skip['password'])) {
                $r->post('password/forgot', $c . 'PasswordController::forgot', ['as' => 'api.auth.password.forgot']);
                $r->post('password/reset', $c . 'PasswordController::reset', ['as' => 'api.auth.password.reset']);
            }

            if (! isset($skip['change'])) {
                $r->post('password/change', $c . 'PasswordController::change', $protected('api.auth.password.change'));
            }

            if (! isset($skip['verify'])) {
                $r->post('verify/send', $c . 'VerifyController::send', ['as' => 'api.auth.verify.send']);
                $r->post('verify/confirm', $c . 'VerifyController::confirm', ['as' => 'api.auth.verify.confirm']);
            }
        };

        $prefix = trim($prefix, '/');

        if ($prefix === '') {
            $define($routes);

            return;
        }

        $routes->group($prefix, $define);
    }
}
