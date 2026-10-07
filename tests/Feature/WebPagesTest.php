<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Tests\Feature;

use CodeIgniter\Test\FeatureTestTrait;
use CodeIgniter\Test\TestResponse;
use Config\Services;
use Ephraitech\Auth\Routing\AuthRoutes;
use Ephraitech\Auth\Tests\Support\AuthTestCase;
use Ephraitech\Auth\Tests\Support\CapturingNotifier;

final class WebPagesTest extends AuthTestCase
{
    use FeatureTestTrait;

    protected function setUp(): void
    {
        parent::setUp();

        $routes = service('routes');
        $routes->resetRoutes();
        AuthRoutes::web($routes, $this->authConfig);

        $this->routes = $routes;
    }

    /**
     * @param array<string, mixed> $params
     */
    private function page(string $method, string $path, array $params = []): TestResponse
    {
        Services::resetSingle('auth');

        return $method === 'get' ? $this->get($path, $params) : $this->post($path, $params);
    }

    public function testLoginPageRenders(): void
    {
        $response = $this->page('get', 'login');

        $response->assertStatus(200);
        $response->assertSee('Sign in');
        $response->assertSee('Forgot password?');
    }

    public function testSuccessfulLoginSignsInAndRedirects(): void
    {
        $this->createUser();

        $response = $this->page('post', 'login', ['login' => 'jane@example.com', 'password' => self::PASSWORD]);

        $response->assertRedirect();
        $response->assertSessionHas($this->authConfig->sessionKey);
    }

    public function testFailedLoginNeverPutsThePasswordInTheSession(): void
    {
        $this->createUser();

        $response = $this->page('post', 'login', ['login' => 'jane@example.com', 'password' => 'Wrong-Pass-1']);

        $response->assertRedirect();
        $response->assertSessionHas('error');
        $response->assertSessionHas('old', ['login' => 'jane@example.com']);
        $response->assertSessionMissing('_ci_old_input');
    }

    public function testRegistrationCreatesTheAccountAndSignsIn(): void
    {
        $response = $this->page('post', 'register', [
            'email'            => 'new@example.com',
            'password'         => self::PASSWORD,
            'password_confirm' => self::PASSWORD,
        ]);

        $response->assertRedirect();
        $response->assertSessionHas($this->authConfig->sessionKey);
        $this->seeInDatabase('auth_identities', ['identifier' => 'new@example.com']);
    }

    public function testRegistrationRejectsMismatchedPasswords(): void
    {
        $response = $this->page('post', 'register', [
            'email'            => 'new@example.com',
            'password'         => self::PASSWORD,
            'password_confirm' => 'Something-Else-1',
        ]);

        $response->assertRedirect();
        $response->assertSessionHas('errors');
        $this->dontSeeInDatabase('auth_identities', ['identifier' => 'new@example.com']);
    }

    public function testRegistrationNeedingVerificationGoesToTheVerifyPage(): void
    {
        $this->authConfig->requireVerifiedToLogin['email'] = true;

        $response = $this->page('post', 'register', [
            'email'            => 'new@example.com',
            'password'         => self::PASSWORD,
            'password_confirm' => self::PASSWORD,
        ]);

        $response->assertRedirectTo(url_to('auth.verify'));
        $response->assertSessionMissing($this->authConfig->sessionKey);
        $this->assertCount(1, CapturingNotifier::$messages);
    }

    public function testForgotPasswordGivesTheSameAnswerForUnknownAccounts(): void
    {
        $response = $this->page('post', 'forgot-password', ['login' => 'nobody@example.com']);

        $response->assertRedirectTo(url_to('auth.reset'));
        $response->assertSessionHas('message');
        $this->assertSame([], CapturingNotifier::$messages);
    }

    public function testExpiredResetLinkShowsTheExpiredPage(): void
    {
        $response = $this->page('get', 'reset-password', ['s' => str_repeat('a', 32), 'c' => '123456']);

        $response->assertStatus(200);
        $response->assertSee('This link has expired');
        $this->assertSame('no-referrer', $response->response()->getHeaderLine('Referrer-Policy'));
    }

    public function testChangePasswordRequiresSignIn(): void
    {
        $this->page('get', 'account/password')->assertRedirect();
    }
}
