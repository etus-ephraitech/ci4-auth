<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Tests\Feature;

use CodeIgniter\Test\FeatureTestTrait;
use CodeIgniter\Test\TestResponse;
use Config\Services;
use Ephraitech\Auth\Routing\AuthRoutes;
use Ephraitech\Auth\Tests\Support\AuthTestCase;
use Ephraitech\Auth\Tests\Support\CapturingNotifier;

final class ApiEndpointsTest extends AuthTestCase
{
    use FeatureTestTrait;

    protected function setUp(): void
    {
        parent::setUp();

        $routes = service('routes');
        $routes->resetRoutes();
        AuthRoutes::api($routes, $this->authConfig);

        $this->routes = $routes;
    }

    /**
     * @param array<string, mixed> $body
     */
    private function api(string $method, string $path, array $body = [], ?string $token = null): TestResponse
    {
        Services::resetSingle('auth');

        $headers = ['Accept' => 'application/json'];

        if ($token !== null) {
            $headers['Authorization'] = 'Bearer ' . $token;
        }

        $request = $this->withHeaders($headers)->withBodyFormat('json');

        return $method === 'get' ? $request->get($path) : $request->post($path, $body);
    }

    /**
     * @return array<string, mixed>
     */
    private function json(TestResponse $response): array
    {
        return json_decode((string) $response->response()->getBody(), true) ?? [];
    }

    private function loginToken(): string
    {
        $json = $this->json($this->api('post', 'api/auth/login', [
            'login'    => 'jane@example.com',
            'password' => self::PASSWORD,
        ]));

        return (string) $json['data']['token']['token'];
    }

    // ------------------------------------------------------------------
    // Login, me, logout
    // ------------------------------------------------------------------

    public function testLoginReturnsATokenAndTheUser(): void
    {
        $this->createUser();

        $response = $this->api('post', 'api/auth/login', [
            'login'       => 'jane@example.com',
            'password'    => self::PASSWORD,
            'device_name' => 'Tecno Spark 20',
        ]);

        $response->assertStatus(200);
        $json = $this->json($response);

        $this->assertStringStartsWith('eph_', $json['data']['token']['token']);
        $this->assertSame('Bearer', $json['data']['token']['token_type']);
        $this->assertSame('jane@example.com', $json['data']['user']['identifiers']['email']['value']);
    }

    public function testLoginAcceptsAPhoneNumberSentAsAJsonNumber(): void
    {
        $this->enablePhone();
        $this->createUserWithPhone();

        $this->api('post', 'api/auth/login', [
            'login'    => 772123456,
            'password' => self::PASSWORD,
        ])->assertStatus(200);
    }

    public function testWrongPasswordIs401(): void
    {
        $this->createUser();

        $response = $this->api('post', 'api/auth/login', ['login' => 'jane@example.com', 'password' => 'Wrong-Pass-1']);

        $response->assertStatus(401);
        $this->assertSame('invalid_credentials', $this->json($response)['error']);
    }

    public function testMissingFieldsAre422WithFieldErrors(): void
    {
        $response = $this->api('post', 'api/auth/login', []);

        $response->assertStatus(422);
        $json = $this->json($response);

        $this->assertSame('validation_failed', $json['error']);
        $this->assertArrayHasKey('login', $json['errors']);
        $this->assertArrayHasKey('password', $json['errors']);
    }

    public function testLockoutIs429WithRetryAfter(): void
    {
        $this->authConfig->maxLoginAttempts = 2;
        $this->createUser();

        $this->api('post', 'api/auth/login', ['login' => 'jane@example.com', 'password' => 'Wrong-Pass-1']);
        $this->api('post', 'api/auth/login', ['login' => 'jane@example.com', 'password' => 'Wrong-Pass-1']);

        $response = $this->api('post', 'api/auth/login', ['login' => 'jane@example.com', 'password' => self::PASSWORD]);

        $response->assertStatus(429);
        $this->assertSame('locked_out', $this->json($response)['error']);
        $this->assertNotSame('', $response->response()->getHeaderLine('Retry-After'));
    }

    public function testVerificationRequiredThenConfirmThenLogin(): void
    {
        $this->authConfig->requireVerifiedToLogin['email'] = true;
        $this->createUser();

        $blocked = $this->api('post', 'api/auth/login', ['login' => 'jane@example.com', 'password' => self::PASSWORD]);

        $blocked->assertStatus(403);
        $json = $this->json($blocked);
        $this->assertSame('verification_required', $json['error']);
        $this->assertSame('email', $json['identifier_type']);
        $this->assertTrue($json['code_sent']);
        $this->assertStringNotContainsString('jane@', (string) $json['destination'], 'destination must be masked');

        $this->api('post', 'api/auth/verify/confirm', [
            'login' => 'jane@example.com',
            'code'  => CapturingNotifier::last()->code,
        ])->assertStatus(200);

        $this->api('post', 'api/auth/login', ['login' => 'jane@example.com', 'password' => self::PASSWORD])
            ->assertStatus(200);
    }

    public function testMeRequiresATokenAndReturnsTheUser(): void
    {
        $user = $this->createUser();

        $this->api('get', 'api/auth/me')->assertStatus(401);

        $response = $this->api('get', 'api/auth/me', [], $this->loginToken());

        $response->assertStatus(200);
        $this->assertSame($user->uuid, $this->json($response)['data']['user']['uuid']);
    }

    public function testLogoutRevokesTheToken(): void
    {
        $this->createUser();
        $token = $this->loginToken();

        $this->api('post', 'api/auth/logout', [], $token)->assertStatus(200);
        $this->api('get', 'api/auth/me', [], $token)->assertStatus(401);
    }

    // ------------------------------------------------------------------
    // Registration
    // ------------------------------------------------------------------

    public function testRegisterReturns201WithAToken(): void
    {
        $response = $this->api('post', 'api/auth/register', [
            'email'    => 'new@example.com',
            'password' => self::PASSWORD,
        ]);

        $response->assertStatus(201);
        $this->assertStringStartsWith('eph_', $this->json($response)['data']['token']['token']);
    }

    public function testRegisterValidationErrorsAre422(): void
    {
        $response = $this->api('post', 'api/auth/register', ['email' => 'not-an-email', 'password' => self::PASSWORD]);

        $response->assertStatus(422);
        $this->assertArrayHasKey('email', $this->json($response)['errors']);
    }

    public function testRegisterIs404WhenDisabled(): void
    {
        $this->authConfig->allowRegistration = false;

        $this->api('post', 'api/auth/register', ['email' => 'new@example.com', 'password' => self::PASSWORD])
            ->assertStatus(404);
    }

    // ------------------------------------------------------------------
    // Passwords
    // ------------------------------------------------------------------

    public function testForgotAlwaysReturns202(): void
    {
        $this->createUser();

        $this->api('post', 'api/auth/password/forgot', ['login' => 'nobody@example.com'])->assertStatus(202);
        $this->assertSame([], CapturingNotifier::$messages);

        $this->api('post', 'api/auth/password/forgot', ['login' => 'jane@example.com'])->assertStatus(202);
        $this->assertCount(1, CapturingNotifier::$messages);
    }

    public function testResetWithCodeThenLoginWithTheNewPassword(): void
    {
        $this->createUser();

        $this->api('post', 'api/auth/password/forgot', ['login' => 'jane@example.com']);

        $this->api('post', 'api/auth/password/reset', [
            'login'    => 'jane@example.com',
            'code'     => CapturingNotifier::last()->code,
            'password' => 'Brand-New-Pass-99',
        ])->assertStatus(200);

        $this->api('post', 'api/auth/login', ['login' => 'jane@example.com', 'password' => 'Brand-New-Pass-99'])
            ->assertStatus(200);
    }

    public function testInvalidResetCodeIs422(): void
    {
        $this->createUser();

        $response = $this->api('post', 'api/auth/password/reset', [
            'login'    => 'jane@example.com',
            'code'     => '123456',
            'password' => 'Brand-New-Pass-99',
        ]);

        $response->assertStatus(422);
        $this->assertSame('invalid_code', $this->json($response)['error']);
    }

    public function testChangePasswordKeepsTheCurrentTokenAndRevokesOthers(): void
    {
        $this->createUser();
        $other   = $this->loginToken();
        $current = $this->loginToken();

        $this->api('post', 'api/auth/password/change', [
            'current_password' => self::PASSWORD,
            'password'         => 'Brand-New-Pass-99',
        ], $current)->assertStatus(200);

        $this->api('get', 'api/auth/me', [], $current)->assertStatus(200);
        $this->api('get', 'api/auth/me', [], $other)->assertStatus(401);
    }
}
