<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Tests\Support;

use CodeIgniter\HTTP\IncomingRequest;
use CodeIgniter\I18n\Time;
use CodeIgniter\Test\CIUnitTestCase;
use CodeIgniter\Test\DatabaseTestTrait;
use Config\Services;
use Ephraitech\Auth\Authorization\RbacSynchronizer;
use Ephraitech\Auth\Config\Auth;
use Ephraitech\Auth\Entities\User;


/**
 * Base for tests needing the database. Each test gets freshly migrated
 * tables and RBAC synced from the default config.
 *
 * To change config for one test, modify $this->authConfig BEFORE the
 * first service() call in that test; services are rebuilt per test.
 */
abstract class AuthTestCase extends CIUnitTestCase
{
    use DatabaseTestTrait;

    protected const PASSWORD = 'Correct-Horse-42';

    protected $migrate     = true;
    protected $migrateOnce = false;
    protected $refresh     = true;
    protected $namespace   = 'Ephraitech\Auth';

    protected Auth $authConfig;

    protected function setUp(): void
    {
        // Shared services (auth, authAuthorizer, authTokens, ...) otherwise
        // survive from the previous test, still holding that test's config
        // and request. Reset first; parent::setUp() then re-injects the
        // mock session and fresh factories.
        $this->resetServices();

        parent::setUp();

        /** @var Auth $config */
        $config           = config(Auth::class);
        $this->authConfig = $config;

        /** @var Auth $config */
        $config           = config(Auth::class);
        $this->authConfig = $config;

        CapturingNotifier::reset();
        $this->authConfig->notifiers = ['email' => CapturingNotifier::class, 'sms' => CapturingNotifier::class];

        RbacSynchronizer::create($this->authConfig)->sync();
        
        // // Minimum bcrypt cost: identical behaviour, a fraction of the time.
        // $this->authConfig->hashOptions = ['cost' => 4];

        // RbacSynchronizer::create($this->authConfig)->sync();
    }

    protected function tearDown(): void
    {
        Time::setTestNow();

        parent::tearDown();
    }

    /**
     * @param list<string>         $roles
     * @param array<string, mixed> $options
     */
    protected function createUser(
        string $email = 'jane@example.com',
        array $roles = ['user'],
        array $options = [],
        string $password = self::PASSWORD,
    ): User {
        return service('authRegistrar')->register(
            ['email' => $email],
            $password,
            [],
            array_merge(['roles' => $roles], $options)
        );
    }

    /**
     * Inject a fresh HTTP request (with headers) as the request service.
     * Call before the first service('auth') in a test.
     *
     * @param array<string, string> $headers
     */
    protected function useRequest(array $headers = []): IncomingRequest
    {
        /** @var IncomingRequest $request */
        $request = service('incomingrequest', null, false);

        foreach ($headers as $name => $value) {
            $request->setHeader($name, $value);
        }

        Services::injectMock('request', $request);

        return $request;
    }

    /**
     * Enable email + phone, with email required.
     */
    protected function enablePhone(): void
    {
        $this->authConfig->identifiers         = ['email', 'phone'];
        $this->authConfig->loginIdentifiers    = ['email', 'phone'];
        $this->authConfig->requiredIdentifiers = ['email'];
    }

    /**
     * @param array<string, mixed> $options
     */
    protected function createUserWithPhone(
        string $email = 'jane@example.com',
        string $phone = '+256772123456',
        array $options = [],
    ): User {
        return service('authRegistrar')->register(
            ['email' => $email, 'phone' => $phone],
            self::PASSWORD,
            [],
            array_merge(['roles' => ['user']], $options)
        );
    }
}
