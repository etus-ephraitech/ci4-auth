<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Tests\Database;

use CodeIgniter\Events\Events;
use Ephraitech\Auth\AuthEvents;
use Ephraitech\Auth\Entities\User;
use Ephraitech\Auth\Exceptions\AuthException;
use Ephraitech\Auth\Exceptions\RegistrationException;
use Ephraitech\Auth\Tests\Support\AuthTestCase;

final class RegistrationTest extends AuthTestCase
{
    protected function tearDown(): void
    {
        Events::removeAllListeners(AuthEvents::REGISTERED);

        parent::tearDown();
    }

    public function testRegistersCompleteAccount(): void
    {
        $user = $this->createUser('Jane@Example.com');

        $this->assertSame('jane@example.com', $user->email);
        $this->assertNotEmpty($user->uuid);
        $this->assertTrue($user->isActive());
        $this->assertTrue(service('authPasswords')->verify((int) $user->id, self::PASSWORD));
        $this->assertTrue(service('authAuthorizer')->hasRole($user, 'user'));
    }

    public function testAllFieldErrorsAreReportedTogether(): void
    {
        try {
            service('authRegistrar')->register(['email' => 'not-an-email'], 'short');
            $this->fail('Expected RegistrationException');
        } catch (RegistrationException $e) {
            $errors = $e->getErrors();

            $this->assertArrayHasKey('email', $errors);
            $this->assertArrayHasKey('password', $errors);
        }
    }

    public function testDuplicateEmailIsRejectedCaseInsensitively(): void
    {
        $this->createUser('jane@example.com');

        $this->expectException(RegistrationException::class);

        $this->createUser('JANE@Example.com');
    }

    public function testFailureMidwayRollsBackEverything(): void
    {
        try {
            $this->createUser('jane@example.com', ['role-that-does-not-exist']);
            $this->fail('Expected AuthException');
        } catch (AuthException $e) {
            $this->assertNotInstanceOf(RegistrationException::class, $e);
        }

        $this->assertSame(0, $this->db->table('users')->countAllResults());
        $this->dontSeeInDatabase('auth_identities', ['identifier' => 'jane@example.com']);
    }

    public function testProtectedColumnsCannotBeSetThroughAttributes(): void
    {
        $this->expectException(AuthException::class);

        service('authRegistrar')->register(['email' => 'jane@example.com'], self::PASSWORD, ['status' => 'active']);
    }

    public function testRegisteredEventFires(): void
    {
        $received = null;

        Events::on(AuthEvents::REGISTERED, static function (User $user) use (&$received): void {
            $received = $user;
        });

        $user = $this->createUser();

        $this->assertInstanceOf(User::class, $received);
        $this->assertSame($user->id, $received->id);
    }
}
