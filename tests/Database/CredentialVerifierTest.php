<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Tests\Database;

use CodeIgniter\Config\Factories;
use Ephraitech\Auth\Exceptions\AccountNotActiveException;
use Ephraitech\Auth\Exceptions\InvalidCredentialsException;
use Ephraitech\Auth\Exceptions\LockedOutException;
use Ephraitech\Auth\Models\UserModel;
use Ephraitech\Auth\Tests\Support\AuthTestCase;

final class CredentialVerifierTest extends AuthTestCase
{
    public function testValidCredentialsReturnTheUser(): void
    {
        $user = $this->createUser();

        $verified = service('authCredentials')->verify('JANE@example.com', self::PASSWORD);

        $this->assertSame($user->id, $verified->id);
    }

    public function testWrongPasswordAndUnknownUserAreIndistinguishable(): void
    {
        $this->createUser();

        $messages = [];

        foreach ([['jane@example.com', 'Wrong-Pass-1'], ['nobody@example.com', self::PASSWORD]] as [$login, $password]) {
            try {
                service('authCredentials')->verify($login, $password);
                $this->fail('Expected InvalidCredentialsException');
            } catch (InvalidCredentialsException $e) {
                $messages[] = $e->getMessage();
            }
        }

        $this->assertSame($messages[0], $messages[1]);
    }

    public function testLockoutAfterMaxAttemptsEvenWithCorrectPassword(): void
    {
        $this->authConfig->maxLoginAttempts = 3;
        $this->createUser();

        for ($i = 0; $i < 3; $i++) {
            try {
                service('authCredentials')->verify('jane@example.com', 'Wrong-Pass-1');
            } catch (InvalidCredentialsException) {
                // expected
            }
        }

        $this->expectException(LockedOutException::class);

        service('authCredentials')->verify('jane@example.com', self::PASSWORD);
    }

    public function testSuspensionIsRevealedOnlyWithTheCorrectPassword(): void
    {
        $user = $this->createUser();

        /** @var UserModel $users */
        $users = Factories::models(UserModel::class, ['preferApp' => false]);
        $users->setStatus((int) $user->id, 'suspended', 'Unpaid subscription');

        try {
            service('authCredentials')->verify('jane@example.com', 'Wrong-Pass-1');
            $this->fail('Expected InvalidCredentialsException');
        } catch (InvalidCredentialsException) {
            // a wrong password must not reveal the suspension
        }

        try {
            service('authCredentials')->verify('jane@example.com', self::PASSWORD);
            $this->fail('Expected AccountNotActiveException');
        } catch (AccountNotActiveException $e) {
            $this->assertSame('suspended', $e->getStatus());
            $this->assertSame('Unpaid subscription', $e->getReason());
        }
    }

    public function testLoginWithLocalPhoneFormat(): void
    {
        $this->authConfig->identifiers         = ['email', 'phone'];
        $this->authConfig->loginIdentifiers    = ['email', 'phone'];
        $this->authConfig->requiredIdentifiers = ['email'];

        $user = service('authRegistrar')->register(
            ['email' => 'jane@example.com', 'phone' => '+256 772 123 456'],
            self::PASSWORD,
            [],
            ['roles' => ['user']]
        );

        $verified = service('authCredentials')->verify('0772123456', self::PASSWORD);

        $this->assertSame($user->id, $verified->id);
    }
}
