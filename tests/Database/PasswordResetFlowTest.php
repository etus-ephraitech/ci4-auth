<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Tests\Database;

use CodeIgniter\Config\Factories;
use Ephraitech\Auth\Entities\OneTimeCode;
use Ephraitech\Auth\Exceptions\InvalidCodeException;
use Ephraitech\Auth\Exceptions\WeakPasswordException;
use Ephraitech\Auth\Models\UserModel;
use Ephraitech\Auth\Tests\Support\AuthTestCase;
use Ephraitech\Auth\Tests\Support\CapturingNotifier;

final class PasswordResetFlowTest extends AuthTestCase
{
    private const NEW_PASSWORD = 'Brand-New-Pass-99';

    public function testRequestSendsAResetCodeByEmail(): void
    {
        $this->createUser();

        service('authPasswordReset')->request('JANE@example.com');

        $message = CapturingNotifier::last();

        $this->assertCount(1, CapturingNotifier::$messages);
        $this->assertSame('email', $message->channel);
        $this->assertSame('jane@example.com', $message->destination);
        $this->assertSame(OneTimeCode::PURPOSE_PASSWORD_RESET, $message->purpose);
    }

    public function testUnknownAccountSendsNothingAndLooksTheSame(): void
    {
        service('authPasswordReset')->request('nobody@example.com');

        $this->assertSame([], CapturingNotifier::$messages);
    }

    public function testSuspendedAccountSendsNothing(): void
    {
        $user = $this->createUser();

        /** @var UserModel $users */
        $users = Factories::models(UserModel::class, ['preferApp' => false]);
        $users->setStatus((int) $user->id, 'suspended');

        service('authPasswordReset')->request('jane@example.com');

        $this->assertSame([], CapturingNotifier::$messages);
    }

    public function testDeliveryFailureIsSilentAndBurnsTheCode(): void
    {
        $this->createUser();
        CapturingNotifier::$fail = true;

        service('authPasswordReset')->request('jane@example.com');

        $this->assertSame([], CapturingNotifier::$messages);
        $this->dontSeeInDatabase('auth_one_time_codes', ['consumed_at' => null]);
    }

    public function testResetWithCodeChangesPasswordRevokesTokensAndVerifies(): void
    {
        $user  = $this->createUser();
        $token = service('authTokens')->issueSessionToken((int) $user->id, 'Old phone');

        service('authPasswordReset')->request('jane@example.com');

        $updated = service('authPasswordReset')->resetWithCode(
            'jane@example.com',
            CapturingNotifier::last()->code,
            self::NEW_PASSWORD
        );

        $this->assertTrue(service('authPasswords')->verify((int) $user->id, self::NEW_PASSWORD));
        $this->assertNull(service('authTokens')->validate($token->plaintext), 'reset must revoke every token');
        $this->assertTrue($updated->hasVerified('email'), 'receiving the code proves control of the email');
    }

    public function testWeakPasswordKeepsTheCodeUsable(): void
    {
        $this->createUser();
        $flow = service('authPasswordReset');

        $flow->request('jane@example.com');
        $code = CapturingNotifier::last()->code;

        try {
            $flow->resetWithCode('jane@example.com', $code, 'short');
            $this->fail('Expected WeakPasswordException');
        } catch (WeakPasswordException) {
            // the user can fix the password and resubmit
        }

        $flow->resetWithCode('jane@example.com', $code, self::NEW_PASSWORD);

        $this->assertTrue(service('authPasswords')->verify(1, self::NEW_PASSWORD));
    }

    public function testCodeCannotBeReused(): void
    {
        $this->createUser();
        $flow = service('authPasswordReset');

        $flow->request('jane@example.com');
        $code = CapturingNotifier::last()->code;

        $flow->resetWithCode('jane@example.com', $code, self::NEW_PASSWORD);

        $this->expectException(InvalidCodeException::class);

        $flow->resetWithCode('jane@example.com', $code, 'Another-Pass-2027');
    }

    public function testResetWithEmailLink(): void
    {
        $this->createUser();
        $flow     = service('authPasswordReset');
        $selector = null;
        $code     = null;

        $flow->request('jane@example.com', null, static function (string $s, string $c) use (&$selector, &$code): string {
            $selector = $s;
            $code     = $c;

            return "https://example.com/reset-password?s={$s}&c={$c}";
        });

        $this->assertStringContainsString('reset-password?s=', (string) CapturingNotifier::last()->link);
        $this->assertTrue($flow->linkIsUsable($selector));

        $flow->resetWithLink($selector, $code, self::NEW_PASSWORD);

        $this->assertFalse($flow->linkIsUsable($selector), 'a used link must stop working');
    }

    public function testUsernameIsDeliveredToTheUsersEmail(): void
    {
        $this->authConfig->identifiers         = ['email', 'username'];
        $this->authConfig->loginIdentifiers    = ['email', 'username'];
        $this->authConfig->requiredIdentifiers = ['email'];

        service('authRegistrar')->register(
            ['email' => 'jane@example.com', 'username' => 'jane.doe'],
            self::PASSWORD,
            [],
            ['roles' => ['user']]
        );

        service('authPasswordReset')->request('jane.doe');

        $this->assertSame('jane@example.com', CapturingNotifier::last()?->destination);
    }

    public function testWrongCodeAndUnknownAccountGiveTheSameError(): void
    {
        $this->createUser();
        $flow = service('authPasswordReset');
        $flow->request('jane@example.com');

        $wrong    = CapturingNotifier::last()->code === '000000' ? '111111' : '000000';
        $messages = [];

        foreach ([['jane@example.com', $wrong], ['nobody@example.com', '123456']] as [$login, $code]) {
            try {
                $flow->resetWithCode($login, $code, self::NEW_PASSWORD);
                $this->fail('Expected InvalidCodeException');
            } catch (InvalidCodeException $e) {
                $messages[] = $e->getMessage();
            }
        }

        $this->assertSame($messages[0], $messages[1]);
    }
}
