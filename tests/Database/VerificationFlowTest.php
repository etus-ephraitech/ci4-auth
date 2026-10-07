<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Tests\Database;

use CodeIgniter\Events\Events;
use Ephraitech\Auth\AuthEvents;
use Ephraitech\Auth\Entities\User;
use Ephraitech\Auth\Exceptions\AuthException;
use Ephraitech\Auth\Exceptions\InvalidCodeException;
use Ephraitech\Auth\Exceptions\NotificationException;
use Ephraitech\Auth\Tests\Support\AuthTestCase;
use Ephraitech\Auth\Tests\Support\CapturingNotifier;

final class VerificationFlowTest extends AuthTestCase
{
    protected function tearDown(): void
    {
        Events::removeAllListeners(AuthEvents::IDENTIFIER_VERIFIED);

        parent::tearDown();
    }

    public function testSendAndConfirmVerifiesTheIdentifier(): void
    {
        $user = $this->createUser();
        $flow = service('authVerification');

        $flow->send($user, 'email');
        $verified = $flow->confirm($user, 'email', CapturingNotifier::last()->code);

        $this->assertTrue($verified->hasVerified('email'));
    }

    public function testVerifiedEventFires(): void
    {
        $received = null;

        Events::on(AuthEvents::IDENTIFIER_VERIFIED, static function (User $user, string $type) use (&$received): void {
            $received = $type;
        });

        $user = $this->createUser();
        $flow = service('authVerification');

        $flow->send($user, 'email');
        $flow->confirm($user, 'email', CapturingNotifier::last()->code);

        $this->assertSame('email', $received);
    }

    public function testPendingUserIsActivatedWhenConfigured(): void
    {
        $this->authConfig->activateOnVerification = true;

        $user = $this->createUser('jane@example.com', ['user'], ['status' => 'pending']);
        $flow = service('authVerification');

        $flow->send($user, 'email');
        $verified = $flow->confirm($user, 'email', CapturingNotifier::last()->code);

        $this->assertTrue($verified->isActive());
    }

    public function testPendingUserStaysPendingByDefault(): void
    {
        $user = $this->createUser('jane@example.com', ['user'], ['status' => 'pending']);
        $flow = service('authVerification');

        $flow->send($user, 'email');
        $verified = $flow->confirm($user, 'email', CapturingNotifier::last()->code);

        $this->assertTrue($verified->isPending());
    }

    public function testAlreadyVerifiedIdentifierCannotBeSentAgain(): void
    {
        $user = $this->createUser();
        $flow = service('authVerification');

        $flow->send($user, 'email');
        $verified = $flow->confirm($user, 'email', CapturingNotifier::last()->code);

        $this->expectException(AuthException::class);

        $flow->send($verified, 'email');
    }

    public function testDisabledChannelIsReportedHonestly(): void
    {
        $this->enablePhone();
        $this->authConfig->notifiers = ['email' => CapturingNotifier::class, 'sms' => null];

        $user = $this->createUserWithPhone();

        $this->expectException(NotificationException::class);

        service('authVerification')->send($user, 'phone');
    }

    public function testConfirmByPhoneInLocalFormat(): void
    {
        $this->enablePhone();

        $user = $this->createUserWithPhone();
        $flow = service('authVerification');

        $flow->send($user, 'phone');

        $this->assertSame('sms', CapturingNotifier::last()->channel);

        $verified = $flow->confirmByIdentifier('0772 123 456', CapturingNotifier::last()->code);

        $this->assertTrue($verified->hasVerified('phone'));
    }

    public function testWrongCodeIsRejected(): void
    {
        $user = $this->createUser();
        $flow = service('authVerification');

        $flow->send($user, 'email');
        $wrong = CapturingNotifier::last()->code === '000000' ? '111111' : '000000';

        $this->expectException(InvalidCodeException::class);

        $flow->confirm($user, 'email', $wrong);
    }

    public function testRequiredForFollowsConfig(): void
    {
        $user = $this->createUser();
        $flow = service('authVerification');

        $this->assertNull($flow->requiredFor($user), 'nothing is required by default');

        $this->authConfig->requireVerifiedToLogin['email'] = true;

        $this->assertSame('email', $flow->requiredFor($user));
    }
}
