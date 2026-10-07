<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Tests\Database;

use CodeIgniter\I18n\Time;
use Ephraitech\Auth\Entities\OneTimeCode;
use Ephraitech\Auth\Entities\User;
use Ephraitech\Auth\Exceptions\AuthException;
use Ephraitech\Auth\Exceptions\ResendTooSoonException;
use Ephraitech\Auth\OneTimeCodes\IssuedCode;
use Ephraitech\Auth\Tests\Support\AuthTestCase;

final class OneTimeCodeManagerTest extends AuthTestCase
{
    private function issueFor(User $user): IssuedCode
    {
        return service('authOneTimeCodes')->issue(
            $user,
            $user->getIdentity('email'),
            OneTimeCode::PURPOSE_PASSWORD_RESET
        );
    }

    /**
     * Each request loads the code fresh; tests do the same between guesses.
     */
    private function reload(IssuedCode $issued): OneTimeCode
    {
        $record = service('authOneTimeCodes')->findBySelector($issued->selector(), OneTimeCode::PURPOSE_PASSWORD_RESET);

        $this->assertNotNull($record);

        return $record;
    }

    private function wrongCode(string $code): string
    {
        return $code === '000000' ? '111111' : '000000';
    }

    public function testIssuedCodeIsNumericAndOnlyItsHashIsStored(): void
    {
        $issued = $this->issueFor($this->createUser());

        $this->assertMatchesRegularExpression('/^\d{6}$/', $issued->code);
        $this->assertSame('email', $issued->channel);
        $this->assertSame('jane@example.com', $issued->destination);
        $this->dontSeeInDatabase('auth_one_time_codes', ['code_hash' => $issued->code]);
        $this->seeInDatabase('auth_one_time_codes', ['selector' => $issued->selector()]);
    }

    public function testCheckDoesNotConsumeAndConsumeWorksOnlyOnce(): void
    {
        $codes  = service('authOneTimeCodes');
        $issued = $this->issueFor($this->createUser());

        $this->assertTrue($codes->check($this->reload($issued), $issued->code));
        $this->assertTrue($codes->check($this->reload($issued), $issued->code), 'check() must not burn the code');

        $this->assertTrue($codes->consume($this->reload($issued)));
        $this->assertFalse($codes->consume($this->reload($issued)), 'a code can only be consumed once');
        $this->assertFalse($codes->check($this->reload($issued), $issued->code));
    }

    public function testWrongGuessesBurnTheCodeAfterMaxAttempts(): void
    {
        $this->authConfig->otpMaxAttempts = 3;

        $codes  = service('authOneTimeCodes');
        $issued = $this->issueFor($this->createUser());
        $wrong  = $this->wrongCode($issued->code);

        for ($i = 0; $i < 3; $i++) {
            $this->assertFalse($codes->check($this->reload($issued), $wrong));
        }

        $this->assertSame(3, $this->reload($issued)->attempts);
        $this->assertFalse($codes->check($this->reload($issued), $issued->code), 'correct code must fail once attempts are exhausted');
    }

    public function testMalformedInputDoesNotCountAsAnAttempt(): void
    {
        $codes  = service('authOneTimeCodes');
        $issued = $this->issueFor($this->createUser());

        $this->assertFalse($codes->check($this->reload($issued), 'abcdef'));
        $this->assertFalse($codes->check($this->reload($issued), '12'));

        $this->assertSame(0, $this->reload($issued)->attempts);
    }

    public function testCodeWithSpacesOrDashesIsAccepted(): void
    {
        $codes  = service('authOneTimeCodes');
        $issued = $this->issueFor($this->createUser());

        $spaced = substr($issued->code, 0, 3) . ' - ' . substr($issued->code, 3);

        $this->assertTrue($codes->check($this->reload($issued), $spaced));
    }

    public function testANewCodeInvalidatesThePreviousOne(): void
    {
        $this->authConfig->otpResendInterval = 0;

        $codes  = service('authOneTimeCodes');
        $user   = $this->createUser();
        $first  = $this->issueFor($user);
        $second = $this->issueFor($user);

        $this->assertTrue($this->reload($first)->isConsumed());
        $this->assertFalse($codes->check($this->reload($first), $first->code));
        $this->assertTrue($codes->check($this->reload($second), $second->code));
    }

    public function testResendCooldownIsEnforced(): void
    {
        $user = $this->createUser();
        $this->issueFor($user);

        $this->expectException(ResendTooSoonException::class);

        $this->issueFor($user);
    }

    public function testCodeExpires(): void
    {
        Time::setTestNow('2026-10-08 10:00:00');

        $codes  = service('authOneTimeCodes');
        $issued = $this->issueFor($this->createUser());

        Time::setTestNow('2026-10-08 10:16:00'); // past the 15-minute default

        $this->assertFalse($codes->check($this->reload($issued), $issued->code));
    }

    public function testUsernamesCannotReceiveCodes(): void
    {
        $this->authConfig->identifiers         = ['email', 'username'];
        $this->authConfig->requiredIdentifiers = ['email'];

        $user = service('authRegistrar')->register(
            ['email' => 'jane@example.com', 'username' => 'jane.doe'],
            self::PASSWORD,
            [],
            ['roles' => ['user']]
        );

        $this->expectException(AuthException::class);

        service('authOneTimeCodes')->issue($user, $user->getIdentity('username'), OneTimeCode::PURPOSE_PASSWORD_RESET);
    }
}
