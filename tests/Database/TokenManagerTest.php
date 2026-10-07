<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Tests\Database;

use CodeIgniter\I18n\Time;
use Ephraitech\Auth\Tests\Support\AuthTestCase;

final class TokenManagerTest extends AuthTestCase
{
    public function testIssuedTokenValidatesAndOnlyItsHashIsStored(): void
    {
        $user = $this->createUser();
        $new  = service('authTokens')->issueSessionToken((int) $user->id, 'Test device');

        $this->assertStringStartsWith('eph_', $new->plaintext);
        $this->assertNotNull(service('authTokens')->validate($new->plaintext));

        $this->dontSeeInDatabase('auth_access_tokens', ['token_hash' => $new->plaintext]);
        $this->seeInDatabase('auth_access_tokens', ['token_hash' => hash('sha256', $new->plaintext)]);
    }

    public function testRevocationTakesEffectImmediately(): void
    {
        $user   = $this->createUser();
        $tokens = service('authTokens');
        $new    = $tokens->issueSessionToken((int) $user->id, 'Test device');

        $this->assertTrue($tokens->revokePlaintext($new->plaintext));
        $this->assertNull($tokens->validate($new->plaintext));
    }

    public function testExpiredTokenIsRejected(): void
    {
        Time::setTestNow('2026-01-01 10:00:00');

        $user = $this->createUser();
        $new  = service('authTokens')->issueSessionToken((int) $user->id, 'Test device');

        Time::setTestNow('2026-02-15 10:00:00'); // past the default 30-day lifetime

        $this->assertNull(service('authTokens')->validate($new->plaintext));
    }

    public function testAbilitiesAreACeilingEvenForAdmins(): void
    {
        $user = $this->createUser('jane@example.com', ['admin']);
        $key  = service('authTokens')->issueApiKey((int) $user->id, 'Read-only', ['users.view']);

        $abilities  = $key->token->abilityList();
        $authorizer = service('authAuthorizer');

        $this->assertTrue($authorizer->can($user, 'users.view', null, $abilities));
        $this->assertFalse($authorizer->can($user, 'users.delete', null, $abilities));
        $this->assertTrue($authorizer->can($user, 'users.delete'), 'the user still holds it without the token ceiling');
    }

    public function testSessionCapRevokesTheOldestToken(): void
    {
        $this->authConfig->maxSessionTokensPerUser = 2;

        $user   = $this->createUser();
        $tokens = service('authTokens');

        $first = $tokens->issueSessionToken((int) $user->id, 'Device 1');
        $tokens->issueSessionToken((int) $user->id, 'Device 2');
        $third = $tokens->issueSessionToken((int) $user->id, 'Device 3');

        $this->assertNull($tokens->validate($first->plaintext));
        $this->assertNotNull($tokens->validate($third->plaintext));
    }

    public function testApiKeysDoNotCountTowardTheSessionCap(): void
    {
        $this->authConfig->maxSessionTokensPerUser = 1;

        $user   = $this->createUser();
        $tokens = service('authTokens');

        $key = $tokens->issueApiKey((int) $user->id, 'Integration');
        $tokens->issueSessionToken((int) $user->id, 'Phone');

        $this->assertNotNull($tokens->validate($key->plaintext));
    }

    public function testPasswordChangeRevokesOtherTokensButKeepsTheCurrentOne(): void
    {
        $user   = $this->createUser();
        $tokens = service('authTokens');

        $other   = $tokens->issueSessionToken((int) $user->id, 'Old laptop');
        $current = $tokens->issueSessionToken((int) $user->id, 'This phone');

        service('authPasswordChanger')->change($user, self::PASSWORD, 'New-Password-2026', (int) $current->token->id);

        $this->assertNull($tokens->validate($other->plaintext));
        $this->assertNotNull($tokens->validate($current->plaintext));
        $this->assertTrue(service('authPasswords')->verify((int) $user->id, 'New-Password-2026'));
    }
}
