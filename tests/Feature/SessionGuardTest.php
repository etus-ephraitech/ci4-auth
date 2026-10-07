<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Tests\Feature;

use Ephraitech\Auth\Tests\Support\AuthTestCase;

final class SessionGuardTest extends AuthTestCase
{
    public function testAttemptSignsInAndPersistsTheUser(): void
    {
        $user = $this->createUser();
        $this->useRequest();

        $guard = service('auth')->session();
        $guard->attempt('jane@example.com', self::PASSWORD);

        $this->assertTrue($guard->check());
        $this->assertSame((int) $user->id, session($this->authConfig->sessionKey)['user_id']);
    }

    public function testANewRequestRestoresTheUserFromTheSession(): void
    {
        $user = $this->createUser();
        $this->useRequest();

        service('auth')->session()->attempt('jane@example.com', self::PASSWORD);

        $fresh = service('auth', false)->session();

        $this->assertSame($user->id, $fresh->id());
    }

    public function testPasswordResetEndsExistingWebSessions(): void
    {
        $user = $this->createUser();
        $this->useRequest();

        service('auth')->session()->attempt('jane@example.com', self::PASSWORD);

        service('authPasswordChanger')->reset($user, 'Brand-New-Pass-99');

        $this->assertFalse(service('auth', false)->session()->check());
    }

    public function testLogoutClearsTheSession(): void
    {
        $this->createUser();
        $this->useRequest();

        $guard = service('auth')->session();
        $guard->attempt('jane@example.com', self::PASSWORD);
        $guard->logout();

        $this->assertFalse($guard->check());
        $this->assertNull(session($this->authConfig->sessionKey));
    }
}
