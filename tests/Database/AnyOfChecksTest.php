<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Tests\Database;

use Ephraitech\Auth\Tests\Support\AuthTestCase;

/**
 * 'a|b' means any of, everywhere; can_user() checks a given user without a session.
 */
final class AnyOfChecksTest extends AuthTestCase
{
    public function testPipeMeansAnyInTheAuthorizer(): void
    {
        $user  = $this->createUser('a@example.com', ['admin']);
        $authz = service('authAuthorizer');

        $this->assertTrue($authz->can($user, 'reports.export|users.view'));
        $this->assertFalse($authz->can($user, 'reports.export|reports.view'));
        $this->assertTrue($authz->hasRole($user, 'manager|admin'));
        $this->assertTrue($authz->hasRole($user, ['manager|admin']));
    }

    public function testCanUserNeedsNoSignedInUser(): void
    {
        $user = $this->createUser('a@example.com', ['admin']);

        $this->assertNull(user_id(), 'nobody is signed in');
        $this->assertTrue(can_user($user, 'users.view'));
        $this->assertTrue(can_user((int) $user->id, 'reports.view|users.view'));
        $this->assertTrue(can_user($user, ['users.view', 'users.create']), 'array means all');
        $this->assertFalse(can_user($user, ['users.view', 'reports.view']));
        $this->assertFalse(can('users.view'), 'can() checks the signed-in user, of whom there is none');
    }

    public function testCanAnyAcceptsThePipeForm(): void
    {
        $this->assertFalse(can_any('users.view|users.create'), 'no signed-in user');
    }

    public function testAbilitiesStillApplyToEachAlternative(): void
    {
        $user = $this->createUser('a@example.com', ['admin']);

        $this->assertFalse(
            service('authAuthorizer')->can($user, 'users.delete|tokens.manage', null, ['users.view']),
            'neither alternative is within the token abilities'
        );
    }
}
