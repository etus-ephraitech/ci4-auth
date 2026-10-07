<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Tests\Unit;

use CodeIgniter\Test\CIUnitTestCase;
use Ephraitech\Auth\Authorization\PermissionMatcher;

final class PermissionMatcherTest extends CIUnitTestCase
{
    public function testMatching(): void
    {
        $this->assertTrue(PermissionMatcher::matches('*', 'users.view'));
        $this->assertTrue(PermissionMatcher::matches('users.*', 'users.view'));
        $this->assertTrue(PermissionMatcher::matches('users.*', 'users.roles.assign'));
        $this->assertTrue(PermissionMatcher::matches('users.view', 'users.view'));

        $this->assertFalse(PermissionMatcher::matches('users.view', 'users.create'));
        $this->assertFalse(PermissionMatcher::matches('users.*', 'usersx.view'));
        $this->assertFalse(PermissionMatcher::matches('reports.*', 'users.view'));
    }

    public function testExpandReturnsSortedConcreteNames(): void
    {
        $known = ['users.view', 'users.create', 'roles.manage', 'tokens.manage'];

        $this->assertSame(
            ['roles.manage', 'users.create', 'users.view'],
            PermissionMatcher::expand(['users.*', 'roles.manage'], $known)
        );

        $this->assertSame([], PermissionMatcher::expand(['reports.*'], $known));
    }
}
