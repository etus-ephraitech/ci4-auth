<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Tests\Database;

use Ephraitech\Auth\Authorization\RbacSynchronizer;
use Ephraitech\Auth\Exceptions\AuthException;
use Ephraitech\Auth\Tests\Support\AuthTestCase;

final class RoleManagerTest extends AuthTestCase
{
    public function testCreateRoleInTheAppWithWildcards(): void
    {
        $role = service('authRoles')->createRole('auditor', 'Auditor', 'Reads everything about users', ['users.view', 'tokens.*']);
        $user = $this->createUser('a@example.com', ['auditor']);

        $this->assertTrue($role->isAppManaged());
        $this->assertFalse($role->is_system);
        $this->assertSame(['tokens.manage', 'users.view'], service('authRoles')->permissionsOf('auditor'));
        $this->assertTrue(can_user($user, 'tokens.manage'));
    }

    public function testSyncLeavesAnAppEditedConfigRoleAlone(): void
    {
        service('authRoles')->setPermissions('admin', ['users.view']);
        service('authRoles')->updateRole('admin', 'Office admin');

        $report = RbacSynchronizer::create($this->authConfig)->run(true);

        $this->assertContains('admin', $report->rolesSkipped);
        $this->assertFalse($report->hasChanges());
        $this->assertSame(['users.view'], service('authRoles')->permissionsOf('admin'));
        $this->assertSame('Office admin', service('authRoles')->find('admin')->title);
    }

    public function testReleaseHandsTheRoleBackToConfig(): void
    {
        service('authRoles')->setPermissions('admin', ['users.view']);
        service('authRoles')->release('admin');

        $report = RbacSynchronizer::create($this->authConfig)->run();

        $this->assertNotContains('admin', $report->rolesSkipped);
        $this->assertContains('roles.manage', service('authRoles')->permissionsOf('admin'));
    }

    public function testPruneNeverDeletesAppManagedRoles(): void
    {
        service('authRoles')->setPermissions('admin', ['users.view']);
        unset($this->authConfig->roles['admin'], $this->authConfig->matrix['admin']);

        RbacSynchronizer::create($this->authConfig)->run(true);

        $this->assertNotNull(service('authRoles')->find('admin'));
    }

    public function testPermissionChangesApplyImmediatelyToCachedChecks(): void
    {
        $user = $this->createUser('m@example.com', ['admin']);

        $this->assertTrue(can_user($user, 'users.delete'));   // loads and caches

        service('authRoles')->setPermissions('admin', ['users.view']);

        $this->assertFalse(can_user($user, 'users.delete'), 'cache must be cleared by the edit');
    }

    public function testUnknownPermissionsAreRejectedByName(): void
    {
        $this->expectException(AuthException::class);
        $this->expectExceptionMessage('documents.sign');

        service('authRoles')->createRole('clerk', 'Clerk', null, ['users.view', 'documents.sign']);
    }

    public function testConfigRolesAndTheSuperRoleCannotBeDeleted(): void
    {
        foreach (['admin', 'superadmin'] as $role) {
            try {
                service('authRoles')->deleteRole($role);
                $this->fail("Deleting '{$role}' should be refused");
            } catch (AuthException) {
                $this->assertNotNull(service('authRoles')->find($role));
            }
        }
    }

    public function testAppRolesCanBeDeleted(): void
    {
        service('authRoles')->createRole('temp', 'Temporary');
        service('authRoles')->deleteRole('temp');

        $this->assertNull(service('authRoles')->find('temp'));
    }
}
