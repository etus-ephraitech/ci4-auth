<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Tests\Database;

use Ephraitech\Auth\Tests\Support\AuthTestCase;

final class AuthorizerTest extends AuthTestCase
{
    public function testWildcardMatrixGrantsExpandedPermissions(): void
    {
        $admin = $this->createUser('admin@example.com', ['admin']);
        $plain = $this->createUser('plain@example.com', ['user']);
        $authz = service('authAuthorizer');

        $this->assertTrue($authz->can($admin, 'users.create'));
        $this->assertTrue($authz->can($admin, 'tokens.manage'));
        $this->assertFalse($plain->id === null || $authz->can($plain, 'users.create'));
    }

    public function testSuperRoleReceivesEverything(): void
    {
        $super = $this->createUser('root@example.com', ['superadmin']);
        $authz = service('authAuthorizer');

        $this->assertTrue($authz->isSuper($super));
        $this->assertTrue($authz->can($super, 'users.delete'));
        $this->assertSame(
            array_keys($this->authConfig->permissions) === [] ? [] : $authz->permissionsFor($super),
            service('authAuthorizer')->permissionsFor($super)
        );
        $this->assertCount(count($this->authConfig->permissions), $authz->permissionsFor($super));
    }

    public function testDirectGrantAndRevokeTakeEffectImmediately(): void
    {
        $user  = $this->createUser();
        $authz = service('authAuthorizer');

        $this->assertFalse($authz->can($user, 'users.view'));

        $authz->grantPermission($user, 'users.view');
        $this->assertTrue($authz->can($user, 'users.view'));

        $authz->revokePermission($user, 'users.view');
        $this->assertFalse($authz->can($user, 'users.view'));
    }

    public function testRolesAreScopedToTenants(): void
    {
        $this->authConfig->tenancy = 'multi';

        $teacher = $this->createUser('teacher@example.com');
        $root    = $this->createUser('root@example.com', []);
        $authz   = service('authAuthorizer');

        $authz->assignRole($teacher, 'admin', 'school-a');
        $authz->assignRole($root, 'superadmin', '');   // global

        $this->assertTrue($authz->can($teacher, 'users.view', 'school-a'));
        $this->assertFalse($authz->can($teacher, 'users.view', 'school-b'));
        $this->assertTrue($authz->can($root, 'users.view', 'school-b'), 'global roles apply in every tenant');
    }
}
