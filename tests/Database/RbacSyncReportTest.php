<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Tests\Database;

use Ephraitech\Auth\Authorization\RbacSynchronizer;
use Ephraitech\Auth\Tests\Support\AuthTestCase;

final class RbacSyncReportTest extends AuthTestCase
{
    public function testASecondSyncReportsNoChanges(): void
    {
        // setUp() already synced the default config once.
        $report = RbacSynchronizer::create($this->authConfig)->run();

        $this->assertFalse($report->hasChanges());
        $this->assertSame(0, $report->linksAdded());
        $this->assertSame(0, $report->linksRemoved());
        $this->assertSame(0, $report->counts()['role_permission_links']);
    }

    public function testDryRunReportsChangesWithoutWritingThem(): void
    {
        $this->authConfig->permissions['users.export'] = 'Export users';

        $report = RbacSynchronizer::create($this->authConfig)->run(false, true);

        $this->assertTrue($report->dryRun);
        $this->assertSame(['users.export'], $report->permissionsCreated);
        $this->assertSame(['users.export'], $report->links['admin']['added']);
        $this->dontSeeInDatabase('auth_permissions', ['name' => 'users.export']);
    }

    public function testRealRunAppliesAndReportsLinkChangesByName(): void
    {
        $this->authConfig->permissions['users.export'] = 'Export users';
        $this->authConfig->matrix['admin']              = ['users.*', 'tokens.manage'];   // drops roles.manage

        $report = RbacSynchronizer::create($this->authConfig)->run();

        $this->seeInDatabase('auth_permissions', ['name' => 'users.export']);
        $this->assertSame(['users.export'], $report->links['admin']['added']);
        $this->assertSame(['roles.manage'], $report->links['admin']['removed']);
        $this->assertSame(['users.export'], $report->links['superadmin']['added'], "'*' picks up new permissions");
        $this->assertArrayNotHasKey('user', $report->links, 'unchanged roles are not reported');
    }

    public function testUpdatedDescriptionsAreNamed(): void
    {
        $this->authConfig->permissions['users.view'] = 'See the user list';
        $this->authConfig->roles['admin']['title']    = 'Admin';

        $report = RbacSynchronizer::create($this->authConfig)->run();

        $this->assertSame(['users.view'], $report->permissionsUpdated);
        $this->assertSame(['admin'], $report->rolesUpdated);
    }
}
