<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Tests\Database;

use CodeIgniter\Config\Factories;
use Ephraitech\Auth\Authorization\RbacSynchronizer;
use Ephraitech\Auth\Config\Auth;
use Ephraitech\Auth\Config\ConfigResolver;
use Ephraitech\Auth\Models\UserModel;
use Ephraitech\Auth\Tests\Support\AuthTestCase;
use Ephraitech\Auth\Tests\Support\Config\AppAuth;
use stdClass;

/**
 * Regression for the v0.10.2 deploy bug: the package read its own config
 * class and ignored the app's Config\Auth (3 roles instead of 12, unknown
 * user columns).
 */
final class ConfigResolverTest extends AuthTestCase
{
    protected function tearDown(): void
    {
        ConfigResolver::useAppClass(null);

        parent::tearDown();
    }

    private function useAppConfig(): void
    {
        ConfigResolver::useAppClass(AppAuth::class);

        // Drop services and models built with the package config in setUp().
        $this->resetServices();
        Factories::reset('models');
    }

    public function testFallsBackToPackageDefaultsWithoutAnAppConfig(): void
    {
        ConfigResolver::useAppClass('Config\DoesNotExist');

        $this->assertSame(Auth::class, ConfigResolver::resolvedClass());
        $this->assertNull(ConfigResolver::ignoredAppClassReason());
    }

    public function testPrefersTheAppConfig(): void
    {
        $this->useAppConfig();

        $this->assertInstanceOf(AppAuth::class, ConfigResolver::resolve());
        $this->assertSame(AppAuth::class, ConfigResolver::resolvedClass());
    }

    public function testIgnoresAnAppConfigThatDoesNotExtendThePackageAndSaysWhy(): void
    {
        ConfigResolver::useAppClass(stdClass::class);

        $this->assertSame(Auth::class, ConfigResolver::resolvedClass());
        $this->assertStringContainsString('does not extend', (string) ConfigResolver::ignoredAppClassReason());
    }

    public function testSyncUsesTheAppRoles(): void
    {
        $this->useAppConfig();

        $report = RbacSynchronizer::create()->run();

        $this->assertSame(AppAuth::class, $report->configClass);
        $this->assertSame(4, $report->configRoleCount);
        $this->assertContains('manager', $report->rolesCreated);
        $this->assertContains('visits.view', $report->permissionsCreated);
    }

    public function testServicesUseTheAppConfig(): void
    {
        $this->useAppConfig();
        RbacSynchronizer::create()->run();

        $user = service('authRegistrar')->register(
            ['email' => 'manager@example.com'],
            self::PASSWORD,
            [],
            ['roles' => ['manager']]
        );

        $this->assertTrue(service('authAuthorizer')->can($user, 'visits.view'));
    }

    public function testUserModelAcceptsTheAppUserColumns(): void
    {
        $this->useAppConfig();

        /** @var UserModel $users */
        $users = Factories::models(UserModel::class, ['preferApp' => false, 'getShared' => false]);

        $this->assertContains('first_name', $users->profileFields());
    }
}
