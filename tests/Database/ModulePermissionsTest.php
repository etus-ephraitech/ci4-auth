<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Tests\Database;

use CodeIgniter\Config\Factories;
use Ephraitech\Auth\Authorization\ModulePermissions;
use Ephraitech\Auth\Authorization\RbacSynchronizer;
use Ephraitech\Auth\Config\Auth;
use Ephraitech\Auth\Config\ConfigResolver;
use Ephraitech\Auth\Tests\Support\AuthTestCase;
use Ephraitech\Auth\Tests\Support\Modules\Documents\Config\AuthPermissions as DocumentsPermissions;

final class ModulePermissionsTest extends AuthTestCase
{
    private const MODULE_NAMESPACE = 'TestModules\Documents';

    protected function tearDown(): void
    {
        service('autoloader')->removeNamespace(self::MODULE_NAMESPACE);

        parent::tearDown();
    }

    private function registerModule(): void
    {
        service('autoloader')->addNamespace(self::MODULE_NAMESPACE, dirname(__DIR__) . '/_support/Modules/Documents');
    }

    public function testMergeAddsPermissionsRolesAndGrantsButTheAppWins(): void
    {
        $config  = new Auth();
        $summary = ModulePermissions::apply($config, [new DocumentsPermissions()]);

        $this->assertSame('Sign documents', $config->permissions['documents.sign']);
        $this->assertSame('View users', $config->permissions['users.view'], 'app wording wins');
        $this->assertArrayHasKey('signatory', $config->roles);
        $this->assertContains('documents.*', $config->matrix['admin']);
        $this->assertContains('users.*', $config->matrix['admin'], 'module grants are added, not replacing');

        $this->assertSame(2, $summary[0]['permissions']);
        $this->assertSame(1, $summary[0]['roles']);
        $config->assertValid();
    }

    public function testDiscoveryFindsModuleConfigAndSkipsTheAbstractBase(): void
    {
        $this->registerModule();

        $this->assertSame([DocumentsPermissions::class], ModulePermissions::discover());
    }

    public function testResolvedConfigIncludesModulesAndSyncCreatesThem(): void
    {
        // Fresh config, services and models, then the module (resetting
        // services also resets the autoloader, dropping the namespace).
        Factories::reset('config');
        Factories::reset('models');
        $this->resetServices();
        $this->registerModule();

        $config = ConfigResolver::resolve();

        $this->assertArrayHasKey('documents.sign', $config->permissions);
        $this->assertSame(DocumentsPermissions::class, ConfigResolver::modules()[0]['class']);

        $report = RbacSynchronizer::create()->run();

        $this->assertSame(['documents.sign', 'documents.view'], $this->sorted($report->permissionsCreated));
        $this->assertSame(['signatory'], $report->rolesCreated);
    }

    public function testDiscoveryCanBeTurnedOff(): void
    {
        $this->registerModule();
        Factories::reset('config');

        /** @var Auth $config */
        $config                            = config(Auth::class);
        $config->discoverModulePermissions = false;

        $this->assertArrayNotHasKey('documents.sign', ConfigResolver::resolve()->permissions);
    }

    /**
     * @param list<string> $names
     *
     * @return list<string>
     */
    private function sorted(array $names): array
    {
        sort($names);

        return $names;
    }
}
