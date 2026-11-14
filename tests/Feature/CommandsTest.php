<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Tests\Feature;

use CodeIgniter\Test\StreamFilterTrait;
use Ephraitech\Auth\Tests\Support\AuthTestCase;

/**
 * Runs the real commands through CodeIgniter's CLI parser.
 */
final class CommandsTest extends AuthTestCase
{
    use StreamFilterTrait;

    private function spark(string $command): string
    {
        $this->resetStreamFilterBuffer();

        command($command);

        return $this->getStreamFilterBuffer();
    }

    public function testSyncNamesTheConfigAndReportsNothingToChange(): void
    {
        $output = $this->spark('auth:sync');

        $this->assertStringContainsString('Config:  Ephraitech\Auth\Config\Auth', $output);
        $this->assertStringContainsString('Defines: 3 role(s), 6 permission(s)', $output);
        $this->assertStringContainsString('Nothing to change', $output);
    }

    public function testSyncDryRunListsChangesAndWritesNothing(): void
    {
        $this->authConfig->permissions['users.export'] = 'Export users';

        $output = $this->spark('auth:sync --dry-run');

        $this->assertStringContainsString('Permissions would be created (1):', $output);
        $this->assertStringContainsString('admin: +users.export', $output);
        $this->assertStringContainsString('Dry run: nothing was written', $output);
        $this->dontSeeInDatabase('auth_permissions', ['name' => 'users.export']);
    }

    public function testUserCreateAcceptsEqualsSignOptions(): void
    {
        $output = $this->spark(
            'auth:user:create --email=jane@example.com --password=Correct-Horse-42 --role=admin --no-interaction'
        );

        $this->assertStringContainsString('User created', $output);
        $this->seeInDatabase('auth_identities', ['identifier' => 'jane@example.com']);
    }
}
