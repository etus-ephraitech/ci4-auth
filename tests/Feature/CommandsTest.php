<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Tests\Feature;

use CodeIgniter\Config\Factories;
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
    private function addProfileColumns(): void
    {
        \Config\Database::forge()->addColumn('users', [
            'first_name' => ['type' => 'VARCHAR', 'constraint' => 100, 'null' => true],
            'job_title'  => ['type' => 'VARCHAR', 'constraint' => 100, 'null' => true],
        ]);

        $this->authConfig->userAllowedFields = ['first_name', 'job_title'];
        Factories::reset('models');
        $this->resetServices();
    }

    public function testUserCreateSetsProfileColumns(): void
    {
        $this->addProfileColumns();

        $output = $this->spark(
            'auth:user:create --email=owner@example.com --password=Correct-Horse-42 --role=superadmin'
            . ' --first-name=Mark --job_title=Director --no-interaction --no-header'
        );

        $this->assertStringContainsString('User created', $output);
        $this->seeInDatabase('users', ['first_name' => 'Mark', 'job_title' => 'Director']);
    }

    public function testUserCreateRejectsUnknownOptions(): void
    {
        $this->addProfileColumns();

        $output = $this->spark(
            'auth:user:create --email=owner@example.com --password=Correct-Horse-42 --fist-name=Mark --no-interaction'
        );

        $this->assertStringContainsString('Unknown option(s): --fist-name', $output);
        $this->assertStringContainsString('--first-name, --job-title', $output);
        $this->dontSeeInDatabase('auth_identities', ['identifier' => 'owner@example.com']);
    }
}
