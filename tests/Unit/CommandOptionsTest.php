<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Tests\Unit;

use CodeIgniter\Test\CIUnitTestCase;
use Ephraitech\Auth\Commands\Concerns\InteractsWithAuth;

/**
 * Regression: "--email=jane@example.com" used to lose its value, because
 * CodeIgniter's parser stores it as an option named "email=jane@example.com".
 */
final class CommandOptionsTest extends CIUnitTestCase
{
    private object $command;

    protected function setUp(): void
    {
        parent::setUp();

        $this->command = new class () {
            use InteractsWithAuth;

            /**
             * @param array<int|string, string|null> $params
             */
            public function value(array $params, string $name): ?string
            {
                return $this->option($params, $name);
            }

            /**
             * @param array<int|string, string|null> $params
             */
            public function has(array $params, string $name): bool
            {
                return $this->hasOption($params, $name);
            }

            /**
             * @param array<int|string, string|null> $params
             *
             * @return list<string>|null
             */
            public function list(array $params, string $name): ?array
            {
                return $this->listOption($params, $name);
            }
        };
    }

    public function testEqualsFormIsParsed(): void
    {
        $params = [0 => 'assign', 'email=jane@example.com' => null, 'role=admin,manager' => null];

        $this->assertSame('jane@example.com', $this->command->value($params, 'email'));
        $this->assertTrue($this->command->has($params, 'email'));
        $this->assertSame(['admin', 'manager'], $this->command->list($params, 'role'));
    }

    public function testSpaceFormStillWorks(): void
    {
        $this->assertSame('jane@example.com', $this->command->value(['email' => 'jane@example.com'], 'email'));
    }

    public function testValueMayContainEqualsSigns(): void
    {
        $this->assertSame('a=b=c', $this->command->value(['password=a=b=c' => null], 'password'));
    }

    public function testBareFlagsAndEmptyValues(): void
    {
        $params = ['verified' => null, 'tenant=' => null];

        $this->assertTrue($this->command->has($params, 'verified'));
        $this->assertNull($this->command->value($params, 'verified'));
        $this->assertSame('', $this->command->value($params, 'tenant'));
        $this->assertFalse($this->command->has($params, 'generate'));
    }
}
