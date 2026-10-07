<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Tests\Unit;

use CodeIgniter\Test\CIUnitTestCase;
use Ephraitech\Auth\Config\Auth;
use Ephraitech\Auth\Exceptions\WeakPasswordException;
use Ephraitech\Auth\Passwords\PasswordPolicy;

final class PasswordPolicyTest extends CIUnitTestCase
{
    private PasswordPolicy $policy;

    protected function setUp(): void
    {
        parent::setUp();

        $this->policy = new PasswordPolicy(new Auth());
    }

    public function testCompliantPasswordPasses(): void
    {
        $this->assertSame([], $this->policy->errors('Kampala-Bukuli-77'));
    }

    public function testAllFailuresAreCollected(): void
    {
        $errors = $this->policy->errors('abc');

        $this->assertCount(2, $errors, 'expected both min-length and number errors');
    }

    public function testPasswordContainingEmailLocalPartIsRejected(): void
    {
        $errors = $this->policy->errors('john2026xyz', ['email' => 'john@example.com']);

        $this->assertContains('The password cannot contain your email address.', $errors);
    }

    public function testPasswordContainingNationalPhoneNumberIsRejected(): void
    {
        $errors = $this->policy->errors('x0772123456', ['phone' => '+256772123456']);

        $this->assertContains('The password cannot contain your phone number.', $errors);
    }

    public function testBcryptByteLimitCountsMultibyteCharacters(): void
    {
        // 40 x "é" (2 bytes each) + "1" = 81 bytes, but only 41 characters.
        $errors = $this->policy->errors(str_repeat('é', 40) . '1');

        $this->assertCount(1, $errors);
        $this->assertStringContainsString('bytes', $errors[0]);
    }

    public function testNullByteIsRejected(): void
    {
        $this->assertNotSame([], $this->policy->errors("Valid-Pass-1\0"));
    }

    public function testAssertThrowsWithAllErrors(): void
    {
        try {
            $this->policy->assert('abc');
            $this->fail('Expected WeakPasswordException');
        } catch (WeakPasswordException $e) {
            $this->assertCount(2, $e->getErrors());
        }
    }
}
