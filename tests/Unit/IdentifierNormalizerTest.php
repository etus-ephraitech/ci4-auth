<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Tests\Unit;

use CodeIgniter\Test\CIUnitTestCase;
use Ephraitech\Auth\Config\Auth;
use Ephraitech\Auth\Exceptions\InvalidIdentifierException;
use Ephraitech\Auth\Support\IdentifierNormalizer;
use PHPUnit\Framework\Attributes\DataProvider;

final class IdentifierNormalizerTest extends CIUnitTestCase
{
    /**
     * @param list<string> $enabled
     */
    private function normalizer(array $enabled = ['email', 'username', 'phone']): IdentifierNormalizer
    {
        $config                      = new Auth();
        $config->identifiers         = $enabled;
        $config->loginIdentifiers    = $enabled;
        $config->requiredIdentifiers = [$enabled[0]];

        return new IdentifierNormalizer($config);
    }

    public function testEmailIsTrimmedAndLowercased(): void
    {
        $this->assertSame('john@example.com', $this->normalizer()->normalize('email', '  John@Example.COM '));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function ugandanPhoneFormats(): array
    {
        return [
            'local with trunk zero'   => ['0772123456'],
            'national without zero'   => ['772123456'],
            'international no plus'   => ['256772123456'],
            'international spaced'    => ['+256 772 123 456'],
            'international 00 prefix' => ['00256772123456'],
            'punctuated'              => ['(0772) 123-456'],
        ];
    }

    #[DataProvider('ugandanPhoneFormats')]
    public function testUgandanPhoneFormatsNormalizeToE164(string $input): void
    {
        $this->assertSame('+256772123456', $this->normalizer()->normalize('phone', $input));
    }

    public function testForeignInternationalNumberIsKept(): void
    {
        $this->assertSame('+254712345678', $this->normalizer()->normalize('phone', '+254 712 345 678'));
    }

    public function testNormalizationIsIdempotent(): void
    {
        $normalizer = $this->normalizer();

        foreach (['email' => 'A@B.com', 'username' => 'John.Doe', 'phone' => '0772123456'] as $type => $value) {
            $once = $normalizer->normalize($type, $value);

            $this->assertSame($once, $normalizer->normalize($type, $once), "{$type} should be idempotent");
        }
    }

    public function testInvalidEmailIsRejected(): void
    {
        $this->expectException(InvalidIdentifierException::class);

        $this->normalizer()->normalize('email', 'not-an-email');
    }

    public function testReservedUsernameIsRejected(): void
    {
        $this->expectException(InvalidIdentifierException::class);

        $this->normalizer()->normalize('username', 'Root');
    }

    public function testUsernameWithSpacesIsRejected(): void
    {
        $this->expectException(InvalidIdentifierException::class);

        $this->normalizer()->normalize('username', 'john doe');
    }

    public function testDisabledTypeIsRejected(): void
    {
        $this->expectException(InvalidIdentifierException::class);

        $this->normalizer(['email'])->normalize('phone', '0772123456');
    }

    public function testTryNormalizeReturnsNullInsteadOfThrowing(): void
    {
        $this->assertNull($this->normalizer()->tryNormalize('email', 'nope'));
    }

    public function testLoginTypeDetection(): void
    {
        $normalizer = $this->normalizer();

        $this->assertSame('email', $normalizer->detectLoginType('jane@example.com'));
        $this->assertSame('phone', $normalizer->detectLoginType('0772 123 456'));
        $this->assertSame('username', $normalizer->detectLoginType('jane.doe'));
        $this->assertSame('username', $normalizer->detectLoginType('12345'), 'short digit strings are usernames');
    }

    public function testSingleLoginIdentifierSkipsDetection(): void
    {
        $this->assertSame('email', $this->normalizer(['email'])->detectLoginType('anything'));
    }
}
