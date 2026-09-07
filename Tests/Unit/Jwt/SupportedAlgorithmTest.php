<?php

declare(strict_types=1);

namespace Flownative\OpenIdConnect\Client\Tests\Unit\Jwt;

use Flownative\OpenIdConnect\Client\Jwt\JwkValidationFailed;
use Flownative\OpenIdConnect\Client\Jwt\SupportedAlgorithm;
use PHPUnit\Framework\Assert;
use PHPUnit\Framework\TestCase;

class SupportedAlgorithmTest extends TestCase
{
    /**
     * @dataProvider keyTypeAndCurveProvider
     */
    public function testFromKeyTypeAndCurve(
        string $keyType,
        ?string $curve,
        ?SupportedAlgorithm $expectedAlgorithm,
        ?\Throwable $expectedException,
        ?int $expectedExceptionCode,
    ): void {
        try {
            $actualAlgorithm = SupportedAlgorithm::fromKeyTypeAndCurve($keyType, $curve);
            Assert::assertNull($expectedException);
            Assert::assertSame($expectedAlgorithm, $actualAlgorithm);
        } catch (\Throwable $actualException) {
            Assert::assertNull($expectedAlgorithm);
            Assert::assertIsString($expectedException);
            Assert::assertEquals($expectedException, $actualException);
            Assert::assertIsInt($expectedExceptionCode);
            Assert::assertSame($expectedExceptionCode, $actualException->getCode());
        }
    }

    /**
     * @return iterable<string,array{
     *     keyType: string,
     *     curve: ?string,
     *     expectedAlgorithm: ?SupportedAlgorithm,
     *     expectedException: class-string<\Throwable>|null
     * }>
     */
    public static function keyTypeAndCurveProvider(): iterable
    {
        yield 'EC key without curve' => [
            'keyType' => 'EC',
            'curve' => null,
            'expectedAlgorithm' => null,
            'expectedException' => JwkValidationFailed::becauseECCurveIsNotSupported(null),
        ];

        yield 'EC key with invalid curve' => [
            'keyType' => 'EC',
            'curve' => 'P-128',
            'expectedAlgorithm' => null,
            'expectedException' => JwkValidationFailed::becauseECCurveIsNotSupported('P-128'),
        ];

        yield 'EC key with valid curve' => [
            'keyType' => 'EC',
            'curve' => 'P-521',
            'expectedAlgorithm' => SupportedAlgorithm::ES512,
            'expectedException' => null,
        ];

        yield 'OKP key without curve' => [
            'keyType' => 'OKP',
            'curve' => null,
            'expectedAlgorithm' => null,
            'expectedException' => JwkValidationFailed::becauseOKPCurveIsNotSupported(null),
        ];

        yield 'OKP key with invalid curve' => [
            'keyType' => 'OKP',
            // Key agreement curve, not suitable for signatures
            'curve' => 'X25519',
            'expectedAlgorithm' => null,
            'expectedException' => JwkValidationFailed::becauseOKPCurveIsNotSupported('X25519'),
        ];

        yield 'unsupported key type' => [
            'keyType' => 'okp',
            'curve' => null,
            'expectedAlgorithm' => null,
            'expectedException' => JwkValidationFailed::becauseKeyTypeIsNotSupported('X25519'),
        ];
    }
}
