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
    ): void {
        try {
            $actualAlgorithm = SupportedAlgorithm::fromKeyTypeAndCurve($keyType, $curve);
            Assert::assertNull($expectedException);
            Assert::assertSame($expectedAlgorithm, $actualAlgorithm, $actualAlgorithm->value);
        } catch (\Throwable $actualException) {
            Assert::assertEquals($expectedException, $actualException);
            Assert::assertNull($expectedAlgorithm);
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

        yield 'OKP key with valid curve' => [
            'keyType' => 'OKP',
            'curve' => 'Ed25519',
            'expectedAlgorithm' => SupportedAlgorithm::EdDSA,
            'expectedException' => null,
        ];

        yield 'unsupported key type' => [
            'keyType' => 'okp',
            'curve' => null,
            'expectedAlgorithm' => null,
            'expectedException' => JwkValidationFailed::becauseTheKeyTypeIsNotSupported('okp'),
        ];

        yield 'RSA default' => [
            'keyType' => 'RSA',
            'curve' => null,
            'expectedAlgorithm' => SupportedAlgorithm::RS256,
            'expectedException' => null,
        ];
    }
}
