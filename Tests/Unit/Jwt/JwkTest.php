<?php

declare(strict_types=1);

namespace Flownative\OpenIdConnect\Client\Tests\Unit\Jwt;

use Flownative\OpenIdConnect\Client\Jwt\Jwk;
use Flownative\OpenIdConnect\Client\Jwt\JwkValidationFailed;
use Flownative\OpenIdConnect\Client\Jwt\SupportedAlgorithm;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Validation\Validator;
use PHPUnit\Framework\Assert;
use PHPUnit\Framework\TestCase;

class JwkTest extends TestCase
{
    /**
     * @param array<string,mixed> $values
     * @dataProvider invalidValuesProvider
     */
    public function testFromArrayRejectsInvalidValues(
        array $values,
        ?\Throwable $expectedException,
    ): void {
        try {
            Jwk::fromArray($values);
            $actualException = null;
        } catch (\Throwable $actualException) {
        }

        Assert::assertEquals($expectedException, $actualException);
    }

    /**
     * @return iterable<string,array{
     *     values: array<string,mixed>,
     *     expectedException: class-string<\Throwable>|null
     * }>
     */
    public static function invalidValuesProvider(): iterable
    {
        yield 'values without key type' => [
            'values' => [],
            'expectedException' => JwkValidationFailed::becauseNoTypeWasSupplied(),
        ];

        yield 'values with unsupported algorithm' => [
            'values' => [
                'kty' => 'EC',
                'alg' => 'RS128'
            ],
            'expectedException' => JwkValidationFailed::becauseAlgorithmIsNotSupported('RS128'),
        ];

        yield 'values with unsupported key type' => [
            'values' => [
                'kty' => 'oct',
            ],
            'expectedException' => JwkValidationFailed::becauseTheKeyTypeIsNotSupported('oct'),
        ];

        yield 'values with a curve no algorithm supports' => [
            'values' => [
                'kty' => 'EC',
                'crv' => 'P-224',
            ],
            'expectedException' => JwkValidationFailed::becauseECCurveIsNotSupported('P-224'),
        ];

        yield 'values with a mismatch between key type and algorithm' => [
            'values' => [
                'kty' => 'OKP',
                'alg' => 'RS256',
            ],
            'expectedException' => JwkValidationFailed::becauseTheAlgorithmDoesNotMatchTheKeyType('RS256', 'OKP'),
        ];
    }

    /**
     * @dataProvider algorithmsProvider
     */
    public function testFromArraySupportsAllSupportedAlgorithms(
        SupportedAlgorithm $algorithm,
    ): void {
        $keyPair = TestKeyPair::create($algorithm);
        $unparameterizedJwk = Jwk::fromArray(array_merge(
            $keyPair->publicJwk,
            [
                'alg' => $algorithm->value,
            ]
        ));
        self::assertSame($algorithm, $unparameterizedJwk->algorithm);
        self::assertSame(null, $unparameterizedJwk->intendedUse);
        self::assertSame(null, $unparameterizedJwk->keyId);

        $jwk = Jwk::fromArray(array_merge(
            $keyPair->publicJwk,
            [
                'use' => 'sig',
                'kid' => 'test',
                'alg' => $algorithm->value,
            ]
        ));

        self::assertSame($algorithm, $jwk->algorithm);
        self::assertSame('sig', $jwk->intendedUse);
        self::assertSame('test', $jwk->keyId);

        $parser = new Parser(decoder: new JoseEncoder());
        $validator = new Validator();

        $foreignKeyPair = TestKeyPair::create($algorithm);
        $constraint = $jwk->getSignatureConstraint();

        self::assertTrue($validator->validate($parser->parse($keyPair->sign()), $constraint));
        self::assertFalse($validator->validate($parser->parse($foreignKeyPair->sign()), $constraint));
    }

    /**
     * @return iterable<string,array{
     *     algorithm: SupportedAlgorithm,
     * }>
     */
    public static function algorithmsProvider(): iterable
    {
        foreach (SupportedAlgorithm::cases() as $algorithm) {
            yield $algorithm->value => [
                'algorithm' => $algorithm
            ];
        }
    }

    public function testFromArrayDefaultsRsaKeysToRs256(): void
    {
        $keyPair = TestKeyPair::create(SupportedAlgorithm::RS512);

        // We explicitly default to RS256 if no algorithm is provided in the JWK
        $jwk = Jwk::fromArray($keyPair->publicJwk);

        self::assertSame(SupportedAlgorithm::RS256, $jwk->algorithm);
    }

    public function testFromArrayWrapsFailuresOfTheUnderlyingKeyLoader(): void
    {
        // A key type this client supports, but without the members phpseclib needs
        $this->expectException(JwkValidationFailed::class);
        $this->expectExceptionCode(1787915591);

        Jwk::fromArray(['kty' => 'RSA', 'alg' => 'RS256']);
    }

    /**
     * @dataProvider keyProvider
     */
    public function testQualifiesForSignatureVerification(
        Jwk $key,
        ?string $keyId,
        ?string $algorithm,
        bool $expectedResult,
    ): void {
        $reason = '';

        self::assertSame(
            $expectedResult,
            $key->qualifiesForSignatureVerification($keyId, $algorithm, $reason)
        );
    }

    /**
     * @return iterable<string,array{
     *     key: Jwk,
     *     keyId: ?string,
     *     algorithm: ?string,
     *     expectedResult: bool,
     * }>
     */
    public static function keyProvider(): iterable
    {
        $keyPair = TestKeyPair::create(SupportedAlgorithm::RS512);

        yield 'general usage key without additional constraints' => [
            'key' => Jwk::fromArray(
                $keyPair->publicJwk,
            ),
            'keyId' => null,
            'algorithm' => null,
            'expectedResult' => true,
        ];

        yield 'general usage key with non-matching key id' => [
            'key' => Jwk::fromArray(
                $keyPair->publicJwk,
            ),
            'keyId' => 'my-key',
            'algorithm' => null,
            'expectedResult' => false,
        ];

        yield 'general usage key with non-matching algorithm' => [
            'key' => Jwk::fromArray(
                $keyPair->publicJwk,
            ),
            'keyId' => null,
            'algorithm' => SupportedAlgorithm::RS384->value,
            'expectedResult' => false,
        ];

        yield 'general usage key with matching constraints' => [
            'key' => Jwk::fromArray(array_merge(
                $keyPair->publicJwk,
                [
                    'kid' => 'my-key',
                    'alg' => SupportedAlgorithm::RS512->value,
                ],
            )),
            'keyId' => 'my-key',
            'algorithm' => SupportedAlgorithm::RS512->value,
            'expectedResult' => true,
        ];

        yield 'non-signature key without additional constraints' => [
            'key' => Jwk::fromArray(array_merge(
                $keyPair->publicJwk,
                [
                    'use' => 'enc',
                ],
            )),
            'keyId' => null,
            'algorithm' => null,
            'expectedResult' => false,
        ];

        yield 'non-signature key with matching constraints' => [
            'key' => Jwk::fromArray(array_merge(
                $keyPair->publicJwk,
                [
                    'kid' => 'my-key',
                    'alg' => SupportedAlgorithm::RS512->value,
                    'use' => 'enc',
                ],
            )),
            'keyId' => 'my-key',
            'algorithm' => SupportedAlgorithm::RS512->value,
            'expectedResult' => false,
        ];

        yield 'signature key without additional constraints' => [
            'key' => Jwk::fromArray(array_merge(
                $keyPair->publicJwk,
                [
                    'use' => 'sig',
                ],
            )),
            'keyId' => null,
            'algorithm' => null,
            'expectedResult' => true,
        ];

        yield 'signature key with matching constraints' => [
            'key' => Jwk::fromArray(array_merge(
                $keyPair->publicJwk,
                [
                    'kid' => 'my-key',
                    'alg' => SupportedAlgorithm::RS512->value,
                    'use' => 'sig',
                ],
            )),
            'keyId' => 'my-key',
            'algorithm' => SupportedAlgorithm::RS512->value,
            'expectedResult' => true,
        ];
    }
}
