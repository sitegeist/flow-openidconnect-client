<?php

declare(strict_types=1);

namespace Flownative\OpenIdConnect\Client\Tests\Unit\Jwt;

use Flownative\OpenIdConnect\Client\Jwt\Jwk;
use Flownative\OpenIdConnect\Client\Jwt\JwkSet;
use Flownative\OpenIdConnect\Client\Jwt\SignatureVerificationKeyCouldNotBeResolved;
use Flownative\OpenIdConnect\Client\Jwt\SignatureVerificationKeyIsAmbiguous;
use Flownative\OpenIdConnect\Client\Jwt\SupportedAlgorithm;
use PHPUnit\Framework\Assert;
use PHPUnit\Framework\TestCase;

class JwkSetTest extends TestCase
{
    /**
     * @param array<int,array<string,mixed>> $values
     * @dataProvider valuesProvider
     */
    public function testFromArray(array $values, JwkSet $expectedSet): void
    {
        $actualSet = JwkSet::fromArray($values);
        Assert::assertEquals($expectedSet, $actualSet);
    }

    /**
     * @return iterable<string,array{
     *     values: array<int,array<string,mixed>>,
     *     expectedSet: JwkSet
     * }>>
     */
    public static function valuesProvider(): iterable
    {
        yield 'empty values' => [
            'values' => [],
            'expectedSet' => JwkSet::create([]),
        ];

        $keyPair = TestKeyPair::create(SupportedAlgorithm::RS512);

        yield 'partially valid values' => [
            'values' => [
                array_merge(
                    $keyPair->publicJwk,
                    [
                        'alg' => SupportedAlgorithm::RS512->value,
                    ]
                ),
                [
                    'kty' => 'wat',
                ]
            ],
            'expectedSet' => JwkSet::create(
                [
                    Jwk::fromArray(array_merge(
                        $keyPair->publicJwk,
                        [
                            'alg' => SupportedAlgorithm::RS512->value,
                        ]
                    ))
                ],
                [
                    1 => 'Key 1: Requested Jwk type wat is not supported',
                ]
            ),
        ];
    }

    /**
     * @dataProvider keySetProvider
     */
    public function testRequireSignatureVerificationKey(
        JwkSet $subject,
        ?string $keyId,
        ?string $algorithm,
        ?Jwk $expectedKey,
        ?\Throwable $expectedException,
    ): void {
        $actualException = null;
        try {
            $actualKey = $subject->requireSignatureVerificationKey(
                $keyId,
                $algorithm,
            );
            Assert::assertSame($expectedKey, $actualKey);
            Assert::assertNull($expectedException);
        } catch (\Throwable $actualException) {
            Assert::assertNull($expectedKey);
        }
        Assert::assertEquals($expectedException, $actualException);
    }

    /**
     * @return iterable<string,array{
     *     subject: JwkSet,
     *     keyId: ?string,
     *     algorithm: ?string,
     *     expectedKey: ?Jwk,
     *     expectedException: ?\Throwable,
     * }>
     */
    public static function keySetProvider(): iterable
    {
        $RS512KeyPair = TestKeyPair::create(SupportedAlgorithm::RS512);
        $myRS512Key = Jwk::fromArray(array_merge(
            $RS512KeyPair->publicJwk,
            [
                'alg' => SupportedAlgorithm::RS512->value,
                'kid' => 'my-rs512-key',
            ]
        ));

        $RS384KeyPair = TestKeyPair::create(SupportedAlgorithm::RS384);
        $myRS384Key = Jwk::fromArray(array_merge(
            $RS384KeyPair->publicJwk,
            [
                'alg' => SupportedAlgorithm::RS384->value,
                'kid' => 'my-rs384-key',
            ]
        ));

        yield 'empty set' => [
            'subject' => JwkSet::create([]),
            'keyId' => null,
            'algorithm' => null,
            'expectedKey' => null,
            'expectedException' => SignatureVerificationKeyCouldNotBeResolved::becauseNoKeyMatched([]),
        ];

        yield 'singleton with a signature key and no additional constraints' => [
            'subject' => JwkSet::create([$myRS512Key]),
            'keyId' => null,
            'algorithm' => null,
            'expectedKey' => $myRS512Key,
            'expectedException' => null,
        ];

        yield 'set with no signature key matching the id constraint' => [
            'subject' => JwkSet::create([$myRS512Key]),
            'keyId' => 'my-other-key',
            'algorithm' => null,
            'expectedKey' => null,
            'expectedException' => SignatureVerificationKeyCouldNotBeResolved::becauseNoKeyMatched([
                'Key my-rs512-key: Does not match the requested ID'
            ]),
        ];

        yield 'set with no signature key matching the algorithm constraint' => [
            'subject' => JwkSet::create([$myRS512Key]),
            'keyId' => null,
            'algorithm' => SupportedAlgorithm::RS256->value,
            'expectedKey' => null,
            'expectedException' => SignatureVerificationKeyCouldNotBeResolved::becauseNoKeyMatched([
                'Key my-rs512-key: Does not match the requested algorithm'
            ]),
        ];

        yield 'set with no signature key' => [
            'subject' => JwkSet::create(
                [Jwk::fromArray(array_merge(
                    $RS512KeyPair->publicJwk,
                    [
                        'alg' => SupportedAlgorithm::RS512->value,
                        'kid' => 'my-rs512-key',
                        'use' => 'enc',
                    ]
                ))]
            ),
            'keyId' => null,
            'algorithm' => null,
            'expectedKey' => null,
            'expectedException' => SignatureVerificationKeyCouldNotBeResolved::becauseNoKeyMatched([
                'Key my-rs512-key: Not intended to be used for signature verification'
            ]),
        ];

        yield 'set with multiple signature keys and no constraints' => [
            'subject' => JwkSet::create([
                $myRS384Key,
                $myRS512Key,
            ]),
            'keyId' => null,
            'algorithm' => null,
            'expectedKey' => null,
            'expectedException' => SignatureVerificationKeyIsAmbiguous::becauseMultipleKeysMatched([
                'my-rs384-key',
                'my-rs512-key',
            ]),
        ];

        yield 'set with multiple signature keys and one matching the id constraint' => [
            'subject' => JwkSet::create([
                $myRS384Key,
                $myRS512Key,
            ]),
            'keyId' => 'my-rs512-key',
            'algorithm' => null,
            'expectedKey' => $myRS512Key,
            'expectedException' => null,
        ];

        yield 'set with multiple signature keys and one matching the algorithm constraint' => [
            'subject' => JwkSet::create([
                $myRS384Key,
                $myRS512Key,
            ]),
            'keyId' => null,
            'algorithm' => SupportedAlgorithm::RS384->value,
            'expectedKey' => $myRS384Key,
            'expectedException' => null,
        ];
    }
}
