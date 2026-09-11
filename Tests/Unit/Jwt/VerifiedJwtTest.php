<?php

declare(strict_types=1);

namespace Flownative\OpenIdConnect\Client\Tests\Unit\Jwt;

use Flownative\OpenIdConnect\Client\Jwt\AudiencesAreTrusted;
use Flownative\OpenIdConnect\Client\Jwt\Jwk;
use Flownative\OpenIdConnect\Client\Jwt\JwkSet;
use Flownative\OpenIdConnect\Client\Jwt\JwtMissesSignatureKey;
use Flownative\OpenIdConnect\Client\Jwt\JwtVerification;
use Flownative\OpenIdConnect\Client\Jwt\JwtVerificationSucceeded;
use Flownative\OpenIdConnect\Client\Jwt\JwtViolatesConstraints;
use Flownative\OpenIdConnect\Client\Jwt\SupportedAlgorithm;
use Flownative\OpenIdConnect\Client\Jwt\VerifiedJwt;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Builder;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\ConstraintViolation;
use PHPUnit\Framework\Assert;
use PHPUnit\Framework\TestCase;

class VerifiedJwtTest extends TestCase
{
    private const NOW = '2026-09-08 10:08:25';

    private static ?TestKeyPair $keyPair = null;
    private ?JwtVerification $policy;

    protected function setUp(): void
    {
        parent::setUp();

        $key = Jwk::fromArray(array_merge(
            self::requireKeyPair()->publicJwk,
            [
                'alg' => SupportedAlgorithm::RS512->value,
                'kid' => 'my-key',
            ]
        ));
        $this->policy = new JwtVerification(
            jwkSet: JwkSet::create([$key]),
            expectedIssuer: 'me',
            expectedAudience: 'us',
            trustedAudiences: ['partner'],
        );
    }

    /**
     * @dataProvider jwtProvider
     */
    public function testTryFromJWTString(
        string|callable $jwt,
        TestKeyPair $keyPair,
        bool $tokenExpected,
        mixed $expectedResult,
    ): void {
        Assert::assertNotNull($this->policy);
        $actualResult = null;
        if (!is_string($jwt)) {
            $jwt = $keyPair->sign($jwt);
        }
        $actualToken = VerifiedJwt::tryFromJWTString($jwt, $this->policy, null, $actualResult);

        if ($tokenExpected) {
            Assert::assertNotNull($actualToken);
            Assert::assertSame($jwt, $actualToken?->token->toString());
        } else {
            Assert::assertNull($actualToken);
        }
        Assert::assertEquals($expectedResult, $actualResult);
    }

    /**
     * @return iterable<string,array{
     *     jwt: string|callable,
     *     keyPair: TestKeyPair,
     *     tokenExpected: bool,
     *     expectedResult: mixed,
     * }>
     */
    public static function jwtProvider(): iterable
    {
        yield 'invalid token structure' => [
            'jwt' => '',
            'keyPair' => self::requireKeyPair(),
            'tokenExpected' => false,
            'expectedResult' => null,
        ];

        yield 'undecodable content' => [
            'jwt' => '!.!.!',
            'keyPair' => self::requireKeyPair(),
            'tokenExpected' => false,
            'expectedResult' => null,
        ];

        yield 'unsupported header' => [
            'jwt' => static fn (Builder $builder): Builder => $builder
                ->withHeader('kid', 'my-key')
                ->withHeader('enc', 'A128CBC-HS256')
                ->issuedBy('me')
                ->permittedFor('us', 'partner')
                ->issuedAt((new \DateTimeImmutable(self::NOW))->modify('-10 seconds')),
            'keyPair' => self::requireKeyPair(),
            'tokenExpected' => false,
            'expectedResult' => null,
        ];

        $encoder = new JoseEncoder();

        yield 'no algorithm' => [
            'jwt' => $encoder->base64UrlEncode($encoder->jsonEncode(['alg' => 'none', 'typ' => 'JWT']))
                . '.' . $encoder->base64UrlEncode($encoder->jsonEncode(['iss' => 'me', 'aud' => 'us'])) . '.',
            'keyPair' => self::requireKeyPair(),
            'tokenExpected' => false,
            'expectedResult' => new JwtMissesSignatureKey(),
        ];

        yield 'valid token' => [
            'jwt' => static fn (Builder $builder): Builder => $builder
                ->withHeader('kid', 'my-key')
                ->issuedBy('me')
                ->permittedFor('us', 'partner')
                ->issuedAt((new \DateTimeImmutable(self::NOW))->modify('+60 seconds')),
            'keyPair' => self::requireKeyPair(),
            'tokenExpected' => true,
            'expectedResult' => new JwtVerificationSucceeded(),
        ];

        yield 'valid token without issuing time' => [
            'jwt' => static fn (Builder $builder): Builder => $builder
                ->withHeader('kid', 'my-key')
                ->issuedBy('me')
                ->permittedFor('us'),
            'keyPair' => self::requireKeyPair(),
            'tokenExpected' => true,
            'expectedResult' => new JwtVerificationSucceeded(),
        ];

        yield 'wrong signature' => [
            'jwt' => static fn (Builder $builder): Builder => $builder
                ->withHeader('kid', 'my-key')
                ->issuedBy('me')
                ->permittedFor('us')
                ->issuedAt((new \DateTimeImmutable(self::NOW))->modify('-10 seconds')),
            'keyPair' => TestKeyPair::create(SupportedAlgorithm::RS512),
            'tokenExpected' => false,
            'expectedResult' => new JwtViolatesConstraints([
                ConstraintViolation::error(
                    'Token signature mismatch',
                    Jwk::fromArray(array_merge(
                        self::requireKeyPair()->publicJwk,
                        [
                            'alg' => SupportedAlgorithm::RS512->value,
                            'kid' => 'my-key',
                        ]
                    ))->getSignatureConstraint(),
                )
            ]),
        ];

        yield 'wrong key id' => [
            'jwt' => static fn (Builder $builder): Builder => $builder
                ->withHeader('kid', 'someone-elses-key')
                ->issuedBy('me')
                ->permittedFor('us')
                ->issuedAt((new \DateTimeImmutable(self::NOW))->modify('-10 seconds')),
            'keyPair' => self::requireKeyPair(),
            'tokenExpected' => false,
            'expectedResult' => new JwtMissesSignatureKey(),
        ];

        yield 'wrong issuer' => [
            'jwt' => static fn (Builder $builder): Builder => $builder
                ->withHeader('kid', 'my-key')
                ->issuedBy('someone-else')
                ->permittedFor('us')
                ->issuedAt((new \DateTimeImmutable(self::NOW))->modify('-10 seconds')),
            'keyPair' => self::requireKeyPair(),
            'tokenExpected' => false,
            'expectedResult' => new JwtViolatesConstraints([
                ConstraintViolation::error(
                    'The token was not issued by the given issuers',
                    new IssuedBy('someone-else'),
                )
            ]),
        ];

        yield 'partially wrong audience' => [
            'jwt' => static fn (Builder $builder): Builder => $builder
                ->withHeader('kid', 'my-key')
                ->issuedBy('me')
                ->permittedFor('us', 'someone-else')
                ->issuedAt((new \DateTimeImmutable(self::NOW))->modify('-10 seconds')),
            'keyPair' => self::requireKeyPair(),
            'tokenExpected' => false,
            'expectedResult' => new JwtViolatesConstraints([
                ConstraintViolation::error(
                    'The token claims audience(s) not trusted by this client: someone-else',
                    new AudiencesAreTrusted('us', ['partner']),
                )
            ]),
        ];

        yield 'wrong audience' => [
            'jwt' => static fn (Builder $builder): Builder => $builder
                ->withHeader('kid', 'my-key')
                ->issuedBy('me')
                ->permittedFor('someone-else')
                ->issuedAt((new \DateTimeImmutable(self::NOW))->modify('-10 seconds')),
            'keyPair' => self::requireKeyPair(),
            'tokenExpected' => false,
            'expectedResult' => new JwtViolatesConstraints([
                ConstraintViolation::error(
                    'The token is not allowed to be used by this audience',
                    new PermittedFor('someone-else'),
                ),
                ConstraintViolation::error(
                    'The token claims audience(s) not trusted by this client: someone-else',
                    new AudiencesAreTrusted('us', ['us']),
                )
            ]),
        ];

        yield 'valid, expired token' => [
            'jwt' => static fn (Builder $builder): Builder => $builder
                ->withHeader('kid', 'my-key')
                ->issuedBy('me')
                ->permittedFor('us')
                ->issuedAt((new \DateTimeImmutable(self::NOW))->sub(new \DateInterval('PT1H')))
                ->expiresAt((new \DateTimeImmutable(self::NOW))->sub(new \DateInterval('PT61S'))),
            'keyPair' => self::requireKeyPair(),
            'tokenExpected' => true,
            'expectedResult' => new JwtVerificationSucceeded(),
        ];

        yield 'valid token, but not to be used before a future date' => [
            'jwt' => static fn (Builder $builder): Builder => $builder
                ->withHeader('kid', 'my-key')
                ->issuedBy('me')
                ->permittedFor('us')
                ->canOnlyBeUsedAfter((new \DateTimeImmutable(self::NOW))->modify('+61 seconds'))
                ->issuedAt((new \DateTimeImmutable(self::NOW))->modify('-10 seconds')),
            'keyPair' => self::requireKeyPair(),
            'tokenExpected' => true,
            'expectedResult' => new JwtVerificationSucceeded(),
        ];

        yield 'valid token violating the Temporal Prime Directive' => [
            'jwt' => static fn (Builder $builder): Builder => $builder
                ->withHeader('kid', 'my-key')
                ->issuedBy('me')
                ->permittedFor('us')
                ->issuedAt((new \DateTimeImmutable(self::NOW))->modify('+120 seconds')),
            'keyPair' => self::requireKeyPair(),
            'tokenExpected' => true,
            'expectedResult' => new JwtVerificationSucceeded(),
        ];
    }

    private static function requireKeyPair(): TestKeyPair
    {
        return self::$keyPair ??= TestKeyPair::create(SupportedAlgorithm::RS512);
    }
}
