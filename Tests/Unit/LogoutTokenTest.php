<?php

declare(strict_types=1);

namespace Flownative\OpenIdConnect\Client\Tests\Unit;

use Flownative\OpenIdConnect\Client\BackChannelLogout\AuthenticationRevocationTag;
use Flownative\OpenIdConnect\Client\BackChannelLogout\LogoutToken;
use Flownative\OpenIdConnect\Client\BackChannelLogout\LogoutTokenIsInvalid;
use Flownative\OpenIdConnect\Client\Jwt\Jwk;
use Flownative\OpenIdConnect\Client\Jwt\JwkSet;
use Flownative\OpenIdConnect\Client\Jwt\JwtVerification;
use Flownative\OpenIdConnect\Client\Jwt\SupportedAlgorithm;
use Flownative\OpenIdConnect\Client\Jwt\VerifiedJwt;
use Flownative\OpenIdConnect\Client\Tests\Unit\Jwt\TestKeyPair;
use Lcobucci\JWT\Token\Builder;
use Neos\Flow\Utility\Algorithms;
use PHPUnit\Framework\Assert;
use PHPUnit\Framework\TestCase;

class LogoutTokenTest extends TestCase
{
    private const THEN = '2026-09-09 11:09:26';

    private static ?TestKeyPair $keyPair = null;

    /**
     * @var array<string,JwtVerification> indexed by issuer
     */
    private static array $policies = [];

    /**
     * @dataProvider jwtProvider
     */
    public function testCreate(
        VerifiedJwt $token,
        ?LogoutTokenProperties $expectedTokenProperties,
        ?\Throwable $expectedException,
    ): void {
        try {
            $actualToken = LogoutToken::create($token);
            $actualException = null;
        } catch (\Throwable $actualException) {
            $actualToken = null;
        }

        if ($expectedTokenProperties) {
            Assert::assertInstanceOf(LogoutToken::class, $actualToken);
            Assert::assertSame($expectedTokenProperties->subject, $actualToken->subject);
            Assert::assertSame($expectedTokenProperties->sessionId, $actualToken->sessionId);
            Assert::assertEquals($expectedTokenProperties->expires, $actualToken->expires);
            Assert::assertSame($expectedTokenProperties->identifier, $actualToken->identifier);
            Assert::assertSame($expectedTokenProperties->issuer, $actualToken->issuer);
            Assert::assertSame($expectedTokenProperties->revocationTag->value, $actualToken->revocationTag->value);
        } else {
            Assert::assertNull($actualToken);
        }
        Assert::assertEquals($expectedException, $actualException);
    }

    /**
     * @return iterable<string,array{
     *     token: VerifiedJwt,
     *     expectedTokenProperties: ?LogoutTokenProperties,
     *     expectedException: ?\Throwable,
     * }>
     */
    public static function jwtProvider(): iterable
    {
        $subject = Algorithms::generateUUID();
        $sessionId = Algorithms::generateRandomString(16);

        yield 'valid logout token' => [
            'token' => VerifiedJwt::tryFromJWTString(
                self::requireKeyPair()->sign(
                    static fn (Builder $builder): Builder => $builder
                        ->withHeader('kid', 'my-key')
                        ->issuedBy('me')
                        ->permittedFor('us', 'partner')
                        ->issuedAt((new \DateTimeImmutable(self::THEN))->modify('-10 seconds'))
                        ->withClaim('events', [LogoutToken::EVENT => new \stdClass()])
                        ->identifiedBy('my-id')
                        ->withClaim('sid', $sessionId)
                        ->relatedTo($subject)
                        ->expiresAt(new \DateTimeImmutable(self::THEN))
                ),
                self::requirePolicy(),
            ),
            'expectedTokenProperties' => new LogoutTokenProperties(
                subject: $subject,
                sessionId: $sessionId,
                expires: new \DateTimeImmutable(self::THEN),
                identifier: 'my-id',
                issuer: 'me',
                revocationTag: AuthenticationRevocationTag::forSessionId('me', $sessionId),
            ),
            'expectedException' => null,
        ];

        yield 'valid logout token with only subject' => [
            'token' => VerifiedJwt::tryFromJWTString(
                self::requireKeyPair()->sign(
                    static fn (Builder $builder): Builder => $builder
                        ->withHeader('kid', 'my-key')
                        ->issuedBy('me')
                        ->permittedFor('us', 'partner')
                        ->issuedAt((new \DateTimeImmutable(self::THEN))->modify('-10 seconds'))
                        ->withClaim('events', [LogoutToken::EVENT => new \stdClass()])
                        ->identifiedBy('my-id')
                        ->relatedTo($subject)
                        ->expiresAt(new \DateTimeImmutable(self::THEN))
                ),
                self::requirePolicy(),
            ),
            'expectedTokenProperties' => new LogoutTokenProperties(
                subject: $subject,
                sessionId: null,
                expires: new \DateTimeImmutable(self::THEN),
                identifier: 'my-id',
                issuer: 'me',
                revocationTag: AuthenticationRevocationTag::forSubject('me', $subject),
            ),
            'expectedException' => null,
        ];

        yield 'missing event claim' => [
            'token' => VerifiedJwt::tryFromJWTString(
                self::requireKeyPair()->sign(
                    static fn (Builder $builder): Builder => $builder
                        ->withHeader('kid', 'my-key')
                        ->issuedBy('me')
                        ->permittedFor('us', 'partner')
                        ->issuedAt((new \DateTimeImmutable(self::THEN))->modify('-10 seconds'))
                        ->withClaim('events', ['wat' => new \stdClass()])
                        ->identifiedBy('my-id')
                        ->withClaim('sid', $sessionId)
                        ->relatedTo($subject)
                        ->expiresAt(new \DateTimeImmutable(self::THEN))
                ),
                self::requirePolicy(),
            ),
            'expectedTokenProperties' => null,
            'expectedException' => LogoutTokenIsInvalid::becauseItDoesNotDeclareTheNecessaryEvent(),
        ];

        yield 'nonce claim' => [
            'token' => VerifiedJwt::tryFromJWTString(
                self::requireKeyPair()->sign(
                    static fn (Builder $builder): Builder => $builder
                        ->withHeader('kid', 'my-key')
                        ->issuedBy('me')
                        ->permittedFor('us', 'partner')
                        ->issuedAt((new \DateTimeImmutable(self::THEN))->modify('-10 seconds'))
                        ->withClaim('events', [LogoutToken::EVENT => new \stdClass()])
                        ->identifiedBy('my-id')
                        ->withClaim('sid', $sessionId)
                        ->withClaim('nonce', 'whatever')
                        ->relatedTo($subject)
                        ->expiresAt(new \DateTimeImmutable(self::THEN))
                ),
                self::requirePolicy(),
            ),
            'expectedTokenProperties' => null,
            'expectedException' => LogoutTokenIsInvalid::becauseItClaimsANonce(),
        ];

        yield 'missing issuer claim' => [
            'token' => VerifiedJwt::tryFromJWTString(
                self::requireKeyPair()->sign(
                    static fn (Builder $builder): Builder => $builder
                        ->withHeader('kid', 'my-key')
                        ->issuedBy('')
                        ->permittedFor('us', 'partner')
                        ->issuedAt((new \DateTimeImmutable(self::THEN))->modify('-10 seconds'))
                        ->withClaim('events', [LogoutToken::EVENT => new \stdClass()])
                        ->identifiedBy('my-id')
                        ->withClaim('sid', $sessionId)
                        ->relatedTo($subject)
                        ->expiresAt(new \DateTimeImmutable(self::THEN))
                ),
                self::requirePolicy(''),
            ),
            'expectedTokenProperties' => null,
            'expectedException' => LogoutTokenIsInvalid::becauseItClaimsNoIssuer(),
        ];

        yield 'missing identifier claim' => [
            'token' => VerifiedJwt::tryFromJWTString(
                self::requireKeyPair()->sign(
                    static fn (Builder $builder): Builder => $builder
                        ->withHeader('kid', 'my-key')
                        ->issuedBy('me')
                        ->permittedFor('us', 'partner')
                        ->issuedAt((new \DateTimeImmutable(self::THEN))->modify('-10 seconds'))
                        ->withClaim('events', [LogoutToken::EVENT => new \stdClass()])
                        ->withClaim('sid', $sessionId)
                        ->relatedTo($subject)
                        ->expiresAt(new \DateTimeImmutable(self::THEN))
                ),
                self::requirePolicy(),
            ),
            'expectedTokenProperties' => null,
            'expectedException' => LogoutTokenIsInvalid::becauseItClaimsNoIdentifier(),
        ];

        yield 'missing subject and session id claims' => [
            'token' => VerifiedJwt::tryFromJWTString(
                self::requireKeyPair()->sign(
                    static fn (Builder $builder): Builder => $builder
                        ->withHeader('kid', 'my-key')
                        ->issuedBy('me')
                        ->permittedFor('us', 'partner')
                        ->issuedAt((new \DateTimeImmutable(self::THEN))->modify('-10 seconds'))
                        ->withClaim('events', [LogoutToken::EVENT => new \stdClass()])
                        ->identifiedBy('my-id')
                        ->expiresAt(new \DateTimeImmutable(self::THEN))
                ),
                self::requirePolicy(),
            ),
            'expectedTokenProperties' => null,
            'expectedException' => LogoutTokenIsInvalid::becauseItClaimsNeitherSessionIdNorSubject(),
        ];

        yield 'missing expiration date claim' => [
            'token' => VerifiedJwt::tryFromJWTString(
                self::requireKeyPair()->sign(
                    static fn (Builder $builder): Builder => $builder
                        ->withHeader('kid', 'my-key')
                        ->issuedBy('me')
                        ->permittedFor('us', 'partner')
                        ->issuedAt((new \DateTimeImmutable(self::THEN))->modify('-10 seconds'))
                        ->withClaim('events', [LogoutToken::EVENT => new \stdClass()])
                        ->identifiedBy('my-id')
                        ->withClaim('sid', $sessionId)
                        ->relatedTo($subject)
                ),
                self::requirePolicy(),
            ),
            'expectedTokenProperties' => null,
            'expectedException' => LogoutTokenIsInvalid::becauseItClaimsNoExpirationDate(),
        ];
    }

    /**
     * @dataProvider expirationDateProvider
     */
    public function testIsExpiredAt(\DateTimeImmutable $date, bool $expectedResult): void
    {
        $token = LogoutToken::create(VerifiedJwt::tryFromJWTString(
            self::requireKeyPair()->sign(
                static fn (Builder $builder): Builder => $builder
                    ->withHeader('kid', 'my-key')
                    ->issuedBy('me')
                    ->permittedFor('us', 'partner')
                    ->issuedAt((new \DateTimeImmutable(self::THEN))->modify('-10 seconds'))
                    ->withClaim('events', [LogoutToken::EVENT => new \stdClass()])
                    ->identifiedBy('my-id')
                    ->withClaim('sid', Algorithms::generateUUID())
                    ->relatedTo(Algorithms::generateRandomString(16))
                    ->expiresAt(new \DateTimeImmutable(self::THEN))
            ),
            self::requirePolicy(),
        ));

        Assert::assertSame($expectedResult, $token->isExpiredAt($date));
    }

    public static function expirationDateProvider(): iterable
    {
        yield 'only just not expired' => [
            'date' => (new \DateTimeImmutable(self::THEN))->add(new \DateInterval('PT60S')),
            'expectedResult' => false,
        ];

        yield 'only just expired' => [
            'date' => (new \DateTimeImmutable(self::THEN))->add(new \DateInterval('PT61S')),
            'expectedResult' => true,
        ];
    }

    private static function requireKeyPair(): TestKeyPair
    {
        return self::$keyPair ??= TestKeyPair::create(SupportedAlgorithm::RS512);
    }

    private static function requirePolicy(string $issuer = 'me'): JwtVerification
    {
        if (!array_key_exists($issuer, self::$policies)) {
            $key = Jwk::fromArray(array_merge(
                self::requireKeyPair()->publicJwk,
                [
                    'alg' => SupportedAlgorithm::RS512->value,
                    'kid' => 'my-key',
                ]
            ));
            self::$policies[$issuer] = new JwtVerification(
                jwkSet: JwkSet::create([$key]),
                expectedIssuer: $issuer,
                expectedAudience: 'us',
                trustedAudiences: ['partner'],
                date: new \DateTimeImmutable(self::THEN),
            );
        }

        return self::$policies[$issuer];
    }
}
