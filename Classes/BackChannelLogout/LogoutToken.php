<?php

declare(strict_types=1);

namespace Flownative\OpenIdConnect\Client\BackChannelLogout;

use Flownative\OpenIdConnect\Client\Jwt\VerifiedJwt;
use Lcobucci\JWT\Token\RegisteredClaims;
use Neos\Flow\Annotations as Flow;

/**
 * @see https://openid.net/specs/openid-connect-backchannel-1_0.html#LogoutToken
 */
#[Flow\Proxy(false)]
final class LogoutToken
{
    public const EVENT = 'http://schemas.openid.net/event/backchannel-logout';

    private const CLOCK_SKEW_LEEWAY = 'PT60S';

    private function __construct(
        public readonly string $issuer,
        public readonly ?string $subject,
        public readonly \DateTimeImmutable $issuedAt,
        public readonly \DateTimeImmutable $expiration,
        public readonly string $identifier,
        public readonly ?string $sessionId,
        public readonly AuthenticationRevocationTag $revocationTag,
    ) {
    }

    /**
     * @throws LogoutTokenIsInvalid
     */
    public static function create(VerifiedJwt $verifiedToken, \DateTimeImmutable $now): self
    {
        $issuer = $verifiedToken->getStringClaim(RegisteredClaims::ISSUER);
        if (!$issuer) {
            // REQUIRED as declared in https://openid.net/specs/openid-connect-backchannel-1_0.html#LogoutToken
            throw LogoutTokenIsInvalid::becauseItClaimsNoIssuer();
        }

        $sessionId = $verifiedToken->getStringClaim('sid');
        $subject = $verifiedToken->getStringClaim(RegisteredClaims::SUBJECT);
        if (!$sessionId && !$subject) {
            // MUST as declared in https://openid.net/specs/openid-connect-backchannel-1_0.html#LogoutToken
            throw LogoutTokenIsInvalid::becauseItClaimsNeitherSessionIdNorSubject();
        }

        // REQUIRED 'aud' is already enforced by VerifiedJWT

        $issuedAt = $verifiedToken->getDateClaim(RegisteredClaims::ISSUED_AT);
        if (!$issuedAt) {
            // REQUIRED as declared in https://openid.net/specs/openid-connect-backchannel-1_0.html#LogoutToken
            throw LogoutTokenIsInvalid::becauseItClaimsNoIssuingDate();
        }
        if ($issuedAt > $now->add(new \DateInterval(self::CLOCK_SKEW_LEEWAY))) {
            throw LogoutTokenIsInvalid::becauseItIsIssuedInTheFuture();
        }

        if (
            ($notBefore = $verifiedToken->getDateClaim(RegisteredClaims::NOT_BEFORE))
            && $notBefore > $now->add(new \DateInterval(self::CLOCK_SKEW_LEEWAY))
        ) {
            throw LogoutTokenIsInvalid::becauseItIsNotYetToBeUsed();
        }

        $expiration = $verifiedToken->getDateClaim(RegisteredClaims::EXPIRATION_TIME);
        if (!$expiration) {
            // REQUIRED as declared in https://openid.net/specs/openid-connect-backchannel-1_0.html#LogoutToken
            throw LogoutTokenIsInvalid::becauseItClaimsNoExpirationDate();
        }
        if ($expiration <= $now->sub(new \DateInterval(self::CLOCK_SKEW_LEEWAY))) {
            throw LogoutTokenIsInvalid::becauseItIsExpired();
        }

        $identifier = $verifiedToken->getStringClaim(RegisteredClaims::ID);
        if (!$identifier) {
            // REQUIRED as declared in https://openid.net/specs/openid-connect-backchannel-1_0.html#LogoutToken
            throw LogoutTokenIsInvalid::becauseItClaimsNoIdentifier();
        }

        $events = $verifiedToken->getAssociativeArrayClaim('events') ?: [];
        if (!array_key_exists(self::EVENT, $events)) {
            // REQUIRED as declared in https://openid.net/specs/openid-connect-backchannel-1_0.html#LogoutToken
            throw LogoutTokenIsInvalid::becauseItDoesNotDeclareTheNecessaryEvent();
        }

        if ($verifiedToken->hasClaim('nonce')) {
            // PROHIBITED as declared in https://openid.net/specs/openid-connect-backchannel-1_0.html#LogoutToken
            throw LogoutTokenIsInvalid::becauseItClaimsANonce();
        }

        return new self(
            issuer: $issuer,
            subject: $subject,
            issuedAt: $issuedAt,
            expiration: $expiration,
            identifier: $identifier,
            sessionId: $sessionId,
            revocationTag: $sessionId
                ? AuthenticationRevocationTag::forSessionId($issuer, $sessionId)
                : AuthenticationRevocationTag::forSubject($issuer, $subject),
        );
    }
}
