<?php

declare(strict_types=1);

namespace Flownative\OpenIdConnect\Client\BackChannelLogout;

use Flownative\OpenIdConnect\Client\Jwt\VerifiedJwt;

/**
 * @see https://openid.net/specs/openid-connect-backchannel-1_0.html#LogoutToken
 */
final class LogoutToken
{
    public const EVENT = 'http://schemas.openid.net/event/backchannel-logout';

    private const CLOCK_SKEW_LEEWAY = 'PT60S';

    private function __construct(
        public readonly ?string $subject,
        public readonly ?string $sessionId,
        public readonly \DateTimeImmutable $expires,
        public readonly string $identifier,
        public readonly string $issuer,
        public readonly AuthenticationRevocationTag $revocationTag,
    ) {
    }

    /**
     * @throws LogoutTokenIsInvalid
     */
    public static function create(VerifiedJwt $verifiedToken): self
    {
        $events = $verifiedToken->getAssociativeArrayClaim('events') ?: [];
        if (!array_key_exists(self::EVENT, $events)) {
            throw LogoutTokenIsInvalid::becauseItDoesNotDeclareTheNecessaryEvent();
        }

        if ($verifiedToken->hasClaim('nonce')) {
            throw LogoutTokenIsInvalid::becauseItClaimsANonce();
        }

        $issuer = $verifiedToken->getStringClaim('iss');
        if (!$issuer) {
            throw LogoutTokenIsInvalid::becauseItClaimsNoIssuer();
        }

        $identifier = $verifiedToken->getStringClaim('jti');
        if (!$identifier) {
            throw LogoutTokenIsInvalid::becauseItClaimsNoIdentifier();
        }

        $sessionId = $verifiedToken->getStringClaim('sid');
        $subject = $verifiedToken->getStringClaim('sub');
        if (!$sessionId && !$subject) {
            throw LogoutTokenIsInvalid::becauseItClaimsNeitherSessionIdNorSubject();
        }

        $expires = $verifiedToken->getDateClaim('exp');
        if (!$expires) {
            throw LogoutTokenIsInvalid::becauseItClaimsNoExpirationDate();
        }

        return new self(
            subject: $subject,
            sessionId: $sessionId,
            expires: $expires,
            identifier: $identifier,
            issuer: $issuer,
            revocationTag: $sessionId
                ? AuthenticationRevocationTag::forSessionId($issuer, $sessionId)
                : AuthenticationRevocationTag::forSubject($issuer, $subject)
        );
    }

    public function isExpiredAt(\DateTimeImmutable $now): bool
    {
        return $this->expires < $now->sub(new \DateInterval(self::CLOCK_SKEW_LEEWAY));
    }
}
