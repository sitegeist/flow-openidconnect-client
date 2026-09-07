<?php

declare(strict_types=1);

namespace Flownative\OpenIdConnect\Client\Jwt;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\ConstraintViolation;
use Neos\Flow\Annotations as Flow;

/**
 * @see https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
 * @see https://www.rfc-editor.org/info/rfc8725#section-3.9
 */
#[Flow\Proxy(false)]
final class AudiencesAreTrusted implements Constraint
{
    /**
     * @param array<int,string> $trustedAudiences
     */
    public function __construct(
        private readonly string $expectedAudience,
        private readonly array $trustedAudiences,
    ) {
    }

    public function assert(Token $token): void
    {
        if (!$token instanceof UnencryptedToken) {
            throw ConstraintViolation::error('You should pass a plain token', $this);
        }

        $untrustedAudiences = array_diff(
            $token->claims()->get(RegisteredClaims::AUDIENCE, []),
            [$this->expectedAudience, ...$this->trustedAudiences],
        );

        if ($untrustedAudiences !== []) {
            throw ConstraintViolation::error(
                'The token claims audience(s) not trusted by this client: ' . implode(',', $untrustedAudiences),
                $this,
            );
        }
    }
}
