<?php

declare(strict_types=1);

namespace Flownative\OpenIdConnect\Client\Jwt;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\ConstraintViolation;
use Neos\Flow\Annotations as Flow;

#[Flow\Proxy(false)]
final class TokenIsAlreadyUsable implements Constraint
{
    private const CLOCK_SKEW_LEEWAY = 'PT60S';

    public function __construct(
        private readonly \DateTimeImmutable $date,
    ) {
    }

    public function assert(Token $token): void
    {
        if (!$token instanceof UnencryptedToken) {
            throw ConstraintViolation::error('You should pass a plain token', $this);
        }

        $notBefore = $token->claims()->get(RegisteredClaims::NOT_BEFORE);
        if (
            $notBefore instanceof \DateTimeImmutable
            && $notBefore > $this->date->add(new \DateInterval(self::CLOCK_SKEW_LEEWAY))
        ) {
            throw ConstraintViolation::error(
                'The token cannot be used yet',
                $this,
            );
        }

        $issuedAt = $token->claims()->get(RegisteredClaims::ISSUED_AT);
        if (
            $issuedAt instanceof \DateTimeImmutable
            && $issuedAt > $this->date->add(new \DateInterval(self::CLOCK_SKEW_LEEWAY))
        ) {
            throw ConstraintViolation::error(
                'The token was issued in the future',
                $this,
            );
        }
    }
}
