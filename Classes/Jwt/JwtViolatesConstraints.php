<?php

declare(strict_types=1);

namespace Flownative\OpenIdConnect\Client\Jwt;

use Lcobucci\JWT\Validation\ConstraintViolation;

final class JwtViolatesConstraints
{
    /**
     * @param non-empty-array<ConstraintViolation> $violations
     */
    public function __construct(
        public readonly array $violations,
    ) {
    }
}
