<?php

declare(strict_types=1);

namespace Flownative\OpenIdConnect\Client\Jwt;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\ConstraintViolation;
use Neos\Flow\Annotations as Flow;

/**
 * @see https://www.rfc-editor.org/info/rfc7515/#section-4.1.11
 */
#[Flow\Proxy(false)]
final class AllCriticalHeadersCanBeProcessed implements Constraint
{
    public function assert(Token $token): void
    {
        if (!$token instanceof UnencryptedToken) {
            throw ConstraintViolation::error('You should pass a plain token', $this);
        }

        if ($token->headers()->has('crit')) {
            throw ConstraintViolation::error(
                'The token has critical headers that cannot be processed: ' . \json_encode($token->headers()->get('crit')),
                $this,
            );
        }
    }
}
