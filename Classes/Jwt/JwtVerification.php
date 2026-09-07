<?php

declare(strict_types=1);

namespace Flownative\OpenIdConnect\Client\Jwt;

use Lcobucci\JWT\Token as TokenInterface;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use Lcobucci\JWT\Validation\Validator;

/**
 * The policy for JWT verification
 */
final class JwtVerification
{
    /**
     * @param array<int,string> $trustedAudiences
     */
    public function __construct(
        private readonly JwkSet $jwkSet,
        private readonly string $expectedIssuer,
        private readonly string $expectedAudience,
        private readonly array $trustedAudiences,
    ) {
    }

    public function apply(TokenInterface $token): JwtVerificationSucceeded|JwtViolatesConstraints|JwtMissesSignatureKey|JwtHasAmbiguousSignatureKey
    {
        $validator = new Validator();
        try {
            $validator->assert(
                $token,
                $this->jwkSet->requireSignatureVerificationKey(
                    $token->headers()->get('kid'),
                    $token->headers()->get('alg'),
                )->getSignatureConstraint(),
                new IssuedBy($this->expectedIssuer),
                new PermittedFor($this->expectedAudience),
                new AudiencesAreTrusted($this->expectedAudience, $this->trustedAudiences),
            );
            return new JwtVerificationSucceeded();
        } catch (RequiredConstraintsViolated $exception) {
            return new JwtViolatesConstraints($exception->violations());
        } catch (SignatureVerificationKeyCouldNotBeResolved $exception) {
            return new JwtMissesSignatureKey();
        } catch (SignatureVerificationKeyIsAmbiguous $exception) {
            return new JwtHasAmbiguousSignatureKey();
        }

        /**
         * Restliche Constraints
         * ┌──────────────────────────────────┬────────────────────┬───────────────────────────────────────────────────────────────────────────┐
         * │             Prüfung              │       Träger       │                                 Anmerkung                                 │
         * ├──────────────────────────────────┼────────────────────┼───────────────────────────────────────────────────────────────────────────┤
         * │ azp, falls vorhanden             │ eigener Constraint │ SHOULD                                                                    │
         * ├──────────────────────────────────┼────────────────────┼───────────────────────────────────────────────────────────────────────────┤
         * │ iat mit Leeway                   │ eigener Constraint │ fehlt noch in deiner Todo-Liste — Plan §3.8, plus optionales Maximalalter │
         * ├──────────────────────────────────┼────────────────────┼───────────────────────────────────────────────────────────────────────────┤
         * │ nbf, falls vorhanden             │ eigener Constraint │                                                                           │
         * └──────────────────────────────────┴────────────────────┴───────────────────────────────────────────────────────────────────────────┘
         */

    }

}
