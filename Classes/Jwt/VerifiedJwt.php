<?php

declare(strict_types=1);

namespace Flownative\OpenIdConnect\Client\Jwt;

use Lcobucci\JWT\Encoding\CannotDecodeContent;
use Lcobucci\JWT\Token\InvalidTokenStructure;
use Lcobucci\JWT\Token\UnsupportedHeaderFound;
use Lcobucci\JWT\UnencryptedToken;
use Neos\Flow\Annotations as Flow;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Parser;
use Psr\Log\LoggerInterface;

#[Flow\Proxy(false)]
final class VerifiedJwt
{
    private function __construct(
        public readonly UnencryptedToken $token,
    ) {
    }

    public static function tryFromJWTString(string $jwt, JwtVerification $policy, ?LoggerInterface $logger = null, &$result = null): ?self
    {
        $parser = new Parser(new JoseEncoder());
        try {
            $token = $parser->parse($jwt);
        } catch (CannotDecodeContent | InvalidTokenStructure | UnsupportedHeaderFound $exception) {
            $logger?->warning($exception->getMessage());
            return null;
        }

        if (!$token instanceof UnencryptedToken) {
            $logger?->warning('Parsed token is of type ' . get_class($token) . ', ' . UnencryptedToken::class . ' expected.');
            return null;
        }

        $result = $policy->apply($token);

        return match (get_class($result)) {
            JwtViolatesConstraints::class => (function () use ($result, $logger) {
                foreach ($result->violations as $violation) {
                    $logger?->error($violation->getMessage());
                }
                return null;
            })(),
            JwtHasAmbiguousSignatureKey::class => (function () use ($result, $logger) {
                $logger?->error('Signature key for JWT is ambiguous');
                return null;
            })(),
            JwtMissesSignatureKey::class => (function () use ($result, $logger) {
                return null;
            })(),
            JwtVerificationSucceeded::class => new self($token),
        };
    }

    public function hasClaim(string $name): bool
    {
        return $this->token->claims()->has($name);
    }

    /**
     * @return array<string,mixed>|null
     */
    public function getAssociativeArrayClaim(string $name): ?array
    {
        $claim = $this->token->claims()->get($name);

        return is_array($claim) ? $claim : null;
    }

    /**
     * @return non-empty-string|null
     */
    public function getStringClaim(string $name): ?string
    {
        $claim = $this->token->claims()->get($name);

        return is_string($claim) && $claim !== '' ? $claim : null;
    }

    public function getDateClaim(string $name): ?\DateTimeImmutable
    {
        $claim = $this->token->claims()->get($name);

        return $claim instanceof \DateTimeImmutable ? $claim : null;
    }
}
