<?php

declare(strict_types=1);

namespace Flownative\OpenIdConnect\Client\Jwt;

use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Neos\Flow\Annotations as Flow;
use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\RSA;

/**
 * A JSON Web Key, @see https://datatracker.ietf.org/doc/html/rfc7517#section-4
 */
#[Flow\Proxy(false)]
final class Jwk
{
    /**
     * @param non-empty-string $publicKeyPem
     */
    private function __construct(
        public readonly ?string $intendedUse,
        public readonly ?string $keyId,
        public readonly SupportedAlgorithm $algorithm,
        private readonly string $publicKeyPem,
    ) {
    }

    /**
     * @param array<string,mixed> $values
     * @throws JwkValidationFailed
     * @throws \JsonException
     */
    public static function fromArray(array $values): self
    {
        $json = \json_encode($values, JSON_THROW_ON_ERROR);

        try {
            $keyType = self::extractString($values['kty'] ?? null) ?: throw JwkValidationFailed::becauseNoTypeWasSupplied();
            $rawAlgorithm = self::extractString($values['alg'] ?? null);
            $curve = self::extractString($values['crv'] ?? null);
            try {
                $algorithm = $rawAlgorithm
                    ? SupportedAlgorithm::from($rawAlgorithm)
                    : SupportedAlgorithm::fromKeyTypeAndCurve($keyType, $curve);
            } catch (\ValueError) {
                throw JwkValidationFailed::becauseAlgorithmIsNotSupported($rawAlgorithm);
            }


            return new self(
                intendedUse: self::extractString($values['use'] ?? null),
                keyId: self::extractString($values['kid'] ?? null),
                algorithm: $algorithm,
                publicKeyPem: match ($keyType) {
                    'RSA' => RSA::loadPublicKeyFormat('JWK', $json)->toString('PKCS8'),
                    'OKP' => EC::loadPublicKeyFormat('JWK', $json)->toString('libsodium'),
                    'EC' => EC::loadPublicKeyFormat('JWK', $json)->toString('PKCS8'),
                    default => throw JwkValidationFailed::becauseTheKeyTypeIsNotSupported($values['kty']),
                }
            );
        } catch (JwkValidationFailed $exception) {
            throw $exception;
        } catch (\Throwable $throwable) {
            throw new JwkValidationFailed($throwable->getMessage(), 1787915591, $throwable);
        }
    }

    private static function extractString(mixed $value): ?string
    {
        return is_string($value) ? $value : null;
    }

    public function qualifiesForSignatureVerification(
        ?string $keyId,
        ?string $algorithm,
        string &$disqualificationReason,
    ): bool {
        if ($this->intendedUse !== null && $this->intendedUse !== 'sig') {
            $disqualificationReason = 'Not intended to be used for signature verification';
            return false;
        }
        if ($keyId !== null && $this->keyId !== $keyId) {
            $disqualificationReason = 'Does not match the requested ID';
            return false;
        }
        if ($algorithm !== null && $this->algorithm->value !== $algorithm) {
            $disqualificationReason = 'Does not match the requested algorithm';
            return false;
        }
        return true;
    }

    /**
     * @see https://datatracker.ietf.org/doc/html/rfc8725#section-3.1
     * @throws \InvalidArgumentException
     */
    public function getSignatureConstraint(): SignedWith
    {
        $reason = '';
        if (!$this->qualifiesForSignatureVerification(null, null, $reason)) {
            throw new \InvalidArgumentException('Key does not qualify for signature verification: ' . $reason, 1787925394);
        }

        return new SignedWith(
            $this->algorithm->getSigner(),
            Signer\Key\InMemory::plainText($this->publicKeyPem),
        );
    }
}
