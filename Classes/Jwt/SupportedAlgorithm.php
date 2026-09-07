<?php

declare(strict_types=1);

namespace Flownative\OpenIdConnect\Client\Jwt;

use Lcobucci\JWT\Signer;

/**
 * List of hashing algorithms supported by this package
 */
enum SupportedAlgorithm: string
{
    case RS256 = 'RS256';
    case RS384 = 'RS384';
    case RS512 = 'RS512';
    case ES256 = 'ES256';
    case ES384 = 'ES384';
    case ES512 = 'ES512';
    case EdDSA = 'EdDSA';

    /**
     * @throws JwkValidationFailed
     */
    public static function fromKeyTypeAndCurve(string $keyType, ?string $curve): self
    {
        return match ($keyType) {
            /** @see https://datatracker.ietf.org/doc/html/rfc7518#section-3.4 */
            'EC' => match ($curve) {
                'P-256' => self::ES256,
                'P-384' => self::ES384,
                'P-521' => self::ES512,
                default => throw JwkValidationFailed::becauseECCurveIsNotSupported($curve),
            },
            /** @see https://datatracker.ietf.org/doc/html/rfc8037#section-3.1 */
            'OKP' => match ($curve) {
                'Ed25519' => self::EdDSA,
                default => throw JwkValidationFailed::becauseOKPCurveIsNotSupported($curve),
            },
            /**
             * @see https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
             *      id_token_signed_response_alg — "The default, if omitted, is RS256."
             */
            'RSA' => self::RS256,
            default => throw JwkValidationFailed::becauseKeyTypeIsNotSupported($keyType),
        };
    }

    public function getSigner(): Signer
    {
        return match($this) {
            self::RS256 => new Signer\Rsa\Sha256(),
            self::RS384 => new Signer\Rsa\Sha384(),
            self::RS512 => new Signer\Rsa\Sha512(),
            self::ES256 => new Signer\Ecdsa\Sha256(),
            self::ES384 => new Signer\Ecdsa\Sha384(),
            self::ES512 => new Signer\Ecdsa\Sha512(),
            self::EdDSA => new Signer\Eddsa(),
        };
    }
}
