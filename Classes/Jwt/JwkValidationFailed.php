<?php

declare(strict_types=1);

namespace Flownative\OpenIdConnect\Client\Jwt;

final class JwkValidationFailed extends \Exception
{
    public static function becauseNoTypeWasSupplied(): self
    {
        return new self(
            'No type was given in Jwk payload',
            1787912919,
        );
    }

    public static function becauseTheKeyTypeIsNotSupported(string $keyType): self
    {
        return new self(
            'Requested Jwk type ' . $keyType . ' is not supported',
            1787912748,
        );
    }

    public static function becauseECCurveIsNotSupported(?string $curve): self
    {
        return new self(
            'Requested curve ' . $curve . ' is not supported for signature verification via EC',
            1787912696,
        );
    }

    public static function becauseOKPCurveIsNotSupported(?string $curve): self
    {
        return new self(
            'Requested curve ' . $curve . ' is not supported for signature verification via OKP',
            1787912643,
        );
    }

    public static function becauseKeyTypeIsNotSupported(string $keyType): self
    {
        return new self(
            'Requested key type ' . $keyType . ' is not supported for signature verification',
            1787912525,
        );
    }

    public static function becauseAlgorithmIsNotSupported(string $algorithm): self
    {
        return new self(
            'Requested algorithm ' . $algorithm . ' is not supported for signature verification',
            1787912440,
        );
    }
}
