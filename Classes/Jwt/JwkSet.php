<?php

declare(strict_types=1);

namespace Flownative\OpenIdConnect\Client\Jwt;

use Neos\Flow\Annotations as Flow;

#[Flow\Proxy(false)]
final class JwkSet
{
    /**
     * @param array<int,Jwk> $items
     * @param array<int,string> $rejections Rejection reasons for items on construction
     */
    private function __construct(
        private readonly array $items,
        private readonly array $rejections,
    ) {
    }

    /**
     * @param array<int,array<string,mixed>> $values
     */
    public static function fromArray(array $values): self
    {
        $initialRejections = [];
        $items = array_filter(array_map(
            function (array $item, int $i) use (&$initialRejections): ?Jwk {
                try {
                    return Jwk::fromArray($item);
                } catch (JwkValidationFailed|\JsonException $exception) {
                    $initialRejections[$i] = 'Key ' . (self::extractString($item['kid'] ?? null) ?: $i) . ': ' . $exception->getMessage();
                    return null;
                }
            } ,
            $values,
            array_keys($values),
        ));

        return new self(
            $items,
            $initialRejections,
        );
    }

    private static function extractString(mixed $value): ?string
    {
        return is_string($value) ? $value : null;
    }

    private function reduceToSignatureCandidates(?string $keyId, ?string $algorithm): self
    {
        $rejectionReasons = $this->rejections;
        $items = array_filter(
            $this->items,
            function (Jwk $jwk, $i) use ($keyId, $algorithm, &$rejectionReasons): bool {
                $disqualificationReason = '';
                if (!$jwk->qualifiesForSignatureVerification($keyId, $algorithm, $disqualificationReason)) {
                    $rejectionReasons[$i] = 'Key ' . ($jwk->keyId ?: $i) . ': ' . $disqualificationReason;
                    return false;
                }
                return true;
            },
            ARRAY_FILTER_USE_BOTH,
        );

        return new self(
            $items,
            $rejectionReasons,
        );
    }

    public function requireSignatureVerificationKey(?string $keyId, ?string $algorithm): Jwk
    {
        $signatureSet = $this->reduceToSignatureCandidates($keyId, $algorithm);
        $signatureKeys = $signatureSet->items;

        return match (count($signatureKeys)) {
            0 => throw SignatureVerificationKeyCouldNotBeResolved::becauseNoKeyMatched($signatureSet->rejections),
            1 => reset($signatureKeys),
            default => throw SignatureVerificationKeyIsAmbiguous::becauseMultipleKeysMatched(array_map(
                fn (Jwk $key, int $i): string => $key->keyId ?: (string)$i,
                $signatureKeys,
                array_keys($signatureKeys),
            )),
        };
    }
}
