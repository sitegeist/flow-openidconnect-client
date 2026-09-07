<?php

declare(strict_types=1);

namespace Flownative\OpenIdConnect\Client\Jwt;

final class SignatureVerificationKeyIsAmbiguous extends \Exception
{
    /**
     * @param array<int,string> $candidates
     */
    private function __construct(
        string $message = "",
        int $code = 0,
        ?\Throwable $previous = null,
        public readonly array $candidates = [],
    ) {
        parent::__construct($message, $code, $previous);
    }

    /**
     * @param array<int,string> $candidates
     */
    public static function becauseMultipleKeysMatched(array $candidates): self
    {
        return new self(
            message: 'Multiple keys matched the requirements for signature verification',
            code: 1787920492,
            candidates: $candidates,
        );
    }
}
