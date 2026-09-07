<?php

declare(strict_types=1);

namespace Flownative\OpenIdConnect\Client\Jwt;

final class SignatureVerificationKeyCouldNotBeResolved extends \Exception
{
    /**
     * @param array<int,string> $rejectionReasons
     */
    private function __construct(
        string $message = "",
        int $code = 0,
        ?\Throwable $previous = null,
        public readonly array $rejectionReasons = [],
    ) {
        parent::__construct($message, $code, $previous);
    }

    /**
     * @param array<int,string> $rejectionReasons
     */
    public static function becauseNoKeyMatched(array $rejectionReasons): self
    {
        return new self(
            message: 'No key matched the requirements for signature verification',
            code: 1787920242,
            rejectionReasons: $rejectionReasons,
        );
    }
}
