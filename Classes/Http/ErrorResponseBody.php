<?php

declare(strict_types=1);

namespace Flownative\OpenIdConnect\Client\Http;

use Neos\Flow\Annotations as Flow;
use Psr\Http\Message\UriInterface;

/**
 * The error response body, @see https://www.rfc-editor.org/info/rfc6749/#section-5.2
 */
#[Flow\Proxy(false)]
final class ErrorResponseBody implements \JsonSerializable
{
    private function __construct(
        public readonly ErrorCode $error,
        public readonly ?string $errorDescription,
        public readonly ?UriInterface $errorUri,
    ) {
    }

    public static function create(
        ErrorCode $error,
        ?string $errorDescription = null,
        ?UriInterface $errorUri = null
    ): self {
        return new self(
            $error,
            $errorDescription,
            $errorUri,
        );
    }

    /**
     * @return array<string,mixed>
     */
    public function jsonSerialize(): array
    {
        return array_filter([
            'error' => $this->error->value,
            'error_description' => $this->errorDescription,
            'error_uri' => $this->errorUri ? (string)$this->errorUri : null,
        ]);
    }
}
