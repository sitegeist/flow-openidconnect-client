<?php

declare(strict_types=1);

namespace Flownative\OpenIdConnect\Client;

use Neos\Flow\Annotations as Flow;

#[Flow\Proxy(false)]
final class ServiceName
{
    private function __construct(
        public readonly string $value,
    ) {
    }

    /**
     * @throws ServiceNameIsInvalid
     */
    public static function fromString(string $value): self
    {
        if (\preg_match('/^[a-zA-Z0-9_.-]{1,100}$/', $value) !== 1) {
            throw ServiceNameIsInvalid::butWasAttemptedToBeInstantiated($value);
        }

        return new self($value);
    }
}
