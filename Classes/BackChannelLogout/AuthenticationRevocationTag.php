<?php

declare(strict_types=1);

namespace Flownative\OpenIdConnect\Client\BackChannelLogout;

use Neos\Flow\Annotations as Flow;

#[Flow\Proxy(false)]
final class AuthenticationRevocationTag
{
    private function __construct(
        public readonly string $value,
    ) {
    }

    public static function forSubject(string $issuer, string $subject): self
    {
        return new self('sub-' . hash('sha256', $issuer . "\0" . $subject));
    }

    public static function forSessionId(string $issuer, string $sessionId): self
    {
        return new self('sid-' . hash('sha256', $issuer . "\0" . $sessionId));
    }
}
