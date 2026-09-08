<?php

declare(strict_types=1);

namespace Flownative\OpenIdConnect\Client\Tests\Unit;

use Flownative\OpenIdConnect\Client\BackChannelLogout\AuthenticationRevocationTag;
use Neos\Flow\Annotations as Flow;

#[Flow\Proxy(false)]
final class LogoutTokenProperties
{
    public function __construct(
        public readonly ?string $subject,
        public readonly ?string $sessionId,
        public readonly \DateTimeImmutable $expires,
        public readonly string $identifier,
        public readonly string $issuer,
        public readonly AuthenticationRevocationTag $revocationTag,
    ) {
    }
}
