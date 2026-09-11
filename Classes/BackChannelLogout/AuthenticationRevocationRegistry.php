<?php

declare(strict_types=1);

namespace Flownative\OpenIdConnect\Client\BackChannelLogout;

use Neos\Cache\Frontend\VariableFrontend;
use Neos\Flow\Annotations as Flow;

#[Flow\Scope("singleton")]
class AuthenticationRevocationRegistry
{
    public function __construct(
        private readonly VariableFrontend $cache,
        private readonly int $lifetime,
    ) {
    }

    public function add(AuthenticationRevocationTag $tag, \DateTimeImmutable $time): void
    {
        $this->cache->set($tag->value, $time->getTimestamp(), lifetime: $this->lifetime);
    }

    public function isRevokedAt(AuthenticationRevocationTag $tag, ?\DateTimeImmutable $referenceTime): bool
    {
        if (is_int($revocationTimestamp = $this->cache->get($tag->value))) {
            // both timestamps have been issued by the OP, so direct comparison is valid
            return (!$referenceTime || $revocationTimestamp >= $referenceTime->getTimestamp());
        }

        return false;
    }

    public function remove(AuthenticationRevocationTag $tag): void
    {
        $this->cache->remove($tag->value);
    }
}
