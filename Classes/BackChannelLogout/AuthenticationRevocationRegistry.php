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

    public function add(AuthenticationRevocationTag $tag): void
    {
        $this->cache->set($tag->value, true, lifetime: $this->lifetime);
    }

    public function has(AuthenticationRevocationTag $tag): bool
    {
        return $this->cache->has($tag->value);
    }

    public function remove(AuthenticationRevocationTag $tag): void
    {
        $this->cache->remove($tag->value);
    }
}
