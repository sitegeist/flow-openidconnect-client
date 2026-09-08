<?php

declare(strict_types=1);

namespace Flownative\OpenIdConnect\Client\TokenExchange;

use Flownative\OpenIdConnect\Client\IdentityToken;
use Neos\Cache\Frontend\VariableFrontend;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Utility\Algorithms;

#[Flow\Scope("singleton")]
class IdentityTokenRegistry
{
    public function __construct(
        private readonly VariableFrontend $cache,
        private readonly int $lifetime,
    ) {
    }

    /**
     * IMPORTANT: access restrictions to the ID token must be enforced before calling this
     */
    public function add(IdentityToken $token): string
    {
        $entryId = Algorithms::generateRandomToken(32);
        $this->cache->set($entryId, $token->asJwt(), lifetime: $this->lifetime);

        return $entryId;
    }

    public function claim(string $entryId): ?IdentityToken
    {
        $jwt = $this->cache->get($entryId);
        $this->cache->remove($entryId);

        return is_string($jwt) && $jwt !== '' ? IdentityToken::fromJwt($jwt) : null;
    }
}
