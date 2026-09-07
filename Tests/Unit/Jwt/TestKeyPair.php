<?php

declare(strict_types=1);

namespace Flownative\OpenIdConnect\Client\Tests\Unit\Jwt;

use Flownative\OpenIdConnect\Client\Jwt\SupportedAlgorithm;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token\Builder;
use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\RSA;

/**
 * A key pair generated at runtime, which hands out its public half as a JWK and
 * signs arbitrary JWTs with its private half.
 *
 * Generating the keys per test run keeps private keys out of the repository and
 * makes fixtures possible which no static key material could express, such as a
 * token signed by a key the JWK set does not contain.
 */
final class TestKeyPair
{
    /**
     * @param non-empty-string $privateKey
     * @param array<string,mixed> $publicJwk
     */
    private function __construct(
        public readonly SupportedAlgorithm $algorithm,
        public readonly ?string $keyId,
        private readonly string $privateKey,
        private readonly array $publicJwk,
    ) {
    }

    public static function create(
        SupportedAlgorithm $algorithm = SupportedAlgorithm::ES256,
        ?string $keyId = 'test-key',
    ): self {
        /** @var array<string,string> $jwkAttributes phpseclib merges these into the exported JWK */
        $jwkAttributes = array_filter([
            'kid' => $keyId,
            'use' => 'sig',
            'alg' => $algorithm->value,
        ]);

        [$privateKey, $publicKeyJwk] = match ($algorithm) {
            /** Signer\Rsa loads the private key through OpenSSL, hence PKCS8 */
            SupportedAlgorithm::RS256,
            SupportedAlgorithm::RS384,
            SupportedAlgorithm::RS512 => self::export(RSA::createKey(2048), 'PKCS8', $jwkAttributes),
            SupportedAlgorithm::ES256 => self::export(EC::createKey('secp256r1'), 'PKCS8', $jwkAttributes),
            SupportedAlgorithm::ES384 => self::export(EC::createKey('secp384r1'), 'PKCS8', $jwkAttributes),
            SupportedAlgorithm::ES512 => self::export(EC::createKey('secp521r1'), 'PKCS8', $jwkAttributes),
            /** Signer\Eddsa expects the raw key material rather than PKCS8 */
            SupportedAlgorithm::EdDSA => self::export(EC::createKey('Ed25519'), 'libsodium', $jwkAttributes),
        };

        return new self($algorithm, $keyId, $privateKey, $publicKeyJwk);
    }

    /**
     * @param array<string,string> $jwkAttributes
     * @return array{0:non-empty-string,1:array<string,mixed>}
     */
    private static function export(RSA\PrivateKey|EC\PrivateKey $key, string $privateKeyFormat, array $jwkAttributes): array
    {
        $jwkSet = \json_decode($key->getPublicKey()->toString('JWK', $jwkAttributes), true, 512, JSON_THROW_ON_ERROR);

        return [$key->toString($privateKeyFormat), $jwkSet['keys'][0]];
    }

    /**
     * The public key as a JWK, ready to be passed to JwkSet::fromArray().
     *
     * @param array<string,mixed> $overrides To build rejected keys, e.g. ['use' => 'enc']
     * @return array<string,mixed>
     */
    public function publicJwk(array $overrides = []): array
    {
        return $overrides + $this->publicJwk;
    }

    /**
     * @param array<int,string> $audiences
     * @param string|null $keyIdHeader The "kid" header, null to omit it entirely
     * @param array<string,mixed> $claims Additional claims
     */
    public function sign(
        string $issuer = 'https://issuer.example',
        array $audiences = ['client-id'],
        ?string $keyIdHeader = 'test-key',
        ?\DateTimeImmutable $expiresAt = null,
        array $claims = [],
    ): string {
        $builder = new Builder(new JoseEncoder(), ChainedFormatter::default());

        if ($keyIdHeader !== null) {
            $builder = $builder->withHeader('kid', $keyIdHeader);
        }

        $builder = $builder
            ->issuedBy($issuer)
            ->issuedAt(new \DateTimeImmutable('now'))
            ->expiresAt($expiresAt ?? new \DateTimeImmutable('+1 hour'));

        foreach ($audiences as $audience) {
            $builder = $builder->permittedFor($audience);
        }
        foreach ($claims as $name => $value) {
            $builder = $builder->withClaim($name, $value);
        }

        return $builder
            ->getToken($this->algorithm->getSigner(), InMemory::plainText($this->privateKey))
            ->toString();
    }
}
