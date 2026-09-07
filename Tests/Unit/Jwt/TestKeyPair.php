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
 * A key pair generated at runtime, which hands out its public half as bare JWK
 * key material and signs arbitrary JWTs with its private half.
 *
 * Deliberately knows nothing about JWK metadata such as "kid", "use" or "alg":
 * tests compose those themselves, so that a fixture is always built by adding
 * members rather than by removing the ones this class guessed at.
 */
final class TestKeyPair
{
    /**
     * @param non-empty-string $privateKey
     * @param array<string,mixed> $publicJwk The bare key material, i.e. "kty" plus "crv"/"x"/"y" or "n"/"e"
     */
    private function __construct(
        public readonly SupportedAlgorithm $algorithm,
        private readonly string $privateKey,
        public readonly array $publicJwk,
    ) {
    }

    public static function create(SupportedAlgorithm $algorithm = SupportedAlgorithm::ES256): self
    {
        [$privateKey, $publicJwk] = match ($algorithm) {
            /** Signer\Rsa loads the private key through OpenSSL, hence PKCS8 */
            SupportedAlgorithm::RS256,
            SupportedAlgorithm::RS384,
            SupportedAlgorithm::RS512 => self::export(RSA::createKey(2048), 'PKCS8'),
            SupportedAlgorithm::ES256 => self::export(EC::createKey('secp256r1'), 'PKCS8'),
            SupportedAlgorithm::ES384 => self::export(EC::createKey('secp384r1'), 'PKCS8'),
            SupportedAlgorithm::ES512 => self::export(EC::createKey('secp521r1'), 'PKCS8'),
            /** Signer\Eddsa expects the raw key material rather than PKCS8 */
            SupportedAlgorithm::EdDSA => self::export(EC::createKey('Ed25519'), 'libsodium'),
        };

        return new self($algorithm, $privateKey, $publicJwk);
    }

    /**
     * @return array{0:non-empty-string,1:array<string,mixed>}
     */
    private static function export(RSA\PrivateKey|EC\PrivateKey $key, string $privateKeyFormat): array
    {
        $jwkSet = \json_decode($key->getPublicKey()->toString('JWK'), true, 512, JSON_THROW_ON_ERROR);

        return [$key->toString($privateKeyFormat), $jwkSet['keys'][0]];
    }

    /**
     * A JWT signed with the private half. Claims and headers are the caller's
     * business, because Builder rejects registered claims passed as plain
     * key-value pairs and every test needs a different set of them.
     *
     * @param (callable(Builder):Builder)|null $configure
     */
    public function sign(?callable $configure = null): string
    {
        $builder = new Builder(new JoseEncoder(), ChainedFormatter::default());

        return ($configure === null ? $builder : $configure($builder))
            ->getToken($this->algorithm->getSigner(), InMemory::plainText($this->privateKey))
            ->toString();
    }
}
