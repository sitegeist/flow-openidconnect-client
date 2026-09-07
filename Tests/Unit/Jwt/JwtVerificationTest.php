<?php

declare(strict_types=1);

namespace Flownative\OpenIdConnect\Client\Tests\Unit\Jwt;

use Flownative\OpenIdConnect\Client\Jwt\SignatureVerificationKeyCouldNotBeResolved;
use PHPUnit\Framework\TestCase;

class JwtVerificationTest extends TestCase
{
    public function testApplyRejectsInvalidTokens(): void
    {

    }

    public static function invalidTokenProvider(): iterable
    {
        yield 'unresolveable signature verification key' => [

        ];

    }
}
