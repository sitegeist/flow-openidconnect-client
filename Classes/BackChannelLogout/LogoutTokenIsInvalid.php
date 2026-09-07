<?php

declare(strict_types=1);

namespace Flownative\OpenIdConnect\Client\BackChannelLogout;

final class LogoutTokenIsInvalid extends \Exception
{
    public static function becauseItDoesNotDeclareTheNecessaryEvent(): self
    {
        return new self(
            message: 'Event ' . LogoutToken::EVENT . ' is missing from the logout token events claim',
            code: 1788168736,
        );
    }
    public static function becauseItClaimsANonce(): self
    {
        return new self(
            message: 'The token claims a nonce but must not',
            code: 1788169899,
        );
    }

    public static function becauseItClaimsNoIssuer(): self
    {
        return new self(
            message: 'The token claims no issuer but must',
            code: 1788170101,
        );
    }

    public static function becauseItClaimsNoIdentifier(): self
    {
        return new self(
            message: 'The token claims no identifier but must',
            code: 1788170224,
        );
    }

    public static function becauseItClaimsNeitherSessionIdNorSubject(): self
    {
        return new self(
            message: 'The token claims neither session id nor subject',
            code: 1788171885,
        );
    }

    public static function becauseItClaimsNoExpirationDate(): self
    {
        return new self(
            message: 'The token claims no expiration date',
            code: 1788182557,
        );
    }
}
