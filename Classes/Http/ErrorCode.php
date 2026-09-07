<?php

declare(strict_types=1);

namespace Flownative\OpenIdConnect\Client\Http;

/**
 * An RFC6749 error code
 *
 * @see https://www.rfc-editor.org/info/rfc6749/#section-5.2
 */
enum ErrorCode: string implements \JsonSerializable
{
    /**
     * The request is missing a required parameter, includes an
     * unsupported parameter value (other than grant type),
     * repeats a parameter, includes multiple credentials,
     * utilizes more than one mechanism for authenticating the
     * client, or is otherwise malformed.
     */
    case INVALID_REQUEST = 'invalid_request';

    /**
     * Client authentication failed (e.g., unknown client, no
     * client authentication included, or unsupported
     * authentication method).  The authorization server MAY
     * return an HTTP 401 (Unauthorized) status code to indicate
     * which HTTP authentication schemes are supported.  If the
     * client attempted to authenticate via the "Authorization"
     * request header field, the authorization server MUST
     * respond with an HTTP 401 (Unauthorized) status code and
     * include the "WWW-Authenticate" response header field
     * matching the authentication scheme used by the client.
     */
    case INVALID_CLIENT = 'invalid_client';

    /**
     * The provided authorization grant (e.g., authorization
     * code, resource owner credentials) or refresh token is
     * invalid, expired, revoked, does not match the redirection
     * URI used in the authorization request, or was issued to
     * another client.
     */
    case INVALID_GRANT = 'invalid_grant';

    /**
     * The authenticated client is not authorized to use this
     * authorization grant type.
     */
    case UNAUTHORIZED_CLIENT = 'unauthorized_client';

    /**
     * The authorization grant type is not supported by the
     * authorization server.
     */
    case UNSUPPORTED_GRANT_TYPE = 'unsupported_grant_type';

    /**
     * The requested scope is invalid, unknown, malformed, or
     * exceeds the scope granted by the resource owner.
     */
    case INVALID_SCOPE = 'invalid_scope';

    public function jsonSerialize(): string
    {
        return $this->value;
    }
}
