<?php

declare(strict_types=1);

namespace Flownative\OpenIdConnect\Client\Http;

use Flownative\OpenIdConnect\Client\Authentication\OpenIdConnectProvider;
use Flownative\OpenIdConnect\Client\BackChannelLogout\AuthenticationRevocationRegistry;
use Flownative\OpenIdConnect\Client\BackChannelLogout\LogoutTokenIsInvalid;
use Flownative\OpenIdConnect\Client\ConfigurationException;
use Flownative\OpenIdConnect\Client\ConnectionException;
use Flownative\OpenIdConnect\Client\ServiceName;
use Flownative\OpenIdConnect\Client\OpenIdConnectClient;
use Flownative\OpenIdConnect\Client\ServiceException;
use Flownative\OpenIdConnect\Client\ServiceNameIsInvalid;
use GuzzleHttp\Psr7\Response;
use Neos\Cache\Exception as CacheException;
use Neos\Flow\Session\SessionManagerInterface;
use Neos\Http\Factories\StreamFactoryTrait;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class BackChannelLogoutMiddleware implements MiddlewareInterface
{
    use StreamFactoryTrait;

    private const URI_PATH = '/oidc/backchannellogout/';

    public function __construct(
        private readonly SessionManagerInterface $sessionManager,
        private readonly AuthenticationRevocationRegistry $authenticationRevocationRegistry,
    ) {
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if (!\str_starts_with($request->getUri()->getPath(), self::URI_PATH)) {
            return $handler->handle($request);
        }

        if (\strtolower($request->getMethod()) !== 'post') {
            return $this->createErrorResponse(
                ErrorResponseBody::create(
                    ErrorCode::INVALID_REQUEST,
                    'Expected POST request, got ' . $request->getMethod(),
                )
            );
        }

        try {
            $serviceName = ServiceName::fromString(\mb_substr($request->getUri()->getPath(), \mb_strlen(self::URI_PATH)));
        } catch (ServiceNameIsInvalid) {
            return $this->createErrorResponse(
                ErrorResponseBody::create(
                    ErrorCode::INVALID_REQUEST,
                    'Unknown service',
                )
            );
        }

        $fields = $request->getParsedBody();
        if (!is_array($fields)) {
            $fields = [];
            parse_str((string)$request->getBody(), $fields);
        }
        $logoutTokenValue = is_string($fields['logout_token'] ?? null) ? $fields['logout_token'] : null;

        if (!$logoutTokenValue) {
            return $this->createErrorResponse(
                ErrorResponseBody::create(
                    ErrorCode::INVALID_REQUEST,
                    'No logout token given',
                )
            );
        }

        try {
            $oidcClient = new OpenIdConnectClient($serviceName->value);
            $logoutToken = $oidcClient->getLogoutToken($logoutTokenValue);
            if (!$logoutToken) {
                return $this->createErrorResponse(
                    ErrorResponseBody::create(
                        ErrorCode::INVALID_REQUEST,
                        'Token verification failed',
                    )
                );
            }
        } catch (LogoutTokenIsInvalid $exception) {
            return $this->createErrorResponse(
                ErrorResponseBody::create(
                    ErrorCode::INVALID_REQUEST,
                    $exception->getMessage(),
                )
            );
        } catch (ConfigurationException) {
            return $this->createErrorResponse(
                ErrorResponseBody::create(
                    ErrorCode::INVALID_REQUEST,
                    'Unknown service'
                )
            );
        } catch (ConnectionException|ServiceException|CacheException) {
            return (new Response())
                ->withStatus(503)
                ->withHeader('Cache-Control', 'no-store')
                ->withHeader('Retry-After', '60');
        }

        /**
         * register tag for revocation in @see OpenIdConnectProvider::authenticate()
         */
        $this->authenticationRevocationRegistry->add($logoutToken->revocationTag, $logoutToken->issuedAt);
        /**
         * clear refresh token sessions, @see OpenIdConnectProvider::authenticate()
         */
        $this->sessionManager->destroySessionsByTag($logoutToken->revocationTag->value);

        return (new Response())
            ->withStatus(200)
            ->withHeader('Cache-Control', 'no-store');
    }

    /** @see https://openid.net/specs/openid-connect-backchannel-1_0.html#BCResponse */
    private function createErrorResponse(ErrorResponseBody $body): ResponseInterface
    {
        return (new Response())
            ->withStatus(400)
            ->withHeader('Cache-Control', 'no-store')
            ->withHeader('Content-Type', 'application/json')
            ->withBody($this->createStream(\json_encode($body)));
    }
}
