<?php

declare(strict_types=1);

namespace Flownative\OpenIdConnect\Client;

final class ServiceNameIsInvalid extends \Exception
{
    public static function butWasAttemptedToBeInstantiated(string $attemptedServiceName): self
    {
        return new self($attemptedServiceName . ' is no valid service name', 1788767826);
    }
}
