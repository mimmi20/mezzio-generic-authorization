<?php



declare(strict_types=1);

namespace Mezzio\GenericAuthorization;

use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseInterface;
use Laminas\Log\Logger;

use function sprintf;

class AuthorizationMiddlewareFactory
{
    public function __invoke(ContainerInterface $container) : AuthorizationMiddleware
    {
        if (! $container->has(AuthorizationInterface::class)) {
            throw new Exception\InvalidConfigException(
                sprintf(
                    'Cannot create %s service; dependency %s is missing',
                    AuthorizationMiddleware::class,
                    AuthorizationInterface::class
                )
            );
        }

        return new AuthorizationMiddleware(
            $container->get(AuthorizationInterface::class),
            $container->get(Logger::class),
            $container->get(ResponseInterface::class)
        );
    }
}
