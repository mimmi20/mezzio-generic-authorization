<?php
/**
 * This file is part of the mimmi20/mezzio-generic-authorization-rbac package.
 *
 * Copyright (c) 2020-2023, Thomas Mueller <mimmi20@live.de>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types = 1);

namespace Mimmi20\Mezzio\GenericAuthorization;

use Mimmi20\Mezzio\GenericAuthorization\Exception\InvalidConfigException;
use Psr\Container\ContainerExceptionInterface;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseInterface;

use function assert;
use function sprintf;

final class AuthorizationMiddlewareFactory
{
    /** @throws InvalidConfigException */
    public function __invoke(ContainerInterface $container): AuthorizationMiddleware
    {
        if (!$container->has(AuthorizationInterface::class)) {
            throw new InvalidConfigException(
                sprintf(
                    'Cannot create %s service; dependency %s is missing',
                    AuthorizationMiddleware::class,
                    AuthorizationInterface::class,
                ),
            );
        }

        if (!$container->has(ResponseInterface::class)) {
            throw new InvalidConfigException(
                sprintf(
                    'Cannot create %s service; dependency %s is missing',
                    AuthorizationMiddleware::class,
                    ResponseInterface::class,
                ),
            );
        }

        try {
            $auth     = $container->get(AuthorizationInterface::class);
            $response = $container->get(ResponseInterface::class);
        } catch (ContainerExceptionInterface) {
            throw new InvalidConfigException(
                sprintf(
                    'Cannot create %s service; could not initialize dependency %s or %s',
                    AuthorizationMiddleware::class,
                    AuthorizationInterface::class,
                    ResponseInterface::class,
                ),
            );
        }

        assert($auth instanceof AuthorizationInterface);
        assert($response instanceof ResponseInterface);

        return new AuthorizationMiddleware($auth, $response);
    }
}
