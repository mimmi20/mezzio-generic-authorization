<?php
/**
 * This file is part of the mimmi20/mezzio-generic-authorization package.
 *
 * Copyright (c) 2020, Thomas Mueller <mimmi20@live.de>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types = 1);
namespace Mezzio\GenericAuthorization;

use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseInterface;

final class AuthorizationMiddlewareFactory
{
    /**
     * @param \Psr\Container\ContainerInterface $container
     *
     * @return \Mezzio\GenericAuthorization\AuthorizationMiddleware
     */
    public function __invoke(ContainerInterface $container): AuthorizationMiddleware
    {
        if (!$container->has(AuthorizationInterface::class)) {
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
            $container->get(ResponseInterface::class)
        );
    }
}
