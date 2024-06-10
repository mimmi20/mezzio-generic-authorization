<?php
/**
 * This file is part of the mimmi20/mezzio-generic-authorization-rbac package.
 *
 * Copyright (c) 2020-2024, Thomas Mueller <mimmi20@live.de>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types = 1);

namespace Mimmi20\Mezzio\GenericAuthorization;

use Mimmi20\Mezzio\GenericAuthorization\Exception\InvalidConfigException;
use Psr\Container\ContainerExceptionInterface;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseFactoryInterface;

use function assert;
use function is_string;
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

        if (!$container->has(ResponseFactoryInterface::class)) {
            throw new InvalidConfigException(
                sprintf(
                    'Cannot create %s service; dependency %s is missing',
                    AuthorizationMiddleware::class,
                    ResponseFactoryInterface::class,
                ),
            );
        }

        try {
            $auth             = $container->get(AuthorizationInterface::class);
            $response         = $container->get(ResponseFactoryInterface::class);
            $defaultPrivilege = $container->get('config')['authorization']['default-privilege'] ?? null;
        } catch (ContainerExceptionInterface $e) {
            throw new InvalidConfigException(
                sprintf(
                    'Cannot create %s service; could not initialize dependency %s or %s',
                    AuthorizationMiddleware::class,
                    AuthorizationInterface::class,
                    ResponseFactoryInterface::class,
                ),
                0,
                $e,
            );
        }

        assert($auth instanceof AuthorizationInterface);
        assert($response instanceof ResponseFactoryInterface);
        assert($defaultPrivilege === null || is_string($defaultPrivilege));

        return new AuthorizationMiddleware($auth, $response, $defaultPrivilege);
    }
}
