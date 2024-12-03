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

use Laminas\ServiceManager\Exception\ServiceNotCreatedException;
use Mimmi20\Mezzio\GenericAuthorization\Exception\InvalidConfigException;
use PHPUnit\Framework\Exception;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use ReflectionException;
use ReflectionProperty;

use function assert;

final class AuthorizationMiddlewareFactoryTest extends TestCase
{
    /**
     * @throws Exception
     * @throws InvalidConfigException
     */
    public function testFactoryWithoutAuthorization(): void
    {
        $container = $this->createMock(ContainerInterface::class);
        $container->expects(self::once())
            ->method('has')
            ->with(AuthorizationInterface::class)
            ->willReturn(false);
        $container->expects(self::never())
            ->method('get');

        $factory = new AuthorizationMiddlewareFactory();

        $this->expectException(InvalidConfigException::class);
        $this->expectExceptionMessage(
            'Cannot create Mimmi20\Mezzio\GenericAuthorization\AuthorizationMiddleware service; dependency Mimmi20\Mezzio\GenericAuthorization\AuthorizationInterface is missing',
        );
        $this->expectExceptionCode(0);

        assert($container instanceof ContainerInterface);
        $factory($container);
    }

    /**
     * @throws Exception
     * @throws InvalidConfigException
     */
    public function testFactoryWithoutResponse(): void
    {
        $container = $this->createMock(ContainerInterface::class);
        $matcher   = self::exactly(2);
        $container->expects($matcher)
            ->method('has')
            ->willReturnCallback(
                static function (string $id) use ($matcher): bool {
                    match ($matcher->numberOfInvocations()) {
                        1 => self::assertSame(AuthorizationInterface::class, $id),
                        default => self::assertSame(ResponseFactoryInterface::class, $id),
                    };

                    return match ($matcher->numberOfInvocations()) {
                        1 => true,
                        default => false,
                    };
                },
            );
        $container->expects(self::never())
            ->method('get');

        $factory = new AuthorizationMiddlewareFactory();

        $this->expectException(InvalidConfigException::class);
        $this->expectExceptionMessage(
            'Cannot create Mimmi20\Mezzio\GenericAuthorization\AuthorizationMiddleware service; dependency Psr\Http\Message\ResponseFactoryInterface is missing',
        );
        $this->expectExceptionCode(0);

        assert($container instanceof ContainerInterface);
        $factory($container);
    }

    /**
     * @throws Exception
     * @throws InvalidConfigException
     * @throws ReflectionException
     */
    public function testFactory(): void
    {
        $authorization   = $this->createMock(AuthorizationInterface::class);
        $responseFactory = $this->createMock(ResponseFactoryInterface::class);

        $container = $this->createMock(ContainerInterface::class);
        $matcher   = self::exactly(2);
        $container->expects($matcher)
            ->method('has')
            ->willReturnCallback(
                static function (string $id) use ($matcher): bool {
                    match ($matcher->numberOfInvocations()) {
                        1 => self::assertSame(AuthorizationInterface::class, $id),
                        default => self::assertSame(ResponseFactoryInterface::class, $id),
                    };

                    return true;
                },
            );
        $matcher = self::exactly(3);
        $container->expects($matcher)
            ->method('get')
            ->willReturnCallback(
                static function (string $id) use ($matcher, $authorization, $responseFactory): mixed {
                    match ($matcher->numberOfInvocations()) {
                        1 => self::assertSame(AuthorizationInterface::class, $id),
                        3 => self::assertSame('config', $id),
                        default => self::assertSame(ResponseFactoryInterface::class, $id),
                    };

                    return match ($matcher->numberOfInvocations()) {
                        1 => $authorization,
                        3 => null,
                        default => $responseFactory,
                    };
                },
            );

        $factory = new AuthorizationMiddlewareFactory();

        assert($container instanceof ContainerInterface);
        $middleware = $factory($container);
        self::assertInstanceOf(AuthorizationMiddleware::class, $middleware);

        $auth = new ReflectionProperty($middleware, 'authorization');
        self::assertSame($authorization, $auth->getValue($middleware));

        $rf = new ReflectionProperty($middleware, 'responseFactory');
        self::assertSame($responseFactory, $rf->getValue($middleware));

        $dp = new ReflectionProperty($middleware, 'defaultPrivilege');
        self::assertNull($dp->getValue($middleware));
    }

    /**
     * @throws Exception
     * @throws InvalidConfigException
     */
    public function testFactoryContainerException(): void
    {
        $exception = new ServiceNotCreatedException('test');
        $container = $this->createMock(ContainerInterface::class);
        $matcher   = self::exactly(2);
        $container->expects($matcher)
            ->method('has')
            ->willReturnCallback(
                static function (string $id) use ($matcher): bool {
                    match ($matcher->numberOfInvocations()) {
                        1 => self::assertSame(AuthorizationInterface::class, $id),
                        default => self::assertSame(ResponseFactoryInterface::class, $id),
                    };

                    return true;
                },
            );
        $container->expects(self::once())
            ->method('get')
            ->with(AuthorizationInterface::class)
            ->willThrowException($exception);

        $factory = new AuthorizationMiddlewareFactory();

        $this->expectException(InvalidConfigException::class);
        $this->expectExceptionMessage(
            'Cannot create Mimmi20\Mezzio\GenericAuthorization\AuthorizationMiddleware service; could not initialize dependency Mimmi20\Mezzio\GenericAuthorization\AuthorizationInterface or Psr\Http\Message\ResponseFactoryInterface',
        );
        $this->expectExceptionCode(0);

        assert($container instanceof ContainerInterface);
        $factory($container);
    }

    /**
     * @throws Exception
     * @throws InvalidConfigException
     * @throws ReflectionException
     */
    public function testFactoryWithConfigWithoutPrivilege(): void
    {
        $authorization   = $this->createMock(AuthorizationInterface::class);
        $responseFactory = $this->createMock(ResponseFactoryInterface::class);
        $config          = [];

        $container = $this->createMock(ContainerInterface::class);
        $matcher   = self::exactly(2);
        $container->expects($matcher)
            ->method('has')
            ->willReturnCallback(
                static function (string $id) use ($matcher): bool {
                    match ($matcher->numberOfInvocations()) {
                        1 => self::assertSame(AuthorizationInterface::class, $id),
                        default => self::assertSame(ResponseFactoryInterface::class, $id),
                    };

                    return true;
                },
            );
        $matcher = self::exactly(3);
        $container->expects($matcher)
            ->method('get')
            ->willReturnCallback(
                static function (string $id) use ($matcher, $authorization, $responseFactory, $config): mixed {
                    match ($matcher->numberOfInvocations()) {
                        1 => self::assertSame(AuthorizationInterface::class, $id),
                        3 => self::assertSame('config', $id),
                        default => self::assertSame(ResponseFactoryInterface::class, $id),
                    };

                    return match ($matcher->numberOfInvocations()) {
                        1 => $authorization,
                        3 => $config,
                        default => $responseFactory,
                    };
                },
            );

        $factory = new AuthorizationMiddlewareFactory();

        assert($container instanceof ContainerInterface);
        $middleware = $factory($container);
        self::assertInstanceOf(AuthorizationMiddleware::class, $middleware);

        $auth = new ReflectionProperty($middleware, 'authorization');
        self::assertSame($authorization, $auth->getValue($middleware));

        $rf = new ReflectionProperty($middleware, 'responseFactory');
        self::assertSame($responseFactory, $rf->getValue($middleware));

        $dp = new ReflectionProperty($middleware, 'defaultPrivilege');
        self::assertNull($dp->getValue($middleware));
    }

    /**
     * @throws Exception
     * @throws InvalidConfigException
     * @throws ReflectionException
     */
    public function testFactoryWithConfigAndPrivilege(): void
    {
        $authorization   = $this->createMock(AuthorizationInterface::class);
        $responseFactory = $this->createMock(ResponseFactoryInterface::class);
        $privilege       = 'default-privilege';
        $config          = ['authorization' => ['default-privilege' => $privilege]];

        $container = $this->createMock(ContainerInterface::class);
        $matcher   = self::exactly(2);
        $container->expects($matcher)
            ->method('has')
            ->willReturnCallback(
                static function (string $id) use ($matcher): bool {
                    match ($matcher->numberOfInvocations()) {
                        1 => self::assertSame(AuthorizationInterface::class, $id),
                        default => self::assertSame(ResponseFactoryInterface::class, $id),
                    };

                    return true;
                },
            );
        $matcher = self::exactly(3);
        $container->expects($matcher)
            ->method('get')
            ->willReturnCallback(
                static function (string $id) use ($matcher, $authorization, $responseFactory, $config): mixed {
                    match ($matcher->numberOfInvocations()) {
                        1 => self::assertSame(AuthorizationInterface::class, $id),
                        3 => self::assertSame('config', $id),
                        default => self::assertSame(ResponseFactoryInterface::class, $id),
                    };

                    return match ($matcher->numberOfInvocations()) {
                        1 => $authorization,
                        3 => $config,
                        default => $responseFactory,
                    };
                },
            );

        $factory = new AuthorizationMiddlewareFactory();

        assert($container instanceof ContainerInterface);
        $middleware = $factory($container);
        self::assertInstanceOf(AuthorizationMiddleware::class, $middleware);

        $auth = new ReflectionProperty($middleware, 'authorization');
        self::assertSame($authorization, $auth->getValue($middleware));

        $rf = new ReflectionProperty($middleware, 'responseFactory');
        self::assertSame($responseFactory, $rf->getValue($middleware));

        $dp = new ReflectionProperty($middleware, 'defaultPrivilege');
        self::assertSame($privilege, $dp->getValue($middleware));
    }

    /**
     * @throws Exception
     * @throws InvalidConfigException
     * @throws ReflectionException
     */
    public function testFactoryWithConfigAndWrongPrivilegeType(): void
    {
        $authorization   = $this->createMock(AuthorizationInterface::class);
        $responseFactory = $this->createMock(ResponseFactoryInterface::class);
        $privilege       = 1;
        $config          = ['authorization' => ['default-privilege' => $privilege]];

        $container = $this->createMock(ContainerInterface::class);
        $matcher   = self::exactly(2);
        $container->expects($matcher)
            ->method('has')
            ->willReturnCallback(
                static function (string $id) use ($matcher): bool {
                    match ($matcher->numberOfInvocations()) {
                        1 => self::assertSame(AuthorizationInterface::class, $id),
                        default => self::assertSame(ResponseFactoryInterface::class, $id),
                    };

                    return true;
                },
            );
        $matcher = self::exactly(3);
        $container->expects($matcher)
            ->method('get')
            ->willReturnCallback(
                static function (string $id) use ($matcher, $authorization, $responseFactory, $config): mixed {
                    match ($matcher->numberOfInvocations()) {
                        1 => self::assertSame(AuthorizationInterface::class, $id),
                        3 => self::assertSame('config', $id),
                        default => self::assertSame(ResponseFactoryInterface::class, $id),
                    };

                    return match ($matcher->numberOfInvocations()) {
                        1 => $authorization,
                        3 => $config,
                        default => $responseFactory,
                    };
                },
            );

        $factory = new AuthorizationMiddlewareFactory();

        assert($container instanceof ContainerInterface);
        $middleware = $factory($container);
        self::assertInstanceOf(AuthorizationMiddleware::class, $middleware);

        $auth = new ReflectionProperty($middleware, 'authorization');
        self::assertSame($authorization, $auth->getValue($middleware));

        $rf = new ReflectionProperty($middleware, 'responseFactory');
        self::assertSame($responseFactory, $rf->getValue($middleware));

        $dp = new ReflectionProperty($middleware, 'defaultPrivilege');
        self::assertNull($dp->getValue($middleware));
    }

    /**
     * @throws Exception
     * @throws InvalidConfigException
     * @throws ReflectionException
     */
    public function testFactoryWithConfigAndWrongPrivilegeType2(): void
    {
        $authorization   = $this->createMock(AuthorizationInterface::class);
        $responseFactory = $this->createMock(ResponseFactoryInterface::class);
        $config          = ['authorization' => 'abc'];

        $container = $this->createMock(ContainerInterface::class);
        $matcher   = self::exactly(2);
        $container->expects($matcher)
            ->method('has')
            ->willReturnCallback(
                static function (string $id) use ($matcher): bool {
                    match ($matcher->numberOfInvocations()) {
                        1 => self::assertSame(AuthorizationInterface::class, $id),
                        default => self::assertSame(ResponseFactoryInterface::class, $id),
                    };

                    return true;
                },
            );
        $matcher = self::exactly(3);
        $container->expects($matcher)
            ->method('get')
            ->willReturnCallback(
                static function (string $id) use ($matcher, $authorization, $responseFactory, $config): mixed {
                    match ($matcher->numberOfInvocations()) {
                        1 => self::assertSame(AuthorizationInterface::class, $id),
                        3 => self::assertSame('config', $id),
                        default => self::assertSame(ResponseFactoryInterface::class, $id),
                    };

                    return match ($matcher->numberOfInvocations()) {
                        1 => $authorization,
                        3 => $config,
                        default => $responseFactory,
                    };
                },
            );

        $factory = new AuthorizationMiddlewareFactory();

        assert($container instanceof ContainerInterface);
        $middleware = $factory($container);
        self::assertInstanceOf(AuthorizationMiddleware::class, $middleware);

        $auth = new ReflectionProperty($middleware, 'authorization');
        self::assertSame($authorization, $auth->getValue($middleware));

        $rf = new ReflectionProperty($middleware, 'responseFactory');
        self::assertSame($responseFactory, $rf->getValue($middleware));

        $dp = new ReflectionProperty($middleware, 'defaultPrivilege');
        self::assertNull($dp->getValue($middleware));
    }
}
