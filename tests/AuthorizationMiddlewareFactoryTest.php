<?php

/**
 * This file is part of the mimmi20/mezzio-generic-authorization package.
 *
 * Copyright (c) 2020-2026, Thomas Mueller <mimmi20@live.de>
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
    /** @throws InvalidConfigException */
    public function testFactoryWithoutAuthorization(): void
    {
        $container = $this->createMock(ContainerInterface::class);
        $container->expects(self::once())
            ->method('has')
            ->with(AuthorizationInterface::class)
            ->willReturn(value: false);
        $container->expects(self::never())
            ->method('get');

        $authorizationMiddlewareFactory = new AuthorizationMiddlewareFactory();

        $this->expectException(InvalidConfigException::class);
        $this->expectExceptionMessage(
            'Cannot create Mimmi20\Mezzio\GenericAuthorization\AuthorizationMiddleware service; dependency Mimmi20\Mezzio\GenericAuthorization\AuthorizationInterface is missing',
        );
        $this->expectExceptionCode(0);

        assert($container instanceof ContainerInterface);
        $authorizationMiddlewareFactory($container);
    }

    /** @throws InvalidConfigException */
    public function testFactoryWithoutResponse(): void
    {
        $container    = $this->createMock(ContainerInterface::class);
        $invokedCount = self::exactly(2);
        $container->expects($invokedCount)
            ->method('has')
            ->willReturnCallback(
                static function (string $id) use ($invokedCount): bool {
                    match ($invokedCount->numberOfInvocations()) {
                        1 => self::assertSame(AuthorizationInterface::class, $id),
                        default => self::assertSame(ResponseFactoryInterface::class, $id),
                    };

                    return match ($invokedCount->numberOfInvocations()) {
                        1 => true,
                        default => false,
                    };
                },
            );
        $container->expects(self::never())
            ->method('get');

        $authorizationMiddlewareFactory = new AuthorizationMiddlewareFactory();

        $this->expectException(InvalidConfigException::class);
        $this->expectExceptionMessage(
            'Cannot create Mimmi20\Mezzio\GenericAuthorization\AuthorizationMiddleware service; dependency Psr\Http\Message\ResponseFactoryInterface is missing',
        );
        $this->expectExceptionCode(0);

        assert($container instanceof ContainerInterface);
        $authorizationMiddlewareFactory($container);
    }

    /**
     * @throws Exception
     * @throws InvalidConfigException
     * @throws ReflectionException
     */
    public function testFactory(): void
    {
        $authorization   = self::createStub(AuthorizationInterface::class);
        $responseFactory = self::createStub(ResponseFactoryInterface::class);

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

        $authorizationMiddlewareFactory = new AuthorizationMiddlewareFactory();

        assert($container instanceof ContainerInterface);
        $authorizationMiddleware = $authorizationMiddlewareFactory($container);
        self::assertInstanceOf(AuthorizationMiddleware::class, $authorizationMiddleware);

        $auth = new ReflectionProperty($authorizationMiddleware, 'authorization');
        self::assertSame($authorization, $auth->getValue($authorizationMiddleware));

        $rf = new ReflectionProperty($authorizationMiddleware, 'responseFactory');
        self::assertSame($responseFactory, $rf->getValue($authorizationMiddleware));

        $dp = new ReflectionProperty($authorizationMiddleware, 'defaultPrivilege');
        self::assertNull($dp->getValue($authorizationMiddleware));
    }

    /** @throws InvalidConfigException */
    public function testFactoryContainerException(): void
    {
        $serviceNotCreatedException = new ServiceNotCreatedException('test');
        $container                  = $this->createMock(ContainerInterface::class);
        $invokedCount               = self::exactly(2);
        $container->expects($invokedCount)
            ->method('has')
            ->willReturnCallback(
                static function (string $id) use ($invokedCount): bool {
                    match ($invokedCount->numberOfInvocations()) {
                        1 => self::assertSame(AuthorizationInterface::class, $id),
                        default => self::assertSame(ResponseFactoryInterface::class, $id),
                    };

                    return true;
                },
            );
        $container->expects(self::once())
            ->method('get')
            ->with(AuthorizationInterface::class)
            ->willThrowException($serviceNotCreatedException);

        $authorizationMiddlewareFactory = new AuthorizationMiddlewareFactory();

        $this->expectException(InvalidConfigException::class);
        $this->expectExceptionMessage(
            'Cannot create Mimmi20\Mezzio\GenericAuthorization\AuthorizationMiddleware service; could not initialize dependency Mimmi20\Mezzio\GenericAuthorization\AuthorizationInterface or Psr\Http\Message\ResponseFactoryInterface',
        );
        $this->expectExceptionCode(0);

        assert($container instanceof ContainerInterface);
        $authorizationMiddlewareFactory($container);
    }

    /**
     * @throws Exception
     * @throws InvalidConfigException
     * @throws ReflectionException
     */
    public function testFactoryWithConfigWithoutPrivilege(): void
    {
        $authorization   = self::createStub(AuthorizationInterface::class);
        $responseFactory = self::createStub(ResponseFactoryInterface::class);
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

        $authorizationMiddlewareFactory = new AuthorizationMiddlewareFactory();

        assert($container instanceof ContainerInterface);
        $authorizationMiddleware = $authorizationMiddlewareFactory($container);
        self::assertInstanceOf(AuthorizationMiddleware::class, $authorizationMiddleware);

        $auth = new ReflectionProperty($authorizationMiddleware, 'authorization');
        self::assertSame($authorization, $auth->getValue($authorizationMiddleware));

        $rf = new ReflectionProperty($authorizationMiddleware, 'responseFactory');
        self::assertSame($responseFactory, $rf->getValue($authorizationMiddleware));

        $dp = new ReflectionProperty($authorizationMiddleware, 'defaultPrivilege');
        self::assertNull($dp->getValue($authorizationMiddleware));
    }

    /**
     * @throws Exception
     * @throws InvalidConfigException
     * @throws ReflectionException
     */
    public function testFactoryWithConfigAndPrivilege(): void
    {
        $authorization   = self::createStub(AuthorizationInterface::class);
        $responseFactory = self::createStub(ResponseFactoryInterface::class);
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

        $authorizationMiddlewareFactory = new AuthorizationMiddlewareFactory();

        assert($container instanceof ContainerInterface);
        $authorizationMiddleware = $authorizationMiddlewareFactory($container);
        self::assertInstanceOf(AuthorizationMiddleware::class, $authorizationMiddleware);

        $auth = new ReflectionProperty($authorizationMiddleware, 'authorization');
        self::assertSame($authorization, $auth->getValue($authorizationMiddleware));

        $rf = new ReflectionProperty($authorizationMiddleware, 'responseFactory');
        self::assertSame($responseFactory, $rf->getValue($authorizationMiddleware));

        $dp = new ReflectionProperty($authorizationMiddleware, 'defaultPrivilege');
        self::assertSame($privilege, $dp->getValue($authorizationMiddleware));
    }

    /**
     * @throws Exception
     * @throws InvalidConfigException
     * @throws ReflectionException
     */
    public function testFactoryWithConfigAndWrongPrivilegeType(): void
    {
        $authorization   = self::createStub(AuthorizationInterface::class);
        $responseFactory = self::createStub(ResponseFactoryInterface::class);
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

        $authorizationMiddlewareFactory = new AuthorizationMiddlewareFactory();

        assert($container instanceof ContainerInterface);
        $authorizationMiddleware = $authorizationMiddlewareFactory($container);
        self::assertInstanceOf(AuthorizationMiddleware::class, $authorizationMiddleware);

        $auth = new ReflectionProperty($authorizationMiddleware, 'authorization');
        self::assertSame($authorization, $auth->getValue($authorizationMiddleware));

        $rf = new ReflectionProperty($authorizationMiddleware, 'responseFactory');
        self::assertSame($responseFactory, $rf->getValue($authorizationMiddleware));

        $dp = new ReflectionProperty($authorizationMiddleware, 'defaultPrivilege');
        self::assertNull($dp->getValue($authorizationMiddleware));
    }

    /**
     * @throws Exception
     * @throws InvalidConfigException
     * @throws ReflectionException
     */
    public function testFactoryWithConfigAndWrongPrivilegeType2(): void
    {
        $authorization   = self::createStub(AuthorizationInterface::class);
        $responseFactory = self::createStub(ResponseFactoryInterface::class);
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

        $authorizationMiddlewareFactory = new AuthorizationMiddlewareFactory();

        assert($container instanceof ContainerInterface);
        $authorizationMiddleware = $authorizationMiddlewareFactory($container);
        self::assertInstanceOf(AuthorizationMiddleware::class, $authorizationMiddleware);

        $auth = new ReflectionProperty($authorizationMiddleware, 'authorization');
        self::assertSame($authorization, $auth->getValue($authorizationMiddleware));

        $rf = new ReflectionProperty($authorizationMiddleware, 'responseFactory');
        self::assertSame($responseFactory, $rf->getValue($authorizationMiddleware));

        $dp = new ReflectionProperty($authorizationMiddleware, 'defaultPrivilege');
        self::assertNull($dp->getValue($authorizationMiddleware));
    }
}
