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

use Laminas\ServiceManager\Exception\ServiceNotCreatedException;
use Mimmi20\Mezzio\GenericAuthorization\Exception\InvalidConfigException;
use PHPUnit\Framework\Exception;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseInterface;

use function assert;

final class AuthorizationMiddlewareFactoryTest extends TestCase
{
    /**
     * @throws Exception
     * @throws InvalidConfigException
     */
    public function testFactoryWithoutAuthorization(): void
    {
        $container = $this->getMockBuilder(ContainerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
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

        assert($container instanceof ContainerInterface);
        $factory($container);
    }

    /**
     * @throws Exception
     * @throws InvalidConfigException
     */
    public function testFactoryWithoutResponse(): void
    {
        $container = $this->getMockBuilder(ContainerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $matcher   = self::exactly(2);
        $container->expects($matcher)
            ->method('has')
            ->willReturnCallback(
                static function (string $id) use ($matcher): bool {
                    match ($matcher->numberOfInvocations()) {
                        1 => self::assertSame(AuthorizationInterface::class, $id),
                        default => self::assertSame(ResponseInterface::class, $id),
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
            'Cannot create Mimmi20\Mezzio\GenericAuthorization\AuthorizationMiddleware service; dependency Psr\Http\Message\ResponseInterface is missing',
        );

        assert($container instanceof ContainerInterface);
        $factory($container);
    }

    /**
     * @throws Exception
     * @throws InvalidConfigException
     */
    public function testFactory(): void
    {
        $authorization = $this->createMock(AuthorizationInterface::class);
        $response      = $this->createMock(ResponseInterface::class);

        $container = $this->getMockBuilder(ContainerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $matcher   = self::exactly(2);
        $container->expects($matcher)
            ->method('has')
            ->willReturnCallback(
                static function (string $id) use ($matcher): bool {
                    match ($matcher->numberOfInvocations()) {
                        1 => self::assertSame(AuthorizationInterface::class, $id),
                        default => self::assertSame(ResponseInterface::class, $id),
                    };

                    return true;
                },
            );
        $matcher = self::exactly(2);
        $container->expects($matcher)
            ->method('get')
            ->willReturnCallback(
                static function (string $id) use ($matcher, $authorization, $response): mixed {
                    match ($matcher->numberOfInvocations()) {
                        1 => self::assertSame(AuthorizationInterface::class, $id),
                        default => self::assertSame(ResponseInterface::class, $id),
                    };

                    return match ($matcher->numberOfInvocations()) {
                        1 => $authorization,
                        default => $response,
                    };
                },
            );

        $factory = new AuthorizationMiddlewareFactory();

        assert($container instanceof ContainerInterface);
        $middleware = $factory($container);
        self::assertInstanceOf(AuthorizationMiddleware::class, $middleware);
    }

    /**
     * @throws Exception
     * @throws InvalidConfigException
     */
    public function testFactoryContainerException(): void
    {
        $exception = new ServiceNotCreatedException('test');
        $container = $this->getMockBuilder(ContainerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $matcher   = self::exactly(2);
        $container->expects($matcher)
            ->method('has')
            ->willReturnCallback(
                static function (string $id) use ($matcher): bool {
                    match ($matcher->numberOfInvocations()) {
                        1 => self::assertSame(AuthorizationInterface::class, $id),
                        default => self::assertSame(ResponseInterface::class, $id),
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
            'Cannot create Mimmi20\Mezzio\GenericAuthorization\AuthorizationMiddleware service; could not initialize dependency Mimmi20\Mezzio\GenericAuthorization\AuthorizationInterface or Psr\Http\Message\ResponseInterface',
        );

        assert($container instanceof ContainerInterface);
        $factory($container);
    }
}
