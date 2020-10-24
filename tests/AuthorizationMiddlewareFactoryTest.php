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
namespace MezzioTest\GenericAuthorization;

use Laminas\ServiceManager\Exception\ServiceNotCreatedException;
use Mezzio\GenericAuthorization\AuthorizationInterface;
use Mezzio\GenericAuthorization\AuthorizationMiddleware;
use Mezzio\GenericAuthorization\AuthorizationMiddlewareFactory;
use Mezzio\GenericAuthorization\Exception;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseInterface;

final class AuthorizationMiddlewareFactoryTest extends TestCase
{
    /**
     * @throws \PHPUnit\Framework\MockObject\RuntimeException
     *
     * @return void
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

        $this->expectException(Exception\InvalidConfigException::class);
        $this->expectExceptionMessage('Cannot create Mezzio\GenericAuthorization\AuthorizationMiddleware service; dependency Mezzio\GenericAuthorization\AuthorizationInterface is missing');

        /* @var ContainerInterface $container */
        $factory($container);
    }

    /**
     * @throws \PHPUnit\Framework\MockObject\RuntimeException
     *
     * @return void
     */
    public function testFactoryWithoutResponse(): void
    {
        $container = $this->getMockBuilder(ContainerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $container->expects(self::exactly(2))
            ->method('has')
            ->withConsecutive([AuthorizationInterface::class], [ResponseInterface::class])
            ->willReturnOnConsecutiveCalls(true, false);
        $container->expects(self::never())
            ->method('get');

        $factory = new AuthorizationMiddlewareFactory();

        $this->expectException(Exception\InvalidConfigException::class);
        $this->expectExceptionMessage('Cannot create Mezzio\GenericAuthorization\AuthorizationMiddleware service; dependency Psr\Http\Message\ResponseInterface is missing');

        /* @var ContainerInterface $container */
        $factory($container);
    }

    /**
     * @throws \PHPUnit\Framework\ExpectationFailedException
     * @throws \PHPUnit\Framework\MockObject\RuntimeException
     * @throws \SebastianBergmann\RecursionContext\InvalidArgumentException
     *
     * @return void
     */
    public function testFactory(): void
    {
        $authorization = $this->createMock(AuthorizationInterface::class);
        $response      = $this->createMock(ResponseInterface::class);

        $container = $this->getMockBuilder(ContainerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $container->expects(self::exactly(2))
            ->method('has')
            ->withConsecutive([AuthorizationInterface::class], [ResponseInterface::class])
            ->willReturnOnConsecutiveCalls(true, true);
        $container->expects(self::exactly(2))
            ->method('get')
            ->withConsecutive([AuthorizationInterface::class], [ResponseInterface::class])
            ->willReturnOnConsecutiveCalls($authorization, $response);

        $factory = new AuthorizationMiddlewareFactory();

        /** @var ContainerInterface $container */
        $middleware = $factory($container);
        self::assertInstanceOf(AuthorizationMiddleware::class, $middleware);
    }

    /**
     * @throws \PHPUnit\Framework\MockObject\RuntimeException
     *
     * @return void
     */
    public function testFactoryContainerException(): void
    {
        $exception = new ServiceNotCreatedException('test');
        $container = $this->getMockBuilder(ContainerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $container->expects(self::exactly(2))
            ->method('has')
            ->withConsecutive([AuthorizationInterface::class], [ResponseInterface::class])
            ->willReturnOnConsecutiveCalls(true, true);
        $container->expects(self::once())
            ->method('get')
            ->with(AuthorizationInterface::class)
            ->willThrowException($exception);

        $factory = new AuthorizationMiddlewareFactory();

        $this->expectException(Exception\InvalidConfigException::class);
        $this->expectExceptionMessage('Cannot create Mezzio\GenericAuthorization\AuthorizationMiddleware service; could not initialize dependency Mezzio\GenericAuthorization\AuthorizationInterface or Psr\Http\Message\ResponseInterface');

        /* @var ContainerInterface $container */
        $factory($container);
    }
}
