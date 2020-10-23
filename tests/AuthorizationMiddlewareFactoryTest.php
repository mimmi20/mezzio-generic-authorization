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

use Mezzio\GenericAuthorization\AuthorizationInterface;
use Mezzio\GenericAuthorization\AuthorizationMiddleware;
use Mezzio\GenericAuthorization\AuthorizationMiddlewareFactory;
use Mezzio\GenericAuthorization\Exception;
use PHPUnit\Framework\Assert;
use PHPUnit\Framework\TestCase;
use Prophecy\Prophecy\ObjectProphecy;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseInterface;
use ReflectionProperty;

final class AuthorizationMiddlewareFactoryTest extends TestCase
{
    /** @var ContainerInterface|ObjectProphecy */
    private $container;

    /** @var AuthorizationMiddlewareFactory */
    private $factory;

    /** @var AuthorizationInterface|ObjectProphecy */
    private $authorization;

    /** @var ObjectProphecy|ResponseInterface */
    private $responsePrototype;

    /** @var callable */
    private $responseFactory;

    /**
     * @return void
     */
    protected function setUp(): void
    {
        $this->container         = $this->prophesize(ContainerInterface::class);
        $this->factory           = new AuthorizationMiddlewareFactory();
        $this->authorization     = $this->prophesize(AuthorizationInterface::class);
        $this->responsePrototype = $this->prophesize(ResponseInterface::class);
        $this->responseFactory   = function () {
            return $this->responsePrototype->reveal();
        };

        $this->container
            ->get(AuthorizationInterface::class)
            ->will([$this->authorization, 'reveal']);
        $this->container
            ->get(ResponseInterface::class)
            ->willReturn($this->responseFactory);
    }

    /**
     * @return void
     */
    public function testFactoryWithoutAuthorization(): void
    {
        $this->container->has(AuthorizationInterface::class)->willReturn(false);

        $this->expectException(Exception\InvalidConfigException::class);
        ($this->factory)($this->container->reveal());
    }

    /**
     * @return void
     */
    public function testFactory(): void
    {
        $this->container->has(AuthorizationInterface::class)->willReturn(true);
        $this->container->has(ResponseInterface::class)->willReturn(true);

        $middleware = ($this->factory)($this->container->reveal());
        self::assertInstanceOf(AuthorizationMiddleware::class, $middleware);
        $this->assertResponseFactoryReturns($this->responsePrototype->reveal(), $middleware);
    }

    /**
     * @param \Psr\Http\Message\ResponseInterface                  $expected
     * @param \Mezzio\GenericAuthorization\AuthorizationMiddleware $middleware
     *
     * @throws \ReflectionException
     *
     * @return void
     */
    public static function assertResponseFactoryReturns(
        ResponseInterface $expected,
        AuthorizationMiddleware $middleware
    ): void {
        $r = new ReflectionProperty($middleware, 'responseFactory');
        $r->setAccessible(true);
        $responseFactory = $r->getValue($middleware);
        Assert::assertSame($expected, $responseFactory());
    }
}
