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

use Mezzio\Authentication\DefaultUser;
use Mezzio\Authentication\UserInterface;
use Mezzio\GenericAuthorization\AuthorizationInterface;
use Mezzio\GenericAuthorization\AuthorizationMiddleware;
use PHPUnit\Framework\TestCase;
use Prophecy\Argument;
use Prophecy\Prophecy\ObjectProphecy;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class AuthorizationMiddlewareTest extends TestCase
{
    /** @var AuthorizationInterface|ObjectProphecy */
    private $authorization;

    /** @var ObjectProphecy|ServerRequestInterface */
    private $request;

    /** @var ObjectProphecy|RequestHandlerInterface */
    private $handler;

    /** @var ObjectProphecy|ResponseInterface */
    private $responsePrototype;

    /** @var callable */
    private $responseFactory;

    /**
     * @return void
     */
    protected function setUp(): void
    {
        $this->authorization     = $this->prophesize(AuthorizationInterface::class);
        $this->request           = $this->prophesize(ServerRequestInterface::class);
        $this->handler           = $this->prophesize(RequestHandlerInterface::class);
        $this->responsePrototype = $this->prophesize(ResponseInterface::class);
        $this->responseFactory   = function () {
            return $this->responsePrototype->reveal();
        };
    }

    /**
     * @return void
     */
    public function testConstructor(): void
    {
        $middleware = new AuthorizationMiddleware($this->authorization->reveal(), $this->responseFactory);
        self::assertInstanceOf(AuthorizationMiddleware::class, $middleware);
    }

    /**
     * @return void
     */
    public function testProcessWithoutUserAttribute(): void
    {
        $this->request->getAttribute(UserInterface::class, false)->willReturn(false);
        $this->responsePrototype->withStatus(401)->will([$this->responsePrototype, 'reveal']);

        $this->handler
            ->handle(Argument::any())
            ->shouldNotBeCalled();

        $middleware = new AuthorizationMiddleware($this->authorization->reveal(), $this->responseFactory);

        $response = $middleware->process(
            $this->request->reveal(),
            $this->handler->reveal()
        );

        self::assertSame($this->responsePrototype->reveal(), $response);
    }

    /**
     * @return void
     */
    public function testProcessRoleNotGranted(): void
    {
        $this->request
            ->getAttribute(UserInterface::class, false)
            ->willReturn($this->generateUser('foo', ['bar']));
        $this->responsePrototype
            ->withStatus(403)
            ->will([$this->responsePrototype, 'reveal']);
        $this->authorization
            ->isGranted('bar', Argument::that([$this->request, 'reveal']))
            ->willReturn(false);

        $this->handler
            ->handle(Argument::any())
            ->shouldNotBeCalled();

        $middleware = new AuthorizationMiddleware($this->authorization->reveal(), $this->responseFactory);

        $response = $middleware->process(
            $this->request->reveal(),
            $this->handler->reveal()
        );

        self::assertSame($this->responsePrototype->reveal(), $response);
    }

    /**
     * @return void
     */
    public function testProcessRoleGranted(): void
    {
        $this->request
            ->getAttribute(UserInterface::class, false)
            ->willReturn($this->generateUser('foo', ['bar']));
        $this->authorization
            ->isGranted('bar', '', Argument::that([$this->request, 'reveal']))
            ->willReturn(true);

        $this->handler
            ->handle(Argument::any())
            ->will([$this->responsePrototype, 'reveal']);

        $middleware = new AuthorizationMiddleware($this->authorization->reveal(), $this->responseFactory);

        $response = $middleware->process(
            $this->request->reveal(),
            $this->handler->reveal()
        );

        self::assertSame($this->responsePrototype->reveal(), $response);
    }

    /**
     * @param string $identity
     * @param array  $roles
     *
     * @return \Mezzio\Authentication\DefaultUser
     */
    private function generateUser(string $identity, array $roles = []): DefaultUser
    {
        return new DefaultUser($identity, $roles);
    }
}
