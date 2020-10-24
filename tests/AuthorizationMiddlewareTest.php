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

use Mezzio\Authentication\UserInterface;
use Mezzio\GenericAuthorization\AuthorizationInterface;
use Mezzio\GenericAuthorization\AuthorizationMiddleware;
use Mezzio\GenericAuthorization\Exception\RuntimeException;
use Mezzio\Router\RouteResult;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class AuthorizationMiddlewareTest extends TestCase
{
    /**
     * @throws \PHPUnit\Framework\ExpectationFailedException
     * @throws \SebastianBergmann\RecursionContext\InvalidArgumentException
     *
     * @return void
     */
    public function testConstructor(): void
    {
        $authorization   = $this->createMock(AuthorizationInterface::class);
        $responseFactory = $this->createMock(ResponseInterface::class);

        /** @var AuthorizationInterface $authorization */
        /** @var ResponseInterface $responseFactory */
        $middleware = new AuthorizationMiddleware($authorization, $responseFactory);
        self::assertInstanceOf(AuthorizationMiddleware::class, $middleware);
    }

    /**
     * @throws \PHPUnit\Framework\ExpectationFailedException
     * @throws \PHPUnit\Framework\MockObject\RuntimeException
     * @throws \SebastianBergmann\RecursionContext\InvalidArgumentException
     * @throws \Mezzio\GenericAuthorization\Exception\RuntimeException
     *
     * @return void
     */
    public function testProcessWithoutUserAttribute(): void
    {
        $authorization    = $this->createMock(AuthorizationInterface::class);
        $expectedResponse = $this->createMock(ResponseInterface::class);
        $responseFactory  = $this->getMockBuilder(ResponseInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $responseFactory->expects(self::once())
            ->method('withStatus')
            ->with(401)
            ->willReturn($expectedResponse);

        /** @var AuthorizationInterface $authorization */
        /** @var ResponseInterface $responseFactory */
        $middleware = new AuthorizationMiddleware($authorization, $responseFactory);
        self::assertInstanceOf(AuthorizationMiddleware::class, $middleware);

        $request = $this->getMockBuilder(ServerRequestInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $request->expects(self::once())
            ->method('getAttribute')
            ->with(UserInterface::class)
            ->willReturn(null);
        $handler = $this->createMock(RequestHandlerInterface::class);

        /** @var ServerRequestInterface $request */
        /** @var RequestHandlerInterface $handler */
        $response = $middleware->process(
            $request,
            $handler
        );

        self::assertSame($expectedResponse, $response);
    }

    /**
     * @throws \PHPUnit\Framework\ExpectationFailedException
     * @throws \PHPUnit\Framework\MockObject\RuntimeException
     * @throws \SebastianBergmann\RecursionContext\InvalidArgumentException
     * @throws \Mezzio\GenericAuthorization\Exception\RuntimeException
     *
     * @return void
     */
    public function testProcessWithoutRouteAttribute(): void
    {
        $authorization   = $this->createMock(AuthorizationInterface::class);
        $responseFactory = $this->createMock(ResponseInterface::class);
        $user            = $this->createMock(UserInterface::class);

        /** @var AuthorizationInterface $authorization */
        /** @var ResponseInterface $responseFactory */
        $middleware = new AuthorizationMiddleware($authorization, $responseFactory);
        self::assertInstanceOf(AuthorizationMiddleware::class, $middleware);

        $request = $this->getMockBuilder(ServerRequestInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $request->expects(self::exactly(2))
            ->method('getAttribute')
            ->withConsecutive([UserInterface::class], [RouteResult::class])
            ->willReturnOnConsecutiveCalls($user, null);
        $handler = $this->createMock(RequestHandlerInterface::class);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('The Mezzio\Router\RouteResult attribute is missing in the request; cannot perform authorization checks');

        /* @var ServerRequestInterface $request */
        /* @var RequestHandlerInterface $handler */
        $middleware->process(
            $request,
            $handler
        );
    }

    /**
     * @throws \PHPUnit\Framework\ExpectationFailedException
     * @throws \PHPUnit\Framework\MockObject\RuntimeException
     * @throws \SebastianBergmann\RecursionContext\InvalidArgumentException
     * @throws \Mezzio\GenericAuthorization\Exception\RuntimeException
     *
     * @return void
     */
    public function testProcessWithRouteError(): void
    {
        $authorization    = $this->createMock(AuthorizationInterface::class);
        $expectedResponse = $this->createMock(ResponseInterface::class);
        $responseFactory  = $this->createMock(ResponseInterface::class);
        $user             = $this->createMock(UserInterface::class);
        $routeResult      = $this->getMockBuilder(RouteResult::class)
            ->disableOriginalConstructor()
            ->getMock();
        $routeResult->expects(self::once())
            ->method('isFailure')
            ->willReturn(true);

        /** @var AuthorizationInterface $authorization */
        /** @var ResponseInterface $responseFactory */
        $middleware = new AuthorizationMiddleware($authorization, $responseFactory);
        self::assertInstanceOf(AuthorizationMiddleware::class, $middleware);

        $request = $this->getMockBuilder(ServerRequestInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $request->expects(self::exactly(2))
            ->method('getAttribute')
            ->withConsecutive([UserInterface::class], [RouteResult::class])
            ->willReturnOnConsecutiveCalls($user, $routeResult);
        $handler = $this->getMockBuilder(RequestHandlerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $handler->expects(self::once())
            ->method('handle')
            ->with($request)
            ->willReturn($expectedResponse);

        /** @var ServerRequestInterface $request */
        /** @var RequestHandlerInterface $handler */
        $response = $middleware->process(
            $request,
            $handler
        );

        self::assertSame($expectedResponse, $response);
    }

    /**
     * @throws \PHPUnit\Framework\ExpectationFailedException
     * @throws \PHPUnit\Framework\MockObject\RuntimeException
     * @throws \SebastianBergmann\RecursionContext\InvalidArgumentException
     * @throws \Mezzio\GenericAuthorization\Exception\RuntimeException
     *
     * @return void
     */
    public function testProcessRoleNotGranted(): void
    {
        $routeName        = 'test';
        $authorization    = $this->createMock(AuthorizationInterface::class);
        $expectedResponse = $this->createMock(ResponseInterface::class);
        $responseFactory  = $this->getMockBuilder(ResponseInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $responseFactory->expects(self::once())
            ->method('withStatus')
            ->with(403)
            ->willReturn($expectedResponse);

        $user = $this->getMockBuilder(UserInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $user->expects(self::once())
            ->method('getRoles')
            ->willReturn([]);

        $routeResult = $this->getMockBuilder(RouteResult::class)
            ->disableOriginalConstructor()
            ->getMock();
        $routeResult->expects(self::once())
            ->method('isFailure')
            ->willReturn(false);
        $routeResult->expects(self::exactly(2))
            ->method('getMatchedRouteName')
            ->willReturn($routeName);

        /** @var AuthorizationInterface $authorization */
        /** @var ResponseInterface $responseFactory */
        $middleware = new AuthorizationMiddleware($authorization, $responseFactory);
        self::assertInstanceOf(AuthorizationMiddleware::class, $middleware);

        $request = $this->getMockBuilder(ServerRequestInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $request->expects(self::exactly(2))
            ->method('getAttribute')
            ->withConsecutive([UserInterface::class], [RouteResult::class])
            ->willReturnOnConsecutiveCalls($user, $routeResult);
        $handler = $this->createMock(RequestHandlerInterface::class);

        /** @var ServerRequestInterface $request */
        /** @var RequestHandlerInterface $handler */
        $response = $middleware->process(
            $request,
            $handler
        );

        self::assertSame($expectedResponse, $response);
    }

    /**
     * @throws \PHPUnit\Framework\ExpectationFailedException
     * @throws \PHPUnit\Framework\MockObject\RuntimeException
     * @throws \SebastianBergmann\RecursionContext\InvalidArgumentException
     * @throws \Mezzio\GenericAuthorization\Exception\RuntimeException
     *
     * @return void
     */
    public function testProcessRoleGranted(): void
    {
        $routeName = 'test';
        $role1     = 'test-role1';
        $role2     = 'test-role2';

        $user = $this->getMockBuilder(UserInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $user->expects(self::once())
            ->method('getRoles')
            ->willReturn([$role1, $role2]);

        $routeResult = $this->getMockBuilder(RouteResult::class)
            ->disableOriginalConstructor()
            ->getMock();
        $routeResult->expects(self::once())
            ->method('isFailure')
            ->willReturn(false);
        $routeResult->expects(self::exactly(2))
            ->method('getMatchedRouteName')
            ->willReturn($routeName);

        $request = $this->getMockBuilder(ServerRequestInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $request->expects(self::exactly(2))
            ->method('getAttribute')
            ->withConsecutive([UserInterface::class], [RouteResult::class])
            ->willReturnOnConsecutiveCalls($user, $routeResult);

        $authorization = $this->getMockBuilder(AuthorizationInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $authorization->expects(self::exactly(2))
            ->method('isGranted')
            ->withConsecutive([$role1, $routeName, null, $request], [$role2, $routeName, null, $request])
            ->willReturnOnConsecutiveCalls(false, true);

        $expectedResponse = $this->createMock(ResponseInterface::class);
        $responseFactory  = $this->createMock(ResponseInterface::class);

        /** @var AuthorizationInterface $authorization */
        /** @var ResponseInterface $responseFactory */
        $middleware = new AuthorizationMiddleware($authorization, $responseFactory);
        self::assertInstanceOf(AuthorizationMiddleware::class, $middleware);
        $handler = $this->getMockBuilder(RequestHandlerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $handler->expects(self::once())
            ->method('handle')
            ->with($request)
            ->willReturn($expectedResponse);

        /** @var ServerRequestInterface $request */
        /** @var RequestHandlerInterface $handler */
        $response = $middleware->process(
            $request,
            $handler
        );

        self::assertSame($expectedResponse, $response);
    }
}
