<?php
/**
 * This file is part of the mimmi20/mezzio-generic-authorization package.
 *
 * Copyright (c) 2020-2021, Thomas Mueller <mimmi20@live.de>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types = 1);

namespace MezzioTest\GenericAuthorization;

use InvalidArgumentException;
use Mezzio\Authentication\UserInterface;
use Mezzio\GenericAuthorization\AuthorizationInterface;
use Mezzio\GenericAuthorization\AuthorizationMiddleware;
use Mezzio\GenericAuthorization\Exception\RuntimeException;
use Mezzio\Router\RouteResult;
use PHPUnit\Framework\Exception;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

use function assert;

final class AuthorizationMiddlewareTest extends TestCase
{
    private const ROLE1 = 'test-role1';
    private const ROLE2 = 'test-role2';

    /**
     * @throws Exception
     * @throws \SebastianBergmann\RecursionContext\InvalidArgumentException
     */
    public function testConstructor(): void
    {
        $authorization   = $this->createMock(AuthorizationInterface::class);
        $responseFactory = $this->createMock(ResponseInterface::class);

        assert($authorization instanceof AuthorizationInterface);
        assert($responseFactory instanceof ResponseInterface);
        $middleware = new AuthorizationMiddleware($authorization, $responseFactory);
        self::assertInstanceOf(AuthorizationMiddleware::class, $middleware);
    }

    /**
     * @throws Exception
     * @throws \SebastianBergmann\RecursionContext\InvalidArgumentException
     * @throws RuntimeException
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

        assert($authorization instanceof AuthorizationInterface);
        assert($responseFactory instanceof ResponseInterface);
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

        assert($request instanceof ServerRequestInterface);
        assert($handler instanceof RequestHandlerInterface);
        $response = $middleware->process(
            $request,
            $handler
        );

        self::assertSame($expectedResponse, $response);
    }

    /**
     * @throws Exception
     * @throws \SebastianBergmann\RecursionContext\InvalidArgumentException
     * @throws RuntimeException
     */
    public function testProcessWithoutUserAttributeExcption(): void
    {
        $exception       = new InvalidArgumentException('test');
        $authorization   = $this->createMock(AuthorizationInterface::class);
        $responseFactory = $this->getMockBuilder(ResponseInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $responseFactory->expects(self::once())
            ->method('withStatus')
            ->with(401)
            ->willThrowException($exception);

        assert($authorization instanceof AuthorizationInterface);
        assert($responseFactory instanceof ResponseInterface);
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

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('could not set statuscode');

        assert($request instanceof ServerRequestInterface);
        assert($handler instanceof RequestHandlerInterface);
        $middleware->process(
            $request,
            $handler
        );
    }

    /**
     * @throws Exception
     * @throws \SebastianBergmann\RecursionContext\InvalidArgumentException
     * @throws RuntimeException
     */
    public function testProcessWithoutRouteAttribute(): void
    {
        $authorization   = $this->createMock(AuthorizationInterface::class);
        $responseFactory = $this->createMock(ResponseInterface::class);
        $user            = $this->createMock(UserInterface::class);

        assert($authorization instanceof AuthorizationInterface);
        assert($responseFactory instanceof ResponseInterface);
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

        assert($request instanceof ServerRequestInterface);
        assert($handler instanceof RequestHandlerInterface);
        $middleware->process(
            $request,
            $handler
        );
    }

    /**
     * @throws Exception
     * @throws \SebastianBergmann\RecursionContext\InvalidArgumentException
     * @throws RuntimeException
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
        $routeResult->expects(self::never())
            ->method('getMatchedRouteName');

        assert($authorization instanceof AuthorizationInterface);
        assert($responseFactory instanceof ResponseInterface);
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

        assert($request instanceof ServerRequestInterface);
        assert($handler instanceof RequestHandlerInterface);
        $response = $middleware->process(
            $request,
            $handler
        );

        self::assertSame($expectedResponse, $response);
    }

    /**
     * @throws Exception
     * @throws \SebastianBergmann\RecursionContext\InvalidArgumentException
     * @throws RuntimeException
     */
    public function testProcessWithRouteError2(): void
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
            ->willReturn(false);
        $routeResult->expects(self::once())
            ->method('getMatchedRouteName')
            ->willReturn(false);

        assert($authorization instanceof AuthorizationInterface);
        assert($responseFactory instanceof ResponseInterface);
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

        assert($request instanceof ServerRequestInterface);
        assert($handler instanceof RequestHandlerInterface);
        $response = $middleware->process(
            $request,
            $handler
        );

        self::assertSame($expectedResponse, $response);
    }

    /**
     * @throws Exception
     * @throws \SebastianBergmann\RecursionContext\InvalidArgumentException
     * @throws RuntimeException
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

        assert($authorization instanceof AuthorizationInterface);
        assert($responseFactory instanceof ResponseInterface);
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

        assert($request instanceof ServerRequestInterface);
        assert($handler instanceof RequestHandlerInterface);
        $response = $middleware->process(
            $request,
            $handler
        );

        self::assertSame($expectedResponse, $response);
    }

    /**
     * @throws Exception
     * @throws \SebastianBergmann\RecursionContext\InvalidArgumentException
     * @throws RuntimeException
     */
    public function testProcessRoleNotGranted2(): void
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
            ->willReturnOnConsecutiveCalls(true, $routeName);

        assert($authorization instanceof AuthorizationInterface);
        assert($responseFactory instanceof ResponseInterface);
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

        assert($request instanceof ServerRequestInterface);
        assert($handler instanceof RequestHandlerInterface);
        $response = $middleware->process(
            $request,
            $handler
        );

        self::assertSame($expectedResponse, $response);
    }

    /**
     * @throws Exception
     * @throws \SebastianBergmann\RecursionContext\InvalidArgumentException
     * @throws RuntimeException
     */
    public function testProcessRoleNotGrantedException(): void
    {
        $exception       = new InvalidArgumentException('test');
        $routeName       = 'test';
        $authorization   = $this->createMock(AuthorizationInterface::class);
        $responseFactory = $this->getMockBuilder(ResponseInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $responseFactory->expects(self::once())
            ->method('withStatus')
            ->with(403)
            ->willThrowException($exception);

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

        assert($authorization instanceof AuthorizationInterface);
        assert($responseFactory instanceof ResponseInterface);
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

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('could not set statuscode');

        assert($request instanceof ServerRequestInterface);
        assert($handler instanceof RequestHandlerInterface);
        $middleware->process(
            $request,
            $handler
        );
    }

    /**
     * @throws Exception
     * @throws \SebastianBergmann\RecursionContext\InvalidArgumentException
     * @throws RuntimeException
     */
    public function testProcessRoleGranted(): void
    {
        $routeName = 'test';

        $user = $this->getMockBuilder(UserInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $user->expects(self::once())
            ->method('getRoles')
            ->willReturn([self::ROLE1, self::ROLE2]);

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
            ->withConsecutive([self::ROLE1, $routeName, null, $request], [self::ROLE2, $routeName, null, $request])
            ->willReturnOnConsecutiveCalls(false, true);

        $expectedResponse = $this->createMock(ResponseInterface::class);
        $responseFactory  = $this->createMock(ResponseInterface::class);

        assert($authorization instanceof AuthorizationInterface);
        assert($responseFactory instanceof ResponseInterface);
        $middleware = new AuthorizationMiddleware($authorization, $responseFactory);
        self::assertInstanceOf(AuthorizationMiddleware::class, $middleware);
        $handler = $this->getMockBuilder(RequestHandlerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $handler->expects(self::once())
            ->method('handle')
            ->with($request)
            ->willReturn($expectedResponse);

        assert($request instanceof ServerRequestInterface);
        assert($handler instanceof RequestHandlerInterface);
        $response = $middleware->process(
            $request,
            $handler
        );

        self::assertSame($expectedResponse, $response);
    }
}
