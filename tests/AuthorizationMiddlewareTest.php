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

use InvalidArgumentException;
use Mezzio\Authentication\UserInterface;
use Mezzio\Router\RouteResult;
use Mimmi20\Mezzio\GenericAuthorization\Exception\RuntimeException;
use PHPUnit\Framework\Exception;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

use function assert;

final class AuthorizationMiddlewareTest extends TestCase
{
    /** @throws Exception */
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
        $response = $middleware->process($request, $handler);

        self::assertSame($expectedResponse, $response);
    }

    /**
     * @throws Exception
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
        $this->expectExceptionCode(0);

        assert($request instanceof ServerRequestInterface);
        assert($handler instanceof RequestHandlerInterface);
        $middleware->process($request, $handler);
    }

    /**
     * @throws Exception
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
        $matcher = self::exactly(2);
        $request->expects($matcher)
            ->method('getAttribute')
            ->willReturnCallback(
                static function (string $name, mixed $default = null) use ($matcher, $user): mixed {
                    match ($matcher->numberOfInvocations()) {
                        1 => self::assertSame(UserInterface::class, $name),
                        default => self::assertSame(RouteResult::class, $name),
                    };

                    self::assertNull($default);

                    return match ($matcher->numberOfInvocations()) {
                        1 => $user,
                        default => null,
                    };
                },
            );
        $handler = $this->createMock(RequestHandlerInterface::class);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage(
            'The Mezzio\Router\RouteResult attribute is missing in the request; cannot perform authorization checks',
        );

        assert($request instanceof ServerRequestInterface);
        assert($handler instanceof RequestHandlerInterface);
        $middleware->process($request, $handler);
    }

    /**
     * @throws Exception
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
        $matcher = self::exactly(2);
        $request->expects($matcher)
            ->method('getAttribute')
            ->willReturnCallback(
                static function (string $name, mixed $default = null) use ($matcher, $user, $routeResult): mixed {
                    match ($matcher->numberOfInvocations()) {
                        1 => self::assertSame(UserInterface::class, $name),
                        default => self::assertSame(RouteResult::class, $name),
                    };

                    self::assertNull($default);

                    return match ($matcher->numberOfInvocations()) {
                        1 => $user,
                        default => $routeResult,
                    };
                },
            );
        $handler = $this->getMockBuilder(RequestHandlerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $handler->expects(self::once())
            ->method('handle')
            ->with($request)
            ->willReturn($expectedResponse);

        assert($request instanceof ServerRequestInterface);
        assert($handler instanceof RequestHandlerInterface);
        $response = $middleware->process($request, $handler);

        self::assertSame($expectedResponse, $response);
    }

    /**
     * @throws Exception
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
        $matcher = self::exactly(2);
        $request->expects($matcher)
            ->method('getAttribute')
            ->willReturnCallback(
                static function (string $name, mixed $default = null) use ($matcher, $user, $routeResult): mixed {
                    match ($matcher->numberOfInvocations()) {
                        1 => self::assertSame(UserInterface::class, $name),
                        default => self::assertSame(RouteResult::class, $name),
                    };

                    self::assertNull($default);

                    return match ($matcher->numberOfInvocations()) {
                        1 => $user,
                        default => $routeResult,
                    };
                },
            );
        $handler = $this->getMockBuilder(RequestHandlerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $handler->expects(self::once())
            ->method('handle')
            ->with($request)
            ->willReturn($expectedResponse);

        assert($request instanceof ServerRequestInterface);
        assert($handler instanceof RequestHandlerInterface);
        $response = $middleware->process($request, $handler);

        self::assertSame($expectedResponse, $response);
    }

    /**
     * @throws Exception
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
        $matcher = self::exactly(2);
        $request->expects($matcher)
            ->method('getAttribute')
            ->willReturnCallback(
                static function (string $name, mixed $default = null) use ($matcher, $user, $routeResult): mixed {
                    match ($matcher->numberOfInvocations()) {
                        1 => self::assertSame(UserInterface::class, $name),
                        default => self::assertSame(RouteResult::class, $name),
                    };

                    self::assertNull($default);

                    return match ($matcher->numberOfInvocations()) {
                        1 => $user,
                        default => $routeResult,
                    };
                },
            );
        $handler = $this->createMock(RequestHandlerInterface::class);

        assert($request instanceof ServerRequestInterface);
        assert($handler instanceof RequestHandlerInterface);
        $response = $middleware->process($request, $handler);

        self::assertSame($expectedResponse, $response);
    }

    /**
     * @throws Exception
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
        $matcher = self::exactly(2);
        $request->expects($matcher)
            ->method('getAttribute')
            ->willReturnCallback(
                static function (string $name, mixed $default = null) use ($matcher, $user, $routeResult): mixed {
                    match ($matcher->numberOfInvocations()) {
                        1 => self::assertSame(UserInterface::class, $name),
                        default => self::assertSame(RouteResult::class, $name),
                    };

                    self::assertNull($default);

                    return match ($matcher->numberOfInvocations()) {
                        1 => $user,
                        default => $routeResult,
                    };
                },
            );
        $handler = $this->createMock(RequestHandlerInterface::class);

        assert($request instanceof ServerRequestInterface);
        assert($handler instanceof RequestHandlerInterface);
        $response = $middleware->process($request, $handler);

        self::assertSame($expectedResponse, $response);
    }

    /**
     * @throws Exception
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
        $matcher = self::exactly(2);
        $request->expects($matcher)
            ->method('getAttribute')
            ->willReturnCallback(
                static function (string $name, mixed $default = null) use ($matcher, $user, $routeResult): mixed {
                    match ($matcher->numberOfInvocations()) {
                        1 => self::assertSame(UserInterface::class, $name),
                        default => self::assertSame(RouteResult::class, $name),
                    };

                    self::assertNull($default);

                    return match ($matcher->numberOfInvocations()) {
                        1 => $user,
                        default => $routeResult,
                    };
                },
            );
        $handler = $this->createMock(RequestHandlerInterface::class);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('could not set statuscode');
        $this->expectExceptionCode(0);

        assert($request instanceof ServerRequestInterface);
        assert($handler instanceof RequestHandlerInterface);
        $middleware->process($request, $handler);
    }

    /**
     * @throws Exception
     * @throws RuntimeException
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
        $matcher = self::exactly(2);
        $request->expects($matcher)
            ->method('getAttribute')
            ->willReturnCallback(
                static function (string $name, mixed $default = null) use ($matcher, $user, $routeResult): mixed {
                    match ($matcher->numberOfInvocations()) {
                        1 => self::assertSame(UserInterface::class, $name),
                        default => self::assertSame(RouteResult::class, $name),
                    };

                    self::assertNull($default);

                    return match ($matcher->numberOfInvocations()) {
                        1 => $user,
                        default => $routeResult,
                    };
                },
            );

        $authorization = $this->getMockBuilder(AuthorizationInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $matcher       = self::exactly(2);
        $authorization->expects($matcher)
            ->method('isGranted')
            ->willReturnCallback(
                static function (
                    string | null $role = null,
                    string | null $resource = null,
                    string | null $privilege = null,
                    ServerRequestInterface | null $requestParam = null,
                ) use (
                    $matcher,
                    $role1,
                    $role2,
                    $routeName,
                    $request,
                ): bool {
                    match ($matcher->numberOfInvocations()) {
                        1 => self::assertSame($role1, $role),
                        default => self::assertSame($role2, $role),
                    };

                    self::assertSame($routeName, $resource);
                    self::assertNull($privilege);
                    self::assertSame($request, $requestParam);

                    return match ($matcher->numberOfInvocations()) {
                        1 => false,
                        default => true,
                    };
                },
            );

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
        $response = $middleware->process($request, $handler);

        self::assertSame($expectedResponse, $response);
    }
}
