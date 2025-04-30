<?php

/**
 * This file is part of the mimmi20/mezzio-generic-authorization package.
 *
 * Copyright (c) 2020-2025, Thomas Mueller <mimmi20@live.de>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types = 1);

namespace Mimmi20\Mezzio\GenericAuthorization;

use InvalidArgumentException;
use Mezzio\Authentication\UserInterface;
use Mezzio\Router\Route;
use Mezzio\Router\RouteResult;
use Mimmi20\Mezzio\GenericAuthorization\Exception\RuntimeException;
use PHPUnit\Event\NoPreviousThrowableException;
use PHPUnit\Framework\Exception;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

use function assert;

final class AuthorizationMiddlewareTest extends TestCase
{
    /**
     * @throws Exception
     * @throws NoPreviousThrowableException
     * @throws \PHPUnit\Framework\MockObject\Exception
     */
    public function testConstructor(): void
    {
        $authorization   = $this->createMock(AuthorizationInterface::class);
        $responseFactory = $this->createMock(ResponseFactoryInterface::class);
        $responseFactory->expects(self::never())
            ->method('createResponse');

        assert($authorization instanceof AuthorizationInterface);
        assert($responseFactory instanceof ResponseFactoryInterface);
        $middleware = new AuthorizationMiddleware($authorization, $responseFactory, null);
        self::assertInstanceOf(AuthorizationMiddleware::class, $middleware);
    }

    /**
     * @throws Exception
     * @throws RuntimeException
     * @throws NoPreviousThrowableException
     * @throws \PHPUnit\Framework\MockObject\Exception
     */
    public function testProcessWithoutUserAttribute(): void
    {
        $authorization    = $this->createMock(AuthorizationInterface::class);
        $expectedResponse = $this->createMock(ResponseInterface::class);

        $responseFactory = $this->createMock(ResponseFactoryInterface::class);
        $responseFactory->expects(self::once())
            ->method('createResponse')
            ->with(401, '')
            ->willReturn($expectedResponse);

        assert($authorization instanceof AuthorizationInterface);
        assert($responseFactory instanceof ResponseFactoryInterface);
        $middleware = new AuthorizationMiddleware($authorization, $responseFactory, null);
        self::assertInstanceOf(AuthorizationMiddleware::class, $middleware);

        $request = $this->createMock(ServerRequestInterface::class);
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
     * @throws NoPreviousThrowableException
     * @throws \PHPUnit\Framework\MockObject\Exception
     */
    public function testProcessWithoutUserAttributeExcption(): void
    {
        $exception     = new InvalidArgumentException('test');
        $authorization = $this->createMock(AuthorizationInterface::class);

        $responseFactory = $this->createMock(ResponseFactoryInterface::class);
        $responseFactory->expects(self::once())
            ->method('createResponse')
            ->with(401, '')
            ->willThrowException($exception);

        assert($authorization instanceof AuthorizationInterface);
        assert($responseFactory instanceof ResponseFactoryInterface);
        $middleware = new AuthorizationMiddleware($authorization, $responseFactory, null);
        self::assertInstanceOf(AuthorizationMiddleware::class, $middleware);

        $request = $this->createMock(ServerRequestInterface::class);
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
     * @throws NoPreviousThrowableException
     * @throws \PHPUnit\Framework\MockObject\Exception
     */
    public function testProcessWithoutRouteAttribute(): void
    {
        $authorization = $this->createMock(AuthorizationInterface::class);

        $responseFactory = $this->createMock(ResponseFactoryInterface::class);
        $responseFactory->expects(self::never())
            ->method('createResponse');

        $user = $this->createMock(UserInterface::class);

        assert($authorization instanceof AuthorizationInterface);
        assert($responseFactory instanceof ResponseFactoryInterface);
        $middleware = new AuthorizationMiddleware($authorization, $responseFactory, null);
        self::assertInstanceOf(AuthorizationMiddleware::class, $middleware);

        $request = $this->createMock(ServerRequestInterface::class);
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
     * @throws NoPreviousThrowableException
     * @throws \PHPUnit\Framework\MockObject\Exception
     */
    public function testProcessWithRouteError(): void
    {
        $authorization    = $this->createMock(AuthorizationInterface::class);
        $expectedResponse = $this->createMock(ResponseInterface::class);

        $responseFactory = $this->createMock(ResponseFactoryInterface::class);
        $responseFactory->expects(self::never())
            ->method('createResponse');

        $user = $this->createMock(UserInterface::class);

        $routeResult = RouteResult::fromRouteFailure(null);

        assert($authorization instanceof AuthorizationInterface);
        assert($responseFactory instanceof ResponseFactoryInterface);
        $middleware = new AuthorizationMiddleware($authorization, $responseFactory, null);
        self::assertInstanceOf(AuthorizationMiddleware::class, $middleware);

        $request = $this->createMock(ServerRequestInterface::class);
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
     * @throws NoPreviousThrowableException
     * @throws \PHPUnit\Framework\MockObject\Exception
     */
    public function testProcessWithRouteError2(): void
    {
        $authorization    = $this->createMock(AuthorizationInterface::class);
        $expectedResponse = $this->createMock(ResponseInterface::class);

        $responseFactory = $this->createMock(ResponseFactoryInterface::class);
        $responseFactory->expects(self::never())
            ->method('createResponse');

        $user = $this->createMock(UserInterface::class);

        $routeResult = RouteResult::fromRouteFailure(null);

        assert($authorization instanceof AuthorizationInterface);
        assert($responseFactory instanceof ResponseFactoryInterface);
        $middleware = new AuthorizationMiddleware($authorization, $responseFactory, null);
        self::assertInstanceOf(AuthorizationMiddleware::class, $middleware);

        $request = $this->createMock(ServerRequestInterface::class);
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
     * @throws NoPreviousThrowableException
     * @throws \PHPUnit\Framework\MockObject\Exception
     */
    public function testProcessRoleNotGranted(): void
    {
        $routeName        = 'test';
        $authorization    = $this->createMock(AuthorizationInterface::class);
        $expectedResponse = $this->createMock(ResponseInterface::class);

        $responseFactory = $this->createMock(ResponseFactoryInterface::class);
        $responseFactory->expects(self::once())
            ->method('createResponse')
            ->with(403, '')
            ->willReturn($expectedResponse);

        $user = $this->createMock(UserInterface::class);
        $user->expects(self::once())
            ->method('getRoles')
            ->willReturn([]);

        $middleware = new AuthorizationMiddleware($authorization, $responseFactory, null);

        $routeResult = RouteResult::fromRoute(new Route('/', $middleware, name: $routeName));

        self::assertInstanceOf(AuthorizationMiddleware::class, $middleware);

        $request = $this->createMock(ServerRequestInterface::class);
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
     * @throws NoPreviousThrowableException
     * @throws \PHPUnit\Framework\MockObject\Exception
     */
    public function testProcessRoleNotGranted2(): void
    {
        $routeName        = 'test';
        $authorization    = $this->createMock(AuthorizationInterface::class);
        $expectedResponse = $this->createMock(ResponseInterface::class);

        $responseFactory = $this->createMock(ResponseFactoryInterface::class);
        $responseFactory->expects(self::once())
            ->method('createResponse')
            ->with(403, '')
            ->willReturn($expectedResponse);

        $user = $this->createMock(UserInterface::class);
        $user->expects(self::once())
            ->method('getRoles')
            ->willReturn([]);

        $middleware = new AuthorizationMiddleware($authorization, $responseFactory, null);

        $routeResult = RouteResult::fromRoute(new Route('/', $middleware, name: $routeName));

        self::assertInstanceOf(AuthorizationMiddleware::class, $middleware);

        $request = $this->createMock(ServerRequestInterface::class);
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
     * @throws NoPreviousThrowableException
     * @throws \PHPUnit\Framework\MockObject\Exception
     */
    public function testProcessRoleNotGrantedException(): void
    {
        $exception     = new InvalidArgumentException('test');
        $routeName     = 'test';
        $authorization = $this->createMock(AuthorizationInterface::class);

        $responseFactory = $this->createMock(ResponseFactoryInterface::class);
        $responseFactory->expects(self::once())
            ->method('createResponse')
            ->with(403, '')
            ->willThrowException($exception);

        $user = $this->createMock(UserInterface::class);
        $user->expects(self::once())
            ->method('getRoles')
            ->willReturn([]);

        $middleware = new AuthorizationMiddleware($authorization, $responseFactory, null);

        $routeResult = RouteResult::fromRoute(new Route('/', $middleware, name: $routeName));

        self::assertInstanceOf(AuthorizationMiddleware::class, $middleware);

        $request = $this->createMock(ServerRequestInterface::class);
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
     * @throws NoPreviousThrowableException
     * @throws \PHPUnit\Framework\MockObject\Exception
     */
    public function testProcessGrantedWithRoles(): void
    {
        $routeName = 'test';
        $role1     = 'test-role1';
        $role2     = 'test-role2';

        $user = $this->createMock(UserInterface::class);
        $user->expects(self::once())
            ->method('getRoles')
            ->willReturn([$role1, $role2]);

        $authorization = $this->createMock(AuthorizationInterface::class);

        $responseFactory = $this->createMock(ResponseFactoryInterface::class);
        $responseFactory->expects(self::never())
            ->method('createResponse');

        $middleware = new AuthorizationMiddleware($authorization, $responseFactory, null);

        $routeResult = RouteResult::fromRoute(new Route('/', $middleware, name: $routeName));

        $request = $this->createMock(ServerRequestInterface::class);
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

        $matcher = self::exactly(2);
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

        self::assertInstanceOf(AuthorizationMiddleware::class, $middleware);

        $handler = $this->createMock(RequestHandlerInterface::class);
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
     * @throws NoPreviousThrowableException
     * @throws \PHPUnit\Framework\MockObject\Exception
     */
    public function testProcessGrantedWithRoles2(): void
    {
        $routeName = 'test';
        $role1     = 'test-role1';
        $role2     = 'test-role2';

        $user = $this->createMock(UserInterface::class);
        $user->expects(self::once())
            ->method('getRoles')
            ->willReturn([$role1, $role2]);

        $authorization = $this->createMock(AuthorizationInterface::class);

        $responseFactory = $this->createMock(ResponseFactoryInterface::class);
        $responseFactory->expects(self::never())
            ->method('createResponse');

        $middleware = new AuthorizationMiddleware($authorization, $responseFactory, null);

        $routeResult = RouteResult::fromRoute(new Route('/', $middleware, name: $routeName));

        $request = $this->createMock(ServerRequestInterface::class);
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

        $authorization->expects(self::once())
            ->method('isGranted')
            ->with($role1, $routeName, null, $request)
            ->willReturn(true);

        $expectedResponse = $this->createMock(ResponseInterface::class);

        self::assertInstanceOf(AuthorizationMiddleware::class, $middleware);

        $handler = $this->createMock(RequestHandlerInterface::class);
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
     * @throws NoPreviousThrowableException
     * @throws \PHPUnit\Framework\MockObject\Exception
     */
    public function testProcessGrantedWithoutRoles(): void
    {
        $routeName = 'test';

        $user = $this->createMock(UserInterface::class);
        $user->expects(self::once())
            ->method('getRoles')
            ->willReturn([]);

        $authorization = $this->createMock(AuthorizationInterface::class);

        $responseFactory = $this->createMock(ResponseFactoryInterface::class);
        $responseFactory->expects(self::never())
            ->method('createResponse');

        $middleware = new AuthorizationMiddleware($authorization, $responseFactory, null);

        $routeResult = RouteResult::fromRoute(new Route('/', $middleware, name: $routeName));

        $request = $this->createMock(ServerRequestInterface::class);
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

        $authorization->expects(self::once())
            ->method('isGranted')
            ->with(null, $routeName, null, $request)
            ->willReturn(true);

        $expectedResponse = $this->createMock(ResponseInterface::class);

        self::assertInstanceOf(AuthorizationMiddleware::class, $middleware);

        $handler = $this->createMock(RequestHandlerInterface::class);
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
     * @throws NoPreviousThrowableException
     * @throws \PHPUnit\Framework\MockObject\Exception
     */
    public function testProcessNotGrantedWithRoles(): void
    {
        $routeName = 'test';
        $role1     = 'test-role1';
        $role2     = 'test-role2';

        $user = $this->createMock(UserInterface::class);
        $user->expects(self::once())
            ->method('getRoles')
            ->willReturn([$role1, $role2]);

        $expectedResponse = $this->createMock(ResponseInterface::class);

        $responseFactory = $this->createMock(ResponseFactoryInterface::class);
        $responseFactory->expects(self::once())
            ->method('createResponse')
            ->with(403, '')
            ->willReturn($expectedResponse);

        $authorization = $this->createMock(AuthorizationInterface::class);

        $middleware = new AuthorizationMiddleware($authorization, $responseFactory, null);

        $routeResult = RouteResult::fromRoute(new Route('/', $middleware, name: $routeName));

        $request = $this->createMock(ServerRequestInterface::class);
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

        $matcher = self::exactly(2);
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

                    return false;
                },
            );

        self::assertInstanceOf(AuthorizationMiddleware::class, $middleware);

        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects(self::never())
            ->method('handle');

        assert($request instanceof ServerRequestInterface);
        assert($handler instanceof RequestHandlerInterface);
        $response = $middleware->process($request, $handler);

        self::assertSame($expectedResponse, $response);
    }

    /**
     * @throws Exception
     * @throws RuntimeException
     * @throws NoPreviousThrowableException
     * @throws \PHPUnit\Framework\MockObject\Exception
     */
    public function testProcessNotGrantedWithoutRoles(): void
    {
        $routeName = 'test';

        $user = $this->createMock(UserInterface::class);
        $user->expects(self::once())
            ->method('getRoles')
            ->willReturn([]);

        $expectedResponse = $this->createMock(ResponseInterface::class);

        $responseFactory = $this->createMock(ResponseFactoryInterface::class);
        $responseFactory->expects(self::once())
            ->method('createResponse')
            ->with(403, '')
            ->willReturn($expectedResponse);

        $authorization = $this->createMock(AuthorizationInterface::class);

        $middleware = new AuthorizationMiddleware($authorization, $responseFactory, null);

        $routeResult = RouteResult::fromRoute(new Route('/', $middleware, name: $routeName));

        $request = $this->createMock(ServerRequestInterface::class);
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

        $authorization->expects(self::once())
            ->method('isGranted')
            ->with(null, $routeName, null, $request)
            ->willReturn(false);

        self::assertInstanceOf(AuthorizationMiddleware::class, $middleware);

        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects(self::never())
            ->method('handle');

        assert($request instanceof ServerRequestInterface);
        assert($handler instanceof RequestHandlerInterface);
        $response = $middleware->process($request, $handler);

        self::assertSame($expectedResponse, $response);
    }
}
