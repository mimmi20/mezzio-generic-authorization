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
namespace Mezzio\GenericAuthorization;

use Mezzio\Authentication\UserInterface;
use Mezzio\Router\RouteResult;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class AuthorizationMiddleware implements MiddlewareInterface
{
    /** @var AuthorizationInterface */
    private $authorization;

    /** @var callable */
    private $responseFactory;

    /**
     * @param \Mezzio\GenericAuthorization\AuthorizationInterface $authorization
     * @param callable                                            $responseFactory
     */
    public function __construct(AuthorizationInterface $authorization, callable $responseFactory)
    {
        $this->authorization = $authorization;

        // Ensures type safety of the composed factory
        $this->responseFactory = static function () use ($responseFactory): ResponseInterface {
            return $responseFactory();
        };
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     * @param \Psr\Http\Server\RequestHandlerInterface $handler
     *
     * @throws Exception\RuntimeException
     *
     * @return \Psr\Http\Message\ResponseInterface
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $user = $request->getAttribute(UserInterface::class, false);
        if (!$user instanceof UserInterface) {
            return ($this->responseFactory)()->withStatus(401);
        }

        $routeResult = $request->getAttribute(RouteResult::class, false);

        if (false === $routeResult) {
            throw new Exception\RuntimeException(
                sprintf(
                    'The %s attribute is missing in the request; cannot perform ACL authorization checks',
                    RouteResult::class
                )
            );
        }

        // No matching route. Everyone can access.
        if ($routeResult->isFailure()) {
            return $handler->handle($request);
        }

        $routeName = $routeResult->getMatchedRouteName();

        foreach ($user->getRoles() as $role) {
            if ($this->authorization->isGranted($role, $routeName, $request)) {
                return $handler->handle($request);
            }
        }

        return ($this->responseFactory)()->withStatus(403);
    }
}
