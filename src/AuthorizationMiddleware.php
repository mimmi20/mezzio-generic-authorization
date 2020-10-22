<?php



declare(strict_types=1);

namespace Mezzio\GenericAuthorization;

use Mezzio\Authentication\UserInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Laminas\Log\Logger;

class AuthorizationMiddleware implements MiddlewareInterface
{
    /**
     * @var AuthorizationInterface
     */
    private $authorization;

    /**
     * @var callable
     */
    private $responseFactory;

    /**
     * @var Logger;
     */
    private $logger;

    public function __construct(AuthorizationInterface $authorization, Logger $logger, callable $responseFactory)
    {
        $this->authorization = $authorization;
        $this->logger = $logger;

        // Ensures type safety of the composed factory
        $this->responseFactory = function () use ($responseFactory) : ResponseInterface {
            return $responseFactory();
        };
    }

    /**
     * {@inheritDoc}
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler) : ResponseInterface
    {
        $user = $request->getAttribute(UserInterface::class, false);
        if (! $user instanceof UserInterface) {
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
