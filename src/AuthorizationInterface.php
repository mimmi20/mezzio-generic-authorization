<?php



declare(strict_types=1);

namespace Mezzio\GenericAuthorization;

use Psr\Http\Message\ServerRequestInterface;

interface AuthorizationInterface
{
    /**
     * Check if a role is granted for a resource
     */
    public function isGranted(string $role, string $resource, ?ServerRequestInterface $request = null) : bool;
}
