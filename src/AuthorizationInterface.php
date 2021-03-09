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
namespace Mezzio\GenericAuthorization;

use Psr\Http\Message\ServerRequestInterface;

interface AuthorizationInterface
{
    /**
     * Check if a role is granted for a resource
     *
     * @param string|null                 $role
     * @param string|null                 $resource
     * @param string|null                 $privilege
     * @param ServerRequestInterface|null $request
     *
     * @return bool
     */
    public function isGranted(?string $role = null, ?string $resource = null, ?string $privilege = null, ?ServerRequestInterface $request = null): bool;
}
