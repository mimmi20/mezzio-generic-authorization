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

final class ConfigProvider
{
    /**
     * Return the configuration array.
     *
     * @return array[]
     */
    public function __invoke(): array
    {
        return [
            'dependencies' => $this->getDependencies(),
            'authorization' => $this->getAuthorizationConfig(),
        ];
    }

    /**
     * Returns the configuration for the AuthorizationInterface adapter
     *
     * @return array
     */
    public function getAuthorizationConfig(): array
    {
        return [
            /*
             * Example using LaminasAcl:
             *
             * 'roles' => [
             *     // insert the role with parent (if any)
             *     // e.g. 'editor' => ['admin'] (admin is parent of editor)
             * ],
             * 'resources' => [
             *     // an array of resources, as string
             * ],
             * 'allow' => [
             *     // for each role allow some resources
             *     // e.g. 'admin' => ['admin.pages']
             * ],
             * 'deny' => [
             *     // for each role deny some resources
             *     // e.g. 'admin' => ['admin.pages']
             * ],
             *
             * Example using LaminasRbac:
             *
             * 'roles' => [
             *     // insert the role with parent (if any)
             *     // e.g. 'editor' => ['admin'] (admin is parent of editor)
             * ],
             * 'permissions' => [
             *     // for each role insert one or more permissions
             *     // e.g. 'admin' => ['admin.pages']
             * ],
             */
        ];
    }

    /**
     * Returns the container dependencies
     *
     * @return array
     */
    public function getDependencies(): array
    {
        return [
            'factories' => [
                AuthorizationMiddleware::class => AuthorizationMiddlewareFactory::class,
            ],
        ];
    }
}
