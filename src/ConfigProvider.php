<?php



declare(strict_types=1);

namespace Mezzio\GenericAuthorization;

class ConfigProvider
{
    /**
     * Return the configuration array.
     */
    public function __invoke() : array
    {
        return [
            'dependencies'  => $this->getDependencies(),
            'authorization' => $this->getAuthorizationConfig(),
        ];
    }

    /**
     * Returns the configuration for the AuthorizationInterface adapter
     */
    public function getAuthorizationConfig() : array
    {
        return [
            /**
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
     */
    public function getDependencies() : array
    {
        return [
            'factories' => [
                AuthorizationMiddleware::class => AuthorizationMiddlewareFactory::class,
            ],
        ];
    }
}
