<?php

/**
 * This file is part of the mimmi20/mezzio-generic-authorization-rbac package.
 *
 * Copyright (c) 2020-2024, Thomas Mueller <mimmi20@live.de>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types = 1);

namespace Mimmi20\Mezzio\GenericAuthorization;

use PHPUnit\Framework\Exception;
use PHPUnit\Framework\TestCase;

final class ConfigProviderTest extends TestCase
{
    private ConfigProvider $provider;

    /** @throws void */
    protected function setUp(): void
    {
        $this->provider = new ConfigProvider();
    }

    /** @throws Exception */
    public function testProviderDefinesExpectedFactoryServices(): void
    {
        $dependencies = $this->provider->getDependencies();
        self::assertIsArray($dependencies);
        self::assertArrayHasKey('factories', $dependencies);

        $factories = $dependencies['factories'];
        self::assertIsArray($factories);
        self::assertArrayHasKey(AuthorizationMiddleware::class, $factories);
    }

    /** @throws Exception */
    public function testProviderDefinesBaseAuthorizationConfig(): void
    {
        $authorization = $this->provider->getAuthorizationConfig();
        self::assertIsArray($authorization);
    }

    /** @throws Exception */
    public function testInvocationReturnsArrayWithDependencies(): void
    {
        $config = ($this->provider)();

        self::assertIsArray($config);
        self::assertArrayHasKey('authorization', $config);

        $authorization = $config['authorization'];
        self::assertIsArray($authorization);

        self::assertArrayHasKey('dependencies', $config);

        $dependencies = $config['dependencies'];
        self::assertIsArray($dependencies);
        self::assertArrayHasKey('factories', $dependencies);

        $factories = $dependencies['factories'];
        self::assertIsArray($factories);
        self::assertArrayHasKey(AuthorizationMiddleware::class, $factories);
    }
}
