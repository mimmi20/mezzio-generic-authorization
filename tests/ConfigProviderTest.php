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
namespace MezzioTest\GenericAuthorization;

use Mezzio\GenericAuthorization\AuthorizationMiddleware;
use Mezzio\GenericAuthorization\ConfigProvider;
use PHPUnit\Framework\TestCase;

final class ConfigProviderTest extends TestCase
{
    /** @var ConfigProvider */
    private $provider;

    /**
     * @return void
     */
    protected function setUp(): void
    {
        $this->provider = new ConfigProvider();
    }

    /**
     * @return void
     */
    public function testProviderDefinesExpectedFactoryServices(): void
    {
        $config    = $this->provider->getDependencies();
        $factories = $config['factories'];

        self::assertArrayHasKey(AuthorizationMiddleware::class, $factories);
    }

    /**
     * @return void
     */
    public function testInvocationReturnsArrayWithDependencies(): void
    {
        $config = ($this->provider)();

        self::assertIsArray($config);
        self::assertArrayHasKey('authorization', $config);
        self::assertIsArray($config['authorization']);

        self::assertArrayHasKey('dependencies', $config);
        self::assertIsArray($config['dependencies']);
        self::assertArrayHasKey('aliases', $config['dependencies']);
        self::assertArrayHasKey('factories', $config['dependencies']);
    }
}
