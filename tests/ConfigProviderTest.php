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
     * @throws \PHPUnit\Framework\ExpectationFailedException
     * @throws \SebastianBergmann\RecursionContext\InvalidArgumentException
     *
     * @return void
     */
    public function testProviderDefinesExpectedFactoryServices(): void
    {
        $dependencies = $this->provider->getDependencies();
        self::assertIsArray($dependencies);
        self::assertArrayHasKey('factories', $dependencies);

        $factories = $dependencies['factories'];
        self::assertIsArray($factories);
        self::assertArrayHasKey(AuthorizationMiddleware::class, $factories);
    }

    /**
     * @return void
     */
    public function testProviderDefinesBaseAuthorizationConfig(): void
    {
        $authorization = $this->provider->getAuthorizationConfig();
        self::assertIsArray($authorization);
    }

    /**
     * @throws \PHPUnit\Framework\ExpectationFailedException
     * @throws \SebastianBergmann\RecursionContext\InvalidArgumentException
     *
     * @return void
     */
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
