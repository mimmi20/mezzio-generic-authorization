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

use Generator;
use Mezzio\GenericAuthorization\Exception\ExceptionInterface;
use PHPUnit\Framework\TestCase;

final class ExceptionTest extends TestCase
{
    /**
     * @return \Generator
     */
    public function exception(): Generator
    {
        $namespace = mb_substr(ExceptionInterface::class, 0, mb_strrpos(ExceptionInterface::class, '\\') + 1);

        $exceptions = glob(__DIR__ . '/../src/Exception/*.php');
        foreach ($exceptions as $exception) {
            $class = mb_substr(basename($exception), 0, -4);

            yield $class => [$namespace . $class];
        }
    }

    /**
     * @dataProvider exception
     *
     * @param string $exception
     *
     * @return void
     */
    public function testExceptionIsInstanceOfExceptionInterface(string $exception): void
    {
        self::assertContains('Exception', $exception);
        self::assertTrue(is_a($exception, ExceptionInterface::class, true));
    }
}
