<?php
/**
 * The inistial bootstrap file to check that dependencies are satisfied.
 *
 * @category Shone
 * @package  Scanner
 * @author   Thomas Shone <xsist10@gmail.com>
 */

/**
 * Does the vendor include file exist?
 *
 * @param string $file The file tocheck for
 *
 * @return bool
 */

if (file_exists(__DIR__.'/../vendor/autoload.php')) {
    if (!$loader = include __DIR__.'/../vendor/autoload.php') {
        throw new Exception('You must set up the project dependencies, run the following commands:' . PHP_EOL .
            'curl -sS https://getcomposer.org/installer | php' . PHP_EOL .
            'php composer.phar install' . PHP_EOL);
    }
}

return $loader;
