<?php
/**
 * The Shone Security Scanner is used to help a developer determine if the versions of the
 * dependencies he is using are vulnerable to known exploits.
 *
 * @category Shone
 * @package  Scanner
 * @author   Thomas Shone <xsist10@gmail.com>
 */

namespace Shone\Scanner;

use Symfony\Component\Finder\Finder;
use Symfony\Component\Process\Process;

/**
 * The Compiler class compiles shone into a phar
 *
 * @author Thomas Shone <thomas@shone.co.za>
 */
class Compiler
{
    /**
     * @var string
     */
    private $version;

    /**
     * @var string
     */
    private $versionDate;

    /**
     * Compiles shone into a single phar file
     *
     * @throws \RuntimeException
     * @param  string            $pharFile The full path to the file to create
     */
    public function compile($pharFile = 'shone.phar')
    {
        if (file_exists($pharFile)) {
            unlink($pharFile);
        }

        $this->version = '1.0';

        $phar = new \Phar($pharFile, 0, 'shone.phar');
        $phar->setSignatureAlgorithm(\Phar::SHA1);

        $phar->startBuffering();

        // Add scanner files
        $this->addFile($phar, new \SplFileInfo(__DIR__.'/../../bootstrap.php'));

        $finder = new Finder();
        $finder->files()
            ->ignoreVCS(true)
            ->name('*.php')
            ->notName('Compiler.php')
            ->notName('Application.php')
            ->in(__DIR__.'/..')
        ;
        foreach ($finder as $file) {
            $this->addFile($phar, $file);
        }
        $this->addFile($phar, new \SplFileInfo(__DIR__ . '/Console/Application.php'), false);

        // Add all symfony dependencies
        $finder = new Finder();
        $finder->files()
            ->ignoreVCS(true)
            ->name('*.php')
            ->exclude('Tests')
            ->in(__DIR__.'/../../../vendor/symfony/')
        ;
        foreach ($finder as $file) {
            $this->addFile($phar, $file);
        }

        // Add autoloading files
        $this->addFile($phar, new \SplFileInfo(__DIR__.'/../../../vendor/autoload.php'));
        $this->addFile($phar, new \SplFileInfo(__DIR__.'/../../../vendor/composer/ClassLoader.php'));
        $this->addFile($phar, new \SplFileInfo(__DIR__.'/../../../vendor/composer/autoload_namespaces.php'));
        $this->addFile($phar, new \SplFileInfo(__DIR__.'/../../../vendor/composer/autoload_classmap.php'));
        $this->addFile($phar, new \SplFileInfo(__DIR__.'/../../../vendor/composer/autoload_real.php'));
        if (file_exists(__DIR__.'/../../../vendor/composer/include_paths.php')) {
            $this->addFile($phar, new \SplFileInfo(__DIR__.'/../../../vendor/composer/include_paths.php'));
        }
        $this->addShoneBin($phar);

        // Add resources
        $this->addFile($phar, new \SplFileInfo(__DIR__.'/../../../res/config.json'));
        $this->addFile($phar, new \SplFileInfo(__DIR__.'/../../../res/thawte.pem'));

        // Stubs
        $phar->setStub($this->getStub());

        $phar->stopBuffering();

        // disabled for interoperability with systems without gzip ext
        // $phar->compressFiles(\Phar::GZ);

        $this->addFile($phar, new \SplFileInfo(__DIR__.'/../../../LICENSE'), false);

        unset($phar);
    }

    private function addFile($phar, $file, $strip = true)
    {
        $path = str_replace(getcwd() . DIRECTORY_SEPARATOR, '', $file->getRealPath());

        $content = file_get_contents($file);
        if ($strip) {
            $content = $this->stripWhitespace($content);
        } elseif ('LICENSE' === basename($file)) {
            $content = "\n".$content."\n";
        }

        $content = str_replace('@package_version@', $this->version, $content);
        $content = str_replace('@release_date@', $this->versionDate, $content);

        $phar->addFromString($path, $content);
    }

    /**
     * Removes whitespace from a PHP source string while preserving line numbers.
     *
     * @param  string $source A PHP string
     * @return string The PHP string with the whitespace removed
     */
    private function stripWhitespace($source)
    {
        if (!function_exists('token_get_all')) {
            return $source;
        }

        $output = '';
        foreach (token_get_all($source) as $token) {
            if (is_string($token)) {
                $output .= $token;
            } elseif (in_array($token[0], array(T_COMMENT, T_DOC_COMMENT))) {
                $output .= str_repeat("\n", substr_count($token[1], "\n"));
            } elseif (T_WHITESPACE === $token[0]) {
                // reduce wide spaces
                $whitespace = preg_replace('{[ \t]+}', ' ', $token[1]);
                // normalize newlines to \n
                $whitespace = preg_replace('{(?:\r\n|\r|\n\n|\n)}', "\n", $whitespace);
                // trim leading spaces
                $whitespace = preg_replace('{\n\s+}', "\n", $whitespace);
                // remove double breaklines
                $output .= $whitespace;
            } else {
                $output .= $token[1];
            }
        }

        $output = preg_replace('{\n\s+}', "\n", $output);

        return $output;
    }

    private function addShoneBin($phar)
    {
        $content = file_get_contents(__DIR__.'/../../../bin/shone');
        $content = preg_replace('{^#!/usr/bin/env php\s*}', '', $content);
        $phar->addFromString('bin/shone', $content);
    }


    private function getStub()
    {
        $stub = <<<'EOF'
#!/usr/bin/env php
<?php
/*
 * This file is part of Shone Security Scanner.
 *
 * (c) Thomas Shone <xsist10@gmail.com>
 *
 * For the full copyright and license information, please view
 * the license that is located at the bottom of this file.
 */

Phar::mapPhar('shone.phar');

EOF;

        // Generate a warning about the age of the phar
        $warningTime = time() + 30*86400;
        $stub .= "define('WARNING_TIME', $warningTime);\n";

        return $stub . <<<'EOF'
require 'phar://shone.phar/bin/shone';

__HALT_COMPILER();
EOF;
    }
}
