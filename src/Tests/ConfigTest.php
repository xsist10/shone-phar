<?php
/**
 * The Shone Security Scanner is used to help a developer determine if the versions of the
 * dependencies he is using are vulnerable to known exploits.
 *
 * @category Shone
 * @package  Scanner
 * @author   Thomas Shone <xsist10@gmail.com>
 */

namespace Shone\Scanner\Tests;

use Shone\Scanner\Config;

use Symfony\Component\Console\Tester\CommandTester;

class ConfigTest extends \PHPUnit_Framework_TestCase
{
    public function testExecuteForCommandAlias()
    {
        $raw = array('tmp' => 'tmp', 'replace' => '{$tmp}');
        $config = new Config();
        $oldRaw = $config->raw() + $raw;

        $config->merge($raw);
        $this->assertTrue($config->has('tmp'));
        $this->assertEquals('tmp', $config->get('tmp'));
        $this->assertEquals('tmp', $config->get('replace'));

        $newRaw = $config->raw();
        $this->assertEquals($oldRaw, $newRaw);
    }

    public function testGet()
    {
        $config = new Config();
        $this->assertEquals(null, $config->get('non-existant-key'));
        $this->assertEquals(1, $config->get('ssl-cert-check'));
    }

    public function testSet()
    {
        $config = new Config();
        $this->assertEquals(1, $config->get('ssl-cert-check'));
        $config->set('ssl-cert-check', 0);
        $this->assertEquals(0, $config->get('ssl-cert-check'));
    }
}
