<?php
/**
 * The Shone Security Scanner is used to help a developer determine if the versions of the
 * dependencies he is using are vulnerable to known exploits.
 *
 * @category Shone
 * @package  Scanner
 * @author   Thomas Shone <xsist10@gmail.com>
 */

namespace Shone\Scanner\Tests\Console;

use Shone\Scanner\Console\Application;
use Shone\Scanner\Config;
use Shone\Scanner\Scanner;

class ApplicationTest extends \PHPUnit_Framework_TestCase
{
    protected $application;

    public function setUp()
    {
        $this->application = new Application();
    }

    public function testScanner()
    {
        $this->assertInstanceOf('Shone\Scanner\Scanner', $this->application->getScanner());
    }

    public function testConfig()
    {
        $this->assertInstanceOf('Shone\Scanner\Config', $this->application->getConfig());
    }

    public function testHelp()
    {
        $this->assertContains('Shone Security Scanner', $this->application->getHelp());
    }

    public function testVersion()
    {
        $this->assertTrue(strpos($this->application->getLongVersion(), Scanner::RELEASE_DATE) !== false);
    }
}