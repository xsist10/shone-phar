<?php
/**
 * The Shone Security Scanner is used to help a developer determine if the versions of the
 * dependencies he is using are vulnerable to known exploits.
 *
 * @category Shone
 * @package  Scanner
 * @author   Thomas Shone <xsist10@gmail.com>
 */

namespace Shone\Scanner\Tests\Command;

use Shone\Scanner\Console\Application;
use Shone\Scanner\Scanner;
use Shone\Scanner\Command\JobCommand;

use Symfony\Component\Console\Tester\CommandTester;

class JobCommandTest extends \PHPUnit_Framework_TestCase
{
    private function runCommand($action, $parameters, $json)
    {
        // Mock the scanner
        $scanner = $this->getMock('Shone\Scanner\Scanner', array($action));

        $scanner->expects($this->once())
            ->method($action)
            ->will($this->returnValue(json_decode($json)));

        $application = $this->getMock('Shone\Scanner\Console\Application', array('getScanner'));
        $application->expects($this->once())
            ->method('getScanner')
            ->will($this->returnValue($scanner));

        $command = new JobCommand();
        $command->setApplication($application);
        $commandTester = new CommandTester($command);
        $commandTester->execute($parameters);
        return $commandTester->getDisplay();
    }

    public function testSecureJobs()
    {
        $json = '[{"job_id":"1","hash":"abc123","label":"test","ip_address":"127.0.0.1","server":"127.0.0.1","ts_created":"1234567890","ts_completed":"1234567899","username":"bob.smith","pending":"0","processing":"0","processed":"1","failed":"0","software":"2","software_found":"Joomla!,Wordpress","match_found":"2","severity":"0","is_deprecated":"0","files":"7315","is_vulnerable":"0","status":"Completed"}]';
        $parameters = array('--key' => 'test', '--label' => 'test', '--status' => 'secure');
        $display = $this->runCommand('getJobs', $parameters, $json);

        $this->assertRegExp('/secure/', $display);
        $this->assertRegExp('/2 bundle\(s\) found in 7315 file\(s\) on 127\.0\.0\.1/', $display);
    }

    public function testDeprecatedJobs()
    {
        $json = '[{"job_id":"1","hash":"abc123","label":"test","ip_address":"127.0.0.1","server":"127.0.0.1","ts_created":"1234567890","ts_completed":"1234567899","username":"bob.smith","pending":"0","processing":"0","processed":"1","failed":"0","software":"2","software_found":"Joomla!,Wordpress","match_found":"2","severity":"0","is_deprecated":"1","files":"7315","is_vulnerable":"0","status":"Completed"}]';
        $parameters = array('--key' => 'test', '--label' => 'test', '--status' => 'deprecated');
        $display = $this->runCommand('getJobs', $parameters, $json);

        $this->assertRegExp('/deprecated/', $display);
        $this->assertRegExp('/2 bundle\(s\) found in 7315 file\(s\) on 127\.0\.0\.1/', $display);
    }

    public function testVulnerableJobs()
    {
        $json = '[{"job_id":"1","hash":"abc123","label":"test","ip_address":"127.0.0.1","server":"127.0.0.1","ts_created":"1234567890","ts_completed":"1234567899","username":"bob.smith","pending":"0","processing":"0","processed":"1","failed":"0","software":"2","software_found":"Joomla!,Wordpress","match_found":"2","severity":"5","is_deprecated":"0","files":"7315","is_vulnerable":"1","status":"Completed"}]';
        $parameters = array('--key' => 'test', '--label' => 'test', '--status' => 'insecure');
        $display = $this->runCommand('getJobs', $parameters, $json);

        $this->assertRegExp('/vulnerable/', $display);
    }

    public function testPendingJobs()
    {
        $json = '[{"job_id":"1","hash":"abc123","label":"test","ip_address":"127.0.0.1","server":"127.0.0.1","ts_created":"1234567890","ts_completed":"1234567899","username":"bob.smith","pending":"1","processing":"0","processed":"0","failed":"0","software":"","software_found":"","match_found":"","severity":"","is_deprecated":"","files":"","is_vulnerable":"","status":"Processing"}]';
        $parameters = array('--key' => 'test', '--label' => 'test', '--status' => 'insecure');
        $display = $this->runCommand('getJobs', $parameters, $json);

        $this->assertRegExp('/pending/', $display);
    }

    public function testProcessingJobs()
    {
        $json = '[{"job_id":"1","hash":"abc123","label":"test","ip_address":"127.0.0.1","server":"127.0.0.1","ts_created":"1234567890","ts_completed":"1234567899","username":"bob.smith","pending":"0","processing":"1","processed":"0","failed":"0","software":"","software_found":"","match_found":"","severity":"","is_deprecated":"","files":"","is_vulnerable":"","status":"Processing"}]';
        $parameters = array('--key' => 'test', '--label' => 'test', '--status' => 'insecure');
        $display = $this->runCommand('getJobs', $parameters, $json);

        $this->assertRegExp('/processing/', $display);
    }

    public function testFailedJobs()
    {
        $json = '[{"job_id":"1","hash":"abc123","label":"test","ip_address":"127.0.0.1","server":"127.0.0.1","ts_created":"1234567890","ts_completed":"1234567899","username":"bob.smith","pending":"0","processing":"0","processed":"0","failed":"1","software":"","software_found":"","match_found":"","severity":"","is_deprecated":"","files":"","is_vulnerable":"","status":"Processing"}]';
        $parameters = array('--key' => 'test', '--label' => 'test', '--status' => 'insecure');
        $display = $this->runCommand('getJobs', $parameters, $json);

        $this->assertRegExp('/failed/', $display);
    }

    public function testGetHash()
    {
        $json = '{"result":{"\/":{"6470":{"download_id":"6470","path":"\/","name":"Joomla!","version_id":"4475","version":"2.5.10","match":"96.00%","is_vulnerable":"1","software_id":"4","is_deprecated":"0","favicon":"http:\/\/www.joomla.org\/favicon.ico","risk":"10"},"6570":{"download_id":"6570","path":"\/","name":"Joomla!","version_id":"4631","version":"2.5.13","match":"94.00%","is_vulnerable":"1","software_id":"4","is_deprecated":"1","favicon":"http:\/\/www.joomla.org\/favicon.ico","risk":"10"}},"\/media\/editors\/tinymce\/jscripts\/tiny_mce":{"4798":{"download_id":"4798","path":"\/media\/editors\/tinymce\/jscripts\/tiny_mce","name":"tinymce","version_id":"3511","version":"3.5.2","match":"10.00%","is_vulnerable":"0","software_id":"17","is_deprecated":"0","favicon":"http:\/\/tinymce.moxiecode.com\/favicon.ico","risk":0}}}}';
        $parameters = array('--hash' => 'abc123');
        $display = $this->runCommand('getJob', $parameters, $json);

        $this->assertRegExp('/| Joomla!  | 2.5.10  | vulnerable | 10\/10 | 96.00% |/', $display);
        $this->assertRegExp('/| tinymce  | 3.5.2   | deprecated | N\/A  | 10.00% |/', $display);
    }
}
