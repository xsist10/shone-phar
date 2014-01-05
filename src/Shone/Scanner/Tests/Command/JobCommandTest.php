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
    public function testMissingParameters()
    {
        // Mock the scanner
        $scanner = $this->getMock('Shone\Scanner\Scanner', array('getJobs'));

        $json = '[{"job_id":"1","hash":"abc123","label":"test","ip_address":"127.0.0.1","server":"127.0.0.1","ts_created":"1234567890","ts_completed":"1234567899","username":"bob.smith","pending":"0","processing":"0","processed":"1","failed":"0","software":"2","software_found":"Joomla!,Wordpress","match_found":"2","severity":"0","is_deprecated":"0","files":"7315","is_vulnerable":"0","status":"Completed"}]';

        $scanner->expects($this->once())
            ->method('getJobs')
            ->will($this->returnValue(json_decode($json)));

        $application = $this->getMock('Shone\Scanner\Console\Application', array('getScanner'));
        $application->expects($this->once())
            ->method('getScanner')
            ->will($this->returnValue($scanner));

        $command = new JobCommand();
        $command->setApplication($application);
        $commandTester = new CommandTester($command);
        $commandTester->execute(array('--key' => 'test'));
        $display = $commandTester->getDisplay();
        $this->assertRegExp('/2009-02-14/', $display);
        $this->assertRegExp('/secure/', $display);
        $this->assertRegExp('/2 bundle\(s\) found in 7315 file\(s\) on 127\.0\.0\.1/', $display);
    }
}
