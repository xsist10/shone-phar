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

use Shone\Scanner\Scanner;
use Shone\Scanner\Console\Application;
use Shone\Scanner\Command\SelfUpdateCommand;
use Shone\Scanner\Utils\RemoteFileSystem;

use Symfony\Component\Console\Tester\CommandTester;

class SelfUpdateCommandTest extends \PHPUnit_Framework_TestCase
{
    public function testInstantiate()
    {
        $command = new SelfUpdateCommand();
        $this->assertInstanceOf('Shone\Scanner\Utils\RemoteFileSystem', $command->getRemoteFileSystem());
    }

    public function testExecuteForCommandAliasWithNewVersion()
    {
        $_SERVER['argv'][0] = getcwd() . "/shone.phar";

        // Mock the remote file system
        $rfs = $this->getMock('Shone\Scanner\Utils\RemoteFileSystem');
        $rfs->expects($this->once())
            ->method('getFile')
            ->will($this->returnValue(json_encode(array('version' => '1.0.0'))));

        $command = $this->getMock('Shone\Scanner\Command\SelfUpdateCommand', array('getRemoteFileSystem'));

        $command->expects($this->once())
            ->method('getRemoteFileSystem')
            ->will($this->returnValue($rfs));

        //$command = new SelfUpdateCommand();
        $command->setApplication(new Application());
        $commandTester = new CommandTester($command);
        $commandTester->execute(array());
        $this->assertRegExp('/Updating to version 1.0.0/', $commandTester->getDisplay());
    }

    public function testExecuteForCommandAliasWithSameVersion()
    {
        $_SERVER['argv'][0] = getcwd() . "/shone.phar";

        // Mock the remote file system
        $rfs = $this->getMock('Shone\Scanner\Utils\RemoteFileSystem');
        $rfs->expects($this->atLeastOnce())
            ->method('getFile')
            ->will($this->returnValue(json_encode(array('version' => Scanner::VERSION))));

        $command = $this->getMock('Shone\Scanner\Command\SelfUpdateCommand', array('getRemoteFileSystem'));

        $command->expects($this->atLeastOnce())
            ->method('getRemoteFileSystem')
            ->will($this->returnValue($rfs));

        //$command = new SelfUpdateCommand();
        $command->setApplication(new Application());
        $commandTester = new CommandTester($command);
        $commandTester->execute(array());

        $commandTester->execute(array());
        $this->assertRegExp('/You are using the latest Shone Scanner version/', $commandTester->getDisplay());
    }
}
