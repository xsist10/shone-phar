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
use Shone\Scanner\Command\FtpScanCommand;


use Symfony\Component\Console\Tester\CommandTester;

class FtpScanCommandTest extends \PHPUnit_Framework_TestCase
{
    private function mockPacket()
    {
        $job = array();
        $job['job']['version'] = array(
            'value' => '1.0'
        );

        $job['job']['control'] = array(
          'md5'     => hash('md5', 'control'),
          'sha1'    => hash('sha1', 'control')
        );

        $job['job']['files']['file'][] = array(
            'name' => 'test',
            'md5'  => hash('md5', 'test'),
            'sha1' => hash('sha1', 'test'),
        );

        $packet = array(
            'job'       => json_encode($job),
            'label'     => 'test',
            'encode'    => 'json'
        );

        return $packet;
    }

    public function testMissingParameters()
    {
        // Mock the scanner
        $methods = array('buildJobPacket', 'submitJob', 'excludeCommonChecksums');
        $scanner = $this->getMock('Shone\Scanner\Scanner', $methods);

        $scanner->expects($this->once())
            ->method('buildJobPacket')
            ->will($this->returnValue($this->mockPacket()));

        $scanner->expects($this->once())
            ->method('excludeCommonChecksums')
            ->will($this->returnValue(false));

        $json = '{"Status":"Failed","Detail":"Because"}';

        $scanner->expects($this->once())
            ->method('submitJob')
            ->will($this->returnValue(json_decode($json)));

        $application = $this->getMock('Shone\Scanner\Console\Application', array('getScanner'));
        $application->expects($this->once())
            ->method('getScanner')
            ->will($this->returnValue($scanner));

        // Mock our file system
        $listContents = array(
            array(
                'type' => 'file',
                'path' => 'file.php'
            )
        );
        $filesystem = $this->getMockBuilder('League\Flysystem\Filesystem', array('listContents'))
                     ->disableOriginalConstructor()
                     ->getMock();
        $filesystem->expects($this->once())
            ->method('listContents')
            ->will($this->returnValue($listContents));

        $command = $this->getMock('Shone\Scanner\Command\FtpScanCommand', array('getFilesystem'));
        $command->expects($this->once())
            ->method('getFilesystem')
            ->will($this->returnValue($filesystem));

        $command->setApplication($application);
        $commandTester = new CommandTester($command);
        $commandTester->execute(array('--label' => 'label', '--common-checksum' => true, 'localhost'));
        $this->assertRegExp('/Because/', $commandTester->getDisplay());
    }

    public function testExecuteForCommandAlias()
    {
        // Mock the scanner
        $methods = array('buildJobPacket', 'submitJob', 'excludeCommonChecksums');
        $scanner = $this->getMock('Shone\Scanner\Scanner', $methods);

        $scanner->expects($this->once())
            ->method('buildJobPacket')
            ->will($this->returnValue($this->mockPacket()));

        $scanner->expects($this->once())
            ->method('excludeCommonChecksums')
            ->will($this->returnValue(true));

        $json = '{"Status":"Success","Hash":"e950eb2d35asa51e2bb59621add300e3","Detail":"303KB of usage remaining for the month."}';

        $scanner->expects($this->once())
            ->method('submitJob')
            ->will($this->returnValue(json_decode($json)));

        $application = $this->getMock('Shone\Scanner\Console\Application', array('getScanner'));
        $application->expects($this->once())
            ->method('getScanner')
            ->will($this->returnValue($scanner));

        // Mock our file system
        $listContents = array(
            array(
                'type' => 'file',
                'path' => 'file.php'
            )
        );
        $filesystem = $this->getMockBuilder('League\Flysystem\Filesystem', array('listContents'))
                     ->disableOriginalConstructor()
                     ->getMock();
        $filesystem->expects($this->once())
            ->method('listContents')
            ->will($this->returnValue($listContents));

        $command = $this->getMock('Shone\Scanner\Command\FtpScanCommand', array('getFilesystem'));
        $command->expects($this->once())
            ->method('getFilesystem')
            ->will($this->returnValue($filesystem));

        $command->setApplication($application);
        $commandTester = new CommandTester($command);
        $commandTester->execute(array('--label' => 'label', '--common-checksum' => true, 'localhost'));
        $this->assertRegExp('/303KB of usage remaining for the month/', $commandTester->getDisplay());
        $this->assertRegExp('/hash=e950eb2d35asa51e2bb59621add300e3/', $commandTester->getDisplay());
    }
}
