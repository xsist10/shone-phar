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
use Shone\Scanner\Command\FingerprintCommand;

use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\Finder\Finder;

class FingerprintCommandTest extends \PHPUnit_Framework_TestCase
{
    public function testInvalidFile()
    {
        $command = new FingerprintCommand();
        $command->setApplication(new Application());
        $commandTester = new CommandTester($command);
        $commandTester->execute(array('file' => '/none/existant/file'));
        $this->assertRegExp('/File does not exists or is not readable/', $commandTester->getDisplay());
    }

    public function testFailed()
    {
        // Mock the scanner
        $scanner = $this->getMock('Shone\Scanner\Scanner', array('fingerprintFile'));

        $json = '{"Status":"Failed","Detail":"Access denied"}';

        $scanner->expects($this->once())
            ->method('fingerprintFile')
            ->will($this->returnValue(json_decode($json)));

        $application = $this->getMock('Shone\Scanner\Console\Application', array('getScanner'));
        $application->expects($this->once())
            ->method('getScanner')
            ->will($this->returnValue($scanner));

        $command = new FingerprintCommand();
        $command->setApplication($application);
        $commandTester = new CommandTester($command);
        $commandTester->execute(array('file' => __FILE__));
        $this->assertRegExp('/Access denied/', $commandTester->getDisplay());
    }

    public function testNoMatch()
    {
        // Mock the scanner
        $scanner = $this->getMock('Shone\Scanner\Scanner', array('fingerprintFile'));

        $json = '{"Status":"Success","Detail":"No match found"}';

        $scanner->expects($this->once())
            ->method('fingerprintFile')
            ->will($this->returnValue(json_decode($json)));

        $application = $this->getMock('Shone\Scanner\Console\Application', array('getScanner'));
        $application->expects($this->once())
            ->method('getScanner')
            ->will($this->returnValue($scanner));

        $command = new FingerprintCommand();
        $command->setApplication($application);
        $commandTester = new CommandTester($command);
        $commandTester->execute(array('file' => __FILE__));
        $this->assertRegExp('/No match found/', $commandTester->getDisplay());
    }

    public function testMatch()
    {
        // Mock the scanner
        $scanner = $this->getMock('Shone\Scanner\Scanner', array('fingerprintFile'));

        $json = json_encode(
            array(
                'Status'  => 'Success',
                'Detail'  => '3 matches found',
                'Matches' => array(
                    array(
                        'software'      => 'Zend Framework',
                        'version'       => '1.11.4',
                        'file'          => 'library/Zend/Locale/Data/gez_ER.xml',
                        'is_vulnerable' => '0',
                        'is_malicious'  => '1',
                    ),
                    array(
                        'software'      => 'Zend Framework',
                        'version'       => '1.11.5',
                        'file'          => 'library/Zend/Locale/Data/gez_ER.xml',
                        'is_vulnerable' => '1',
                        'is_malicious'  => '0',
                    ),
                    array(
                        'software'      => 'Zend Framework',
                        'version'       => '1.11.6',
                        'file'          => 'library/Zend/Locale/Data/gez_ER.xml',
                        'is_vulnerable' => '0',
                        'is_malicious'  => '0',
                    )
                )
            )
        );

        $scanner->expects($this->once())
            ->method('fingerprintFile')
            ->will($this->returnValue(json_decode($json)));

        $application = $this->getMock('Shone\Scanner\Console\Application', array('getScanner'));
        $application->expects($this->once())
            ->method('getScanner')
            ->will($this->returnValue($scanner));

        $command = new FingerprintCommand();
        $command->setApplication($application);
        $commandTester = new CommandTester($command);
        $commandTester->execute(array('file' => __FILE__));
        $this->assertRegExp('/3 matches found/', $commandTester->getDisplay());
        $this->assertRegExp('/| Zend Framework | 1.11.4  | Malicious  |/', $commandTester->getDisplay());
        $this->assertRegExp('/| Zend Framework | 1.11.5  | Vulnerable |/', $commandTester->getDisplay());
        $this->assertRegExp('/| Zend Framework | 1.11.6  | Secure     |/', $commandTester->getDisplay());
    }
}
