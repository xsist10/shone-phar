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
use Shone\Scanner\Command\AboutCommand;

use Symfony\Component\Console\Tester\CommandTester;

class AboutCommandTest extends \PHPUnit_Framework_TestCase
{
    public function testExecuteForCommandAlias()
    {
        $command = new AboutCommand();
        $command->setApplication(new Application());
        $commandTester = new CommandTester($command);
        $commandTester->execute(array());
        $this->assertRegExp('/Shone Security Scanner - Software version scanner for PHP/', $commandTester->getDisplay(), '->execute() returns a text help for the given command alias');
    }

    public function testExecuteForApplicationCommand()
    {
        $application = new Application();
        $commandTester = new CommandTester($application->get('about'));
        $commandTester->execute(array());
        $this->assertRegExp('/Shone Security Scanner - Software version scanner for PHP/', $commandTester->getDisplay(), '->execute() returns a text help for the given command alias');
    }
}
