<?php
/**
 * The Shone Security Scanner is used to help a developer determine if the versions of the
 * dependencies he is using are vulnerable to known exploits.
 *
 * @category Shone
 * @package  Scanner
 * @author   Thomas Shone <xsist10@gmail.com>
 */

namespace Shone\Scanner\Command;

use Shone\Scanner\Scanner;
use Shone\Scanner\Utils\RemoteFileSystem;

use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Command\Command;

use \Exception;
use \UnexpectedValueException;
use \PharException;

/**
 * The self-update command only accessable when accessing from a phar
 *
 * @category Shone
 * @package  Scanner\Command
 * @author   Thomas Shone <xsist10@gmail.com>
 */
class SelfUpdateCommand extends Command
{
    /**
     * Configure our command call
     *
     * @return void
     */
    protected function configure()
    {
        $help = <<<EOT
The <info>self-update</info> command checks github.com for newer
versions of Shone Scanner and if found, installs the latest.

<info>php shone.phar self-update</info>

EOT;

        $this
            ->setName('self-update')
            ->setHelp($help)
            ->setAliases(array('selfupdate'))
            ->setDescription('Updates shone.phar to the latest version.');
    }

    public function getRemoteFileSystem()
    {
        return new RemoteFileSystem();
    }

    /**
     * Execute our command call
     *
     * @param Symfony\Component\Console\Input\InputInterface   $input  Input source
     * @param Symfony\Component\Console\Output\OutputInterface $output Output source
     *
     * @return void
     * @codeCoverageIgnore
     */
    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $localFilename = realpath($_SERVER['argv'][0]) ?: $_SERVER['argv'][0];
        $tempFilename = dirname($localFilename) . '/' . basename($localFilename, '.phar').'.phar';

        // check for permissions in local filesystem before start connection process
        if (!is_writable($tempDirectory = dirname($tempFilename))) {
            throw new Exception('The "' . $tempDirectory . '" directory is not writable');
        }

        if (!is_writable($localFilename)) {
            throw new Exception('The "' . $localFilename . '" file is not writable');
        }

        $rfs = $this->getRemoteFileSystem();
        $latest = @json_decode($rfs->getFile('raw.github.com/xsist10/shone-phar/master/res/config.json'));
        if (!$latest) {
            $output->writeln("<error>Unable to retrieve remote version file.</error>");
        } elseif (Scanner::VERSION !== $latest->version) {
            $output->writeln(sprintf("Updating to version <info>%s</info>.", $latest->version));

            try {
                $rfs->copyPhar('raw.github.com/xsist10/shone-phar/master/shone.phar', $tempFilename);
                $output->writeln("<info>Successfully installed.</info>");
            } catch (Exception $e) {
                $output->writeln('<error>' . $e->getMessage() . '</error>');
            }
        } else {
            $output->writeln("<info>You are using the latest Shone Scanner version.</info>");
        }
    }
}
