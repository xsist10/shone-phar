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

use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Command\Command;

use \Exception;

/**
 * The self-update command only accessable when accessing from a phar
 *
 * @category Shone
 * @package  Scanner\Command
 * @author   Thomas Shone <xsist10@gmail.com>
 */
class SetConfigCommand extends Command
{
    /**
     * Configure our command call
     *
     * @return void
     */
    protected function configure()
    {
        $help = <<<EOT
The <info>set-config</info> command sets the configuration for a user.

EOT;

        $this
            ->setName('set-config')
            ->setHelp($help)
            ->setAliases(array('setconfig'))
            ->setDescription('Setup the configuration for a user.')
            ->setDefinition(array(
                new InputOption('key', null, InputOption::VALUE_REQUIRED, 'Set an API key.'),
                new InputOption('common-checksum', 'c', InputOption::VALUE_REQUIRED, 'Set whether to always ignore files that are very common.', true),
                new InputOption('no-cert-check', null, InputOption::VALUE_REQUIRED, 'Set whether to disable CA certificate checks.', false),
            ));
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
        $config = $this->getApplication()->getConfig();

        $no_cert_check = $input->getOption('no-cert-check') ? true : false;
        $config->set('no-cert-check', $no_cert_check);
        $output->writeln(sprintf("Setting no-cert-check to <info>%b</info>.", $no_cert_check));

        $common_checksum = $input->getOption('common-checksum') ? true : false;
        $config->set('common-checksum', $common_checksum);
        $output->writeln(sprintf("Setting common-checksum to <info>%b</info>.", $common_checksum));

        if ($input->getOption('key'))
        {
            $config->set('key', $input->getOption('key'));
            $output->writeln(sprintf("Setting key to <info>%s</info>.", $config->get('key')));
        }
        
        $output->writeln("<info>Config file saved.</info>");
        $config->save();
    }
}
