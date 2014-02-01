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

use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Command\Command;

/**
 * The about command provides some basic information about the Shone Security scanner tool
 *
 * @category Shone
 * @package  Scanner\Command
 * @author   Thomas Shone <xsist10@gmail.com>
 */
class AboutCommand extends Command
{
    /**
     * Configure our command call
     *
     * @return void
     */
    protected function configure()
    {
        $help = <<<EOT
<info>php shone.phar about</info>

EOT;
        $this
            ->setName('about')
            ->setHelp($help)
            ->setDescription('Short information about Shone Security Scanner');
    }

    /**
     * Execute our command call
     *
     * @param Symfony\Component\Console\Input\InputInterface   $input  Input source
     * @param Symfony\Component\Console\Output\OutputInterface $output Output source
     *
     * @return void
     */
    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $help = <<<EOT
<info>Shone Security Scanner - Software version scanner for PHP</info>
<comment>Shone security scanner identifies versions of common vendor libraries and matches them
against known vulnerabilities. See https://www.shone.co.za/ for more information.</comment>
EOT;
        $output->writeln($help);

    }
}
