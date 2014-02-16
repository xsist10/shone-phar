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
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Command\Command;

use Shone\Scanner\Scanner;
use Shone\Scanner\Config;

use \RuntimeException;

/**
 * The fingerprint command identifies which software a file belongs to
 *
 * @category Shone
 * @package  Scanner\Command
 * @author   Thomas Shone <xsist10@gmail.com>
 */
class FingerprintCommand extends Command
{
    /**
     * Configure our command call
     *
     * @return void
     */
    protected function configure()
    {
        $help = <<<EOT
The fingerprint command identifies which software a file is from and which versions of that software it matches.

EOT;

        $this
            ->setName('fingerprint')
            ->setDescription('Indentify which software the file belongs to and which versions of that software.')
            ->setHelp($help)
            ->setDefinition(array(
                new InputArgument('file', InputArgument::REQUIRED, 'Specify a file to examine.'),
                new InputOption('key', null, InputOption::VALUE_REQUIRED, 'Pass an API key.'),
                new InputOption('no-cert-check', null, InputOption::VALUE_NONE, 'Disable CA certificate checks.'),
            ));
    }

    /**
     * Execute our command call
     *
     * @param Symfony\Component\Console\Input\InputInterface   $input  Input source
     * @param Symfony\Component\Console\Output\OutputInterface $output Output source
     *
     * @return void
     */
    protected function log(OutputInterface $output, $message = '', $force = false)
    {
        if ($force || $output->getVerbosity() >= OutputInterface::VERBOSITY_NORMAL) {
            $output->writeln($message);
        }
    }

    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $scanner = $this->getApplication()->getScanner();
        $config = new Config();

        $this->log($output);

        // Setup configuration
        $this->log($output, "<comment>Configuration</comment>");

        // Enable/disable CA certificate checks
        $scanner->setCertCheck($input->hasOption('no-cert-check') ? false : $config->get('ssl-cert-check'));

        // Determine the path we're going to scan
        $file = $input->getArgument('file');
        $this->log($output, ' Setting file to `' . $file . '`');
        if (!file_exists($file) || !is_readable($file)) {
            $this->log($output, '<error>File does not exists or is not readable</error>', true);
            return false;
        }

        // Do we have a key to use?
        $key = $input->hasOption('key') ? $input->getOption('key') : $config->get('key');
        $this->log($output, ' Setting key to `' . $key . '`');
        $scanner->setKey($key);

        $this->log($output);

        // Submit the file to the remote server
        $this->log($output, "<comment>Submitting job to remote server</comment>");
        $result = $scanner->fingerprintFile($file);
        $this->log($output);

        if ($result['Status'] != 'Success') {
            $this->log($output, 'Result: <error>' . $result['Detail'] . '</error>', true);
        } else {
            $this->log($output, 'Result: <info>' . $result['Detail'] . '</info>', true);

            $table = $this->getApplication()->getHelperSet()->get('table');
            $table->setHeaders(array('Software', 'Version', 'Status'));

            $data = array();

            if (!empty($result['Matches'])) {
                foreach ($result['Matches'] as $match) {
                    $warning = array();
                    if ($match['is_malicious']) {
                        $warning[] = 'Malicious';
                    }
                    if ($match['is_vulnerable']) {
                        $warning[] = 'Vulnerable';
                    }
                    if (!$match['is_vulnerable'] && !$match['is_malicious']) {
                        $warning[] = 'Secure';
                    }

                    $data[] = array(
                        $match['software'],
                        $match['version'],
                        implode(', ', $warning)
                    );
                }
            }

            $table->setRows($data);
            $table->render($output);
        }

        $this->log($output);
    }
}
