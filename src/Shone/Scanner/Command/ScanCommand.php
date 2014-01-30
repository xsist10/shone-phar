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
 * The scan command performs the security scan
 *
 * @category Shone
 * @package  Scanner\Command
 * @author   Thomas Shone <xsist10@gmail.com>
 */
class ScanCommand extends Command
{
    /**
     * Configure our command call
     *
     * @return void
     */
    protected function configure()
    {
        $help = <<<EOT
The scan command starts and submits a scan of the local folders and uploads a fingerprint file to
the Shone Security servers.

EOT;

        $this
            ->setName('scan')
            ->setDescription('Scan the project for known versions')
            ->setHelp($help)
            ->setDefinition(array(
                new InputArgument('path', InputArgument::OPTIONAL, 'Specify a customer path to examine.', '.'),
                new InputOption('label', null, InputOption::VALUE_REQUIRED, 'Set the label for this scan.'),
                new InputOption('key', null, InputOption::VALUE_REQUIRED, 'Pass an API key.'),
                new InputOption('common-checksum', 'c', InputOption::VALUE_NONE, 'Ignore files that are very common.'),
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

        $exclude_extensions = $config->get('ignore-ext');
        $this->log($output, ' Setting excluded extensions to `' . implode(', ', $exclude_extensions) . '`');

        // Enable/disable CA certificate checks
        $scanner->setCertCheck($input->hasOption('no-cert-check') ? false : $config->get('ssl-cert-check'));

        // Determine the path we're going to scan
        $path = $input->getArgument('path');
        $this->log($output, ' Setting path to `' . $path . '`');
        $scanner->setPath($path);

        // Has the user specified a label?
        $label = $input->hasOption('label') ? $input->getOption('label') : $config->get('label');
        if ($label !== null)
        {
            $this->log($output, ' Setting label to `' . $label .'`');
            $scanner->setLabel($label);
        }

        // Do we have a key to use?
        $key = $input->hasOption('key') ? $input->getOption('key') : $config->get('key');
        $this->log($output, ' Setting key to `' . $key . '`');
        $scanner->setKey($key);

        $commonChecksums = array();
        if ($input->hasOption('common-checksum') && $input->getOption('common-checksum')) {
            if ($scanner->excludeCommonChecksums()) {
                $this->log($output, ' Filtering out common checksums');
            } else {
                $this->log($output, ' Common checksums inaccessable');
            }
        }
        $this->log($output);

        // Generate a list of files to scan
        $this->log($output, "<comment>Generating file list:</comment>");
        $files = $scanner->getFiles();
        $original_count = $files->count();

        if (count($exclude_extensions)) {
            $this->log($output, " Filtering excluded extensions");
            foreach ($exclude_extensions as $ext) {
                $files->notName('*.' . $ext);
            }
            $this->log($output, " " . ($original_count - $files->count()) . " files filtered");
        }

        $this->log($output, " " . $files->count() . " files to process");
        $this->log($output);

        // Build the job packet
        $this->log($output, "<comment>Building job packet</comment>");
        $packet = $scanner->buildJobPacket($files, $label);
        //$this->log($output, " Packet is " . number_format(strlen(json_encode($packet['job']))/1024) . "KB");
        $this->log($output);

        // Submit the job to the remote server
        $this->log($output, "<comment>Submitting job to remote server</comment>");
        $result = $scanner->submitJob($packet);
        $this->log($output);

        if ($result->Status != 'Success') {
            $this->log($output, 'Result: <error>' . $result->Detail . '</error>', true);
        } else {
            $this->log($output, 'Result: <info>' . $result->Detail . '</info>', true);
            $this->log($output, '<info>The result will be available shortly at:</info>', true);
            $this->log($output, $scanner->getJobUrl($result->Hash), true);
        }

        $this->log($output);
    }
}
