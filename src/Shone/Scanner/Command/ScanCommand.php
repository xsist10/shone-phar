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

use League\Flysystem\Filesystem;
use League\Flysystem\Adapter\Local;

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
    protected $config;

    /**
     * Configure our command call
     *
     * @return void
     */
    protected function configure()
    {
        $help = <<<EOT
The scan command starts and submits a scan of a local folder and uploads a fingerprint file to
the Shone Security servers.

EOT;

        $this
            ->setName('scan')
            ->setDescription('Scan a local project for known software vulnerabilities')
            ->setHelp($help)
            ->setDefinition(array(
                new InputArgument('path', InputArgument::OPTIONAL, 'Specify a customer path to examine.', '.'),
                new InputOption('label', null, InputOption::VALUE_REQUIRED, 'Set the label for this scan.'),
                new InputOption('key', null, InputOption::VALUE_REQUIRED, 'Pass an API key.'),
                new InputOption('common-checksum', 'c', InputOption::VALUE_NONE, 'Ignore files that are very common.'),
                new InputOption('no-cert-check', null, InputOption::VALUE_NONE, 'Disable CA certificate checks.'),
            ));
    }

    protected function getFilesystem(array $config)
    {
        return new Local($config['path']);
    }

    protected function getConfig(InputInterface $input, Config $config)
    {
        $this->config['exclude_extensions'] = $config->get('ignore-ext');
        $this->config['ssl-cert-check'] = $input->hasOption('no-cert-check') ? false : $config->get('ssl-cert-check');
        $this->config['path'] = $input->getArgument('path');
        $this->config['label'] = $input->hasOption('label') ? $input->getOption('label') : $config->get('label');
        $this->config['key'] = $input->hasOption('key') ? $input->getOption('key') : $config->get('key');
        $this->config['common-checksum'] = $input->hasOption('common-checksum') && $input->getOption('common-checksum');

        return $this->config;
    }


    protected function log(OutputInterface $output, $message = '', $force = false)
    {
        if ($force || $output->getVerbosity() >= OutputInterface::VERBOSITY_NORMAL) {
            $output->writeln($message);
        }
    }

    protected function buildFileList(Filesystem $filesystem, $path = '')
    {
        $files = array();
        foreach ($filesystem->listContents($path) as $item)
        {
            if ($item['type'] == 'dir')
            {
                if ($item['basename'] != '.git' && $item['basename'] != '.svn') {
                    $files = array_merge($files, $this->buildFileList($filesystem, $item['path']));
                }
            }
            else if ($item['type'] == 'file')
            {
                if (empty($item['extension']) || !in_array($item['extension'], $this->config['exclude_extensions']))
                {
                    $files[] = $item['path'];
                }
            }
        }
        return $files;
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
        $scanner = $this->getApplication()->getScanner();

        $config = $this->getConfig($input, $this->getApplication()->getConfig());

        $this->log($output);

        // Setup configuration
        $this->log($output, "<comment>Configuration</comment>");

        // Exclude irrelevant extensions
        $this->log($output, ' Setting excluded extensions to `' . implode(', ', $this->config['exclude_extensions']) . '`');

        // Enable/disable CA certificate checks
        $scanner->setCertCheck($config['ssl-cert-check']);

        // Determine the path we're going to scan
        $this->log($output, ' Setting path to `' . $config['path'] . '`');
        $scanner->setPath($config['path']);

        // Has the user specified a label?
        $this->log($output, ' Setting label to `' . $config['label'] .'`');
        $scanner->setLabel($config['label']);

        // Do we have a key to use?
        $this->log($output, ' Setting key to `' . $config['key'] . '`');
        $scanner->setKey($config['key']);

        if ($config['common-checksum']) {
            if ($scanner->excludeCommonChecksums()) {
                $this->log($output, ' Filtering out common checksums');
            } else {
                $this->log($output, ' Common checksums inaccessable');
            }
        }
        $this->log($output);

        // Generate list of files to scan
        $this->log($output, "<comment>Generating file list:</comment>");
        $filesystem = new Filesystem($this->getFilesystem($config));
        $files = $this->buildFileList($filesystem);
        $this->log($output, " " . count($files) . " files to process");
        $this->log($output);

        // Build the job packet using the file list
        $this->log($output, "<comment>Building job packet</comment>");
        $packet = $scanner->buildJobPacket($filesystem, $files);
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
