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
 * The job command returns a list of jobs based on various filters
 *
 * @category Shone
 * @package  Scanner\Command
 * @author   Thomas Shone <xsist10@gmail.com>
 */
class JobCommand extends Command
{
    /**
     * Configure our command call
     *
     * @return void
     */
    protected function configure()
    {
        $help = <<<EOT
The job command returns a list of jobs based on various filters.

EOT;

        $this
            ->setName('job')
            ->setDescription('The job command returns a list of jobs based on various filters.')
            ->setHelp($help)
            ->setDefinition(array(
                new InputOption('key', null, InputOption::VALUE_REQUIRED, 'Pass an API key.'),
                new InputOption('hash', null, InputOption::VALUE_REQUIRED, 'Hash of a specific job.'),
                new InputOption('status', null, InputOption::VALUE_REQUIRED, 'List jobs by result (secure, insecure or deprecated).'),
                new InputOption('label', null, InputOption::VALUE_REQUIRED, 'Return the most recent job for a specific label.'),
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

        // Do we have a key to use?
        $key = $input->hasOption('key') ? $input->getOption('key') : $config->get('key');
        $this->log($output, ' Setting key to `' . $key . '`');
        $scanner->setKey($key);

        $this->log($output);

        if ($input->hasOption('hash') && $input->getOption('hash'))
        {
            $this->log($output, "<comment>Requesting job from remote server</comment>");
            $job = $scanner->getJob($input->getOption('hash'));

            $software = count($job->result);
            $this->log($output, "Found $software results.");
            if ($software)
            {
                foreach ($job->result as $path => $results)
                {
                    $this->log($output);
                    $this->log($output, "Path: $path");

                    $table = $this->getApplication()->getHelperSet()->get('table');
                    $table->setHeaders(array('Software', 'Version', 'Status', 'Risk', 'Match'));

                    $data = array();
                    foreach ($results as $match)
                    {
                        $warning = array();
                        if ($match->is_deprecated) {
                            $warning[] = 'deprecated';
                        }
                        if ($match->is_vulnerable) {
                            $warning[] = 'vulnerable';
                        }
                        if (!$match->is_vulnerable && !$match->is_deprecated) {
                            $warning[] = 'secure';
                        }

                        $data[] = array(
                            $match->name,
                            $match->version,
                            implode(', ', $warning),
                            ($match->risk) ? $match->risk . '/10' : 'N/A',
                            $match->match
                        );
                    }

                    $table->setRows($data);
                    $table->render($output);
                }
            }
        }
        else
        {
            $packet = array();
            // Build the filter packet
            if ($input->hasOption('label') && $input->getOption('label'))
            {
                $packet['label'] = $input->getOption('label');
            }
            if ($input->hasOption('status') && $input->getOption('status'))
            {
                switch ($input->getOption('status'))
                {
                    case 'secure':
                        $packet['is_vulnerable'] = '-1';
                        $packet['is_deprecated'] = '-1';
                        $packet['is_known'] = '1';
                        break;
                    case 'insecure':
                        $packet['is_vulnerable'] = '1';
                        break;
                    case 'deprecated':
                        $packet['is_deprecated'] = '1';
                        break;
                }
            }

            // Submit the file to the remote server
            $this->log($output, "<comment>Requesting jobs from remote server</comment>");
            $this->log($output);
            $jobs = $scanner->getJobs($packet);
            $count = count($jobs);
            $this->log($output, "Found $count job(s).");
            $this->log($output);

            if ($count)
            {
                $table = $this->getApplication()->getHelperSet()->get('table');
                $table->setHeaders(array('Date', 'Job', 'Status', 'Severity', 'Details'));

                $data = array();

                foreach ($jobs as $job)
                {
                    $entry = array(
                        date('Y-m-d', $job->ts_created),
                        ($job->label ? substr($job->label, 0, 32) : $job->hash)
                    );

                    if ($job->processed)
                    {
                        $warning = array();
                        if ($job->is_deprecated) {
                            $warning[] = 'deprecated';
                        }
                        if ($job->is_vulnerable) {
                            $warning[] = 'vulnerable';
                        }
                        if (!$job->is_vulnerable && !$job->is_deprecated) {
                            $warning[] = 'secure';
                        }

                        $entry[] = implode(', ', $warning);
                        $entry[] = ($job->severity ? $job->severity . '/10' : 'N/A');
                        $entry[] = ($job->match_found+0) . ' bundle(s) found in ' . ($job->files+0) . ' file(s) on ' . $job->server;
                    }
                    else if ($job->pending)
                    {
                        $entry[] = 'pending';
                        $entry[] = 'N/A';
                        $entry[] = 'Please check back later';
                    }
                    else if ($job->processing)
                    {
                        $entry[] = 'processing';
                        $entry[] = 'N/A';
                        $entry[] = 'Result should be available in a few seconds';
                    }
                    else if ($job->failed)
                    {
                        $entry[] = 'failed';
                        $entry[] = 'N/A';
                        $entry[] = 'Job failed to process';
                    }

                    $data[] = $entry;
                }

                $table->setRows($data);
                $table->render($output);
            }
        }

        $this->log($output);
    }
}
