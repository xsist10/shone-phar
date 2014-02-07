<?php

namespace Shone\Scanner\Command\Output;

use Shone\Scanner\Command\Output\Output;

class Console extends Output
{
    /**
     * Log our output
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

    public function render($results)
    {
    }
}