<?php

namespace Shone\Scanner\Command\Output;

use Symfony\Component\Console\Output\OutputInterface;

abstract class Output
{
    /**
     * Output object
     * @var \Symfony\Component\Console\Output\OutputInterface
     */
    private $output;

    /**
     * Output options
     * @var array
     */
    private $options;

    /**
     * Create our new output
     *
     * @param \Symfony\Component\Console\Output\OutputInterface $output Output object
     * @param array $options Output options
     */
    public function __construct(OutputInterface $output, $options = array())
    {
        $this->setOutput($output);
        $this->setOptions($options);
    }

    /**
     * Set the Output object instance
     *
     * @param \Symfony\Component\Console\Output\OutputInterface $output Object instance
     */
    public function setOutput(OutputInterface $output)
    {
        $this->output = $output;
    }

    /**
     * Get the Output instance
     *
     * @return object Output instance
     */
    public function getOutput()
    {
        return $this->output;
    }

    /**
     * Set the output options
     *
     * @param array $options Set of options
     */
    public function setOptions($options)
    {
        $this->options = $options;
    }

    /**
     * Get the current set of options
     *
     * @return array Options set
     */
    public function getOptions()
    {
        return $this->options;
    }

    /**
     * Log our output
     *
     * @param Symfony\Component\Console\Input\InputInterface   $input  Input source
     * @param Symfony\Component\Console\Output\OutputInterface $output Output source
     * @param boolean                                          $force  Regardless of verbose level, output this
     *
     * @return void
     */
    protected abstract function log(OutputInterface $output, $message = '', $force = false)

    /**
     * Render the results of the scan
     *
     * @param array $results Set of scan results
     * @return [type]          [description]
     */
    public abstract function render($results);
}