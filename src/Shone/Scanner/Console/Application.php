<?php
/**
 * The Shone Security Scanner is used to help a developer determine if the versions of the
 * dependencies he is using are vulnerable to known exploits.
 *
 * @category Shone
 * @package  Scanner
 * @author   Thomas Shone <xsist10@gmail.com>
 */

namespace Shone\Scanner\Console;

use Symfony\Component\Console\Application as BaseApplication;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Output\ConsoleOutput;
use Symfony\Component\Console\Formatter\OutputFormatter;
use Symfony\Component\Console\Formatter\OutputFormatterStyle;

use Shone\Scanner\Command;
use Shone\Scanner\Config;
use Shone\Scanner\Scanner;

/**
 * The application to handle the console commands
 *
 * This file was heavily influenced by the Composer project (https://github.com/composer/composer)
 *
 * @category Shone
 * @package  Scanner\Console
 * @author   Thomas Shone <xsist10@gmail.com>
 */
class Application extends BaseApplication
{
    /**
     * @var string
     */
    private static $logo = '
   _____ __                        _____                      _ __
  / ___// /_  ____  ____  ___     / ___/___  _______  _______(_) /___  __
  \__ \/ __ \/ __ \/ __ \/ _ \    \__ \/ _ \/ ___/ / / / ___/ / __/ / / /
 ___/ / / / / /_/ / / / /  __/   ___/ /  __/ /__/ /_/ / /  / / /_/ /_/ /
/____/_/ /_/\____/_/ /_/\___/   /____/\___/\___/\__,_/_/  /_/\__/\__, /
                                                                /____/
';

    /**
     * @var Shone\Scanner\Scanner
     */
    protected $scanner;

    /**
     * @var Shone\Scanner\Config
     */
    protected $config;

    /**
     * Construct our application. Disable/enable/set core settings
     *
     * @return Shone\Scanner\Console\Application
     */
    public function __construct()
    {
        // We don't want to see xdebug output
        if (function_exists('ini_set')) {
            ini_set('xdebug.show_exception_trace', false);
            ini_set('xdebug.scream', false);

        }
        // Setup default timezone so we don't get bugged about it
        if (function_exists('date_default_timezone_set') && function_exists('date_default_timezone_get')) {
            date_default_timezone_set(@date_default_timezone_get());
        }

        parent::__construct('Shone Security Scanner', Scanner::VERSION);
    }

    /**
     * {@inheritDoc}
     */
    public function run(InputInterface $input = null, OutputInterface $output = null)
    {
        if ($output === null) {
            $styles = array(
                'highlight' => new OutputFormatterStyle('red'),
                'warning' => new OutputFormatterStyle('black', 'yellow'),
            );
            $formatter = new OutputFormatter(null, $styles);
            $output = new ConsoleOutput(ConsoleOutput::VERBOSITY_NORMAL, null, $formatter);
        }

        return parent::run($input, $output);
    }

    /**
     * {@inheritDoc}
     */
    public function doRun(InputInterface $input, OutputInterface $output)
    {
        if (version_compare(PHP_VERSION, '5.3.2', '<')) {
            $output->writeln(
                '<warning>Shone Security Scanner only officially supports PHP 5.3.2 and above, you '
                . 'will most likely encounter problems with your PHP ' . PHP_VERSION . ', upgrading '
                . 'is strongly recommended.</warning>'
            );
        }

        $command = $this->getCommandName($input);
        if (defined('WARNING_TIME') && $command !== 'self-update' && $command !== 'selfupdate') {
            if (time() > WARNING_TIME) {
                $output->writeln('<warning>Warning: This version of Shone Security Scanner is over 30 days old.</warning>');
                $output->writeln(sprintf('It is recommended to update it by running "%s self-update" to get the latest version.</warning>', $_SERVER['PHP_SELF']));
            }
        }

        return parent::doRun($input, $output);
    }

    /**
     * Get our default configurations for our scanner
     *
     * @return \Shone\Scanner\Config
     */
    public function getConfig()
    {
        if ($this->config === null) {
            $this->config = new Config();
        }

        return $this->config;
    }

    /**
     * Get our scanner class
     *
     * @return \Shone\Scanner\Scanner
     */
    public function getScanner()
    {
        if ($this->scanner == null) {
            $this->scanner = new Scanner();
        }

        return $this->scanner;
    }

    /**
     * Return our help message with logo attached
     *
     * @return string
     */
    public function getHelp()
    {
        return self::$logo . parent::getHelp();
    }

    /**
     * Initializes all the composer commands
     *
     * @return array
     */
    protected function getDefaultCommands()
    {
        $commands = parent::getDefaultCommands();
        $commands[] = new Command\AboutCommand();
        $commands[] = new Command\ScanCommand();

        if ('phar:' === substr(__FILE__, 0, 5)) {
            $commands[] = new Command\SelfUpdateCommand();
        }

        return $commands;
    }

    /**
     * {@inheritDoc}
     */
    public function getLongVersion()
    {
        return parent::getLongVersion() . ' ' . Scanner::RELEASE_DATE;
    }
}
