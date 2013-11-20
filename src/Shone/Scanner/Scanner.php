<?php
/**
 * The Shone Security Scanner is used to help a developer determine if the versions of the
 * dependencies he is using are vulnerable to known exploits.
 *
 * @category Shone
 * @package  Scanner
 * @author   Thomas Shone <xsist10@gmail.com>
 */

namespace Shone\Scanner;

use Symfony\Component\Finder\Finder;

use \Curl;
use \Exception;
use \LogicException;
use \RuntimeException;

/**
 * The scanner handles all packaging of data and interation with the remote server
 *
 * @category Shone
 * @package  Scanner
 * @author   Thomas Shone <xsist10@gmail.com>
 */
class Scanner
{
    const VERSION = '@package_version@';
    const RELEASE_DATE = '@release_date@';

    const USER_AGENT = 'Shone PHAR Client';
    const API_ENDPOINT = 'https://www.shone.co.za/';

    /**
     * @var string
     */
    private $key;

    /**
     * @var string
     */
    private $path;

    /**
     * @var string
     */
    private $label;

    /**
     * @var array
     */
    private $common_checksums;

    /**
     * @var bool
     */
    private $ssl_cert_check;

    /**
     * @var \Curl
     */
    private $curl;

    /**
     * Setup our new scanner
     *
     * @return Shone\Scanner\Scanner
     */
    public function __construct()
    {
        $this->path = getcwd();
        $this->common_checksums = array();
    }

    /**
     * Call the remote API with a POST request
     *
     * @param string $page
     * @param array  $arguments
     *
     * @return array
     * @throws Exception
     */
    protected function post($page, array $arguments = array())
    {
        if (!function_exists('curl_init')) {
            throw new RuntimeException('Please install cURL and enable it for PHP.');
        }

        $url = self::API_ENDPOINT . $page;
        $arguments['file_type'] = 'json';
        if ($this->key) {
            $arguments['key'] = $this->key;
        }

        $curl = $this->getCurl();
        $curl->options['verbose'] = false;
        $curl->options['returntransfer'] = true;
        $curl->options['useragent'] = self::USER_AGENT . ' - ' . self::VERSION;
        $curl->options['url'] = $url;
        $curl->options['httpheader'] = array('Accept: application/json');
        $curl->options['postfields'] = $arguments;
        $curl->options['connecttimeout'] = 5;
        $curl->options['timeout'] = 10;
        $curl->options['followlocation'] = 1;
        $curl->options['maxredirs'] = 3;

        if ($this->ssl_cert_check)
        {
            /*
             * Because the cURL library cannot access files in our phar file we need
             * to extract the CA certificate from the phar and tell cURL to use the
             * temporary file instead
             */
            $tmp_file = tmpfile();
            if (!$tmp_file)
            {
                throw new RuntimeException('Unable to create temporary storage for CA certificate. Try run again with --no-cert-check');
            }
            $file_meta = stream_get_meta_data($tmp_file);
            file_put_contents($file_meta['uri'], file_get_contents(__DIR__ . "/../../../res/thawte.pem"));

            $curl->options['ssl_verifypeer'] = 1;
            $curl->options['ssl_verifyhost'] = 2;
            $curl->options['cainfo'] = $file_meta['uri'];
        }
        else
        {
            $curl->options['ssl_verifypeer'] = 0;
            $curl->options['ssl_verifyhost'] = 0;
        }

        $response = $curl->post($url, $arguments);

        // Clear up our temporary certificate
        if ($this->ssl_cert_check)
        {
            fclose($tmp_file);
        }

        // Check our result for unexpected errors
        if ($response->headers['Status-Code'] === 0) {
            throw new RuntimeException('Failed to load CA certificate. Try configuring it in php.ini or run again with --no-cert-check');
        }
        if ($response->headers['Status-Code'] != 200) {
            throw new RuntimeException('Remote server returned an unexpected response: ' . $response->headers['Status-Code']);
        }
        if (!$response->body) {
            throw new RuntimeException('Empty response from the remote server');
        }

        // Attempt to decode the data
        $result = json_decode($response->body);
        if (empty($result)) {
            throw new Exception('Response contained malformed JSON');
        }

        return $result;
    }

    /**
     * Return the curl class to use for making calls
     *
     * @return \Curl
     */
    public function getCurl()
    {
        if (!$this->curl)
        {
            $this->curl = new Curl();
        }
        return $this->curl;
    }

    /**
     * Set the key for the remote API
     *
     * @param string $key The API key to use when making requests
     *
     * @return Shone\Scanner\Scanner
     */
    public function setKey($key)
    {
        $this->key = $key;
        return $this;
    }

    /**
     * Set the label for the job. The label is used to group jobs of the same code base together.
     * It also makes it easier to search in the results for.
     *
     * @param string $label The label of the job
     *
     * @return Shone\Scanner\Scanner
     */
    public function setLabel($label)
    {
        $this->label = $label;
        return $this;
    }

    /**
     * Enable/disable if we want to do a certificate check on the remote server
     *
     * @param bool $ssl_cert_check Enable/disable certificate check
     *
     * @return Shone\Scanner\Scanner
     */
    public function setCertCheck($ssl_cert_check)
    {
        $this->ssl_cert_check = $ssl_cert_check;
        return $this;
    }

    /**
     * Set the path to scan
     *
     * @param string $path The path to scan
     *
     * @return Shone\Scanner\Scanner
     */
    public function setPath($path)
    {
        $this->path = $path;
        return $this;
    }

    /**
     * Scan a folder for files we wish to transmit to the remote server
     *
     * @return Symfony\Component\Finder\Finder
     */
    public function getFiles()
    {
        if (!$this->path) {
            throw new LogicException('Path required');
        }

        $finder = new Finder();
        $finder->files()
            ->ignoreVCS(true)
            ->ignoreUnreadableDirs(true)
            ->name('*')
            ->in($this->path);

        return $finder;
    }

    /**
     * Exclude common checksums that can be ignored. This helps reduce the amount of data passed to
     * the remote server
     *
     * @return bool
     */
    public function excludeCommonChecksums()
    {
        $result = $this->post('job/common_checksums');

        if ($result->Status == 'Success') {
            $this->common_checksums = (array)$result->Hashes;
            return true;
        }

        return false;
    }

    /**
     * Convert found files into a job packet
     *
     * @param Symfony\Component\Finder\Finder $finder          The reference to the found files
     *
     * @return array
     */
    public function buildJobPacket(Finder $finder)
    {
        $job = array();
        $job['job']['version'] = array(
            'value' => self::VERSION
        );

        $job['job']['control'] = array(
          'md5'     => hash('md5', 'control'),
          'sha1'    => hash('sha1', 'control')
        );

        foreach ($finder->files() as $file) {
            $md5 = hash_file('md5', $file);
            $sha1 = hash_file('sha1', $file);

            if (empty($this->common_checksums[$md5]) && empty($this->common_checksums[$sha1])) {
                $job['job']['files']['file'][] = array(
                    'name' => substr($file, strlen($this->path)),
                    'md5'  => $md5,
                    'sha1' => $sha1,
                );
            }
        }

        $packet = array(
            'job'       => json_encode($job),
            'label'     => $this->label,
            'encode'    => 'json'
        );

        return $packet;
    }

    /**
     * Submit a job to the API
     *
     * @param array $packet The preconstructed packet to send to the API
     *
     * @return string
     */
    public function submitJob(array $packet)
    {
        return $this->post('job/submit', $packet);
    }

    /**
     * Construct a job result url from the hash
     *
     * @param string $hash The hash of the job
     *
     * @return string
     */
    public function getJobUrl($hash)
    {
        return self::API_ENDPOINT . 'job/get?hash=' . $hash;
    }
}