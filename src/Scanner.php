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

use League\Flysystem\Filesystem;
use Guzzle\Http\Client;

use \Exception;
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
    const VERSION = '1.1.4';
    const RELEASE_DATE = '@release_date@';

    const USER_AGENT = 'Shone PHAR Client';
    const API_ENDPOINT = 'https://www.shone.co.za/';
    const CA_FILE = 'vendor/guzzle/guzzle/src/Guzzle/Http/Resources/cacert.pem';

    const MAX_FILE_SIZE = 2097152; // 2MB

    const ERROR_CA_TEMP = 'Unable to create temporary storage for CA certificate. Try run again with --no-cert-check';
    const ERROR_CA_LOAD = 'Failed to load CA certificate. Configure your php.ini or run again with --no-cert-check';
    const ERROR_RESULT_EMPTY  = 'Response contained empty response or malformed JSON';
    const ERROR_RESULT_UNKNOWN = 'Remote server returned an unexpected response';

    /**
     * @var string
     */
    private $key;

    /**
     * @var string
     */
    private $label;

    /**
     * @var array
     */
    private $common_checksums;

    /**
     * @var array
     */
    private $ignore_ext;

    /**
     * @var bool
     */
    private $ssl_cert_check;

    /**
     * @var Guzzle\Http\Client
     */
    private $http_client;

    /**
     * Setup our new scanner
     *
     * @return Shone\Scanner\Scanner
     */
    public function __construct()
    {
        $this->common_checksums = array();
        $this->ignore_ext = array();
    }

    /**
     * Get the user-agent to pass for the scanner
     *
     * @return string
     */
    protected function getUserAgent()
    {
        return self::USER_AGENT . ' - ' . self::VERSION;
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
        if ($this->key) {
            $arguments['key'] = $this->key;
        }
        $arguments['encode'] = 'json';

        $headers = array(
            'Accept-Encoding' => 'application/json'
        );

        // Work around for Guzzle not clearing out old cacert files
        $cert_file = sys_get_temp_dir() . '/guzzle-cacert.pem';
        // @codeCoverageIgnoreStart
        if (is_file($cert_file) && is_writable($cert_file)) {
            unlink($cert_file);
        }
        // @codeCoverageIgnoreEnd

        $client = $this->getHttpClient();
        $client->setBaseUrl(self::API_ENDPOINT);
        $client->setUserAgent($this->getUserAgent());
        if (!$this->ssl_cert_check) {
            $client->setSslVerification(false);
        }

        $request = $client->post(
            $page,
            $headers,
            $arguments
        );

        // You must send a request in order for the transfer to occur
        $response = $request->send();

        // Check our result for unexpected errors
        $status_code = $response->getStatusCode();
        if ($status_code == 0) {
            throw new RuntimeException(self::ERROR_CA_LOAD);
        }
        if ($status_code != 200) {
            throw new RuntimeException(self::ERROR_RESULT_UNKNOWN . ': ' . $status_code);
        }

        // Attempt to grab json data
        $json = $response->json();
        if (!$json) {
            throw new RuntimeException(self::ERROR_RESULT_EMPTY);
        }

        return $json;
    }

    /**
     * Return the curl class to use for making calls
     *
     * @return Guzzle\Http\Client
     */
    public function getHttpClient()
    {
        if (!$this->http_client) {
            $this->http_client = new Client();
        }
        return $this->http_client;
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
     * Exclude common checksums that can be ignored. This helps reduce the amount of data passed to
     * the remote server
     *
     * @return bool
     */
    public function excludeCommonChecksums()
    {
        $result = $this->post('job/common_checksums');

        if ($result['Status'] == 'Success') {
            $this->common_checksums = (array)$result['Hashes'];
            return true;
        }

        return false;
    }

    /**
     * Set the list of file extensions to ignore in the scan
     *
     * @param array $ignore_ext The extensions to ignore (not preceeding '.')
     *
     * @return Shone\Scanner\Scanner
     */
    public function setIgnoreExtensions(array $ignore_ext)
    {
        $this->ignore_ext = $ignore_ext;

        return $this;
    }

    /**
     * Build a list of files to process from the filesystem provided
     *
     * @param League\Flysystem\Filesystem $filesystem The filesystem to use
     * @param string                                  The path inside the filesystem to list
     *
     * @return array
     */
    public function buildFileList(Filesystem $filesystem, $path = '')
    {
        $files = array();
        foreach ($filesystem->listContents($path) as $item) {
            if ($item['type'] == 'dir') {
                if ($item['basename'] != '.git' && $item['basename'] != '.svn') {
                    $files = array_merge($files, $this->buildFileList($filesystem, $item['path']));
                }
            } elseif ($item['type'] == 'file') {
                if (empty($item['extension']) || !in_array($item['extension'], $this->ignore_ext)) {
                    $files[] = $item['path'];
                }
            }
        }
        return $files;
    }

    /**
     * Steam file content into a hashing mechanism
     *
     * @param Symfony\Component\Finder\Finder $finder The reference to the found files
     * @param string                          $file   File to fingerprint
     *
     * @return array
     */
    protected function buildFileFingerprint(Filesystem $filesystem, $file)
    {
        try
        {
            // If the file is over a certain size, ignore it. This
            // prevents large downloads from remote Filesystems.
            if ((int)@$filesystem->getSize($file) > self::MAX_FILE_SIZE) {
                return null;
            }

            // Sometimes the file system throws warnings or the
            // user only has listing permissions on a file and not
            // read permissions.
            $stream = $filesystem->readStream($file);
            if (!is_resource($stream)) {
                return null;
            }

            $context = hash_init('md5');
            hash_update_stream($context, $stream);
            $md5 = hash_final($context);

            // Close the resource to release the handle
            fclose($stream);

            if (!empty($this->common_checksums[$md5])) {
                return null;
            }

            return array(
                'name' => $file,
                'sha1' => '',
                'md5'  => $md5,
            );
        }
        catch (RuntimeException $exception)
        {
            // We had a problem examining the file. It might be because
            // the file no longer exists or we don't have permission to read it
            return null;
        }
    }

    /**
     * Convert found files into a job packet
     *
     * @param Symfony\Component\Finder\Finder $finder The reference to the found files
     * @param array                           $files  List of files to fingerprint
     *
     * @return array
     */
    public function buildJobPacket(Filesystem $filesystem, array $files)
    {
        $job = array();
        $job['job']['version'] = array(
            'value' => self::VERSION
        );

        $job['job']['control'] = array(
            'md5'  => hash('md5', 'control'),
            'sha1' => hash('sha1', 'control')
        );

        foreach ($files as $file) {
            $fingerprint = $this->buildFileFingerprint($filesystem, $file);
            if (!empty($fingerprint))
            {
                $job['job']['files']['file'][] = $fingerprint;
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
        $packet['file_type'] = 'json';
        return $this->post('job/submit', $packet);
    }

    /**
     * Fingerprint a file
     *
     * @param string $file The file to fingerprint
     *
     * @return array
     */
    public function fingerprintFile($file)
    {
        $packet = array(
            'md5'  => hash_file('md5', $file),
            'sha1' => hash_file('sha1', $file),
        );
        return $this->post('file/fingerprint', $packet);
    }

    /**
     * Get job list
     *
     * @param array $param Parameters to filter the jobs on
     *
     * @return array
     */
    public function getJobs(array $param = array())
    {
        return $this->post('job/view', $param);
    }

    /**
     * Get job
     *
     * @param string $hash The hash of the job to retrieve
     *
     * @return array
     */
    public function getJob($hash)
    {
        return $this->post('job/get', array('hash' => $hash));
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
