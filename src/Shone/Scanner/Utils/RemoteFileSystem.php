<?php
/**
 * The Shone Security Scanner is used to help a developer determine if the versions of the
 * dependencies he is using are vulnerable to known exploits.
 *
 * @category Shone
 * @package  Scanner
 * @author   Thomas Shone <xsist10@gmail.com>
 */

namespace Shone\Scanner\Utils;

use \UnexpectedValueException;
use \PharException;
use \Exception;

/**
 * The Compiler class compiles shone into a phar
 *
 * @author Thomas Shone <thomas@shone.co.za>
 */
class RemoteFileSystem
{
    public function __construct()
    {
        if (!ini_get('allow_url_fopen')) {
            throw new Exception('allow_url_fopen must be enabled in php.ini');
        }
    }

    public function getProtocol()
    {
        return extension_loaded('openssl') ? 'https' : 'http';
    }

    public function getFile($remoteFile)
    {
        return trim(file_get_contents($this->getProtocol() . '://' . $remoteFile));
    }

    public function copyPhar($remoteFile, $localFile)
    {
        $tempFilename = dirname($localFile) . '/' . basename($localFile, '.phar').'-temp.phar';
        $remoteUrl = $this->getProtocol() . '://' . $remoteFile;

        if (!file_exists($remoteUrl)) {
            throw new Exception('The remote file is not accessible');
        }

        copy($remoteUrl, $tempFilename);

        if (!file_exists($tempFilename)) {
            throw new Exception('The download failed for an unexpected reason');
        }

        try {
            @chmod($tempFilename, 0777 & ~umask());
            // test the phar validity
            $phar = new \Phar($tempFilename);
            // free the variable to unlock the file
            unset($phar);
            rename($tempFilename, $localFile);
        } catch (Exception $e) {
            @unlink($tempFilename);
            if (!$e instanceof UnexpectedValueException && !$e instanceof PharException) {
                throw $e;
            }
            throw new Exception('The download is corrupted ('.$e->getMessage().')');
        }

        return true;
    }
}