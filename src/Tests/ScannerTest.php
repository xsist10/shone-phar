<?php
/**
 * The Shone Security Scanner is used to help a developer determine if the versions of the
 * dependencies he is using are vulnerable to known exploits.
 *
 * @category Shone
 * @package  Scanner
 * @author   Thomas Shone <xsist10@gmail.com>
 */

namespace Shone\Scanner\Tests;

use Shone\Scanner\Scanner;

use League\Flysystem\Filesystem;
use League\Flysystem\Adapter\Local;

use Guzzle\Http\Client;
use Guzzle\Http\Message\Request;
use Guzzle\Http\Message\Response;

use \ReflectionProperty;

class ScannerTest extends \PHPUnit_Framework_TestCase
{
    private function mockPacket()
    {
        $job = array();
        $job['job']['version'] = array(
            'value' => '1.0'
        );

        $job['job']['control'] = array(
          'md5'     => hash('md5', 'control'),
          'sha1'    => hash('sha1', 'control')
        );

        $job['job']['files']['file'][] = array(
            'name' => 'test',
            'md5'  => hash('md5', 'test'),
            'sha1' => hash('sha1', 'test'),
        );

        $packet = array(
            'job'       => json_encode($job),
            'label'     => 'test',
            'encode'    => 'json'
        );

        return $packet;
    }

    private function _getScannerResult($status_code, $body)
    {
        // Build response object
        $response = $this->getMockBuilder('Guzzle\Http\Message\Response', array('getStatusCode', 'json'))
            ->disableOriginalConstructor()
            ->getMock();

        $response->expects($this->once())
            ->method('getStatusCode')
            ->will($this->returnValue($status_code));

        $response->expects($this->any())
            ->method('json')
            ->will($this->returnValue(json_decode($body, true)));

        // Build request object
        $request = $this->getMockBuilder('Guzzle\Http\Message\Request', array('send'))
            ->disableOriginalConstructor()
            ->getMock();

        $request->expects($this->once())
            ->method('send')
            ->will($this->returnValue($response));

        // Build our Guzzle client
        $client = $this->getMock('Guzzle\Http\Client', array('post', 'setBaseUrl', 'setSslVerification', 'setUserAgent'));
        $client->expects($this->once())
            ->method('post')
            ->will($this->returnValue($request));

        // Mock out our scanners client function so we can mock it out
        $scanner = $this->getMock('Shone\Scanner\Scanner', array('getHttpClient'));
        $scanner->expects($this->once())
            ->method('getHttpClient')
            ->will($this->returnValue($client));

        return $scanner;
    }

    public function testJobPostSuccess()
    {
        $scanner = $this->_getScannerResult(200, '{"Status":"Success","Hash":"48b0f534a391dfa38b023905381452bb","Detail":"38KB of usage remaining for the month."}');

        $scanner->setKey('invalid');
        $scanner->setCertCheck(true);
        $result = $scanner->submitJob($this->mockPacket());
        $this->assertEquals('Success', $result['Status']);
    }

    public function testJobPostFailed()
    {
        $scanner = $this->_getScannerResult(200, '{"Status":"Failed","Detail":"Failed to create job: Exceeded limit by 3KB. Only 38KB remaining"}');

        $scanner->setKey('invalid');
        $result = $scanner->submitJob($this->mockPacket());
        $this->assertEquals('Failed', $result['Status']);
    }

    /**
     * @expectedException RuntimeException
     */
    public function testPostCaFail()
    {
        $scanner = $this->_getScannerResult(0, '');

        $result = $scanner->submitJob($this->mockPacket());
    }

    /**
     * @expectedException RuntimeException
     */
    public function testPostStatusFail()
    {
        $scanner = $this->_getScannerResult(10, '');

        $result = $scanner->submitJob($this->mockPacket());
    }

    /**
     * @expectedException RuntimeException
     */
    public function testPostContentFail()
    {
        $scanner = $this->_getScannerResult(200, '');

        $result = $scanner->submitJob($this->mockPacket());
    }

    public function testExcludeCommonChecksumsSuccess()
    {
        $result = array('Status' => 'Success', 'Hashes' => array());
        $scanner = $this->getMock('Shone\Scanner\Scanner', array('post'));
        $scanner->expects($this->once())
                ->method('post')
                ->with($this->equalTo('job/common_checksums'))
                ->will($this->returnValue($result));

        $this->assertTrue($scanner->excludeCommonChecksums());
    }

    public function testGetCurl()
    {
        $scanner = new Scanner();
        $this->assertInstanceOf('Guzzle\Http\Client', $scanner->getHttpClient());
    }

    public function testExcludeCommonChecksumsFailed()
    {
        $result = array('Status' => 'Failed');
        $scanner = $this->getMock('Shone\Scanner\Scanner', array('post'));
        $scanner->expects($this->once())
                ->method('post')
                ->with($this->equalTo('job/common_checksums'))
                ->will($this->returnValue($result));

        $this->assertFalse($scanner->excludeCommonChecksums());
    }

    public function testSubmitJob()
    {
        $json = '{"Status":"Success","Hash":"e950eb2d35asa51e2bb59621add300e3","Detail":"303KB of usage remaining for the month."}';

        $scanner = $this->getMock('Shone\Scanner\Scanner', array('post'));
        $scanner->expects($this->once())
            ->method('post')
            ->will($this->returnValue(json_decode($json, true)));

        $result = $scanner->submitJob(array());
        $this->assertEquals('Success', $result['Status']);
    }

    public function testJobUrl()
    {
        $scanner = new Scanner();
        $this->assertEquals(Scanner::API_ENDPOINT . 'job/get?hash=a', $scanner->getJobUrl('a'));
    }

    public function testJobPacket()
    {
        $scanner = new Scanner();
        $filesystem = new Filesystem(new Local(__DIR__));

        $property = new ReflectionProperty('Shone\Scanner\Scanner', 'common_checksums');
        $property->setAccessible(true);
        $property->setValue($scanner, array('d41d8cd98f00b204e9800998ecf8427e' => true));

        $files = $scanner->buildFileList($filesystem, '', array('txt'));
        $files[] = "non_existant_file";

        $packet = $scanner->buildJobPacket($filesystem, $files);

        $this->assertNotEmpty($packet);
        // Check that this file is in the list
        $packet = json_decode($packet['job'], true);
        $found = false;
        foreach ($packet['job']['files']['file'] as $file) {
            $found |= strpos(__FILE__, ltrim($file['name'], '/')) !== false;
        }
        $this->assertTrue((bool)$found);
    }

    public function testJobPacketLargeFile()
    {
        $scanner = new Scanner();

        $filesystem = $this->getMockBuilder('League\Flysystem\Filesystem', array('getSize'))
                     ->disableOriginalConstructor()
                     ->getMock();
        // Make sure the files returned are too large to scan
        $filesystem->expects($this->once())
            ->method('getSize')
            ->will($this->returnValue(4*1024*1024));

        // Only use this one file
        $files = array(__FILE__);
        $packet = $scanner->buildJobPacket($filesystem, $files);

        // Check that we don't have any files listed
        $this->assertNotEmpty($packet);
        $packet = json_decode($packet['job'], true);
        $this->assertTrue(empty($packet['job']['files']));
    }

    public function testJobPacketInvalidFile()
    {
        $scanner = new Scanner();

        $filesystem = $this->getMockBuilder('League\Flysystem\Filesystem', array('getSize'))
                     ->disableOriginalConstructor()
                     ->getMock();
        // Mock this out so it passes this step
        $filesystem->expects($this->once())
            ->method('getSize')
            ->will($this->returnValue(10));

        // Only use this one file
        $files = array(__FILE__);
        $packet = $scanner->buildJobPacket($filesystem, $files);

        // Check that we don't have any files listed
        $this->assertNotEmpty($packet);
        $packet = json_decode($packet['job'], true);
        $this->assertTrue(empty($packet['job']['files']));
    }

    public function testFingerprintFile()
    {
        $json = '{"Status":"Success","Detail":"No match found"}';

        $scanner = $this->getMock('Shone\Scanner\Scanner', array('post'));
        $scanner->expects($this->once())
            ->method('post')
            ->will($this->returnValue(json_decode($json, true)));

        $result = $scanner->fingerprintFile(__FILE__);
        $this->assertEquals('Success', $result['Status']);
    }

    public function testJobsView()
    {
        $json = '[{"job_id":"1","hash":"abc123","label":"test","ip_address":"127.0.0.1","server":"127.0.0.1","ts_created":"1234567890","ts_completed":"1234567899","username":"bob.smith","pending":"0","processing":"0","processed":"1","failed":"0","software":"2","software_found":"Joomla!,Wordpress","match_found":"2","severity":"0","is_deprecated":"0","files":"7315","is_vulnerable":"0","status":"Completed"}]';

        $scanner = $this->getMock('Shone\Scanner\Scanner', array('post'));
        $scanner->expects($this->once())
            ->method('post')
            ->will($this->returnValue(json_decode($json, true)));

        $result = $scanner->getJobs();
        $this->assertEquals('Completed', $result[0]['status']);
        $this->assertEquals('abc123', $result[0]['hash']);
    }

    public function testJobView()
    {
        $json = '{"result":{"\/":{"6470":{"download_id":"6470","path":"\/","name":"Joomla!","version_id":"4475","version":"2.5.10","match":"96.00%","is_vulnerable":"1","software_id":"4","is_deprecated":"0","favicon":"http:\/\/www.joomla.org\/favicon.ico","risk":"10"},"6570":{"download_id":"6570","path":"\/","name":"Joomla!","version_id":"4631","version":"2.5.13","match":"94.00%","is_vulnerable":"1","software_id":"4","is_deprecated":"1","favicon":"http:\/\/www.joomla.org\/favicon.ico","risk":"10"}},"\/media\/editors\/tinymce\/jscripts\/tiny_mce":{"4798":{"download_id":"4798","path":"\/media\/editors\/tinymce\/jscripts\/tiny_mce","name":"tinymce","version_id":"3511","version":"3.5.2","match":"10.00%","is_vulnerable":"0","software_id":"17","is_deprecated":"0","favicon":"http:\/\/tinymce.moxiecode.com\/favicon.ico","risk":0}}}}';

        $scanner = $this->getMock('Shone\Scanner\Scanner', array('post'));
        $scanner->expects($this->once())
            ->method('post')
            ->will($this->returnValue(json_decode($json, true)));

        $response = $scanner->getJob('a');
        $result = $response['result']['/'];
        $result = array_shift($result);
        $this->assertEquals('/', $result['path']);
        $this->assertEquals('Joomla!', $result['name']);
        $this->assertEquals('2.5.10', $result['version']);
        $this->assertEquals('96.00%', $result['match']);
    }
}
