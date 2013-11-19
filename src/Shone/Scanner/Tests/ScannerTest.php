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
use Symfony\Component\Finder\Finder;

use \Curl;
use \CurlResponse;

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

    /**
     * @expectedException LogicException
     */
    public function testGetFiles()
    {
        $scanner = new Scanner();

        $scanner->setPath(null);
        $scanner->getFiles();
    }

    public function testJobPostSuccess()
    {
        $response = new CurlResponse(file_get_contents(__DIR__ . '/Fixtures/SuccessJobResult.txt'));

        $curl = $this->getMock('\Curl', array('request'));
        $curl->expects($this->once())
             ->method('request')
             ->will($this->returnValue($response));

        $scanner = $this->getMock('Shone\Scanner\Scanner', array('getCurl'));
        $scanner->expects($this->once())
                ->method('getCurl')
                ->will($this->returnValue($curl));

        $scanner->setKey('invalid');
        $scanner->setCertCheck(true);
        $result = $scanner->submitJob($this->mockPacket());
        $this->assertEquals('Success', $result->Status);
    }

    public function testJobPostFailed()
    {
        $response = new CurlResponse(file_get_contents(__DIR__ . '/Fixtures/FailedJobResult.txt'));

        $curl = $this->getMock('\Curl', array('request'));
        $curl->expects($this->once())
             ->method('request')
             ->will($this->returnValue($response));

        $scanner = $this->getMock('Shone\Scanner\Scanner', array('getCurl'));
        $scanner->expects($this->once())
                ->method('getCurl')
                ->will($this->returnValue($curl));

        $scanner->setKey('invalid');
        $result = $scanner->submitJob($this->mockPacket());
        $this->assertEquals('Failed', $result->Status);
    }

    /**
     * @expectedException RuntimeException
     */
    public function testPostCaFail()
    {
        $response = new CurlResponse('');
        $response->headers['Status-Code'] = 0;

        $curl = $this->getMock('\Curl', array('request'));
        $curl->expects($this->once())
             ->method('request')
             ->will($this->returnValue($response));

        $scanner = $this->getMock('Shone\Scanner\Scanner', array('getCurl'));
        $scanner->expects($this->once())
                ->method('getCurl')
                ->will($this->returnValue($curl));

        $result = $scanner->submitJob($this->mockPacket());
    }

    /**
     * @expectedException RuntimeException
     */
    public function testPostStatusFail()
    {
        $response = new CurlResponse('');
        $response->headers['Status-Code'] = 10;

        $curl = $this->getMock('\Curl', array('request'));
        $curl->expects($this->once())
             ->method('request')
             ->will($this->returnValue($response));

        $scanner = $this->getMock('Shone\Scanner\Scanner', array('getCurl'));
        $scanner->expects($this->once())
                ->method('getCurl')
                ->will($this->returnValue($curl));

        $result = $scanner->submitJob($this->mockPacket());
    }

    /**
     * @expectedException RuntimeException
     */
    public function testPostContentFail()
    {
        $response = new CurlResponse('');
        $response->headers['Status-Code'] = 200;

        $curl = $this->getMock('\Curl', array('request'));
        $curl->expects($this->once())
             ->method('request')
             ->will($this->returnValue($response));

        $scanner = $this->getMock('Shone\Scanner\Scanner', array('getCurl'));
        $scanner->expects($this->once())
                ->method('getCurl')
                ->will($this->returnValue($curl));

        $result = $scanner->submitJob($this->mockPacket());
    }

    public function testExcludeCommonChecksumsSuccess()
    {
        $result = json_decode(json_encode(array('Status' => 'Success', 'Hashes' => array())));
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
        $this->assertInstanceOf('\Curl', $scanner->getCurl());
    }

    public function testExcludeCommonChecksumsFailed()
    {
        $result = json_decode(json_encode(array('Status' => 'Failed')));
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
            ->will($this->returnValue(json_decode($json)));

        $result = $scanner->submitJob(array());
        $this->assertEquals('Success', $result->Status);
    }

    public function testJobUrl()
    {
        $scanner = new Scanner();
        $this->assertEquals(Scanner::API_ENDPOINT . 'job/get?hash=a', $scanner->getJobUrl('a'));
    }

    public function testJobPacket()
    {
        $scanner = new Scanner();
        $scanner->setPath(__DIR__);
        $packet = $scanner->buildJobPacket($scanner->getFiles());

        $this->assertNotEmpty($packet);
        // Check that this file is in the list
        $packet = json_decode($packet['job']);
        $found = false;
        foreach ($packet->job->files->file as $file)
        {
            $found |= strpos(__FILE__, ltrim($file->name, '/')) !== false;
        }
        $this->assertTrue((bool)$found);
    }
}
