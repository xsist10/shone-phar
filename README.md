shone-phar
=======

[![Build Status](https://travis-ci.org/xsist10/shone-phar.png?branch=master)](https://travis-ci.org/xsist10/shone-phar)
[![SensioLabsInsight](https://insight.sensiolabs.com/projects/8c5b02de-3d46-489e-b9aa-d181d011635c/mini.png)](https://insight.sensiolabs.com/projects/8c5b02de-3d46-489e-b9aa-d181d011635c)
[![Coverage Status](https://coveralls.io/repos/xsist10/shone-phar/badge.png)](https://coveralls.io/r/xsist10/shone-phar)
[![Latest Stable Version](https://poser.pugx.org/shone/scanner/version.png)](https://packagist.org/packages/shone/scanner)
[![License](https://poser.pugx.org/shone/scanner/license.png)](https://packagist.org/packages/shone/scanner)

A command-line tool for interacting with the Shone Web Scanner API.

Getting started
-----

**To perform scans you will need to create a free account on https://www.shone.co.za/**

***To get an API Key, log into your account and go to the API tab (https://www.shone.co.za/client/api)***

The easiest way is to just download the phar file and get started

    $ wget raw.github.com/xsist10/shone-phar/master/shone.phar && chmod +x shone.phar

Alternatively you can use [composer](http://www.getcomposer.org)

    {
        "require": {
            "shone/scanner": "1.0.*@dev"
        }
    }

To install the phar globally, do the following:

    $ mv shone.phar /usr/local/bin/shone


Updating the phar
-----
If you are using the `shone.phar` file, you can update it to the latest version by running the following command:

    $ ./shone.phar self-update


Setting up your configuration
-----

There are some basic settings that make it easier to use the tool. It's recommended to set your API key at the start (the configuration file will be stored in your home folder ~/shone.json or similar location).

    # Set the API key so you don't need to declare it everywhere
    $ ./shone.phar set-config --key "[API KEY]"

    # This is not recommended
    $ ./shone.phar set-config  --common-checksum=0 --no-cert-check=1


Using the scanner
-----

**Local file system**

You can scan a web directory like this

    $ ./shone.phar scan --key "[API KEY]" --label "Website Label" /path/to/web/folder

or if you prefer to use the code directly (remember to run `composer update` first)

    $ ./bin/shone scan --key "[API KEY]" --label "Website Label" /path/to/web/folder

If everything went ok you should be provided with a URL to find the result of your scan


**Finger a local file**

You can find out what software package a file belongs to by running the fingerprint command:

    $ ./shone.phar fingerprint --key "[API KEY]" /path/to/file


Expected result:

    Result: 11 matches found
    +----------+-----------+------------+
    | Software | Version   | Status     |
    +----------+-----------+------------+
    | Joomla!  | 2.5.9     | Vulnerable |
    | Joomla!  | 2.5.9     | Vulnerable |
    | Joomla!  | 2.5.11    | Vulnerable |
    | Joomla!  | 2.5.10    | Vulnerable |
    | Joomla!  | 2.5.12    | Vulnerable |
    | Joomla!  | 2.5.14    | Vulnerable |
    | Joomla!  | 2.5.13    | Vulnerable |
    | Joomla!  | 2.5.16    | Secure     |
    | Joomla!  | 2.5.15    | Secure     |
    | Joomla!  | 2.5.17.rc | Secure     |
    | Joomla!  | 2.5.17    | Secure     |
    +----------+-----------+------------+



**Remote file system**

You can scan a remote web directory via FTP like this:

    $ ./shone.phar ftpscan --username [USERNAME] --password --key="[API KEY]" --label "Website Label" [FTP HOST] /path/to/web/folder

There are a number of additional FTP options which will be listed if you run:

    $ ./shone.phar ftpscan --help


Getting results
-----

**Get one job result**

When you submit a job to the API, you will get a URL that will link directly to your scan result. You can also use the hash value to pull the result via the API like this:

    $ ./shone.phar job --hash="[HASH]"


Expected result:

    Found 2 results.

    Path: /
    +----------+---------+------------+-------+--------+
    | Software | Version | Status     | Risk  | Match  |
    +----------+---------+------------+-------+--------+
    | Joomla!  | 2.5.10  | vulnerable | 10/10 | 97.00% |
    | Joomla!  | 2.5.11  | vulnerable | 10/10 | 96.00% |
    | Joomla!  | 2.5.12  | vulnerable | 10/10 | 94.00% |
    | Joomla!  | 2.5.13  | vulnerable | 10/10 | 94.00% |
    | Joomla!  | 2.5.14  | vulnerable | 7/10  | 94.00% |
    +----------+---------+------------+-------+--------+

    Path: media/editors/tinymce/jscripts/tiny_mce
    +----------+---------+--------+------+--------+
    | Software | Version | Status | Risk | Match  |
    +----------+---------+--------+------+--------+
    | tinymce  | 3.5.2   | secure | N/A  | 10.00% |
    | tinymce  | 3.5.3   | secure | N/A  | 10.00% |
    | tinymce  | 3.5.4   | secure | N/A  | 10.00% |
    | tinymce  | 3.5.4.1 | secure | N/A  | 10.00% |
    | tinymce  | 3.5.3.1 | secure | N/A  | 10.00% |
    +----------+---------+--------+------+--------+


**Get recent jobs**

You can pull the jobs for the month by calling this:

    $ ./shone.phar job --key="[API KEY]"


Expected result:

    Found 1 job(s).

    +------------+----------------------------------+------------+----------+------------------------------------------------------+
    | Date       | Job                              | Status     | Severity | Details                                              |
    +------------+----------------------------------+------------+----------+------------------------------------------------------+
    | 2014-04-13 | 14dd8544av1f6f2ea1d55319625f7744 | vulnerable | 10/10    | 2 bundle(s) found in 4444 file(s) on xxx.xxx.xxx.xxx |
    +------------+----------------------------------+------------+----------+------------------------------------------------------+


You can search for the latest scan for a particular label by using the label flag

    $ ./shone.phar job --key="[API KEY]" --label="Website Label"



Compiling the phar
-----
You'll can recompile the phar by calling:

    $ ./bin/compile && chmod +x shone.phar

You can then copy the phar to any server or directory you wish and use it as a stand-alone executable.


More information
-----

For more information run:

    $ ./shone.phar


Using the library directly
-----

If you wish to write your own code to use the Shone API, you can use the library directly like this:


```php

use Shone\Scanner\Scanner;
use League\Flysystem\Filesystem;
use League\Flysystem\Adapter\Local;

$scanner = new Scanner();

// Set your API key
$scanner->setKey([API KEY]);

// Enable SSL certificate checking
$scanner->setCertCheck(true);

// Set the label of the job you want to submit or search for
$scanner->setLabel("Website Label");

// You can build a list of files anyway you want like:
// $files = array('/path/to/file1', '/path/to/file2');
// I find the easiest way is like this:
$filesystem = new Filesystem(new Local("path/to/scan"));
$files = $scanner->buildFileList($filesystem);

// Build our packet to send to the API
$packet = $scanner->buildJobPacket($filesystem, $files);

// Send the packet to the framework
$result = $scanner->submitJob($packet);

if ($result['Status'] != 'Success') {
    // Something went wrong
    throw new \Exception($result['Detail']);
} else {
    $hash = $result['Hash'];
}

// Wait a little while and attempt to get the result (might take a few seconds to process)
$max_retry = 5;
$attempt = 1;
while ($attempt < $max_retry)
{
    sleep(2);
    $job = $scanner->getJob($hash);
    if (empty($job['status']) || $job['status'] != 'In progress')
    {
        break;
    }
    $attempt++;
}

// The job result:
print_r($job);

```


Contributing
----

Please see [CONTRIBUTING](https://github.com/xsist10/shone-phar/blob/master/CONTRIBUTING.md) for details.


[![Bitdeli Badge](https://d2weczhvl823v0.cloudfront.net/xsist10/shone-phar/trend.png)](https://bitdeli.com/free "Bitdeli Badge")
