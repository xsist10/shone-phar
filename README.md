shone-phar
=======

[![Build Status](https://travis-ci.org/xsist10/shone-phar.png?branch=master)](https://travis-ci.org/xsist10/shone-phar)
[![Coverage Status](https://coveralls.io/repos/xsist10/shone-phar/badge.png)](https://coveralls.io/r/xsist10/shone-phar)
[![Latest Stable Version](https://poser.pugx.org/shone/scanner/version.png)](https://packagist.org/packages/shone/scanner)
[![License](https://poser.pugx.org/shone/scanner/license.png)](https://packagist.org/packages/shone/scanner)

A command-line tool for interacting with the Shone Web Scanner API.

Getting started
-----

**To perform scans you will need to create a free account on https://www.shone.co.za/**

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



Compiling the phar
-----
You'll can recompile the phar by calling:

    $ bin/compiler && chmod +x shone.phar

You can then copy the phar to any server or directory you wish and use it as a stand-alone executable.


More information
-----

For more information run:

    $ ./shone.phar



Contributing
----

Please see [CONTRIBUTING](https://github.com/xsist10/shone-phar/blob/master/CONTRIBUTING.md) for details.


[![Bitdeli Badge](https://d2weczhvl823v0.cloudfront.net/xsist10/shone-phar/trend.png)](https://bitdeli.com/free "Bitdeli Badge")
