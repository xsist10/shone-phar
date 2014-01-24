shone-phar
=======

[![Build Status](https://travis-ci.org/xsist10/shone-phar.png?branch=master)](https://travis-ci.org/xsist10/shone-phar)
[![Coverage Status](https://coveralls.io/repos/xsist10/shone-phar/badge.png)](https://coveralls.io/r/xsist10/shone-phar)
[![Latest Stable Version](https://poser.pugx.org/shone/scanner/version.png)](https://packagist.org/packages/shone/scanner)

A command-line tool for interacting with the Shone Web Scanner API.

To perform scans you will need to create a free account on https://www.shone.co.za/

Getting started
-----

The easiest way is to just download the phar file and get started

    wget raw.github.com/xsist10/shone-phar/master/shone.phar && chmod +x shone.phar

Alternatively you can use [composer](http://www.getcomposer.org)

    {
        "require": {
            "shone/scanner": "1.0.*@dev"
        }
    }

Using the scanner
-----

You can scan a web directory like this

    ./shone.phar scan --key "[API KEY]" --label "Website Label" /path/to/web/folder

or if you prefer to use the code directly (remember to run composer update first)

    ./bin/shone scan --key "[API KEY]" --label "Website Label" /path/to/web/folder

If everything went ok you should be provided with a URL to find the result of your scan


Compiling the phar
-----
You'll can recompile the phar by calling:

    bin/compiler && chmod +x shone.phar

You can then copy the phar to any server or directory you wish and use it as a stand-alone executable.


More information
-----

For more information run:

    ./shone.phar



Contributing
----

Please see [CONTRIBUTING](https://github.com/xsist10/shone-phar/blob/master/CONTRIBUTING.md) for details.


[![Bitdeli Badge](https://d2weczhvl823v0.cloudfront.net/xsist10/shone-phar/trend.png)](https://bitdeli.com/free "Bitdeli Badge")
