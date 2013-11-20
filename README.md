shone-phar
=======

A command-line tool for interacting with the Shone Web Scanner API.

You will need to create a free account on https://www.shone.co.za/


Compiling the phar
-----
You'll need to compiler the phar by calling:

    bin/compiler && chmod +x shone.phar

You can then copy the phar to any server or directory you wish and use it as a stand-alone executable.


Using the phar
-----

You can scan a web directory like this:

    ./shone.phar scan --key "[API KEY]" --label "Website Label" /path/to/web/folder

or if you prefer to use the code directly

    ./bin/shone scan --key "[API KEY]" --label "Website Label" /path/to/web/folder

If everything went ok you should be provided with a URL to find the result of your scan


More information
-----

For more information run:

    ./shone.phar