s3edgex
========

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   modules

What is it ?
------------

It is a S3 command line utility written in Python 3 that will allow you to 
access data objects directly using the **edgex_access** API 

Configuration
-------------

They are kept in ~/.s3edgex and they look somewhat like the following

.. code-block:: json

        {
	        "stores" : [ 
	        {
		        "NAME" : "EDGEX-S3",
		        "STORE_TYPE" :"S3",
		        "ACCESS" : "CJSNOSIOJRQL2GXHFGZS",
		        "SECRET" : "waAMD0kGwbTAimeVcRNADORBhnVTMMMQQFCLZZwF",
		        "REGION" : "us-west-1",
		        "ENDPOINT" : "https://edge.nexenta.com",
		        "TOKEN" : "BCADDD34216",
		        "SSL" : "False",
		        "BUCKET" : "sample",
		        "TAG" : "edgex"
	        },
	        {
		        "NAME" : "HOME",
		        "STORE_TYPE" :"FS",
		        "TOKEN" : "ECBBDD3499",
		        "SSL" : "False",
		        "BUCKET" : "/Users/havanix",
		        "TAG" : "havanix"
	        }
	        ],
	        "PRIMARY" : "EDGEX-S3",
                "SYNCIO" : "SYNCIO",
	        "DEBUG" : 5
        }

Commands
--------
.. code-block:: sh

        s3edgex --help
        s3edgex --system
        s3edgex [ --debug <level> ] <command> <objname> <arg>
        Commands:
                setup
                store
                list
                exists
                put
                get
                del
                info
        Examples:

                % s3edgex [ --debug <level> ] list [ -r | -l ]
                % s3edgex [ --debug <level> ] list [ -r | -l ] <bucketname>
                % s3edgex get <bucketname/filename> <filename>
                % s3edgex get [ -r | -l ] <bucketname/dirname> <dirname>
                % s3edgex put <store://bucketname/filename> <filename>
                % s3edgex put [ -r | -l ] <store://bucketname/dirname> <dirname>
                % s3edgex del <store://bucketname/filename>
                % s3edgex del [ -r | -l ] <store://bucketname/dirname>
                % s3edgex info [ -r | -l ] <store://bucketname/filename>
                % s3edgex exists [ -r | -l ] <store://bucketname/filename>

Command Options
---------------

-d <level>
        - Choose the debug level when the command is executed so the logs 
          available as s3edgex.log has the log entries based on this level 
        - if this option is not used no logs are generated as the default debug
          level is 5
        - maximum logging is available with level zero.

-r
        - the specified object is a directory or a folder and all remaining operations
          have to be done recursively on each object in the folder structure

-l
        - The last object specified is local object from the present working directory 
          In the example configuration above "HOME://" is a storage tag that refers to 
          /Users/havanix. e.g.

        - Let's get a file from AWS s3 store from a HOME directory specified in the config

          s3edgex get aws_s3://mybucket/file.txt HOME://somedir/file.txt

        - Let's get the same file in the present working directory 

          s3edgex get -l aws_s3://mybucket/file.txt file.txt

