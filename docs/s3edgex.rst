s3edgex: command line for S3 Store access
------------------------------------------

What is it ?
------------

It is a S3 command line utility written in Python 3 that will allow you to 
access data objects directly using the **edgex_access** API 

Configuration
-------------

They are kept in ~/.s3edgex and they look somewhat like the following

.. code:: json

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
		        "BUCKET" : "nabin",
		        "TAG" : "edgex"
	        },
	        {
		        "NAME" : "HOME",
		        "STORE_TYPE" :"FS",
		        "ACCESS" : "",
		        "SECRET" : "",
		        "REGION" : "",
		        "ENDPOINT" : "",
		        "TOKEN" : "ECBBDD3499",
		        "SSL" : "False",
		        "BUCKET" : "/Users/nabin.acharya",
		        "TAG" : "nabinix"
	        }
	        ],
	        "PRIMARY" : "EDGEX-S3",
	        "DEBUG" : 5,
	        "HOME" : "/Users/nabin.acharya/foo"
        }

Commands
--------
.. code: bash

        s3edgex --help
        s3edgex --system
        s3edgex [ --debug <level> ] <command> <objname> <arg>
        Commands:
                setup
                list
                exists
                put
                get
                del
                metainfo
        Examples:

                % s3edgex [ --debug <level> ] list [ -r ]
                % s3edgex [ --debug <level> ] list [ -r ] <bucketname>
                % s3edgex get <bucketname/filename> <filename>
                % s3edgex get [ -r ] <bucketname/dirname> <dirname>
                % s3edgex put <bucketname/filename> <filename>
                % s3edgex put [ -r ] <bucketname/dirname> <dirname>
                % s3edgex del <bucketname/filename>
                % s3edgex del [ -r ] <bucketname/dirname>
                % s3edgex metainfo <bucketname/filename>
                % s3edgex exists <bucketname/filename>

