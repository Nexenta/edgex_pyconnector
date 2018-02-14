s3edgex: command line for S3 Store access
------------------------------------------

What is it ?
------------

It is a S3 command line utility written in Python 3 that will allow you to 
access data objects directly using the **edgex_access** API 

Configuration
-------------

They are kept in ~/.s3edgex-config. and they look somewhat like the following

.. code:: json

        {
                "EDGEX-S3" : {
                 "ACCESS" : "XXYNOSIOABCC2GXHFGZS",
                 "SECRET" : "12456dfshdfsfeaaaasdfsfsdfsf",
                 "REGION" : "us-west-1",
                 "ENDPOINT" : "https://edge.nexenta.com",
                 "TOKEN" : "BCADDD34216",
                 "USE_SSL" : "False",
                 "DEFAULT_BUCKET" : "mybucket",
                 "TAG" : "edgex"
                },
                "PRIMARY" : "EDGEX-S3",
                "DEBUG_LEVEL" : 5
        }

Commands
--------

s3edgex --help
s3edgex --system
s3edgex [ --debug <level> ] <command> <objname> <arg>
Commands:
        config
        list
        exists
        put
        get
        del
        test

Examples:

        % s3edgex [ --debug <level> ] list [ -r ]
        % s3edgex [ --debug <level> ] list [ -r ] <bucketname>
        % s3edgex get <bucketname/filename> <filename>
        % s3edgex get [ -r ] <bucketname/dirname> <dirname>
        % s3edgex put <bucketname/filename> <filename>
        % s3edgex put [ -r ] <bucketname/dirname> <dirname>
        % s3edgex del <bucketname/filename>
        % s3edgex del [ -r ] <bucketname/dirname>
        % s3edgex info <bucketname/filename>
        % s3edgex exists <bucketname/filename>
