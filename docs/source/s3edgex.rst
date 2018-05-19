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
                % s3edgex [ --debug <level> ] setup [ create show ]
                % s3edgex [ --debug <level> ] store [ list add del ]
                % s3edgex [ --debug <level> ] list [ -r ]
                % s3edgex [ --debug <level> ] list [ -r ] <bucketname>
                % s3edgex get [ -r | -l ] <store://bucketname/filename> <filename>
                % s3edgex get [ -r | -l ] <store://bucketname/dirname> <dirname>
                % s3edgex put [ -r | -l ] <store://bucketname/filename> <filename>
                % s3edgex put [ -r | -l ] <store://bucketname/dirname> <dirname>
                % s3edgex del <store://bucketname/filename>
                % s3edgex del [ -r | -l ] <store://bucketname/dirname>
                % s3edgex del -l <filename>
                % s3edgex info [ -r | -l ] <store://bucketname/filename>
                % s3edgex info -l <filename>
                % s3edgex exists <store://bucketname/filename>
                % s3edgex exists [ -r | -l ] <store://bucketname/filename>
                % s3edgex exists -l <filename>


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

.. code-block:: sh

        # get a remote file into a local store spefified as a store
        % s3edgex get aws_s3://mybucket/file.txt HOME://somedir/file.txt

        # Let's get the same file in the present working directory 
        % s3edgex get -l aws_s3://mybucket/file.txt file.txt


Command Usage Examples
----------------------

.. code-block:: sh

        # Create a bare bones setup template file ~/.s3edgex
        % s3edgex setup create 

        # See the setup 
        % s3edgex setup show 

        # At this time please edit the configuration with the correct ACCESS, SECRET, URL etc 
        % vi ~/.s3edgex

        # Now look at the list of stores we have
        % s3edgex store 

        # Let see which store is primary 
        % s3edgex store primary

        # Go through the list of buckets on this store
        % s3edgex list

        # Let's go through recursively a bucket and list it
        # Please note that if you want -r to go through the folder 
        # the folder must end with a "/" 
        % s3edgex list -r edgex://edge-FO-T/

        # Check and see if this object exists
        % s3edgex exists edgex://edge-FO-T/signer.py

        # retrieve the metadata of the object
        % s3edgex info edgex://edge-FO-T/signer.py

        # retrieve the object and write it locally to the current directory
        # this is where -l comes in 
        % s3edgex get -l edgex://edge-FO-T/signer.py signer.py

        # delete the remote object
        % s3edgex del edgex://edge-FO-T/signer.py

        # take the local file and put it as an object to the remote location 
        % s3edgex put -l edgex://edge-FO-T/signer.py signer.py

        # delete the local file Note theuse of the -l here
        % s3edgex del -l signer.py

        # see if the file we placed to the remote exists 
        % s3edgex exists edgex://edge-FO-T/signer.py

        # Retrieve the metadata for the remote object
        % s3edgex info edgex://edge-FO-T/signer.py

        # let's see if this objects exists in another remote store
        % s3edgex exists aws3://xenocloud/signer.py

        # Get the object from one remote store to another remote store
        % s3edgex get edgex://edge-FO-T/signer.py aws3://xenocloud/signer.py

        # Let's see the meta info for this object in this different store
        % s3edgex info aws3://xenocloud/signer.py

        # delete the object from this store
        % s3edgex del aws3://xenocloud/signer.py

        # Let's generate a directory of small files with random bits
        % s3edgex gend -l dirone/

        # Now put all the files in this directory to the remote store
        # let go down the directory recursively to find each file
        # and place it remotely.
        % s3edgex put -r -l edgex://edge-FO-T/dirone/ dirone/

        # Let's see if all the files made it
        % s3edgex list -r edgex://edge-FO-T/dirone/

        # Retrieve the metadata info for all the objects we placed
        % s3edgex info -r edgex://edge-FO-T/dirone/

        # Let's retrieve all the objects in this folder and place it locally 
        # to a different directory 
        % s3edgex get -r -l edgex://edge-FO-T/dirone/ dirtwo/

        # Delete the entire folder remotely
        % s3edgex del -r edgex://edge-FO-T/dirone/

        # Check if each file exists locally 
        % s3edgex exists -r -l dirone/

        # Retrieve the meta data on each file as the local 
        % s3edgex info -r -l dirone/

        # Delete the local directories. 
        # same as : rm -rf <dir>
        % s3edgex del -r -l dirtwo/
        % s3edgex del -r -l dirone/
