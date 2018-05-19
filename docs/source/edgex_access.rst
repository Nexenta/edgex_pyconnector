edgex_access
============

`edgex_access https://github.com/Nexenta/edgex_pyconnector` is S3 protocol client implementation in **Python 3** which uses
the latest available API of AWS S3 API

What is this ?
--------------

AWS S3 is a very popular protocol to read/write data objects on top of the 
HTTP protocol. `edgex_access https://github.com/Nexenta/edgex_pyconnector`  allows access to multiple S3 Services 
( not only Amazon ) to read/write data objects as efficiently as possible. 
It abstracts out the IO protocol so it is easier to access the data objects without 
attempting to understand the details of how to access the data objects

Installing
----------
.. code-block:: sh 

  pip3 install edgex_access


Loading a S3 configuration 
--------------------------

.. code-block:: python

   import edgex_access

   # This is how to load up the configuration 
   #
   cfg_file = expanduser("~") + "/.edgex_config"
   edgex_cfg = edgex_access.edgex_config()
   edgex_cfg.load_file(cfg_file)

Doing stuff
-----------
.. code-block:: python

    # name of the primary service in the config 
    # there can only be one primary 
    edgex_store = edgex_cfg.get_primary_store()
     
    # Find the access to the store based on the config
    edgex_store = edgex_access.edgex_store_access(edgex_cfg)

    # list the buckets in the primary
    # decide if you want to go down the hierarchy recursively
    recursive = False
    edgex_store.list_buckets(recursive)

    # Let's write an object 
    # get an object that references I/O functions first 
    edgex_obj = edgex_access.edgex_obj_access(edgex_cfg)

    # now do a PUT ising this
    remoteName="mybucket/foofile"
    localFile="foofile"
    edgex_obj.put_obj(remoteName, fileName=localFile)

API
====

Primary API in edgex_access module is in these objects:

edgex_config
edgex_store
edgex_object
edgex_task

edgex_access
        - Access S3 stores using the AWS S3 protocol 

edgex_config
        - Describe the confguration for all the S3 stores and Local Store load_file
        - Load a file configuration fromstreing
        - Load a JSON format string of configuration

edgex_store
        - Describe one instance of store as describe in the configuration list_buckets
        - List a set of buckets for this store edgex_obj
        - Code edgex object for doing I/O exists
        - Check of the object exists in the store metainfo
        - Return the metadata for this object 

edgex_object
        - Create an object instance based on the string representing the object. 
          Each string representation must have the store name or it is assumed to be
          picked up from the local present working directory if the flag is provided

Example
-------
.. code-block:: python

   objname = "aws_s3://mybucket"
   obj = edgex_access.edgex_object(edgex_cfg, objname)
   print("URI : " + obj.pathname())
   print("Bucket : " + obj.bucketname())
   print("Object : " + obj.objname())


edgex_operation
        - Do the I/O operations using these methods, and the object supplied
        - Does the I/O based on the store type to determine how to do the I/O

        Available methods:

        get
                - Retrieve the buffer for this object 
        read
                - Same as get
        put
                - Place a buffer into this object 
        write
                - Same as put
        remove
                - Delete this object from the store
        exists
                - Check if the object actually exists or not
        info
                - Determine the meta only for this object




