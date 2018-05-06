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

    # firt get a this_process object
    this_process = edgex_access.edgex_access()

    # name of the primary service in the config 
    # there can only be one primary 
    store_name = edgex_cfg.get_primary_store()
     
    # Find the access to the store based on the name
    edgex_store = edgex_cfg.get_store(edgex_cfg)

    # list the buckets in the primary
    edgex_store.list_buckets()

    # Let's write an object remotely
    source_obj = edgex_access.edgex_object(cfg, "foofile", as_is=True)
    dest_obj = edgex_access.edgex_object(cfg, "aws3://mybucket/foofile")

    # now do a PUT ising this
    put_obj(this_process, source_obj, dest_obj)


API
====

Primary API in edgex_access module is in these objects:

edgex_access
edgex_config
edgex_store
edgex_object
edgex_task 


edgex_access
        - Create the primary process for scheduling all the tasks for doing I/O 
          to any store

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

        Example:

```python

objname = "aws_s3://mybucket"
obj = edgex_access.edgex_object(edgex_cfg, objname)
print("URI : " + obj.pathname())
print("Bucket : " + obj.bucketname())
print("Object : " + obj.objname())

```

edgex_task
        - Do any I/O operations using these methods implemented using this object
        - edgex_access is the primary process that shcedues these tasks

        Derived classes:

        edgex_get
                - Retrieve the buffer for this object 
        edgex_put
                - Place a buffer into this object 
        edgex_del
                - Delete this object from the store
        edgex_exists
                - Check if the object actually exists or not
        edgex_info
                - Determine the meta only for this object




