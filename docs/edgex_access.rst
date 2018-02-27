edgex_access
============

**edgex_access** is S3 protocol client implementation in **Python 3** which uses
the latest available API of AWS S3 API

What is this ?
--------------

AWS S3 is a very popular protocol to read/write data objects on top of the 
HTTP protocol. **edgex_access** allows access to multiple S3 Services 
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
    store_name = edgex_cfg.getPrimaryService()
     
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
---

.. code-block:: python

edgex_config
  load_file(fileName)
  fromstring(string_config)

edgex_store(edgex_config)
  list_buckets(recursive)

edgex_obj(edgex_config, name)
  put(fileBuffer)
  get()
  exists()
  remove()
  list()
  read()
  write(fileBuffer)
  metainfo()




