# edgex_pyconnector

## What is edgex_access

Edge-X Python connector library for NexentaEdge and AWS using the S3 protocol 

- S3 configuration for more than one S3 store
- signature computation based on configuration
- S3 URI access for GET,PUT, DELETE

### edgex_config

Read in the configuration for accessing various S3 stores and 
other local data stores


```python

from os.path import expanduser
from edgex_access import edgex_config

cfg_file = expanduser("~") + /.mys3config
edgex_cfg = edgex_config()
try:
	edgex_cfg.load_file(cfg_file)
except:
	print(" Error loading " + cfg_file  + " config file")

```

### edgex_store

Each S3 store is represented as a edgex_store, so once the confuration is read,
all the store instances are available

The configuration as a store marked as a primary S3 store. 

Example:
```python

primary_store = edgex_cfg.get_primary_store()
primary_store.show()
buckets = primary_store.list_buckets()

```

### edgex_object

Each data object in any store is represented as an edgex_object. At the time of 
the object creation , only the name is used. The edgex_object uses the URI passed in 
and checks against the stores to determine which store this object is part of.

edgex_object parses the URI to determine which store and bucket this is a part of


### edgex_access

edgex_access is a top level object which defines how each I/O operation
is executed. All main I/O Operations are available as different methods in 
this class.
e.g. list, delete, get, put

In addition to I/O operations, some execution can also be done using the 
threads in this pool 

Example:

Object Deletion 
---------------
```python

# define a callback when the operation is done
def my_cb(obj, result):
    print(obj.pathname() + " " + str(result))

# let's get a aio session 
session = aiobotocore.get_session(loop=loop)

# define the object
del_objname = "aws_s3://mybucket/file_foo.txt"
del_obj = edgex_object(edgex_cfg, logger, del_objname)

# access operation object
op = edgex_access(del_obj, logger)

# make it happen 
deleted = await op.delete(session)

# let's wait on the callback 
await my_cb(edgex_obj, deleted)

```

Object Info
-----------

```python

# define a callback when the operation is done
def my_cb(obj, result):
    print(obj.pathname() + " " + str(result))

# let's get a aio session 
session = aiobotocore.get_session(loop=loop)

# define the object
del_objname = "aws_s3://mybucket/file_foo.txt"
del_obj = edgex_object(edgex_cfg, logger, del_objname)

# access operation object
op = edgex_access(del_obj, logger)

# make it happen 
info = await op.info(session)

# let's wait on the callback 
await my_cb(edgex_obj, info)

```

As you can see the only difference between the above is 

```python
deleted = await op.delete(session)
```

```python
info = await op.info(session)
```

primarily the operation used in edgex_access


Now that we have done a single object operations like delete and info,
let's try to retrieve the object using get or place the object using put . 

Here is a "GET" example:

```python

# first we define the callback when 
# we place the data buffer we got

def put_callback(obj, result):
    print(obj.pathname() + " " + str(result))

# Now we define the callback to retrieve 
# the buffer of the object we are trying to 
# retrieve

def get_callback(session, logger, obj, databuf):
    target_object = obj.arg
    target_object.databuf = databuf
    op = edgex_access(target_obj, logger)
    put_obj = await op.put(session)
    await put_callback(dest_obj, put_obj)

# start of the get operation 

get_objname = "aws_s3://mybucket/file_foo.txt"
get_obj = edgex_object(edgex_cfg, logger, del_objname)

op = edgex_access(source_obj, s3elog)
databuf = await op.get(session)
await get_callback(session, logger, source_obj, databuf)

```

As you can see from the example above, the object data buffer 
is retrieved and placed locally to the desired location using the 
"get" method in edgex_access. 

edgex_access is currently in development. Some of the features are missing and there are bugs 
Please refer to the 'Development Status" below.

### Prerequisites & Requirements


You need Python 3.5 or later to use edgex_access.  You can have multiple Python
versions (2.x and 3.x) installed on the same system without problems.

In Ubuntu, you can install Python 3 like this:

    $ sudo apt-get install python3 python3-pip

Make sure you have Python3 installed. Please check the requirement.txt for a list of Python packages 
that should be pre-installed before edgex_access and s3edgex can be used. 

### Coding Style

The Hitchhiker's Guide to Python [ http://docs.python-guide.org/en/latest/writing/style/ ]


## s3edgex

A simple CLI that uses the edgex_access module for command line access to the S3 stores

- Command line access to s3 web services using edgex access
- edgex_access is the Python class used by s3edgex


## Installing and Getting Started

Just to get you up and running on your local machine for development and testing. 

Install the edgex_access Python3 module
```
pip install edgex_access
```
Add your S3 stores and your home directory first 
```
s3edgex setup
```
Edit the file ~/.s3edgex, and add your ACCESS and SECRET Keys for S3 store access
Once you have added the S3 store configurations, check that they are available
There is sample file under s3edgex/dot.s3edgex.sample in this git repo .
Please use it as an example.


```
s3edgex store list
```
Make sure you have a Primary S3 store set. Here we are setting to a AWS-S3 
```
s3edgex store primary AWS-s3
```
### Example use of s3edgex

Let's upload a file to our primary S3 store

```
s3edgex put -l aws_s3://mybucket/file.txt file.txt
```
Now checkif it is there 
```
s3edgex exists aws_s3://mybucket/file.txt
```
Let's get the file back with a different name
```
s3edgex get -l aws_s3://mybucket/file.txt foo.txt
```
Now make sure the checksums match for both the files
```
sum file.txt
sum foo.txt
```
Cleanup the files now
```
s3edgex del aws_s3://mybucket/file.txt
s3edgex del -l foo.txt
```

## Built With

* [requests](https://github.com/requests/requests) - Requests: HTTP for Humans
* [urllib3](https://github.com/shazow/urllib3) - HTTP client in Python

## Authors

* **nexenta** - *Initial work* - [edgex_pyconnector](https://github.com/Nexenta/edgex_pyconnector ) 


## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details

## Acknowledgments

* Thanks to dyusupov

