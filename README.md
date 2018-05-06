# edgex_pyconnector

## What is edgex_access

Edge-X Python connector library for NexentaEdge and AWS using the S3 protocol 

- S3 configuration  for more than one S3 store
- signature computation based on configuration
- S3 URI access for GET,PUT, DELETE

### edgex_config

Read in the configuration for accessing various S3 stores and 
other local data stores


```python

from os.path import expanduser
import edgex_access

cfg_file = expanduser("~") + /.mys3config
edgex_cfg = edgex_access.edgex_config()
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
the object creation , only the name is used. The edge_object uses the URI passed in 
and checks against the stores to determine which store this object is part of.

edgex_object parses the URI to determine which bucket this is a prt of


### edgex_task

edgex_task is a top level object which defines how a task is executed in a 
threadpool. All main I/O Operations are available as different tasks 
e.g. edgex_list, edgex_delete, edgex_get, edgex_put

In addition to I/O operations, some execution can also be done using the 
threads in this pool 

### edgex_process

This is the main OS "process" object which decides how much memory, thread pools,
execution paradigm etc. All edgex_tasks are scheduled into the edgex_process and this
entity decides how to perform the execution . 

Example:

Here is a small example of how a object deletion is performed, and how the 
delete operation is queued. 

```python


def deleteobj_cb(future_obj):
    obj = fututure_obj.arg
    result = future_obj.result()
    print("Object: " + obj.pathname() + " delete " + str(result))
   
def delete_obj(this_process, obj):
    delete_task = edgex_access.edgex_delete(this_process, obj)
    this_process.submit_task(delete_task, deleteobj_cb)

del_objname = "aws_s3://mybucket/file_foo.txt"
del_obj = edgex_access.edgex_object(edgex_cfg, del_objname)
delete_obj(this_process, del_obj)


```

Here is a small example to whet your appetite

```python

# Check of the object exists in the store
oname = "mybuk1/high_tech_stocks.txt"
primary_store = edgex_cfg.get_primary_store()
remote_edgex_obj = edgex_access.edgex_obj(primary_store, oname)

#
def existsobj_cb(future_obj):
    result = future_obj.result()
    obj = future_obj.arg
    print(obj.pathname() + "\t:\t" + str(result))
    return result

def exists_obj(this_process, obj):
    exists_task = edgex_access.edgex_exists(this_process, obj)
    this_process.submit_task(exists_task, existsobj_cb)

isthere = exists_obj(this_process, remote_edgex_obj)
# is_there is True or False

# Let's get the object
source_obj = edgex_access.edgex_object(cfg, "aws3://mybuck1/stock_file.txt")
dest_obj = edgex_access.edgex_object(cfg, "high_tech_stocks.txt", as_is=True)

# this is the callback that is called when the get object is 
# actually obtained
def getobj_source_cb(future_obj):
    result = future_obj.result()
    source_obj = future_obj.arg
    this_process = source_obj.ctx
    dest_obj = source_obj.arg
    dest_obj.databuf = result
    put_task = edgex_access.edgex_put(this_process, dest_obj)
    this_process.submit_task(put_task, getobj_target_cb)

# when the buffer retrieved is now placed into a local file 
# this callback is called. 
def getobj_target_cb(future_obj):
    result = future_obj.result()
    target_obj = future_obj.arg

# create a get task and hand it off to the process
def get_obj(this_process, source_obj, dest_obj):
    source_obj.arg = dest_obj
    source_obj.ctx = this_process
    get_task = edgex_access.edgex_get(this_process, source_obj)
    this_process.submit_task(get_task, getobj_source_cb)


# in the example above, we simply have to do this .
get_obj(this_process, source_obj, dest_obj)

# Let's remove the remote file
del_objname = "aws_s3://mybucket/file_foo.txt"
del_obj = edgex_access.edgex_object(edgex_cfg, del_objname)
delete_obj(this_process, del_obj)


```

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

