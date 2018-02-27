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

```

### edgex_store

Each S3 store is represented as a edgex_store, so once the confuration is read,
all the store instances are available

The configuration as a store marked as a primary S3 store. 

Example:
```python

primary_store = edgex_cfg.getPrimaryStore()
primary_store.show()
buckets = primary_store.list_buckets()

```

### edgex_obj

Each data object in any store is represented as a edgex_obj. At the time of 
the object creation , only the name is used. Most of the methods of this objects
are more I/O oriented. 

Here is a small example to whet your appetite

```python

# Check of the object exists in the store
oname = "mybuk1/high_tech_stocks.txt"
primary_store = edgex_cfg.getPrimaryStore()
remote_edgex_obj = edgex_access.edgex_obj(primary_store, oname)
is_there = remote_edgex_obj.exists()

# is_there is True or False

# Let's get the object
stock_file_buffer = remote_edgex_obj.get()
stock_file_name = "high_tech_stocks.txt"

# find my local home directory 
home_store = edgex_cfg.getHome()

# create a local object representation in my home directory 
local_edgex_obj = edgex_access.edgex_obj(home_store, stock_file_name)

# now put the remote buffer we got into the local object and write it out
local_edgex_obj.put(stock_file_buffer)

# Let's remove the remote file
remote_edgex_obj.remove()

```

edgex_access is in development. SOme of the features are missing and there are bugs 
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
s3edgex put /mybucket/file.txt file.txt
```
Now checkif it is there 
```
s3edgex exists /mybucket/file.txt
```
Let's get the file back with a different name
```
s3edgex get /mybucket/file.txt foo.txt
```
Now make sure the checksums match for both the files
```
sum file.txt
sum foo.txt
```
Cleanup the files now
```
s3edgex del /mybucket/file.txt
rm file.txt foo.txt
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

