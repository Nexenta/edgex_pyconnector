# edgex_pyconnector


## s3edgex

A simple CLI that uses the edgex_access module for command line access to the S3 stores

- Command line access to s3 web services using edgex access
- edgex_access is the Python class used by s3edgex

### Prerequisites

Make sure you have Python3 installed. Please check the requirement.txt for a list of Python packages 
that should be pre-installed before edgex_access and s3edgex can be used. 


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

## edgex_access

Edge-X Pyhton connector library for NexentaEdge and AWS using the S3 protocol 
- S3 configuration  for more than one S3 store
- signature computation based on configuration
- S3 URI access for GET,PUT, DELETE

### edgex_config

Example:
```
Give an example
```

### edgex_store

Example:
```
Give an example
```

### edgex_obj

Example:
```
Give an example
```

### Example use of all three objects

Explain what these tests test and why


### Coding Style

Explain what these tests test and why

```
Give an example
```

## Deployment

Simple ....
```
pip install edgex_access
```


## Built With

* [requests](https://github.com/requests/requests) - Requests: HTTP for Humans
* [urllib3](https://github.com/shazow/urllib3) - HTTP client in Python

## Versioning

We use [SemVer](http://semver.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/your/project/tags). 

## Authors

* **nexenta** - *Initial work* - [edgex_pyconnector](https://github.com/Nexenta/edgex_pyconnector ) 


## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details

## Acknowledgments

* Thanks to dyusupov

