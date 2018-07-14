"""
See:
    https://packaging.python.org/en/latest/distributing.html
    https://github.com/pypa/sampleproject
    https://hynek.me/articles/sharing-your-labor-of-love-pypi-quick-and-dirty/

"""

import os
import sys
import codecs
import re

from setuptools import setup
from setuptools import setup, find_packages
from codecs import open
from os import path

if sys.version_info < (3, 0, 0):
    sys.stdout.write("Need Python3 or above. Detected: %s\n" % sys.version.split(None,1)[0])
    raise RuntimeError("edgex_access is for Python 3")

HERE = path.abspath(path.dirname(__file__))

vpath = os.path.join(HERE, 'edgex_access', 'version.py')
__version__ = eval(open(vpath).read())


###################################################################
long_description = "Edge-X Python connector library for NexentaEdge and AWS using the S3 protocol"

# Get the long description from the README file
with open(path.join(HERE, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='edgex_access',
    version=__version__,
    description = "S3 protocol Data access to NexentaEdge or AWS S3",
    long_description=long_description,
    url = "http://www.github.com/Nexenta/edgex_pyconnector",
    author = "Nexenta Systems",
    author_email = "support@nexenta.com",
    license = "MIT",
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Science/Research',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3 :: Only',
    ],
    scripts=['s3edgex/s3edgex'],
    keywords='requests edgex_access s3 scaleout store distributed',
    packages=['edgex_access'],
    python_requires = '>=3',
    install_requires = [ 'urllib3', 'requests_aws4auth', 'aiobotocore' , 'simplejson', 'lxml', 'asyncio'],
    project_urls= {
        'Bug Reports': 'https://github.com/Nexenta/edgex_pyconnector/issues',
        'Source': 'https://github.com/Nexenta/edgex_pyconnector/',
    },
)
