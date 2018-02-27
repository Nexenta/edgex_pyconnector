"""

See:
    https://packaging.python.org/en/latest/distributing.html
    https://github.com/pypa/sampleproject
    https://hynek.me/articles/sharing-your-labor-of-love-pypi-quick-and-dirty/

"""

import sys

try:
    py_major = sys.version_info.major
except AttributeError:
    py_major = sys.version_info[0]

if py_major < 3:
    sys.stdout.write("Need Python3 or above. Detected: %s\n" % sys.version.split(None,1)[0])
    sys.exit(-1)
else:
    sys.stdout.write("Python version: %s" % sys.version.split(None,1)[0])

from setuptools import setup, find_packages
from codecs import open
from os import path
import re

HERE = path.abspath(path.dirname(__file__))

###################################################################

long_description = "Edge-X Python connector library for NexentaEdge and AWS using the S3 protocol"

setup(
    name='edgex_access',
    version='0.0.8',
    description = "S3 protocol Data access to NexentaEdge or AWS S3",
    long_description=long_description,
    url = "http://www.github.com/Nexenta/edgex_pyconnector",
    author = "Nexenta Systems",
    author_email = "support@nexenta.com",
    license = "MIT",
    copyright = "Copyright (c) 2018 Nexenta Systems",
    classifiers = [
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Natural Language :: English",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    scripts=['s3edgex/s3edgex'],
    keywords='requests edgex_access edgex_obj',
    packages=find_packages(where='src'),
    package_dir={"": "src"},
    zip_safe=False,
    python_requires = '>=3',
    install_requires = [ 'urllib3', 'requests_aws4auth', 'requests' , 'simplejson']
    )

