"""

See:
    https://packaging.python.org/en/latest/distributing.html
    https://github.com/pypa/sampleproject
    https://hynek.me/articles/sharing-your-labor-of-love-pypi-quick-and-dirty/

"""

import codecs
import os
import re

from setuptools import setup, find_packages

HERE = os.path.abspath(os.path.dirname(__file__))

###################################################################

NAME = "edge_access"
PACKAGES = find_packages(where="src")
META_PATH = os.path.join("src", "edge_access", "__init__.py")
KEYWORDS = ["class", "requests", "edge_access"]
CLASSIFIERS = [
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
]
INSTALL_REQUIRES = [ 'urllib3', 'requests_aws4auth', 'requests' ]

###################################################################

# next two methods taken directly from https://hynek.me/articles/sharing-your-labor-of-love-pypi-quick-and-dirty/ 

def read(*parts):
    """
    Build an absolute path from *parts* and and return the contents of the
    resulting file.  Assume UTF-8 encoding.
    """
    with codecs.open(os.path.join(HERE, *parts), "rb", "utf-8") as f:
        return f.read()


META_FILE = read(META_PATH)

def find_meta(meta):
    """
    Extract __*meta*__ from META_FILE.
    """
    meta_match = re.search(
        r"^__{meta}__ = ['\"]([^'\"]*)['\"]".format(meta=meta),
        META_FILE, re.M
    )
    if meta_match:
        return meta_match.group(1)
    raise RuntimeError("Unable to find __{meta}__ string.".format(meta=meta))

VERSION = find_meta("version")
URI = find_meta("uri")
LONG_DESC = (
    read("README.rst")
)

if __name__ == "__main__":
    setup(
        name=NAME,
        description=find_meta("description"),
        license=find_meta("license"),
        url=URI,
        version=VERSION,
        author=find_meta("author"),
        author_email=find_meta("email"),
        maintainer=find_meta("author"),
        maintainer_email=find_meta("email"),
        keywords=KEYWORDS,
        long_description=LONG_DESC,
        packages=PACKAGES,
        package_dir={"": "src"},
        zip_safe=False,
        classifiers=CLASSIFIERS,
        install_requires=INSTALL_REQUIRES,
    )

