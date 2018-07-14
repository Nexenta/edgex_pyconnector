PYTHON=python

MODULE = edgex_access
VERSION = 0.0.13
S3EDGE = s3edge
SOURCES = $(MODULE)/$(MODULE).py
SETUP = setup.py
DOCS = docs/source/$(MODULE).rst docs/source/s3edgex.rst
SCRIPTS = s3edgex/s3edgex
READMES = README.md LICENSE
TESTLOG = testlog.log
REQ = requirements.txt
DISTDIR = dist 

DIST_FILE = $(DISTDIR)/$(MODULE)-$(VERSION).tar.gz
ALL_FILES = $(SOURCES) $(SETUP) $(READMES) $(TESTS) $(DOCS) $(SCRIPTS) $(REQ)

all: build install test

show:
	@for f in $(ALL_FILES) ; do \
		echo $$f ; \
	done | sort -u

clean:
	rm -rf $(MODULE).egg-info
	rm -rf dist build
	rm -rf __pycache__
	make -C docs clean
	rm test.log

req:
	pip freeze > $(REQ)
	$(PYTHON) -m pip install setuptools wheel twine

init:
	pip install -r requirements.txt

build: $(SOURCES) $(SETUP) req
	$(PYTHON) $(SETUP) build
	$(PYTHON) $(SETUP) sdist bdist_wheel

# dev version only
installd:
	pip install .

install: $(SOURCES) $(SETUP)
	$(PYTHON) $(SETUP) install

uninstall:
	pip uninstall -y $(MODULE)

register: $(SETUP) 
	echo "twine upload dist/*"

docs: $(DOCS)
	make -C docs html

testlog:
	@if [ -f test.log ]; then \
		rm test.log; \
	fi
	make -C test 2>&1 | tee test.log

test: testlog
