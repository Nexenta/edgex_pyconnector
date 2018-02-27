PYTHON=python
PYDOC=pydoc

MODULE = edgex_access
VERSION = 0.0.8
S3EDGE = s3edge
SOURCES = src/$(MODULE)/$(MODULE).py
SETUP = setup.py
DOCS = docs/$(MODULE).txt docs/s3edgex.txt
SCRIPTS = s3edgex/s3edgex
READMES = README.md LICENSE docs/edgex_access.rst docs/s3edgex.rst
TESTS = test/test_$(MODULE).py
REQ = requirements.txt
DISTDIR = dist 

DIST_FILE = $(DISTDIR)/$(MODULE)-$(VERSION).tar.gz
ALL_FILES = $(SOURCES) $(SETUP) $(READMES) $(TESTS) $(DOCS) $(SCRIPTS) $(REQ)

all: build test install

show:
	@for f in $(ALL_FILES) ; do \
		echo $$f ; \
	done | sort -u

clean:
	rm -rf src/$(MODULE).egg-info
	rm -rf dist build

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
	twine upload $(DISTDIR)/*

docs/$(MODULE).txt: src/$(MODULE)/$(MODULE).py
	echo "TODO pydoc"

docs/$(S3EDGE).txt : $(S3EDGE)/$(S3EDGE)
	echo "TODO pydoc"
