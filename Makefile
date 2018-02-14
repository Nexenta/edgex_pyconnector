PKG_NAME=edgex_access

init:
	pip install -r requirements.txt

build_tools:
	python -m pip install setuptools wheel twine
build:
	#wpip freeze > requirements.txt
	python setup.py sdist bdist_wheel

install:
	#pip install $(PKG_NAME)
	pip install .
uninstall:
	pip uninstall -y $(PKG_NAME)

