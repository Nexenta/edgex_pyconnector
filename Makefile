PKG_NAME=edgex_access

init:
	pip install -r requirements.txt

build_tools:
	python -m pip install setuptools wheel twine
build:
	pip freeze > requirements.txt
	python setup.py sdist bdist_wheel

install:
	pip install $(PKG_NAME)
uninstall:
	pip uninstall -y $(PKG_NAME)

