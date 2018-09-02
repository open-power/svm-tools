PROJECT = $(shell sed -n -e "s@\(name = \)\(.*\)@\2@p" pyproject.toml | tr -d '"')
VERSION_FILE = version.py

RPMBUILDDIR = $(shell git rev-parse --show-toplevel)/RPMDIR
export RPMBUILDDIR

all: rpm test

poetry_check:
	@(poetry > /dev/null 2>/dev/null) || \
	(echo "ERROR: Please install poetry tool; Read README.rst for direction" && exit 1)
	#poetry install

poetry_version: poetry_check
	poetry version $(version) 
	
version: poetry_version
	$(eval NEW_VERS := $(shell sed -n -e "s@\(version = \)\(.*\)@\2@p" pyproject.toml | tr -d '"'))
	@sed -i "s/__version__ = .*/__version__ = \"$(NEW_VERS)\"/g" $(PROJECT)/$(VERSION_FILE)

svm-tool-build: version
	@poetry build

passwd-agent-build:
	make -C svm-password-agent build

build: svm-tool-build passwd-agent-build

svm-tool-rpm: svm-tool-build
	cd dist; tar zxvf $(PROJECT)-$(NEW_VERS).tar.gz
	cd dist/svm_tool-$(NEW_VERS); python3 setup.py bdist_rpm --requires "python3-libfdt,python3-pycryptodomex,python3-pyyaml,python3-Cython"
	mkdir -p $(RPMBUILDDIR)/SRPMS $(RPMBUILDDIR)/RPMS
	cp dist/svm_tool-$(NEW_VERS)/dist/*.src.rpm $(RPMBUILDDIR)/SRPMS
	cp dist/svm_tool-$(NEW_VERS)/dist/*.noarch.rpm $(RPMBUILDDIR)/RPMS

passwd-agent-rpm:
	make -C svm-password-agent rpm

rpm: poetry_check passwd-agent-rpm svm-tool-rpm

test: poetry_check
	@poetry run pytest tests/

clean:
	make -C svm-password-agent clean
	rm -rf dist $(RPMBUILDDIR)
