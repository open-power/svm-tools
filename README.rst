svm_tool
========

Install poetry
--------------
 If poetry is not available on your system, install it by running
the following command

.. code-block:: console
curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py | python3 -

Running script with poetry
--------------------------

.. code-block:: console

    $ poetry run svm-tool -h

Running module from python
--------------------------

.. code-block:: console

    $ poetry run python -m svm_tool -h

.. code-block:: console

    $ poetry run python -m svm_tool.esm_digest -h

Running with pdb
----------------

.. code-block:: console

    $ poetry run python -m pdb -m svm_tool -h

Building
--------

Building the svm-tool rpm has been tested on Fedora 31. You can use a VM,
host or a docker container running Fedora 31 to build the svm-tool.

If necessary, use the `build-svm-tool-dockerfile.fc31` Dockerfile with
following commands to create/run a F31 container that is suitable for
building svm-tool. These steps were tested on a Fedora 30 VM.

.. code-block:: console

    $ cd svm-tools.git

    $ docker build -t build-svm-tool -f dockerfiles/build-svm-tool-dockerfile.fc31 .

    $ docker run -it -v ~/svm-tools.git:/svm-tools.git build-svm-tool

Once inside the F31 system (container/laptop/VM etc) use following commands
to build:

.. code-block:: console

    $ cd svm-tools.git
    $ make version=0.0.6 version
    $ make build

Building RPM
------------

.. code-block:: console

    $ cd dist
    $ tar -zxf svm_tool-*.tar.gz
    $ cd svm_tool-${version}
    $ python3 setup.py bdist_rpm --requires "python3-libfdt,python3-pycryptodomex,python3-pyyaml,python3-Cython"


SVM PASSWORD AGENT
==================

Building RPM
------------

.. code-block:: console

    $cd svm-passwd-agent
    $make rpm
