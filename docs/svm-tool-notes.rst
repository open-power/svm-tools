
=========================================
Build an ESM blob and add it to an initrd
=========================================

.. sectnum::
.. contents::
    :depth: 3


To boot a secure virtual machine (SVM), we must first create an ESM blob
and add (concatenate) it to the initrd image that will be used inside the
SVM. We use the ``svm-tool`` to perform both these operations. We refer
to the resulting modified initrd as ``esmb-initrd`` below.

This document serves as a "Quick start" guide to creating an ESM blob and
adding it to the initrd. See the README files in this directory for more
details on the ESM blob as well as the ``svm-tool``.

The process involves several steps:
	- Obtain the ``svm-tool``
	- Gather/organize info for ESM blob
	- Create the ESM blob
	- Add the blob to the initrd to create an ``esmb-initrd``

The following sections describe each the above steps.

**NOTE on Distro release**

The svm-tool relies on python3, libfdt etc. As such, it is recommended
to run the svm-tool on Fedora 31 or similar release.

Obtain the ``svm-tool``
=======================

A version of the svm-tool is available at:

	https://github.ibm.com/Ultravisor/svm-tools/releases/

If a suitable version is not available, refer to the instructions in

	https://github.ibm.com/Ultravisor/svm-tools/blob/master/README.rst

to build a new package.

If you have a Fedora 31 system, install the ``svm-tool`` rpm on the system
after satisfying the dependencies. Then proceed to the section `Gather
information`_ for ESM Blob. Also skip the commands below that involve
starting a container.

If you don not have a Fedora 31 system, see steps to `Create Docker
Container`_.

Create Docker Container
-----------------------

We only need to create the Docker container once for a distro release.
If you already have a container, skip this step and proceed to
`Gather information`_ below.

Use one of the Dockerfiles in the ``dockerfiles/`` directory with the
following commands to create a docker container.

.. code:: sh

	$ cd svm-tools.git

	# See "Obtain the svm-tool" above. This rpm is needed by dockerfile.
	$ ls -l svm-tool-0.0.6-1.noarch.rpm

	$ docker build --force-rm -t my-fc31 -f dockerfiles/Dockerfile.fc31 .

	# Test that svm-tool is installed

	$ docker run -it my-fc31

	$ /usr/bin/svm-tool -h

	$ exit	# leave container


Gather information
==================

To build an ESM blob, you need the following information:

	- Owner's private and public keys, referred to as ``rsaprivkey``
	  and ``rsapubkey`` below. See `Generate New Origin Key`_ section
	  below if you need to create a new key.

	- Public key of the TPM where the SVM is being authorize to run. It is
	  referred to as ``tpmrsapubkey.pem``. From the ``svm-tool`` point of
	  view, this is the *recipient* key. This document uses the terms *TPM
	  key* and *recipient key* interchangably. If the SVM is authorized to
	  run on several systems, then there should be one TPM key per system
	  with a unique name of course (eg: ``tpm2rsapubkey.pem``). See `Obtain
	  System TPM's Key`_ below.

	- ``vmlinux`` file that you want to use with the SVM - this file is
	  only used to compute the SHA and the SHA is stored in the blob.

	- The ``initrd`` image that you want to use with the SVM. Like the
	  vmlinux, SHA of the initrd is stored in the blob. In addition,
	  the blob itself is attached to the initrd.

	- The kernel boot command line args aka `bootargs`. These must be
	  precisely what will be used in the SVM - leading/trailing/consecutive
	  spaces/tabs will **not** be ignored!

	- User attachment files. One or more files aka attachments that the
	  user wants to include/secure in the blob.

	- ``svm_blob.yml`` file - an YAML file dscribing the above attachments
	  and keys. See below for the format of the yaml file. Make sure
	  there are no syntax errors in the yaml file. See `Create YAML
	  configuration file`_.

Organize this as described in the section `Organize the information`_.

Generate New Origin Key
-----------------------

Use the ``svm-tool`` to generate the owner keys if needed.

If running ``svm-tool`` inside a container, first run the container with
the $ESMB_DIR mapped into /esmb-dir in the container:

.. code-block:: sh

	$ docker run -it -v ${ESMB_DIR}:/esmb-dir:z	\
			--user ${UID}:${UID} --group-add ${UID}	\
			my-fc31

	# In the container, ESMB_DIR is mounted at /esmb-dir, set accordingly
	$ export ESMB_DIR=/esmb-dir

Then, in the Fedora 31 system, use the ``svm-tool`` to generate the owner
keys:

.. code-block:: sh

	$ svm-tool esm generate	-p rsapubkey -s rsaprivkey

	$ exit		# exit container if running in one

This generates the files ``rsapubkey`` and ``rsaprivkey`` files in
``$ESMB_DIR`` directory.

Obtain System TPM's key
-----------------------

On the system where you want to the run the SVM, run:

.. code-block:: sh

	$ sudo /bin/bash

	$ export TPM_INTERFACE_TYPE="dev"

	$ export TPM_DEVICE="/dev/tpm0"

	$ tssreadpublic -ho 81800001 -opem tpmrsapubkey.pem

See ``skiboot.git/libstb/tss2/opalcreate.c`` for the constant ``81800001``.

Copy the ``tpmrsapubkey.pem`` file into the appropriate place in the
above directory tree ($ESMB_DIR)

``tssreadpublic`` is provided by ``tss2`` package on Fedora 31 or can be
built from sources found at one of following locations:

	- git clone https://git.code.sf.net/p/ibmtpm20tss/tss ibmtpm20tss-tss
	- git@github.ibm.com:cclaudio/ibmtss.git
	- https://sourceforge.net/projects/ibmswtpm2/files/
	- git://github.ibm.com/linux-integrity/tpm2


Organize the information
========================

Organize the information needed for the ESM blob in a directory tree shown
below. The information can be organized in other layouts to suit your needs.
The only requirement is that the YAML file `svm_blob.yml` correctly point
to the various components (keys, initrd, vmlinux etc).

.. code-block:: c

	$ export ESMB_DIR=$HOME/esmb-dir

	$ mkdir $ESMB_DIR

	$ cd $ESMB_DIR

	$ tree
	.
	├── attachments
	│   └── attachment-1.txt
	├── initrd.img
	├── rsaprivkey
	├── rsapubkey
	├── svm_blob.yml
	├── tpmrsapubkey.pem
	└── vmlinux

	1 directory, 7 files


Create YAML configuration file
==============================

Create an YAML configuration file ``svm_blob.yml`` to describe the contents
of the ESM blob.

A configuration example is shown below.

Note that path names in the yaml file are relative to the ${ESMB_DIR}. This
assumes that the ``svm-tool`` is executed with ${ESMB_DIR} as $PWD.

.. code-block:: bash

	$ cat $ESMB_DIR/svm_blob.yml

.. code-block:: yaml

	- origin:
		pubkey:		"rsapubkey"
		seckey:		"rsaprivkey"
	- recipient:
		comment:	"Machine1 TPM"
		pubkey:		"tpmrsapubkey.pem"
	- digest:
		args:		"init=/bin/sh svm=1"
		initramfs:	"initrd.img"
		kernel:		"vmlinux"
	- file:
		name:		"file-1"
		path:		"attachments/attachments-1.txt"
	- file:
		name:		"file-2"
		path:		"attachments/file-2.dump.xz"
	- file:
		name:		"file-abc"
		path:		"attachments/file-abc"


Create the blob and esmb-initrd
===============================

If running ``svm-tool`` inside a container, first start the container with
the $ESMB_DIR mapped into /esmb-dir in the container:

.. code-block:: sh

	$ docker run -it -v ${ESMB_DIR}:/esmb-dir:z  \
			--user ${UID}:${UID} --group-add ${UID}  \
			my-fc31

	# In the container, ESMB_DIR is mounted at /esmb-dir, set accordingly
	$ export ESMB_DIR=/esmb-dir

Then, in the Fedora 31 system, use the ``svm-tool`` to create the blob:

.. code-block:: sh

	$ cd ${ESMB_DIR}

	$ svm-tool esm make -b test_esmb.dtb -y svm_blob.yml

	# Add blob to initrd. Ensure initrd path to -i matches the yaml file
	$ svm-tool svm add -i initrd.img -b test_esmb.dtb -f esmb-initrd.img

	# exit if inside a container
	$ exit

``$ESMB_DIR/esmb-initrd.img`` contains the initrd that is appended with
the ESM blob and can be used to boot SVM on the appropriate machines.

Updating esmb-initrd
====================

Note that ``esmb-initrd.img`` cannot be directly updated to say add a new
attachment or new TPM key.

Instead update the ESM blob with the new TPM keys and any attachments using
the ``svm-tool esm`` command. Then reattach the updated ESM blob to generate
a new ``esmb-initrd.img``.

Adding lockboxes to ESM Blob
============================

If the ESM blob is intended to be used on another system, we must first
add the TPM key of that system to the blob.  This can be done using the
``svm-tool esm authorize`` command as shown below. (In ``svm-tool`` terms,
the TPM key is placed inside a *lockbox* in the ESM blob).

See README in this directory for more details on authorizing a key.

If running ``svm-tool`` inside a container, first run the container with
the $ESMB_DIR mapped into /esmb-dir in the container:

.. code-block:: sh

	$ docker run -it -v ${ESMB_DIR}:/esmb-dir:z      \
			--user ${UID}:${UID} --group-add ${UID}  \
			my-fc31

	$ export ESMB_DIR=/esmb-dir

Then use the ``svm-tool esm authorize`` to add the lockbox

.. code-block:: sh

	$ svm-tool esm authorize -b test_esmb.dtb -c "Machine2-TPM" \
			-p tpm2rsapubkey.pem -s rsaprivkey

	# exit if inside a container
	$ exit

Alternate Layout
================

We can use a more general layout like the one below to organize the
information needed to build the ESM blob. We just have to make sure
that the path names in the YAML file and to the svm-tool command
invocations correctly identify the various files.

.. code-block:: c

	$ export ESMB_DIR=$HOME/esmb-dir

	$ mkdir $ESMB_DIR

	$ cd $ESMB_DIR

	# Create following tree structure under $ESMB_DIR

	$ tree $ESMB_DIR

	├── boot
	│   └── vmlinux
	│   └── initrd
	├── attachments
	│   └── guest
	│       ├── guest.dump.xz
	│       ├── guest.json
	│       ├── guest-protected.dump.xz
	│       └── guest-protected.json
	├── cfg_files
	│   └── svm_blob.yml
	├── esm_blob
	└── keys
		├── owner
		│   ├── rsaprivkey
		│   └── rsapubkey
		└── tpm
			└── tpmrsapubkey.pem
			└── tpm2rsapubkey.pem

Example YAML file for Alternate Layout
======================================

Create an YAML configuration file in ``$ESMB_DIR/cfg_files`` to describe
the contents of the ESM blob.

A configuration example is show below. The ``svm-setup`` tool will replace
the `initramfs` and `kernel` attributes based on the kernel version used.

Note that path names in the yaml file start with esmb-dir and assume
that the svm-tool is run from **parent directory** of ``esmb-dir``.
If run inside a container, it is assumed that /esmb-dir in the container
is mapped to $ESMB_DIR and PWD is is root dir of the container.

.. code-block:: bash

	$ cat $ESMB_DIR/cfg_files/svm_blob.yml

.. code-block:: yaml

	- origin:
		pubkey: "esmb-dir/keys/owner/rsapubkey"
		seckey: "esmb-dir/keys/owner/rsaprivkey"
	- recipient:
		comment: "ultra_tpm"
		pubkey: "esmb-dir/keys/tpm/tpmrsapubkey.pem"
	- digest:
		args: "init=/bin/sh svm=1"
		initramfs: "esmb-dir/boot/initrd.img"
		kernel: "esmb-dir/boot/vmlinux"
	- file:
		name: "file-1"
		path: "esmb-dir/attachments/guest/file-1.dump.xz"
	- file:
		name: "file-2"
		path: "esmb-dir/attachments/guest/file-2.dump.xz"
	- file:
		name: "file-abc"
		path: "esmb-dir/attachments/guest/file-abc"

