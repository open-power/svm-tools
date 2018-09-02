# SPDX-License-Identifier: BSD-3-Clause
#
# Set default values for variables we expect from rpmbuild.
#
ifeq ($(DESTDIR),)
DESTDIR = $(HOME)
endif

ifeq ($(DRACUT_MOD_DST),)
DRACUT_MOD_DST = /usr/lib/dracut/modules.d/98svm/
endif

ifeq ($(BINDIR),)
BINDIR = /usr/bin/
endif

ifeq ($(RPMBUILDDIR),)
RPMBUILDDIR = $(shell pwd)/RPMDIR
endif

SVM_DRACUT_SRC	= dracut/modules.d/98svm/
SVM_DRACUT_DST	= $(DESTDIR)$(DRACUT_MOD_DST)
SVM_BIN_DST	= $(DESTDIR)$(BINDIR)
INSTALL		= /usr/bin/install
CFLAGS		= -g
NAME		= svm-password-agent
VER		= 0.0.1
TGZ		= $(NAME).tgz
TMP		= $(NAME)-$(VER)
CC		= $(CROSS)gcc$(POSTFIX) $(CFLAGS)

ALL		= src/esmb-get-file			\
		  $(SVM_DRACUT_SRC)module-setup.sh	\
		  $(SVM_DRACUT_SRC)svm-rootfs-askpass	\
		  $(SVM_DRACUT_SRC)svm-rootfs-hook.sh

all:	bin

bin:
	make -C src all

# Run clean so we don't include any binary files in the tgz
build:	clean
	mkdir $(TMP)
	cp -rl fedora/dracut \
		Makefile \
		src \
		fedora/svm-password-agent.spec \
		$(TMP)
	tar czf $(TGZ) $(TMP)
	rm -rf $(TMP)

rpm: build
	rpmbuild --define "_topdir $(RPMBUILDDIR)" -ta $(TGZ)

clean:
	make -C src clean
	rm -f $(TGZ)
	rm -rf $(TMP) $(RPMBUILDDIR)

install: all
	$(INSTALL) -d $(SVM_BIN_DST) $(SVM_DRACUT_DST)
	$(INSTALL) src/esmb-get-file $(SVM_BIN_DST)
	$(INSTALL) $(SVM_DRACUT_SRC)/svm-rootfs-askpass $(SVM_BIN_DST)
	$(INSTALL) $(SVM_DRACUT_SRC)/module-setup.sh $(SVM_DRACUT_DST)
	$(INSTALL) $(SVM_DRACUT_SRC)/svm-rootfs-hook.sh $(SVM_DRACUT_DST)
