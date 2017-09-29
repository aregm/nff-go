# Copyright 2017 Intel Corporation. 
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

PATH_TO_MK = ../mk
IMAGENAME = yanff-base
EXECUTABLES =
NOCHECK_PKTGEN = yes

Dockerfile:
	echo 'FROM fedora' > Dockerfile
	if [ -n '${http_proxy}' ]; then					\
		echo 'ENV http_proxy ${http_proxy}' >> Dockerfile;	\
		echo 'ENV https_proxy ${http_proxy}' >> Dockerfile;	\
	fi
	echo 'RUN dnf -y install numactl-libs.x86_64; dnf clean all' >> Dockerfile
	echo 'CMD ["/bin/bash"]' >> Dockerfile

include $(PATH_TO_MK)/leaf.mk
