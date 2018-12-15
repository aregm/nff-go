# Copyright 2017 Intel Corporation. 
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

PATH_TO_MK = ../mk
IMAGENAME = nff-go-base
EXECUTABLES =
NOCHECK_PKTGEN = yes

# This will not be used from "make deploy" or "make images" by default
# You should change images rule in mk/leaf.mk from "Dockerfile" to "Fedora"
Fedora: Makefile
	echo 'ARG USER_NAME' > Dockerfile
	echo 'FROM fedora' >> Dockerfile
	if [ -n '${http_proxy}' ]; then					\
		echo 'ENV http_proxy ${http_proxy}' >> Dockerfile;	\
		echo 'ENV https_proxy ${https_proxy}' >> Dockerfile;	\
		echo 'RUN echo proxy=${http_proxy} >> /etc/dnf/dnf.conf' >> Dockerfile;	\
	fi
	echo 'RUN dnf -y install numactl-libs.x86_64; dnf clean all' >> Dockerfile
	echo 'CMD ["/bin/bash"]' >> Dockerfile

Dockerfile: Makefile
	echo 'ARG USER_NAME' > Dockerfile
	echo 'FROM ubuntu:cosmic' >> Dockerfile
	if [ -n '${http_proxy}' ]; then                                 \
		echo 'ENV http_proxy ${http_proxy}' >> Dockerfile;      \
		echo 'ENV https_proxy ${https_proxy}' >> Dockerfile;     \
		echo 'RUN echo Acquire::http::Proxy \"${http_proxy}\"\; >> /etc/apt/apt.conf' >> Dockerfile;    \
		echo 'RUN echo Acquire::https::Proxy \"${https_proxy}\"\; >> /etc/apt/apt.conf' >> Dockerfile;    \
	fi
	echo 'RUN apt-get update; apt-get install -y pciutils; apt-get install -y libnuma-dev; apt-get install -y libpcap0.8-dev; apt-get install -y liblua5.3-dev; apt-get clean all' >> Dockerfile
	echo 'CMD ["/bin/bash"]' >> Dockerfile

.PHONY: dpdk
dpdk:

include $(PATH_TO_MK)/leaf.mk
