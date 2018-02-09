# Copyright 2017 Intel Corporation. 
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

include $(PATH_TO_MK)/include.mk

# Always rebuild all tests and examples because changes in the library aren't tracked now
.PHONY: $(EXECUTABLES)

# Build all
.PHONY: clean
$(EXECUTABLES) : % : %.go
	go build $< $(COMMON_FILES)
# Use the following line to build Go files without optimizations
#	go build -gcflags '-N -l' $< $(COMMON_FILES)

ifndef NOCHECK_PKTGEN
all: check-pktgen
endif
all: $(EXECUTABLES)

clean-default:
	-rm $(EXECUTABLES)

clean: clean-default

# Local docker targets
.PHONY: .check-images-env images clean-images

# Add user name to generated images unless it is yanff-base image
# because yanff-base image name is hardcoded in Dockerfiles and cannot
# be different for different users.
ifeq ($(IMAGENAME),yanff-base)
WORKIMAGENAME=$(IMAGENAME)
else
WORKIMAGENAME=$(USER)/$(IMAGENAME)
endif

.check-images-env: .check-defined-IMAGENAME

images: Dockerfile .check-images-env all
	docker build -t $(WORKIMAGENAME) .

clean-images: .check-images-env clean
	-docker rmi $(WORKIMAGENAME)

# Distributed docker targets
.PHONY: .check-deploy-env deploy cleanall

.check-deploy-env: .check-defined-YANFF_HOSTS

deploy: .check-deploy-env images
	$(eval TMPNAME=tmp-$(IMAGENAME).tar)
	docker save $(WORKIMAGENAME) > $(TMPNAME)
	for host in $(YANFF_HOSTS); do								\
		if ! docker -H tcp://$$host load < $(TMPNAME); then break; fi;	\
	done
	rm $(TMPNAME)

cleanall: .check-deploy-env clean-images
	-for host in $(YANFF_HOSTS); do \
		docker -H tcp://$$host rmi -f $(WORKIMAGENAME); \
	done
