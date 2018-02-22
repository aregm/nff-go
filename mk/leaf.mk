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

# Add user name to generated images
ifdef NFF_GO_IMAGE_PREFIX
WORKIMAGENAME=$(NFF_GO_IMAGE_PREFIX)/$(USER)/$(IMAGENAME)
else
WORKIMAGENAME=$(USER)/$(IMAGENAME)
endif

.check-images-env: .check-defined-IMAGENAME

images: Dockerfile .check-images-env all
	docker build --build-arg USER_NAME=$(USER) -t $(WORKIMAGENAME) .

clean-images: .check-images-env clean
	-docker rmi $(WORKIMAGENAME)

# Distributed docker targets
.PHONY: .check-deploy-env deploy cleanall

.check-deploy-env: .check-defined-NFF_GO_HOSTS

deploy: .check-deploy-env images
	$(eval TMPNAME=tmp-$(IMAGENAME).tar)
	docker save $(WORKIMAGENAME) > $(TMPNAME)
	for host in `echo $(NFF_GO_HOSTS) | tr ',' ' '`; do			\
		if ! docker -H tcp://$$host load < $(TMPNAME); then break; fi;	\
	done
	rm $(TMPNAME)

cleanall: .check-deploy-env clean-images
	-for host in `echo $(NFF_GO_HOSTS) | tr ',' ' '`; do	\
		docker -H tcp://$$host rmi -f $(WORKIMAGENAME);	\
	done
