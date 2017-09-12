# Copyright 2017 Intel Corporation. 
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

include $(PATH_TO_MK)/include.mk

# Always rebuild all tests and examples because changes in the library aren't tracked now
.PHONY: $(EXECUTABLES)

# Build all
.PHONY: clean
$(EXECUTABLES) : % : %.go
	go build $<

ifndef NOCHECK_PKTGEN
all: check-pktgen
endif
all: $(EXECUTABLES)

clean-default:
	-rm $(EXECUTABLES)

clean: clean-default

# Local docker targets
.PHONY: images clean-images

images: Dockerfile .check-defined-IMAGENAME all
	docker build -t $(IMAGENAME) .

clean-images: .check-defined-IMAGENAME clean
	-docker rmi $(IMAGENAME)

# Distributed docker targets
.PHONY: .check-deploy-env deploy cleanall

.check-deploy-env: .check-defined-YANFF_HOSTS .check-defined-DOCKER_PORT

deploy: .check-deploy-env images
	$(eval TMPNAME=tmp-$(IMAGENAME).tar)
	docker save $(IMAGENAME) > $(TMPNAME)
	for host in $(YANFF_HOSTS); do								\
		if ! docker -H tcp://$$host:$(DOCKER_PORT) load < $(TMPNAME); then break; fi;	\
	done
	rm $(TMPNAME)

cleanall: .check-deploy-env clean-images
	-for host in $(YANFF_HOSTS); do \
		docker -H tcp://$$host:$(DOCKER_PORT) rmi -f $(IMAGENAME); \
	done

testing:
	echo This target is not defined for this subdirectory
	exit 1
