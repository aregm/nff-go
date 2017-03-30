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

all: $(EXECUTABLES)

clean:
	-rm $(EXECUTABLES)

# Local docker targets
.PHONY: images clean-images

images: .check-defined-IMAGENAME all
	docker build -t $(IMAGENAME) .

clean-images: .check-defined-IMAGENAME clean
	-docker rmi $(IMAGENAME)

# Distributed docker targets
.PHONY: .check-deploy-env deploy cleanall

.check-deploy-env: .check-defined-YANFF_HOSTS .check-defined-DOCKER_PORT

deploy: .check-deploy-env images
	$(eval TMPNAME=tmp-$(IMAGENAME).tar)
	docker save $(IMAGENAME) > $(TMPNAME)
	for host in $(YANFF_HOSTS); do \
		docker -H tcp://$$host:$(DOCKER_PORT) load < $(TMPNAME); \
	done
	rm $(TMPNAME)

cleanall: .check-deploy-env clean-images
	-for host in $(YANFF_HOSTS); do \
		docker -H tcp://$$host:$(DOCKER_PORT) rmi -f $(IMAGENAME); \
	done
