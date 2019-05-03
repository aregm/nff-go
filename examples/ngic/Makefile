# Copyright 2017 Intel Corporation.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

PATH_TO_MK = ../../mk
IMAGENAME = ngicdp
EXECUTABLES = ngicdp
LDFLAGS = -ldflags "

# To enable static arp uncomment the following line
# LDFLAGS += -X main.EnableStaticARP=true

# To enable CP simulator uncomment the following line
# LDFLAGS += -X main.RunCPSimu=true

# To enable PCAP capture uncomment the following line
# LDFLAGS += -X main.EnablePcap=true

LDFLAGS += "

GO_COMPILE_FLAGS += $(LDFLAGS)

include $(PATH_TO_MK)/leaf.mk
