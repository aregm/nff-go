PATH_TO_MK = ../mk
SUBDIRS = nfvbase dpdk main stability performance stash

include $(PATH_TO_MK)/intermediate.mk

apptype_string.go:
	go generate

all: apptype_string.go

