PATH_TO_MK = ../mk
SUBDIRS = yanff-base main stability performance stash

include $(PATH_TO_MK)/intermediate.mk

apptype_string.go:
	go generate

all: check-pktgen apptype_string.go

