PATH_TO_MK = ../mk
SUBDIRS = main stability performance stash

apptype_string.go:
	go generate

main: apptype_string.go

include $(PATH_TO_MK)/intermediate.mk
