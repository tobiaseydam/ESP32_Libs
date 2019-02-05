#
# This is a project Makefile. It is assumed the directory this Makefile resides in is a
# project subdirectory.
#

PROJECT_NAME := ESP32_Libs

GIT_VERSION := $(shell git describe --abbrev=6 --dirty --always --tags)
CPPFLAGS += -DGIT_VERSION=\"$(GIT_VERSION)\"

include $(IDF_PATH)/make/project.mk

