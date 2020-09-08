# -*- mode: Makefile; -*-

#-------------------------------------------------------------------------------
# 2016-11-10
#-------------------------------------------------------------------------------
SHELL=/bin/bash
BASE_DIR := $(subst /build,,$(CURDIR))
PAL_DIR := $(shell cd ../../pal; pwd -P)

PF_POSIX := 1
include $(BASE_DIR)/build/config.mak
include $(BASE_DIR)/build/Makefile.version
include $(PAL_DIR)/build/Makefile.pal

ifeq ($(CENTOS5_BUILD_ENV),1)
ROOT_DIR := $(shell cd ../../..; pwd -P)
DEV_TOOLS_PATH=/opt/rh/devtoolset-2/root/usr/bin:
else
ROOT_DIR := $(shell cd ../..; pwd -P)
DEV_TOOLS_PATH=
endif

ifndef ENABLE_DEBUG
$(error "ENABLE_DEBUG is not set.  Please re-run configure")
endif

INTERMEDIATE_DIR=$(BASE_DIR)/intermediate/$(BUILD_CONFIGURATION)
TARGET_DIR := $(BASE_DIR)/target/$(BUILD_CONFIGURATION)
BUILD_DIR=$(INTERMEDIATE_DIR)/builddir
RELEASE_DIR=$(BUILD_DIR)/release
AUOMS_BIN=$(RELEASE_DIR)/bin/auoms
AUOMSCOLLECT_BIN=$(RELEASE_DIR)/bin/auomscollect
AUOMSCTL_BIN=$(RELEASE_DIR)/bin/auomsctl
SEPOLICY_SRC_DIR=$(BASE_DIR)/installer/selinux
SEPOLICY_DIR=$(INTERMEDIATE_DIR)/selinux

# Compiler flags

#CMAKE_BUILD_TYPE=Release
CMAKE_BUILD_TYPE=RelWithDebInfo
ifeq ($(ENABLE_DEBUG),1)
CMAKE_BUILD_TYPE=Debug
endif

# Support for installbuilder

STAGING_DIR := $(INTERMEDIATE_DIR)/staging
INSTALLER_TMPDIR := $(INTERMEDIATE_DIR)/installer_tmp

INSTALLER_DATAFILES := base_auoms.data linux.data
INSTALLER_DATAFILES_RPM := $(INSTALLER_DATAFILES) linux_rpm.data
INSTALLER_DATAFILES_DPKG := $(INSTALLER_DATAFILES) linux_dpkg.data

ifeq ($(PACKAGE_SUFFIX),rpm)
INSTALLER_DATAFILES_CURRENT := $(INSTALLER_DATAFILES_RPM)
else
INSTALLER_DATAFILES_CURRENT := $(INSTALLER_DATAFILES_DPKG)
endif

ifeq ("$(wildcard /usr/bin/dpkg-deb)","")
DPKG_LOCATION="--DPKG_LOCATION=$(PAL_DIR)/installer/InstallBuilder/tools/bin/dpkg-deb-$(PF_ARCH)"
else
DPKG_LOCATION=
endif

ifeq ($(ULINUX),1)
  OUTPUT_PACKAGE_PREFIX=auoms-$(AUOMS_BUILDVERSION_MAJOR).$(AUOMS_BUILDVERSION_MINOR).$(AUOMS_BUILDVERSION_PATCH)-$(AUOMS_BUILDVERSION_BUILDNR).universal.$(PF_ARCH)
  ifeq ($(CMAKE_BUILD_TYPE),RelWithDebInfo)
    OUTPUT_PACKAGE_PREFIX_DEBUG=auoms-debug-$(AUOMS_BUILDVERSION_MAJOR).$(AUOMS_BUILDVERSION_MINOR).$(AUOMS_BUILDVERSION_PATCH)-$(AUOMS_BUILDVERSION_BUILDNR).universal.$(PF_ARCH)
  endif
else
  PF_DISTRO_LC := $(shell echo $(PF_DISTRO) | tr A-Z a-z)
  OUTPUT_PACKAGE_PREFIX=auoms-$(AUOMS_BUILDVERSION_MAJOR).$(AUOMS_BUILDVERSION_MINOR).$(AUOMS_BUILDVERSION_PATCH)-$(AUOMS_BUILDVERSION_BUILDNR).$(PF_DISTRO_LC).$(PF_MAJOR).$(PF_ARCH)
  ifeq ($(CMAKE_BUILD_TYPE),RelWithDebInfo)
    OUTPUT_PACKAGE_PREFIX_DEBUG=auoms-debug-$(AUOMS_BUILDVERSION_MAJOR).$(AUOMS_BUILDVERSION_MINOR).$(AUOMS_BUILDVERSION_PATCH)-$(AUOMS_BUILDVERSION_BUILDNR).$(PF_DISTRO_LC).$(PF_MAJOR).$(PF_ARCH)
  endif
endif

#--------------------------------------------------------------------------------
# Build targets
.PHONY: all clean distclean clean-status packages kit
.PHONY: tests test

all : $(AUOMS_BIN) sepolicy kit

clean : clean-status
	sudo $(RMDIR) $(BASE_DIR)/intermediate
	sudo $(RMDIR) $(BASE_DIR)/target

clean-kit :
	$(RMDIR) $(BASE_DIR)/target
	$(RMDIR) $(INTERMEDIATE_DIR)/*.{tar,rpm,deb}

distclean : clean
	-$(RM) $(BASE_DIR)/build/Makefile.version
	-$(RM) $(BASE_DIR)/build/config.mak
	-$(RM) $(PAL_DIR)/build/config.mak

clean-status :
	@$(ECHO) "========================= Performing make clean"

#================================================================================
# Internal functions
#================================================================================

# No default rules, please
.SUFFIX:

ifeq ($(ULINUX),1)
$(AUOMS_BIN) : $(INTERMEDIATE_DIR)/ext_include $(INTERMEDIATE_DIR)/boost_root $(BUILD_DIR) $(BASE_DIR)/*.cpp $(BASE_DIR)/*.h
	@echo "========================= Building auoms"
	cd $(BUILD_DIR); PATH=$(DEV_TOOLS_PATH)$(PATH) make install

$(BUILD_DIR) :
	@echo "========================= Creating cmake builddir dir"
	$(MKPATH) $(BUILD_DIR)
	cd $(BUILD_DIR); PATH=$(DEV_TOOLS_PATH)$(PATH) BOOST_ROOT=$(INTERMEDIATE_DIR)/boost_root cmake -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++ -DDO_STATIC_LINK=1 -DCMAKE_BUILD_TYPE=$(CMAKE_BUILD_TYPE) $(BASE_DIR)
else
$(AUOMS_BIN) : $(INTERMEDIATE_DIR)/ext_include $(BUILD_DIR) $(BASE_DIR)/*.cpp $(BASE_DIR)/*.h
	@echo "========================= Building auoms"
	cd $(BUILD_DIR); make install

$(BUILD_DIR) :
	@echo "========================= Creating cmake builddir dir"
	$(MKPATH) $(BUILD_DIR)
	cd $(BUILD_DIR); cmake -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++ -DCMAKE_BUILD_TYPE=$(CMAKE_BUILD_TYPE) $(BASE_DIR)
endif

ifeq ($(ULINUX),1)
$(SEPOLICY_DIR)/auoms.pp : $(SEPOLICY_SRC_DIR)/auoms.te $(SEPOLICY_SRC_DIR)/auoms.fc
	@echo "========================= Building selinux policy module"
	$(MKPATH) $(SEPOLICY_DIR)
	$(COPY) $(SEPOLICY_SRC_DIR)/auoms.te $(SEPOLICY_SRC_DIR)/auoms.fc $(SEPOLICY_DIR)
	cd $(SEPOLICY_DIR); make -f /usr/share/selinux/devel/Makefile
else
$(SEPOLICY_DIR)/auoms.pp : $(SEPOLICY_SRC_DIR)/auoms.te $(SEPOLICY_SRC_DIR)/auoms.fc
	@echo "========================= Building selinux policy module"
	$(MKPATH) $(SEPOLICY_DIR)
	touch $(SEPOLICY_DIR)/auoms.pp
endif

sepolicy : $(SEPOLICY_DIR)/auoms.pp

ifeq ($(ULINUX),1)
test : $(AUOMS_BIN)
	cd $(BUILD_DIR); PATH=$(DEV_TOOLS_PATH)$(PATH) make test
else
test : $(AUOMS_BIN)
	cd $(BUILD_DIR); make test
endif

tests : test

ext_include: $(INTERMEDIATE_DIR)/ext_include

$(INTERMEDIATE_DIR)/ext_include :
	@echo "========================= Creating ext_include dir"
	$(MKPATH) $(INTERMEDIATE_DIR)/tmp/ext_include
	tar zxf $(ROOT_DIR)/rapidjson-1.0.2.tar.gz -C $(INTERMEDIATE_DIR)/tmp
	cp -r $(INTERMEDIATE_DIR)/tmp/rapidjson-1.0.2/include/* $(INTERMEDIATE_DIR)/tmp/ext_include
	unzip -q -d $(INTERMEDIATE_DIR)/tmp $(ROOT_DIR)/msgpack-c-cpp-2.0.0.zip
	cp -r $(INTERMEDIATE_DIR)/tmp/msgpack-c-cpp-2.0.0/include/* $(INTERMEDIATE_DIR)/tmp/ext_include
	mv $(INTERMEDIATE_DIR)/tmp/ext_include $(INTERMEDIATE_DIR)
	$(RMDIR) $(INTERMEDIATE_DIR)/tmp

ifeq ($(ULINUX),1)
$(INTERMEDIATE_DIR)/boost_root :
	@echo "========================= Creating boost_root dir"
	$(MKPATH) $(INTERMEDIATE_DIR)/tmp/boost_root/include
	$(MKPATH) $(INTERMEDIATE_DIR)/tmp/boost_root/lib
	ln -s /usr/include/boost148/boost $(INTERMEDIATE_DIR)/tmp/boost_root/include/boost
	cd $(INTERMEDIATE_DIR)/tmp/boost_root/lib; for file in $$(ls $(USR_LIB_DIR)/libboost*.1.48.0); do name=$$(basename $$file); lname=$$(basename $$file .1.48.0); ln -s $$file $$name; ln -s $$file $$lname; done
	mv $(INTERMEDIATE_DIR)/tmp/boost_root $(INTERMEDIATE_DIR)
	$(RMDIR) $(INTERMEDIATE_DIR)/tmp
endif

#--------------------------------------------------------------------------------
# Build the distribution kit
#
# Build the packages via installbuilder
#
# While the "formal build" only builds ULINUX, we may build something else for DEV purposes.
# Assume we ALWAYS build RPM, but only build DPKG if --enable-ulinux is specified in configure.

$(TARGET_DIR):
	mkdir -p $(TARGET_DIR)

ifeq ($(ULINUX),1)

ifeq ($(CMAKE_BUILD_TYPE),RelWithDebInfo)

packages: $(TARGET_DIR) $(TARGET_DIR)/$(OUTPUT_PACKAGE_PREFIX).rpm $(TARGET_DIR)/$(OUTPUT_PACKAGE_PREFIX).deb $(TARGET_DIR)/$(OUTPUT_PACKAGE_PREFIX_DEBUG).rpm $(TARGET_DIR)/$(OUTPUT_PACKAGE_PREFIX_DEBUG).deb

kit : $(TARGET_DIR)/auoms-bundle-test.sh $(TARGET_DIR)/$(OUTPUT_PACKAGE_PREFIX).sh $(TARGET_DIR)/$(OUTPUT_PACKAGE_PREFIX_DEBUG).rpm $(TARGET_DIR)/$(OUTPUT_PACKAGE_PREFIX_DEBUG).deb

$(TARGET_DIR)/$(OUTPUT_PACKAGE_PREFIX_DEBUG).rpm : $(INTERMEDIATE_DIR)/$(OUTPUT_PACKAGE_PREFIX_DEBUG).rpm
	$(COPY) $(INTERMEDIATE_DIR)/$(OUTPUT_PACKAGE_PREFIX_DEBUG).rpm $(TARGET_DIR)/$(OUTPUT_PACKAGE_PREFIX_DEBUG).rpm

$(TARGET_DIR)/$(OUTPUT_PACKAGE_PREFIX_DEBUG).deb : $(INTERMEDIATE_DIR)/$(OUTPUT_PACKAGE_PREFIX_DEBUG).deb
	$(COPY) $(INTERMEDIATE_DIR)/$(OUTPUT_PACKAGE_PREFIX_DEBUG).deb $(TARGET_DIR)/$(OUTPUT_PACKAGE_PREFIX_DEBUG).deb

else
packages: $(TARGET_DIR) $(TARGET_DIR)/$(OUTPUT_PACKAGE_PREFIX_DEBUG).rpm $(TARGET_DIR)/$(OUTPUT_PACKAGE_PREFIX_DEBUG).deb
kit : $(TARGET_DIR)/auoms-bundle-test.sh $(TARGET_DIR)/$(OUTPUT_PACKAGE_PREFIX).sh
endif

$(TARGET_DIR)/$(OUTPUT_PACKAGE_PREFIX).rpm : $(INTERMEDIATE_DIR)/$(OUTPUT_PACKAGE_PREFIX).rpm
	$(COPY) $(INTERMEDIATE_DIR)/$(OUTPUT_PACKAGE_PREFIX).rpm $(TARGET_DIR)/$(OUTPUT_PACKAGE_PREFIX).rpm

$(TARGET_DIR)/$(OUTPUT_PACKAGE_PREFIX).deb : $(INTERMEDIATE_DIR)/$(OUTPUT_PACKAGE_PREFIX).deb
	$(COPY) $(INTERMEDIATE_DIR)/$(OUTPUT_PACKAGE_PREFIX).deb $(TARGET_DIR)/$(OUTPUT_PACKAGE_PREFIX).deb

$(TARGET_DIR)/auoms-bundle-test.sh : $(TARGET_DIR)/$(OUTPUT_PACKAGE_PREFIX).sh
	$(COPY) ../installer/bundle/auoms-bundle-test.sh $(TARGET_DIR)/auoms-bundle-test.sh

$(TARGET_DIR)/$(OUTPUT_PACKAGE_PREFIX).sh : $(INTERMEDIATE_DIR)/$(OUTPUT_PACKAGE_PREFIX).tar
	@echo "========================= Performing Building shell bundle"
	$(MKPATH) $(TARGET_DIR)
	../installer/bundle/create_bundle.sh $(TARGET_DIR) $(INTERMEDIATE_DIR) $(OUTPUT_PACKAGE_PREFIX).tar

$(INTERMEDIATE_DIR)/$(OUTPUT_PACKAGE_PREFIX).tar : packages

	@echo "========================= Performing Building .tar file"

	# Build the tar file containing both .rpm and .deb packages
	cd $(INTERMEDIATE_DIR); tar cvf $(OUTPUT_PACKAGE_PREFIX).tar $(OUTPUT_PACKAGE_PREFIX).{deb,rpm}

$(INTERMEDIATE_DIR)/$(OUTPUT_PACKAGE_PREFIX).rpm: $(AUOMS_BIN) sepolicy
	@echo "========================= Performing Building RPM package"
	$(MKPATH) $(INSTALLER_TMPDIR)

	sudo $(RMDIR) $(STAGING_DIR)
	python $(PAL_DIR)/installer/InstallBuilder/installbuilder.py \
		--BASE_DIR=$(BASE_DIR) \
		--TARGET_DIR=$(INTERMEDIATE_DIR) \
		--INTERMEDIATE_DIR=$(INSTALLER_TMPDIR) \
		--STAGING_DIR=$(STAGING_DIR) \
		--BUILD_TYPE=$(BUILD_TYPE) \
		--BUILD_CONFIGURATION=$(BUILD_CONFIGURATION) \
		--PFARCH=$(PF_ARCH) \
		--PFDISTRO=$(PF_DISTRO) \
		--PFMAJOR=$(PF_MAJOR) \
		--PFMINOR=$(PF_MINOR) \
		--VERSION=$(AUOMS_BUILDVERSION_MAJOR).$(AUOMS_BUILDVERSION_MINOR).$(AUOMS_BUILDVERSION_PATCH) \
		--RELEASE=$(AUOMS_BUILDVERSION_BUILDNR) \
		--VERSION_IDENT="$(AUOMS_BUILDVERSION_DATE) $(AUOMS_BUILDVERSION_STATUS)" \
		--DATAFILE_PATH=$(BASE_DIR)/installer/datafiles \
		--OUTPUTFILE=$(OUTPUT_PACKAGE_PREFIX) \
		$(INSTALLER_DATAFILES_RPM)
	sudo $(RMDIR) $(STAGING_DIR)

$(INTERMEDIATE_DIR)/$(OUTPUT_PACKAGE_PREFIX).deb: $(AUOMS_BIN) sepolicy
	@echo "========================= Performing Building DEB package"
	$(MKPATH) $(INSTALLER_TMPDIR)

	sudo $(RMDIR) $(STAGING_DIR)
	sudo python $(PAL_DIR)/installer/InstallBuilder/installbuilder.py \
		--BASE_DIR=$(BASE_DIR) \
		--TARGET_DIR=$(INTERMEDIATE_DIR) \
		--INTERMEDIATE_DIR=$(INSTALLER_TMPDIR) \
		--STAGING_DIR=$(STAGING_DIR) \
		--BUILD_TYPE=$(BUILD_TYPE) \
		--BUILD_CONFIGURATION=$(BUILD_CONFIGURATION) \
		--PFARCH=$(PF_ARCH) \
		--PFDISTRO=$(PF_DISTRO) \
		--PFMAJOR=$(PF_MAJOR) \
		--PFMINOR=$(PF_MINOR) \
		--VERSION=$(AUOMS_BUILDVERSION_MAJOR).$(AUOMS_BUILDVERSION_MINOR).$(AUOMS_BUILDVERSION_PATCH) \
		--RELEASE=$(AUOMS_BUILDVERSION_BUILDNR) \
		--VERSION_IDENT="$(AUOMS_BUILDVERSION_DATE) $(AUOMS_BUILDVERSION_STATUS)" \
		$(DPKG_LOCATION) \
		--DATAFILE_PATH=$(BASE_DIR)/installer/datafiles \
		--OUTPUTFILE=$(OUTPUT_PACKAGE_PREFIX) \
		$(INSTALLER_DATAFILES_DPKG)
	sudo chown --reference=$(BASE_DIR) $(INTERMEDIATE_DIR)/$(OUTPUT_PACKAGE_PREFIX).deb
	sudo $(RMDIR) $(STAGING_DIR)

ifeq ($(CMAKE_BUILD_TYPE),RelWithDebInfo)
$(INTERMEDIATE_DIR)/$(OUTPUT_PACKAGE_PREFIX_DEBUG).rpm: $(AUOMS_BIN).debug
	@echo "========================= Performing Building RPM package"
	$(MKPATH) $(INSTALLER_TMPDIR)

	sudo $(RMDIR) $(STAGING_DIR)
	python $(PAL_DIR)/installer/InstallBuilder/installbuilder.py \
		--BASE_DIR=$(BASE_DIR) \
		--TARGET_DIR=$(INTERMEDIATE_DIR) \
		--INTERMEDIATE_DIR=$(INSTALLER_TMPDIR) \
		--STAGING_DIR=$(STAGING_DIR) \
		--BUILD_TYPE=$(BUILD_TYPE) \
		--BUILD_CONFIGURATION=$(BUILD_CONFIGURATION) \
		--PFARCH=$(PF_ARCH) \
		--PFDISTRO=$(PF_DISTRO) \
		--PFMAJOR=$(PF_MAJOR) \
		--PFMINOR=$(PF_MINOR) \
		--VERSION=$(AUOMS_BUILDVERSION_MAJOR).$(AUOMS_BUILDVERSION_MINOR).$(AUOMS_BUILDVERSION_PATCH) \
		--RELEASE=$(AUOMS_BUILDVERSION_BUILDNR) \
		--VERSION_IDENT="$(AUOMS_BUILDVERSION_DATE) $(AUOMS_BUILDVERSION_STATUS)" \
		--DATAFILE_PATH=$(BASE_DIR)/installer/datafiles-debug \
		--OUTPUTFILE=$(OUTPUT_PACKAGE_PREFIX_DEBUG) \
		$(INSTALLER_DATAFILES_RPM)
	sudo $(RMDIR) $(STAGING_DIR)

$(INTERMEDIATE_DIR)/$(OUTPUT_PACKAGE_PREFIX_DEBUG).deb: $(AUOMS_BIN).debug
	@echo "========================= Performing Building DEB package"
	$(MKPATH) $(INSTALLER_TMPDIR)

	sudo $(RMDIR) $(STAGING_DIR)
	sudo python $(PAL_DIR)/installer/InstallBuilder/installbuilder.py \
		--BASE_DIR=$(BASE_DIR) \
		--TARGET_DIR=$(INTERMEDIATE_DIR) \
		--INTERMEDIATE_DIR=$(INSTALLER_TMPDIR) \
		--STAGING_DIR=$(STAGING_DIR) \
		--BUILD_TYPE=$(BUILD_TYPE) \
		--BUILD_CONFIGURATION=$(BUILD_CONFIGURATION) \
		--PFARCH=$(PF_ARCH) \
		--PFDISTRO=$(PF_DISTRO) \
		--PFMAJOR=$(PF_MAJOR) \
		--PFMINOR=$(PF_MINOR) \
		--VERSION=$(AUOMS_BUILDVERSION_MAJOR).$(AUOMS_BUILDVERSION_MINOR).$(AUOMS_BUILDVERSION_PATCH) \
		--RELEASE=$(AUOMS_BUILDVERSION_BUILDNR) \
		--VERSION_IDENT="$(AUOMS_BUILDVERSION_DATE) $(AUOMS_BUILDVERSION_STATUS)" \
		$(DPKG_LOCATION) \
		--DATAFILE_PATH=$(BASE_DIR)/installer/datafiles-debug \
		--OUTPUTFILE=$(OUTPUT_PACKAGE_PREFIX_DEBUG) \
		$(INSTALLER_DATAFILES_DPKG)
	sudo chown --reference=$(BASE_DIR) $(INTERMEDIATE_DIR)/$(OUTPUT_PACKAGE_PREFIX_DEBUG).deb
	sudo $(RMDIR) $(STAGING_DIR)
endif

else

ifeq ($(CMAKE_BUILD_TYPE),RelWithDebInfo)
packages : $(TARGET_DIR) $(TARGET_DIR)/$(OUTPUT_PACKAGE_PREFIX).$(PACKAGE_SUFFIX) $(INTERMEDIATE_DIR)/$(OUTPUT_PACKAGE_PREFIX_DEBUG).rpm $(INTERMEDIATE_DIR)/$(OUTPUT_PACKAGE_PREFIX_DEBUG).deb
kit: packages
else
packages : $(TARGET_DIR) $(TARGET_DIR)/$(OUTPUT_PACKAGE_PREFIX).$(PACKAGE_SUFFIX)
kit: packages
endif

$(TARGET_DIR)/$(OUTPUT_PACKAGE_PREFIX).$(PACKAGE_SUFFIX) : $(AUOMS_BIN) sepolicy

	@echo "========================= Performing Building installation package"
	$(MKPATH) $(TARGET_DIR)
	$(MKPATH) $(INSTALLER_TMPDIR)
	sudo $(RMDIR) $(STAGING_DIR)
	sudo python $(PAL_DIR)/installer/InstallBuilder/installbuilder.py \
		--BASE_DIR=$(BASE_DIR) \
		--TARGET_DIR=$(TARGET_DIR) \
		--INTERMEDIATE_DIR=$(INSTALLER_TMPDIR) \
		--STAGING_DIR=$(STAGING_DIR) \
		--BUILD_TYPE=$(BUILD_TYPE) \
		--BUILD_CONFIGURATION=$(BUILD_CONFIGURATION) \
		--PFARCH=$(PF_ARCH) \
		--PFDISTRO=$(PF_DISTRO) \
		--PFMAJOR=$(PF_MAJOR) \
		--PFMINOR=$(PF_MINOR) \
		--VERSION=$(AUOMS_BUILDVERSION_MAJOR).$(AUOMS_BUILDVERSION_MINOR).$(AUOMS_BUILDVERSION_PATCH) \
		--RELEASE=$(AUOMS_BUILDVERSION_BUILDNR) \
		--VERSION_IDENT="$(AUOMS_BUILDVERSION_DATE) $(AUOMS_BUILDVERSION_STATUS)" \
		--DATAFILE_PATH=$(BASE_DIR)/installer/datafiles \
		--OUTPUTFILE=$(OUTPUT_PACKAGE_PREFIX) \
		$(INSTALLER_DATAFILES_CURRENT)
	sudo $(RMDIR) $(STAGING_DIR)

ifeq ($(CMAKE_BUILD_TYPE),RelWithDebInfo)
$(TARGET_DIR)/$(OUTPUT_PACKAGE_PREFIX_DEBUG).$(PACKAGE_SUFFIX) : $(AUOMS_BIN).debug

	@echo "========================= Performing Building installation package"
	$(MKPATH) $(TARGET_DIR)
	$(MKPATH) $(INSTALLER_TMPDIR)
	sudo $(RMDIR) $(STAGING_DIR)
	sudo python $(PAL_DIR)/installer/InstallBuilder/installbuilder.py \
		--BASE_DIR=$(BASE_DIR) \
		--TARGET_DIR=$(TARGET_DIR) \
		--INTERMEDIATE_DIR=$(INSTALLER_TMPDIR) \
		--STAGING_DIR=$(STAGING_DIR) \
		--BUILD_TYPE=$(BUILD_TYPE) \
		--BUILD_CONFIGURATION=$(BUILD_CONFIGURATION) \
		--PFARCH=$(PF_ARCH) \
		--PFDISTRO=$(PF_DISTRO) \
		--PFMAJOR=$(PF_MAJOR) \
		--PFMINOR=$(PF_MINOR) \
		--VERSION=$(AUOMS_BUILDVERSION_MAJOR).$(AUOMS_BUILDVERSION_MINOR).$(AUOMS_BUILDVERSION_PATCH) \
		--RELEASE=$(AUOMS_BUILDVERSION_BUILDNR) \
		--VERSION_IDENT="$(AUOMS_BUILDVERSION_DATE) $(AUOMS_BUILDVERSION_STATUS)" \
		--DATAFILE_PATH=$(BASE_DIR)/installer/datafiles-debug \
		--OUTPUTFILE=$(OUTPUT_PACKAGE_PREFIX_DEBUG) \
		$(INSTALLER_DATAFILES_CURRENT)
	sudo $(RMDIR) $(STAGING_DIR)
endif

endif
