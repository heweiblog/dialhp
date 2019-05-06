TGT=dialhp
DIALHP=./src
UDT = ./lib/udt4/
CLIB = ./clib/src/

all: build

build:
	cd $(UDT)    		   		&& $(MAKE)
	cd $(CLIB)    		   		&& $(MAKE)
	cd $(DIALHP)        		&& $(MAKE)

clean:
	rm -rf 	*~ *.swp $(TGT)
	cd $(DIALHP)        		&& $(MAKE) clean
	cd $(UDT)             		&& $(MAKE) clean
	cd $(CLIB)    		   		&& $(MAKE) clean
	
.PHONY: rpmclean 

RPM_VERSION=$(shell sed -ne 's/\#define\(\ \)\{1,\}VERSION\(\ \)\{1,\}\"\(.*\)\"/\3/p' ./include/version.h)
COMMIT = $(shell git rev-list HEAD |head -1|cut -c 1-6)
#RPM_RELEASE = $(shell git branch --no-color 2> /dev/null | sed -e '/^[^*]/d' -e 's/* \(.*\)/\1/' -e 's/-/_/g')_$(COMMIT)
RPM_RELEASE = dev
RPM_TOP_DIR = $(shell rpm -E %{_topdir})
PRJHOME = $(shell pwd)

rpm:
	@echo [RPM] ; \
    	sed -e "s/@VERSION@/$(RPM_VERSION)/g" -e "s/@RELEASE@/$(RPM_RELEASE)/g" spec/$(TGT).spec.tmp > ${RPM_TOP_DIR}/SPECS/$(TGT).spec ; \
    	cp -a -r ${PRJHOME} /tmp/$(TGT)-$(RPM_VERSION) ; \
    	cd /tmp ; \
    	tar zcvf $(RPM_TOP_DIR)/SOURCES/$(TGT)-$(RPM_VERSION).tar.gz $(TGT)-$(RPM_VERSION) ; \
    	rm -rf $(TGT)-$(RPM_VERSION) ; \
    	rpmbuild -bb $(RPM_TOP_DIR)/SPECS/$(TGT).spec ; \

rpmclean:	
	cp -r ~/rpmbuild/RPMS/x86_64/$(TGT)*$(RPM_VERSION)* ./  
	rm -rf ~/rpmbuild/SOURCES/$(TGT)* \
	~/rpmbuild/BUILD/$(TGT)* \
	~/rpmbuild/RPMS/x86_64/$(TGT)* \
	~/rpmbuild/SPEC/$(TGT)* 



