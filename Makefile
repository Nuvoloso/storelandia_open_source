# Copyright 2019 Tad Lebeck
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#
# Rudimentary make calling cmake and ctest, etc.

ifeq ($(TEST_TREE),)
TEST_TREE := Debug
endif
TEST_DIR := "build/$(TEST_TREE)"

.PHONY:all
all: test

.PHONY:clean
clean:
	rm -rf build

.PHONY: release
release:
	mkdir -p build/Release
	(cd build/Release; cmake -G"Unix Makefiles" -DCMAKE_BUILD_TYPE=Release ../..)
	(cd build/Release; make -j)

.PHONY: debug
debug:
	mkdir -p build/Debug
	(cd build/Debug; cmake -G"Unix Makefiles" -DCMAKE_BUILD_TYPE=Debug ../..)
	(cd build/Debug; make -j)

.PHONY: coverage
coverage:
	mkdir -p build/Coverage
	chmod 0777 build/Coverage
	(cd build/Coverage; COVERAGE=1 cmake -G"Unix Makefiles" -DCMAKE_BUILD_TYPE=Debug ../..)
	(cd build/Coverage; make -j)

.PHONY: coverage_html
coverage_html:
	(cd build/Coverage/nuvo/CMakeFiles; sudo lcov --directory .. --capture --rc lcov_branch_coverage=1 --output-file coverage.info)
	(cd build/Coverage/nuvo/CMakeFiles; genhtml coverage.info --branch-coverage --output-directory ../../coverage_report)

.PHONY: coverage_todor
coverage_todor:
	make coverage
	TEST_TREE=Coverage make test
	TEST_TREE=Coverage make func_test
	make coverage_html

.PHONY: coverage_unit
coverage_unit:
	make coverage
	TEST_TREE=Coverage make test
	make coverage_html

.PHONY:test
test: debug
	@echo "help"
	@echo "$(TEST_DIR)"
	(cd $(TEST_DIR); make test)

.PHONY:valgrind
valgrind: debug
	(cd $(TEST_DIR); ctest -T memcheck -E "nuvo_unit_tests_gc|nuvo_unit_tests_map|nuvo_unit_tests_map_replay")

# This is not great. Really need an auto generated target that will run this.
.PHONY: func_test
func_test: debug
	# FUNC_TEST can be overridden at command line
	FUNC_TEST=all
	(cd $(TEST_DIR)/nuvo/func_tests; ./run_func_tests.sh $(FUNC_TEST))

.PHONY: extended_func_test
extended_func_test: debug
	# FUNC_TEST can be overridden at command line
	FUNC_TEST=all
	(cd $(TEST_DIR)/nuvo/func_tests; ./run_extended_func_tests.sh  $(FUNC_TEST))

.PHONY:docs
docs:
	(cd $(TEST_DIR); make doxygen)

.PHONY:setup
setup:

.PHONY:packages
packages:
	sudo apt-get install $$(cat pkglist) -y

.PHONY:config_ubuntu_common
config_ubuntu_common:
	sudo apt-get install software-properties-common -y
	sudo add-apt-repository ppa:ubuntu-toolchain-r/test -y
	sudo apt-get update -y
	sudo apt-get install openssh-server -y
	sudo apt-get install openssh-client -y
	sudo apt -y install cmake
	sudo apt-get install $$(cat pkglist) -y
	curl -v -k -u "$(JENKINS_CRED)" -O https://jenkins.nuvoloso.com:8443/job/libfuse3/lastSuccessfulBuild/artifact/build/libfuse3-dev.deb
	sudo dpkg -i libfuse3-dev.deb
	make uncrustify_install

.PHONY:config_ubuntu_16
config_ubuntu_16: config_ubuntu_common
	sudo apt-get install build-essential -y
	sudo apt-get install gcc-snapshot -y
	sudo apt-get install gcc-6 g++-6 -y
	sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-6 60 --slave /usr/bin/g++ g++ /usr/bin/g++-6
	sudo update-alternatives --config gcc
	echo "/usr/local/lib/x86_64-linux-gnu" | sudo tee -a /etc/ld.so.conf.d/x86_64-linux-gnu.conf
	sudo ldconfig

.PHONY:config_ubuntu_17
config_ubuntu_17: config_ubuntu_common
	echo "/usr/local/lib/x86_64-linux-gnu" | sudo tee -a /etc/ld.so.conf.d/x86_64-linux-gnu.conf
	sudo ldconfig

.PHONY:config_ubuntu_18
config_ubuntu_18: config_ubuntu_17

OS_DISTRIBUTOR = $(shell lsb_release -si)
OS_VERSION = $(shell lsb_release -sr)
.PHONY:config_ubuntu
config_ubuntu:
ifneq (Ubuntu,$(OS_DISTRIBUTOR))
	@echo "Not Ubuntu, you are on your own"
else ifeq (18.04,$(OS_VERSION))
	@echo "Ubuntu 18.04"
	make config_ubuntu_18
else ifeq (17.04,$(OS_VERSION))
	@echo "Ubuntu 17.04"
	make config_ubuntu_17
else ifeq (16.04,$(OS_VERSION))
	@echo "Ubuntu 16.04"
	make config_ubuntu_16
else
	echo "Not Ubuntu 16.04 17.04 or 18.04, you are on your own"
endif

.PHONY:uncrustify_install
uncrustify_install:
	curl -L http://ftp.us.debian.org/debian/pool/main/u/uncrustify/uncrustify_0.64+dfsg1-1_amd64.deb -o /tmp/uncrustify.deb
	echo "2be80e84b55557d4baba08e76cfd5ddc5d2619f4981803f4c5190d380b7b4f98  /tmp/uncrustify.deb" | sha256sum -c
	sudo dpkg --install /tmp/uncrustify.deb

CONTAINER_TAG?=latest
container_build:
	curl -v -k -u "$(JENKINS_CRED)" -O https://jenkins.nuvoloso.com:8443/job/libfuse3/lastSuccessfulBuild/artifact/build/libfuse3-dev.deb
	mv libfuse3-dev.deb build
	docker build -t 407798037446.dkr.ecr.us-west-2.amazonaws.com/nuvoloso/nuvo:$(CONTAINER_TAG) --pull=true --file=deploy/Dockerfile .

container_push:
	docker push 407798037446.dkr.ecr.us-west-2.amazonaws.com/nuvoloso/nuvo:$(CONTAINER_TAG)

container: container_build container_push

format:
	find nuvo -maxdepth 1 -name "*.[hc]" > files.txt
	uncrustify -c uncrustify.cfg -l C -F files.txt --replace --no-backup
	rm files.txt

format_file:
	# USAGE "make format_file FILE=nuvo/test/unit_test_gc.c"
	echo $(FILE) > files.txt
	uncrustify -c uncrustify.cfg -l C -F files.txt --replace --no-backup
	rm files.txt

format_check:
	find nuvo -maxdepth 1 -name "*.[hc]" > files.txt
	uncrustify --check -c uncrustify.cfg -l C -F files.txt
	rm files.txt
