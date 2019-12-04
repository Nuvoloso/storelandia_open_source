# Storelandia

Behold: Storelandia!

Copyright 2019 Tad Lebeck

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

## SETUP

### Install Ubuntu

### AWS

Create an instance using an Amazon Ubuntu 16.04 AMI

### VMWare Fusion

Create a VM of your choice. 18 will make you happier in the long run than will 16.  Server/workstation is up to you.
*   ubuntu-18.04.1-server-amd64.iso
*   ubuntu-17.04-server-amd64.iso
*   ubuntu-16.04.3-server-amd64.iso
*   some other vm that you are willing to support yourself

Default config will fail to run tests, increase storage and memory:
*   Min Storage: 30GB
*   Min Memory:  4GB
*   Min Cores: 2

Optionally, install VMWare tools or equivalent.

### Common

Run the following commands

    export JENKINS_CRED='get a jenkins cred from somebody'
    sudo apt install git make -y
    git clone https://github.com/Nuvoloso/storelandia.git
    cd storelandia
    make config_ubuntu

## BUILD

We currently have three builds of the executables: debug, release, coverage. The three builds will populate in build/Debug, build/Release and build/Coverage respectively. You can build any of these below. Once you've done the top level build of one of these targets you can go into it's particular directory and do make from there, if you'd like. There are lots of targets in each of these "make help" is your friend.

To build debug:

    make debug

To build non-debug:

    make release

To build debug with coverage linked in:

    make coverage

To clean up:

    make clean

## TESTING

Unit tests (with and without valgrind)

    make test
    make valgrind

To run a single test, find it in the build directory and run it directly or with that targets make e.g.:

    build/Debug/nuvo/tests/unit_test_nuvo
    (cd build/Debug); make unit_test_nuvo
    (cd build/Coverage; make unit_test_nuvo)

Any `make test` or `ctest` errors get logged in build/Debug/Testing/Temporary

### Functional tests:

The functional tests require nuvo_vm and (optionally) nuvo.proto from Kontroller. This requires exporting one
of three variables: NUVO_VM_CMD, JENKINS_CRED, or NUVO_FUNC_KONTROLLER

Examples:

    # Download files from Jenkins.  Use your own creds.
    export JENKINS_CRED=jke:a2e3a2a5437dd1c53064060075152749
    make func_test

    # Use your local Kontroller
    export NUVO_FUNC_KONTROLLER=~/your_path_to/kontroller/
    make func_test

    # Skip the proto check and use a nuvo_vm you have.
    # You can download a recent version at https://jenkins.nuvoloso.com:8443/job/kontroller_master/lastSuccessfulBuild/artifact/cmd/nuvo_vm/nuvo_vm
    # Use your own path.

    export NUVO_VM_CMD=/home/jedwards/nuvo_vm

    make func_test

If you want to use an analysis tool with nuvo, export NUVO_FUNC_TEST_TOOL defined as "valgrind", "callgrind", "profile", or "gdb".
This may run a slightly different "nuvo" process due to linking requirements of gperftools, which hate me.
This functionality is described further in nuvo/func_test/README

### Overriding Build Type

Also, you can override which tree the tests are run on by setting "Debug", "Coverage", or "Release" as TEST_TREE environmen, e.g.

    TEST_TREE=Coverage make test

The tests still depend on debug and build debug, not coverage or release because cmake is naming the dirs with capital letters, I want the make targets to be lower case, and I don't want to go to the effort of getting it right. TL;DR : I suck.

### VALGRIND

As described above, you can make valgrind to run unit tests under valgrind.
Sometimes you will get an error from a library that you cannot fix. When this happens
the valrind log (such as build/Debug/Testing/Temporary/MemoryChecker.2.log) will show the
error and suppression xml. When this happens, and it is literally an issue you cannot fix,
paste that xml into valgrind_supp.xml (in this directory). Change the name of the suppression in the xml. Go on with your life.

## COVERAGE

To get covergage output, build with coverage, run tests under the Coverage tree and then generate the report with cover_html.

    make coverage
    TEST_TREE=Coverage make test
    TEST_TREE=Coverage make func_test
    make coverage_html

Browse the report at "build/Coverage/coverage_report/index.html"

## DOXYGEN

Generate doxygen with:

    make doxygen

Browse at build/Debug/nuvo/doxygen/html/index.html

## CODE FORMATTING

Reformat your C code with

    make format

Check the format of your C code, but do not reformat with

    make format_check

Github pre-submit checks don't do this.

## USE

### Use (nuvo):

Download the nuvo cmd (or you can use build/Debug/nuvo/nuvo)

    curl -k -u 'bender:dac894582ae886fd5d0d708b78cf0c61be4fe2ae' -O  https://jenkins.nuvoloso.com:8443/job/storelandia/lastSuccessfulBuild/artifact/build/Debug/nuvo/nuvo
    chmod +x nuvo

Download the nuvo_vm command:

    curl -k -u 'bender:dac894582ae886fd5d0d708b78cf0c61be4fe2ae' -O  https://jenkins.nuvoloso.com:8443/job/kontroller/lastSuccessfulBuild/artifact/cmd/nuvo_vm/nuvo_vm
    chmod +x nuvo_vm

Create nuvoloso a 1024000 byte file "/home/jedwards/disk1" and start a nuvoloso volume "nvol1" on it:

    sudo mkdir /mnt/nuvoloso
    sudo build/Debug/nuvo/nuvo /mnt/nuvoloso
    sudo ./nuvo_vm passthrough-volume -d /home/jedwards/disk1 -n nvol1 -s 1024000 -c

Make a file system in it and mount it (replace /dev/loopN with output of losetup)

    sudo losetup --find --show /mnt/nuvoloso/nvol1
    sudo mkfs -t ext4 -b 4096 /dev/loopN
    sudo mkdir /mnt/nvol1
    sudo mount /dev/loopN /mnt/nvol1

Enjoy. You can repeat with other disk and volume names.

    cd /mnt/nvol1
    ls

Shut it all down:

    sudo umount /mnt/nvol1
    sudo losetup --detach /dev/loopN
    sudo ./nuvo_vm halt

## Jenkins Build Job Configuration

The details of the Jenkins job configuration can be found here:
[storelandia Repo GitHub and Jenkins Job Configuration Details](https://docs.google.com/document/d/1BP8pyYzT0CJZazuDX7fO_eD1SElPCKFak5OfxBfrYCc)

## JIRA Integration

Supposedly we can close JIRA issues with submits.
Include a line somewhere in your commit message:

     CUM-NNNNN #resolve #comment Does this work

(https://confluence.atlassian.com/bitbucket/processing-jira-software-issues-with-smart-commit-messages-298979931.html)

## Building containers locally

You can build and push a container locally instead of routing builds for incremental changes through Jenkins.

**Pre-requisite Setup**

* You must be authorized to push and pull container images directly to the AWS ECR repo.
   See this [link](https://docs.google.com/document/d/1U37yiUh41nRKYEzz4XA-AfyUcBgh9ne9W3MPbycjDZI/edit#heading=h.bu0fra5aymdf).
* Setup your environment to run docker without sudo. [Manage Docker as a non-root user](https://docs.docker.com/install/linux/linux-postinstall)

**Building the Container**

* Login to the container registry.

        eval $(aws ecr get-login --registry-ids 407798037446 | sed 's|-e none https://||')

* Build the container. Set the `CONTAINER_TAG` environment variable, or specify it when you run make. This tag identifies the container in the AWS ECR repo.

        make container CONTAINER_TAG=my_tag

**Changing the container configuration**

The Docker instructions to build the container image are in `deploy/Dockerfile`

**Running your nuvo container**

nuvo requires a privileged container with volume mounts which give the process access to the FUSE mount location `/var/local/nuvoloso` and the socket directory `/var/run/nuvoloso`. Note that these directorys may be named anything.

    sudo mkdir /var/local/nuvoloso
    sudo mkdir /var/run/nuvoloso

Start the nuvo container with the required bind mounts.
In this example `/dev` is used so nuvo can access the disk. if you prefer to run nuvo using a file as backing device use `/tmp`.
The FUSE mount directory must have `bind-propogration=shared`, allowing the nuvo volume sub-mounts to be seen outside the container.

    docker run --privileged \
    --mount type=bind,source="/var/run/nuvoloso",target="/var/run/nuvoloso" \
    --mount type=bind,source="/var/local/nuvoloso",target="/var/local/nuvoloso",bind-propagation=shared \
    --mount type=bind,source="/dev",target="/dev" \
    407798037446.dkr.ecr.us-west-2.amazonaws.com/nuvoloso/nuvo:my_tag

This command will display nuvo stderr output to the terminal.

The `nuvo_vm` command can now be used to complete the nuvo configuration, add and format devices, create volumes, etc. When using the `nuvo_vm` command the -s option must be used to specify the socket `/var/run/nuvoloso/nuvo.sock`

The container may also be deployed as part of the full product kubernetes deployment. After downloanding the YAML for the application cluster, edit this YAML file to use the tag for your container image instead of the default tag. See [Deploying Nuvoloso using nuvodev](https://docs.google.com/document/d/14vEGmdB06FRJ2T-Y7VVs0f26R0RuibrsCSNU4uGMgqQ)

The Jenkins builds use a different mechanism for creating containers.
