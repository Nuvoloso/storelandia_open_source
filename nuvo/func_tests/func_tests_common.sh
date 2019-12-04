#!/bin/bash

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


# This does some setup for func tests.  In particular it needs a nuvo_vm executable
# from somewhere.  There are four ways to get this:
#
# NUVO_VM_CMD - The environment has a pointer to a copy of the command.  Use that.
#    If you only have this, the script will skip the check_proto test since that is actually
#    comparing tree contents and this method has no tree.
# NUVO_FUNC_KONTROLLER - Get the command from a local Kontroller branch.  This assumes that has
#    already been built.
# Regular kontroller source location - If it has been built
# JENKINS_CRED - Go pull the command from jenkins.
#
# The copy command from controller is also an externally built executable needed by
# some of the tests.  The same proceedure is used to find the copy executable
#
# COPY_CMD - The environment pointer to the copy command. Use that.
# NUVO_FUNC_KONTROLLER and JENKINS_CRED just like for nuvo_vm

# set -e make the script fail on any command error
set -e

KONTROLLER_SRC=~/go/src/github.com/Nuvoloso/kontroller
DEPLOY_DIR=$KONTROLLER_SRC/deploy/bin

if [[ -z ${JENKINS_CRED} && -z ${NUVO_FUNC_KONTROLLER} && -z ${NUVO_VM_CMD} && ! -f $DEPLOY_DIR/nuvo_vm ]]; then
    echo "Must supply one of JENKINS_CRED, NUVO_FUNC_KONTROLLER or NUVO_VM_CMD or $DEPLOY_DIR"
    exit 1
fi

if [[ -z ${JENKINS_CRED} && -z ${NUVO_FUNC_KONTROLLER} && -z ${COPY_CMD} && ! -f $DEPLOY_DIR/copy ]]; then
    echo "Must supply one of JENKINS_CRED, NUVO_FUNC_KONTROLLER or COPY_CMD or $DEPLOY_DIR"
    exit 1
fi

# Create temporary files to hold the nuvo_vm and the copy command.
# Really just want the name, as we will copy the commands here.
NUVO_VM_FT_CMD="$(mktemp /tmp/nuvo_vm.XXXXXXXX)"
COPY_FT_CMD="$(mktemp /tmp/copy.XXXXXXXX)"
function finish {
    echo "Cleaning up"
    rm $NUVO_VM_FT_CMD
    rm $COPY_FT_CMD
}
trap finish EXIT

# Now get a copy of nuvo_vm into NUVO_VM_FT_CMD
if [[ -e "${NUVO_VM_CMD}" ]]; then
    echo "Using NUVO_VM_CMD"
    cp $NUVO_VM_CMD $NUVO_VM_FT_CMD
elif [[ -f "${NUVO_FUNC_KONTROLLER}/deploy/bin/nuvo_vm" ]];  then
    echo "Using nuvo_vm from local kontroller: ${NUVO_FUNC_KONTROLLER}"
    cp ${NUVO_FUNC_KONTROLLER}/deploy/bin/nuvo_vm $NUVO_VM_FT_CMD
elif [[ -f "$DEPLOY_DIR/nuvo_vm" ]]; then
    echo "Using nuvo_vm from $DEPLOY_DIR/nuvo_vm:"
    cp $DEPLOY_DIR/nuvo_vm $NUVO_VM_FT_CMD
elif [[ -z "${JENKINS_CRED}" ]]; then
    echo "Failed to get nuvo_vm all four ways."
    exit 1
else
    echo "Downloading kontroller version of nuvo"
    curl -f -k -u $JENKINS_CRED -o $NUVO_VM_FT_CMD  https://jenkins.nuvoloso.com:8443/job/kontroller_master/lastSuccessfulBuild/artifact/deploy/bin/nuvo_vm
fi
chmod +x $NUVO_VM_FT_CMD

# Now get the copy program into COPY_FT_CMD
if [[ -e "${COPY_CMD}" ]]; then
    echo "Using COPY_CMD at $COPY_CMD"
    cp $COPY_CMD $COPY_FT_CMD
elif [[ -f "${NUVO_FUNC_KONTROLLER}/deploy/bin/copy" ]];  then
    echo "Using copy from NUVO_FUNC_KONTROLLER: ${NUVO_FUNC_KONTROLLER}/deploy/bin/copy"
    cp ${NUVO_FUNC_KONTROLLER}/deploy/bin/copy $COPY_FT_CMD
elif [[ -f "$DEPLOY_DIR/copy" ]];  then
    # Standard location of a kontroller workspace
    echo "Using copy from $DEPLOY_DIR/copy"
    cp $DEPLOY_DIR/copy $COPY_FT_CMD
elif [[ -z "${JENKINS_CRED}" ]]; then
    echo "Failed to get copy all four ways."
    exit 1
else
    echo "Downloading kontroller version of copy"
    curl -f -k -u $JENKINS_CRED -o $COPY_FT_CMD  https://jenkins.nuvoloso.com:8443/job/kontroller_master/lastSuccessfulBuild/artifact/deploy/bin/copy
fi
chmod +x $COPY_FT_CMD
set -x

# Got the commands.  Done "setup".   Now do tests.

# The check_proto test only makes sense in the case that we have a separate repository,
# not in the case that someone passed in the command.
if [[ -z ${JENKINS_CRED} && -z ${NUVO_FUNC_KONTROLLER} ]]; then
    echo "Neither JENKINS_CRED nor NUVO_FUNC_KONTROLLER: skipping check_proto"
else
    (cd check_proto; export NUVO_FUNC_KONTROLLER; export JENKINS_CRED; ./check_proto.sh)
fi

echo "------------------------------------------------"

if [ -z "$NUVO_FUNC_TEST_TOOL" ]; then
    export NUVO_FUNC_TEST_TOOL=default
fi

export NUVO_FUNC_TEST_TOOL
if [ $NUVO_FUNC_TEST_TOOL = "valgrind" ]; then
    echo "Nuvo will run under valgrind"
    export NUVO_WAIT_FOR_GDB=false
elif [ $NUVO_FUNC_TEST_TOOL = "callgrind" ]; then
    export NUVO_WAIT_FOR_GDB=false
    echo "Nuvo will run under callgrind"
elif [ $NUVO_FUNC_TEST_TOOL = "profile" ]; then
    export NUVO_WAIT_FOR_GDB=false
    echo "Nuvo will run under gperftools profile"
elif [ $NUVO_FUNC_TEST_TOOL = "gdb" ]; then
    echo "Nuvo will wait for gdb"
    export NUVO_WAIT_FOR_GDB=true
else
    echo "Nuvo will run normally."
fi
