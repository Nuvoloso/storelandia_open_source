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


echo "---------- STARTING CHECK_PROTO FUNC TEST ----------"

TEST_DIR=`mktemp -d /tmp/nuvo_test.XXXXXXXXXXXXXXXX`
echo "Created test directory $TEST_DIR"
FAIL=0

# Two modes. If a kontroller tree is set in the environment
# use that one.  If there is not, download the most
# one from jenkins.   This let's developers make the
# parallel changes and make sure they are good before
# submitting to the respective repositories.
if [[ -z "${NUVO_FUNC_KONTROLLER}" ]]; then
  echo "Downloading kontroller version of proto"
  curl -k -u $JENKINS_CRED -o $TEST_DIR/kontroller.proto  https://jenkins.nuvoloso.com:8443/job/kontroller_master/lastSuccessfulBuild/artifact/pkg/nuvoapi/nuvo_pb/nuvo.proto
else
  echo "Using nuvo.proto from local kontroller: ${NUVO_FUNC_KONTROLLER}"
  cp ${NUVO_FUNC_KONTROLLER}/pkg/nuvoapi/nuvo_pb/nuvo.proto $TEST_DIR/kontroller.proto
fi

# I always like to list the directory.
ls -l $TEST_DIR

echo "Diffing files:"
if diff --text ../../nuvo.proto $TEST_DIR/kontroller.proto; then
    echo "Protobuf files the same."
else
    echo "ERROR Protobuf files different!"
    FAIL=1
fi

if rm -rf $TEST_DIR; then
    echo "Cleaned up"
else
    echo "ERROR - Failed to clean up"
    FAIL=1
fi

if [ "$FAIL" -eq 0 ]; then
    echo "Success"
    exit 0
else
    echo "Failed"
    exit 1
fi