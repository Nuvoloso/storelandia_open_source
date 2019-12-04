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


# This test runs the volume manager and tests
# sending API requests, some good, many bad, to it.
echo "---------- STARTING PM_API_CMD FUNC TEST ----------"
set -x
NUVO_VM_FT_CMD=$1

# Create a directory
TEST_DIR=`mktemp -d /tmp/nuvo_test.XXXXXXXXXXXXXXXX`
echo "Created test directory $TEST_DIR"

# Create FUSE directory
FUSE_DIR="$TEST_DIR/fuse"
mkdir $FUSE_DIR

# Create directory to mount volume
VOL_NAME="test_vol"
VOL_MNT="$TEST_DIR/$VOL_NAME"
mkdir $VOL_MNT

# Backing store file name location for volume
# Will be created by nuvo_vm
DISK="$TEST_DIR/$VOL_NAME.backing"

# Use a non-default api socket
SOCKET_NAME="$TEST_DIR/nuvo_socket"

function finish {
    echo "Cleaning up"
    umount $FUSE_DIR
    rm -rf $TEST_DIR
}
trap finish EXIT

FAIL=0

function failed() {
    echo "ERROR - $1"
    FAIL=1
    exit 1
}

# Point to the NUVO_CMD in this tree.
NUVO_CMD="../../nuvo"
EPHEM_CMD="../../../util/nuvo_ephemeral"
NODE_PORT=$( $EPHEM_CMD )
NODE_UUID=$( uuidgen )

# Start up the volume manager
echo "Starting nuvo process"

valgrind --error-exitcode=1 --leak-check=full --trace-children=no --gen-suppressions=all --suppressions=valgrind_supp.xml \
    $NUVO_CMD -f -o allow_other $FUSE_DIR socket=$SOCKET_NAME port=$NODE_PORT &

FUSE_PID=$!

for i in {1..30}
do
      if [ -e $SOCKET_NAME ]; then
          break
      fi
      echo "Waiting for socket"
      sleep 2
done

if [ ! -e "$SOCKET_NAME" ]; then
    failed "Socket never came up"
fi

DEV_UUID=$( uuidgen )
DEV_PARCEL_SZ=536870912
DEVICE=`mktemp $TEST_DIR/nuvo_device.XXXXXXXXXXXXXXXX`
truncate -s 2G $DEVICE
if [[ $? -ne 0 ]] ; then
    failed "unable to create test device"
fi

# SET NODE UUID
NODE_UUID=$( uuidgen )
$NUVO_VM_FT_CMD -s $SOCKET_NAME -v use-node-uuid -u $NODE_UUID
if [ $? -ne 0 ] ; then
    failed "use-node-id command failed. That's messed up."
fi
NODE_UUID2=$( uuidgen )
$NUVO_VM_FT_CMD -s $SOCKET_NAME -v node-location -n $NODE_UUID2 -i "127.0.0.2" -p 123
if [ $? -ne 0 ] ; then
    failed "node-location command failed. That's messed up."
fi

# FORMAT_DEVICE
if $NUVO_VM_FT_CMD -s $SOCKET_NAME -v format-device -d "/dev/no_exist" -u $DEV_UUID -p $DEV_PARCEL_SZ; then
    failed "Command worked.  That's messed up."
fi

if $NUVO_VM_FT_CMD -s $SOCKET_NAME -v format-device -d $DEVICE -u "bad-uuid" -p $DEV_PARCEL_SZ; then
    failed "Command worked.  That's messed up."
fi

if $NUVO_VM_FT_CMD -s $SOCKET_NAME -v format-device -d $DEVICE -u $DEV_UUID -p 10; then
    failed "Command worked.  That's messed up."
fi

if $NUVO_VM_FT_CMD -s $SOCKET_NAME -v format-device -d $DEVICE -u $DEV_UUID -p $DEV_PARCEL_SZ; then
    echo "$DEVICE successfully formatted"
else
    failed "Command failed. failed to format device $DEVICE with $DEV_UUID parcel size $DEV_PARCEL_SZ"
fi

# USE_DEVICE
if $NUVO_VM_FT_CMD -s $SOCKET_NAME -v use-device -d "/dev/no-exist" -u $DEV_UUID; then
    failed "Command worked.  That's messed up."
fi

if $NUVO_VM_FT_CMD -s $SOCKET_NAME -v use-device -d $DEVICE -u "bad-uuid"; then
    failed "Command worked.  That's messed up."
fi

if $NUVO_VM_FT_CMD -s $SOCKET_NAME -v use-device -d $DEVICE -u $DEV_UUID; then
    echo "$DEVICE successfully opened for use"
else
    failed "Command failed. failed to open device $DEVICE with $DEV_UUID"
fi

if $NUVO_VM_FT_CMD -s $SOCKET_NAME -v use-device -d $DEVICE -u $DEV_UUID; then
    echo "$DEVICE successfully re-opened for use"
else
    failed "Command failed. failed to re-open device $DEVICE with $DEV_UUID"
fi

# DEVICE_LOCATION
if $NUVO_VM_FT_CMD -s $SOCKET_NAME -v device-location -d $DEV_UUID -n $NODE_UUID; then
    echo "$DEVICE location successfully added"
else
    failed "Command failed. failed to add device location"
fi

if $NUVO_VM_FT_CMD -s $SOCKET_NAME -v device-location -d $DEV_UUID -n $NODE_UUID; then
    echo "$DEVICE location successfully re-added"
else
    failed "Command failed. failed to re-add device location"
fi

if $NUVO_VM_FT_CMD -s $SOCKET_NAME -v device-location -d $DEV_UUID -n $NODE_UUID2; then
    echo "$DEVICE location successfully changed"
else
    failed "Command failed. failed to change device location"
fi

# Return the device-location to the right value
if $NUVO_VM_FT_CMD -s $SOCKET_NAME -v device-location -d $DEV_UUID -n $NODE_UUID; then
    echo "$DEVICE location successfully changed"
else
    failed "Command failed. failed to change device location"
fi

# CREATE_VOLUME
VOL_UUID=$( uuidgen )
ROOT_PARCEL=$( uuidgen )
VOLUME_SIZE=40960000000
NUM_PARCELS=3
if $NUVO_VM_FT_CMD -s $SOCKET_NAME create-volume -d $DEV_UUID -v $VOL_UUID -p $ROOT_PARCEL -s $VOLUME_SIZE; then
    echo "Create volume $VOL_NAME succesful"
else
    failed "Command failed. Failed to create volume $VOL_NAME"
fi

# ALLOC_PARCELS
if $NUVO_VM_FT_CMD -s $SOCKET_NAME alloc-parcels -v $VOL_UUID -d $DEV_UUID -n $NUM_PARCELS; then
    echo "Allocation of $NUM_PARCELS parcels successful"
else
    failed "Command failed. Failed to allocate $NUM_PARCELS parcels"
fi

# EXPORT
if $NUVO_VM_FT_CMD -s $SOCKET_NAME export -v $VOL_UUID -e $VOL_NAME; then
    echo "Export volume $VOL_NAME successful"
else
    failed "Command failed. Failed to export volume $VOL_NAME"
fi

# Test the close volume api, should fail since lun is still exported.
if $NUVO_VM_FT_CMD -s $SOCKET_NAME close-volume -v $VOL_UUID; then
    failed "Command worked. But it should have failed. If there are still exported LUNS, volume close should fail."
fi

# Leaving volume exported, this will test if shutdown process cleans up successfully.


echo "Tearing down nuvo"
$NUVO_VM_FT_CMD -s $SOCKET_NAME halt
if ! wait "$FUSE_PID"; then
    failed "$NUVO_CMD exited uncleanly"
fi

if [ "$FAIL" -eq 0 ]; then
    echo "Success"
    exit 0
else
    failed "Parcel Manager functional test failed."
fi

rm -rf $DEVICE
