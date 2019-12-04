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


set -x

OTHER_ARGS=
CORE_DIR=
MOUNT_PATH="/var/local/nuvoloso"
SOCKET_PATH="socket=/var/run/nuvoloso/nuvo.sock"
PORT="port=32145"
CLEANUP=0
WAIT_ON_FAILURE=0
while [ $# -gt 0 ]; do
    case $1 in
    (--nuvo-core-dir) CORE_DIR=$2; shift;;
    (--nuvo-cleanup) CLEANUP=1;;
    (--nuvo-wait-on-failure) WAIT_ON_FAILURE=1;;
    (-f) ;;
    (/*) MOUNT_PATH=$1;;
    (socket=*) SOCKET_PATH=$1;;
    (port=*) PORT=$1;;
    (*) OTHER_ARGS="$OTHER_ARGS $1";;
    esac
    shift
done

if [ "$CORE_DIR" != "" ]; then
    # must be a mount point
    mount | grep "$CORE_DIR" >/dev/null 2>&1
    if [ $? -eq 0 ] ; then
        echo "$CORE_DIR/core.%e.%P" | tee /proc/sys/kernel/core_pattern
        ulimit -c unlimited
    fi
fi

# in case previous instance did not clean up (e.g. hung nuvo process), pre-clean the mount path
cleanup_mount() {
    if [ $CLEANUP -eq 1 ]; then
        for d in $MOUNT_PATH
        do
            /usr/local/bin/fusermount3 -uz $d
            rmdir $d
        done
    fi
}

cleanup_mount

mkdir -p $MOUNT_PATH
if [ $? -ne 0 ]; then
    exit 1
fi

SOCKDIR=$(dirname ${SOCKET_PATH/socket=})
mkdir -p $SOCKDIR
if [ $? -ne 0 ]; then
    exit 1
fi

# see https://unix.stackexchange.com/questions/146756/forward-sigterm-to-child-in-bash/444676#444676
prep_term() {
    unset child_pid
    unset kill_needed
    trap 'handle_term' TERM INT
}

handle_term() {
    handle_term_called="yes"
    if [ "$child_pid" ]; then
        kill -TERM "$child_pid" 2>/dev/null
    else
        kill_needed="yes"
    fi
}

wait_term() {
    child_pid=$!
    if [ "$kill_needed" ]; then
        kill -TERM "$child_pid" 2>/dev/null
    fi
    wait $child_pid
    RC=$?
    trap - TERM INT
    wait $child_pid
    RC2=$?
    # only use result of the 2nd wait if it is the real exit status
    # 127 means the first wait got the real exit status, not the result of a trapped signal
    if [ $RC2 -ne 127 ]; then
        RC=$RC2
    fi
    if [ ! "$handle_term_called" -a $RC -ne 0 -a $WAIT_ON_FAILURE -eq 1 ]; then
        echo "nuvo terminated: $RC"
        echo "BLOCKING UNTIL TERMINATED"
        while (( 1 )) ; do sleep 1000; done
    fi
}

prep_term
/opt/nuvoloso/bin/nuvo -f $PORT $MOUNT_PATH $SOCKET_PATH $OTHER_ARGS &
wait_term

cleanup_mount

exit $RC
