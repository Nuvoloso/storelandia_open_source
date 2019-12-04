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


# set -e make the script fail on any command error
set -e

pwd
source func_tests_common.sh

set -x

which_test=${1:-all}

# Got the commands.  Done "setup".   Now do tests.

# The check_proto test only makes sense in the case that we have a separate repository,
# not in the case that someone passed in the command.
if [[ -z ${JENKINS_CRED} && -z ${NUVO_FUNC_KONTROLLER} ]]; then
    echo "Neither JENKINS_CRED nor NUVO_FUNC_KONTROLLER: skipping check_proto"
else
    (cd check_proto; export NUVO_FUNC_KONTROLLER; export JENKINS_CRED; ./check_proto.sh)
fi
if [ "$which_test" = "fio_heavy" ] || [ "$which_test" = "all" ] ; then
  (cd log_vol; sudo -E ./fio_heavy $NUVO_VM_FT_CMD)
fi
if [ "$which_test" = "gc_rand" ] || [ "$which_test" = "all" ] ; then
    (cd log_vol; sudo -E ./gc_rand $NUVO_VM_FT_CMD 4 2 256 75 200)
fi
if [ "$which_test" = "differ_test" ] || [ "$which_test" = "all" ] ; then
    (cd log_vol; sudo -E ./differ_test $NUVO_VM_FT_CMD $COPY_FT_CMD 1024)
fi
if [ "$which_test" = "sequential" ] || [ "$which_test" = "all" ] ; then
    (cd log_vol; sudo -E ./sequential $NUVO_VM_FT_CMD)
fi
if [ "$which_test" = "random" ] || [ "$which_test" = "all" ] ; then
    (cd log_vol; sudo -E ./random $NUVO_VM_FT_CMD)
fi
if [ "$which_test" = "PiTs_extended" ] || [ "$which_test" = "all" ] ; then
    (cd log_vol; sudo -E ./PiTs_extended $NUVO_VM_FT_CMD)
fi
if [ "$which_test" = "cache" ] || [ "$which_test" = "all" ] ; then
    (cd log_vol; sudo -E ./cache $NUVO_VM_FT_CMD)
fi
if [ "$which_test" = "cache_hint" ] || [ "$which_test" = "all" ] ; then
        (cd log_vol; sudo -E ./cache_hint $NUVO_VM_FT_CMD)
fi
if [ "$which_test" = "cache_hint_gc" ] || [ "$which_test" = "all" ] ; then
        (cd log_vol; sudo -E ./cache_hint_gc $NUVO_VM_FT_CMD)
fi
if [ "$which_test" = "passthrough_test" ] || [ "$which_test" = "all" ] ; then
    (cd passthrough; sudo ./passthrough_test $NUVO_VM_FT_CMD)
fi
if [ "$which_test" = "parcel_vol" ] || [ "$which_test" = "all" ] ; then
    (cd parcel_vol; sudo -E ./parcel_vol_test $NUVO_VM_FT_CMD)
fi
if [ "$which_test" = "gc_rand_pit_large" ] ; then
  (cd log_vol; sudo -E ./gc_rand_pit $NUVO_VM_FT_CMD 4 2 512 60 300)
fi
if [ "$which_test" = "delete_pit_fio_loop" ]; then
    for i in `seq 1 100`
    do
        (cd log_vol; sudo -E ./delete_pit_concurrent_fio $NUVO_VM_FT_CMD 4 1 256 50 70)
    done
fi
