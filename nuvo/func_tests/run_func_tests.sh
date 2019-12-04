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
# We still do this even if you specify a single test, because it is very short and
# fundamental to any other test working.  I'm commenting in hopes of triggering a new
# Jenkins build.
if [[ -z ${JENKINS_CRED} && -z ${NUVO_FUNC_KONTROLLER} ]]; then
    echo "Neither JENKINS_CRED nor NUVO_FUNC_KONTROLLER: skipping check_proto"
else
    (cd check_proto; export NUVO_FUNC_KONTROLLER; export JENKINS_CRED; ./check_proto.sh)
fi

if [ "$which_test" = "fail_volume_replay" ] || [ "$which_test" = "all" ] ; then
  (cd log_vol; sudo -E ./fail_volume_replay $NUVO_VM_FT_CMD)
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
if [ "$which_test" = "zero" ] || [ "$which_test" = "all" ] ; then
  (cd log_vol; sudo -E ./zero $NUVO_VM_FT_CMD)
fi
if [ "$which_test" = "zero_do_io" ] || [ "$which_test" = "all" ] ; then
  (cd log_vol; sudo -E ./zero $NUVO_VM_FT_CMD "do_io")
fi
if [ "$which_test" = "gc_replay" ] || [ "$which_test" = "all" ] ; then
    (cd log_vol; sudo -E ./gc_replay $NUVO_VM_FT_CMD 1 1 1 256 100 10 4096 2)
fi
if [ "$which_test" = "differ_test" ] || [ "$which_test" = "all" ] ; then
    (cd log_vol; sudo -E ./differ_test $NUVO_VM_FT_CMD $COPY_FT_CMD 20)
fi
if [ "$which_test" = "pm_api_cmds" ] || [ "$which_test" = "all" ] ; then
    (cd pm_api_cmds; sudo ./pm_api_cmds.sh $NUVO_VM_FT_CMD)
fi
if [ "$which_test" = "log_vol_test" ] || [ "$which_test" = "all" ] ; then
    (cd log_vol; sudo -E ./log_vol_test $NUVO_VM_FT_CMD)
fi
if [ "$which_test" = "PiT_basic" ] || [ "$which_test" = "all" ] ; then
    (cd log_vol; sudo -E ./PiT_basic $NUVO_VM_FT_CMD)
fi
if [ "$which_test" = "bad_order" ] || [ "$which_test" = "all" ] ; then
    (cd log_vol; sudo -E ./bad_order $NUVO_VM_FT_CMD)
fi
if [ "$which_test" = "misaligned" ] || [ "$which_test" = "all" ] ; then
    (cd log_vol; sudo -E ./misaligned $NUVO_VM_FT_CMD)
fi
if [ "$which_test" = "cum_1044" ] || [ "$which_test" = "all" ] ; then
    (cd log_vol; sudo -E ./cum_1044 $NUVO_VM_FT_CMD)
fi
if [ "$which_test" = "gc_rand_pit" ] || [ "$which_test" = "all" ] ; then
    (cd log_vol; sudo -E ./gc_rand_pit $NUVO_VM_FT_CMD 4 1 256 50 70)
fi
if [ "$which_test" = "delete_pit_suite" ] ; then
    (cd log_vol; sudo -E ./delete_pit $NUVO_VM_FT_CMD 4 1 256 50 70)
    (cd log_vol; sudo -E ./delete_pit $NUVO_VM_FT_CMD 4 1 256 50 70 1)
    (cd log_vol; sudo -E ./delete_pit_concurrent_fio $NUVO_VM_FT_CMD 4 1 256 50 70)
fi

if [ "$which_test" = "delete_pit_basic" ] || [ "$which_test" = "all" ] ; then
    (cd log_vol; sudo -E ./delete_pit $NUVO_VM_FT_CMD 4 1 256 50 70)
fi
if [ "$which_test" = "delete_pit_crash" ] || [ "$which_test" = "all" ] ; then
    (cd log_vol; sudo -E ./delete_pit $NUVO_VM_FT_CMD 4 1 256 50 70 1)
fi
if [ "$which_test" = "delete_pit_fio" ] || [ "$which_test" = "all" ] ; then
    (cd log_vol; sudo -E ./delete_pit_concurrent_fio $NUVO_VM_FT_CMD 4 1 256 50 70)
fi
if [ "$which_test" = "cum_1515" ] || [ "$which_test" = "all" ] ; then
    (cd log_vol; sudo -E ./cum_1515 $NUVO_VM_FT_CMD 4 1 256 50 70)
fi
if [ "$which_test" = "gc_replay-CUM1302" ] || [ "$which_test" = "all" ] ; then
    (cd log_vol; sudo -E ./gc_replay-CUM1302 $NUVO_VM_FT_CMD 1 1 1 256 100 10 4096 2)
fi
if [ "$which_test" = "crash_replay" ] || [ "$which_test" = "all" ] ; then
    (cd log_vol; sudo -E ./crash_replay $NUVO_VM_FT_CMD 1 1 1 256 100 10 4096 2)
fi
if [ "$which_test" = "api_parallel" ] || [ "$which_test" = "all" ] ; then
    (cd log_vol;  sudo -E ./api_parallel $NUVO_VM_FT_CMD 20)
fi
if [ "$which_test" = "pit_mutability" ] || [ "$which_test" = "all" ] ; then
    (cd log_vol;  sudo -E ./pit_mutability $NUVO_VM_FT_CMD)
fi
if [ "$which_test" = "pr_errors" ] || [ "$which_test" = "all" ] ; then
  (cd log_vol; sudo -E ./pr_errors $NUVO_VM_FT_CMD 1 1)
fi
if [ "$which_test" = "vol_destroy" ] || [ "$which_test" = "all" ] ; then
  (cd log_vol; sudo -E ./vol_destroy $NUVO_VM_FT_CMD 4 1 256 50 70)
fi
if [ "$which_test" = "sequential_space" ] || [ "$which_test" = "all" ] ; then
	(cd log_vol; sudo -E ./sequential_space $NUVO_VM_FT_CMD 2 2 512 70 70)
fi
if [ "$which_test" = "sequential_space2" ] || [ "$which_test" = "all" ] ; then
	(cd log_vol; sudo -E ./sequential_space2 $NUVO_VM_FT_CMD 2 4 512 70 70)
fi

# Tests which are not automatically run with make func_test
if [ "$which_test" = "pr_errors_loop" ] ; then
  (cd log_vol; sudo -E ./pr_errors $NUVO_VM_FT_CMD 0 10)
fi
if [ "$which_test" = "conn_mgr_errors" ] ; then
  (cd log_vol; sudo -E ./conn_mgr_errors $NUVO_VM_FT_CMD 1 1)
fi
if [ "$which_test" = "gc_rand_pit_large" ] ; then
  (cd log_vol; sudo -E ./gc_rand_pit $NUVO_VM_FT_CMD 4 2 256 60 300)
fi
if [ "$which_test" = "passthrough_test" ] ; then
    (cd passthrough; sudo ./passthrough_test $NUVO_VM_FT_CMD)
fi
if [ "$which_test" = "parcel_vol" ] ; then
    (cd parcel_vol; sudo -E ./parcel_vol_test $NUVO_VM_FT_CMD)
fi
if [ "$which_test" = "gc_rand" ] ; then
    (cd log_vol; sudo -E ./gc_rand $NUVO_VM_FT_CMD 4 1 64 75 75)
fi
if [ "$which_test" = "crash_replay" ] ; then
    (cd log_vol; sudo -E ./crash_replay $NUVO_VM_FT_CMD 1 1 1 1024 10000 20 4096 2)
fi
if [ "$which_test" = "umount_ebusy" ] ; then
        (cd log_vol; sudo -E ./umount_ebusy $NUVO_VM_FT_CMD)
fi
