#!/bin/bash

# Copyright 2019 The gVisor Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -xeo pipefail

if [[ -f $(dirname $0)/common_google.sh ]]; then
  source $(dirname $0)/common_google.sh
else
  source $(dirname $0)/common_bazel.sh
fi


function set_runtime() {
  RUNTIME=$1
  RUNSC_LOGS=/tmp/"${RUNTIME?}"/logs/runsc.log.%TEST%.%TIMESTAMP%.%COMMAND%
  RUNSC_LOGS_DIR=$(dirname "${RUNSC_LOGS?}")
}

function install_runsc_for_test() {
  local -r test_name=$1
  shift

  # Add test to the name, so it doesn't conflict with other runtimes.
  set_runtime $(find_branch_name)_"${test_name?}"

  install_runsc "${RUNTIME?}" \
      --TESTONLY-test-name-env=RUNSC_TEST_NAME \
      --debug \
      --strace \
      --log-packets \
      "$@"
}

function install_runsc() {
  local -r runtime=$1
  shift
  run_as_root //runsc install --experimental=true --runtime="${runtime?}" -- --debug-log "${RUNSC_LOGS?}" "$@"

  # Clear old logs files that may exist.
  sudo rm -f "${RUNSC_LOGS_DIR?}"/*

  # Restart docker to pick up the new runtime configuration.
  sudo systemctl restart docker
}
