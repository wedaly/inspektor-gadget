#!/bin/bash
# Copyright 2016 The Kubernetes Authors.
# Copyright 2022 The Inspektor Gadget authors
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

. $(dirname ${BASH_SOURCE})/../util.sh

desc "Install the Trace custom resource for socket-collector"
run "cat <<EOF | kubectl apply -f -
apiVersion: gadget.kinvolk.io/v1alpha1
kind: Trace
metadata:
  name: socket-collector
  namespace: gadget
spec:
  gadget: socket-collector
  filter:
    namespace: demo
  runMode: Manual
  outputMode: Status
  parameters:
    proto: all
EOF"

desc "Start a pod making HTTP requests"
run "kubectl run -n demo test-pod --image busybox -- sh -c 'while true ; do wget -qO- http://www.example.com &> /dev/null ; sleep 1 ; done'"
run "kubectl wait -n demo --for=condition=ready pod/test-pod"

desc "Collect a snapshot of open sockets"
run "kubectl annotate -n gadget trace/socket-collector gadget.kinvolk.io/operation=collect"

sleep 2

desc "Check the status of the Trace resource"
run "kubectl get trace -n gadget socket-collector | jq -r ".items[0].status.output" | head -n 14"

sleep 5
