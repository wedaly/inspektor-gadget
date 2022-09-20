#!/bin/bash

kubectl delete pod -n demo test-pod --force
kubectl delete ns demo || true
kubectl delete -n gadget socket-collector || true
