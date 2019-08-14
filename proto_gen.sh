#!/bin/sh

protoc --go_out=plugins=grpc:. protocol/protocol.proto
