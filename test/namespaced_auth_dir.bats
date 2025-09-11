#!/usr/bin/env bats
# vim:set ft=bash :

load helpers

IMAGE=quay.io/crio/fedora-crio-ci:latest
IMAGE_SHA256=8d6fc65c3d3cde17eb31200268f4b4eb6140f0809cd924ac65e9f8f0b3960bbf
NAMESPACE=default

function setup() {
	setup_test
	CONTAINER_NAMESPACED_AUTH_DIR="$TESTDIR/auth" start_crio
}

function teardown() {
	cleanup_test
}

@test "should use and remove a namespaced auth file if available" {
	echo '{}' > "$TESTDIR/auth/$NAMESPACE-$IMAGE_SHA256.json"
	jq '.metadata.namespace = "'$NAMESPACE'"' "$TESTDATA/sandbox_config.json" > "$TESTDIR/sb.json"

	crictl pull --pod-config "$TESTDIR/sb.json" $IMAGE

	grep -q "Using auth file for namespace $NAMESPACE" "$CRIO_LOG"
	grep -q "Removed short-lived auth file: .*$NAMESPACE-$IMAGE_SHA256.json" "$CRIO_LOG"
}

@test "should fail with invalid credentials" {
	echo '{"auths":{"quay.io":{"auth": "bXl1c2VyOm15cGFzc3dvcmQ="}}}' > "$TESTDIR/auth/$NAMESPACE-$IMAGE_SHA256.json"
	jq '.metadata.namespace = "'$NAMESPACE'"' "$TESTDATA/sandbox_config.json" > "$TESTDIR/sb.json"

	run ! crictl pull --pod-config "$TESTDIR/sb.json" $IMAGE

	grep -q "Using auth file for namespace $NAMESPACE" "$CRIO_LOG"
	grep -q "Removed short-lived auth file: .*$NAMESPACE-$IMAGE_SHA256.json" "$CRIO_LOG"
	grep -q "invalid username/password: unauthorized" "$CRIO_LOG"
}

@test "should not use auth file if namespace does not match" {
	echo '{}' > "$TESTDIR/auth/$NAMESPACE-$IMAGE_SHA256.json"
	crictl pull --pod-config "$TESTDATA/sandbox_config.json" $IMAGE

	grep -vq "Using auth file for namespace $NAMESPACE" "$CRIO_LOG"
	grep -vq "Removed short-lived auth file: .*$NAMESPACE-$IMAGE_SHA256.json" "$CRIO_LOG"
}

@test "should fail to pull if auth file is malformed" {
	echo wrong-content > "$TESTDIR/auth/$NAMESPACE-$IMAGE_SHA256.json"
	jq '.metadata.namespace = "'$NAMESPACE'"' "$TESTDATA/sandbox_config.json" > "$TESTDIR/sb.json"

	run ! crictl pull --pod-config "$TESTDIR/sb.json" $IMAGE

	grep -q "Using auth file for namespace $NAMESPACE" "$CRIO_LOG"
	grep -q "Removed short-lived auth file: .*$NAMESPACE-$IMAGE_SHA256.json" "$CRIO_LOG"
	grep -q "invalid character 'w' looking for beginning of value" "$CRIO_LOG"
}
