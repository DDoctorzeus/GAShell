#!/usr/bin/env bash

set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
readonly ROOT
readonly SCRIPT="$ROOT/gashell.sh"
readonly MOCK_BIN="$ROOT/tests/mocks"
TEST_ROOT=$(mktemp -d)
readonly TEST_ROOT
GASHELL_REAL_GPG=$(command -v gpg)
readonly GASHELL_REAL_GPG
readonly TEST_PATH="$MOCK_BIN:$PATH"

export GASHELL_REAL_GPG

cleanup() {
	rm -rf -- "$TEST_ROOT"
}
trap cleanup EXIT

fail() {
	printf 'not ok - %s\n' "$*" >&2
	exit 1
}

assert_contains() {
	local haystack=$1
	local needle=$2

	[[ "$haystack" == *"$needle"* ]] || fail "expected output to contain: $needle"
}

assert_not_contains() {
	local haystack=$1
	local needle=$2

	[[ "$haystack" != *"$needle"* ]] || fail "expected output not to contain: $needle"
}

assert_mode() {
	local expected=$1
	local path=$2
	local actual

	actual=$(stat -c '%a' "$path")
	[[ "$actual" == "$expected" ]] || fail "expected $path mode $expected, got $actual"
}

run_gashell() {
	local config=$1
	shift
	env PATH="$TEST_PATH" GASHELL_CONFIG_DIR="$config" "$SCRIPT" "$@"
}

create_legacy_vault() {
	local config=$1
	local password=$2
	local salt='legacy-test-salt'

	mkdir -p "$config"
	printf '%s\n' "$salt" > "$config/salt"
	printf '%s\n' 'JBSWY3DPEHPK3PXP\tLegacy Account' | openssl enc \
		-e \
		-pbkdf2 \
		-aes-256-cbc \
		-a \
		-nosalt \
		-pass fd:3 \
		-out "$config/secrets" \
		3< <(printf '%s\n' "$salt$password$salt")
}

test_help_without_runtime_dependencies() {
	local output

	output=$(env PATH="/usr/bin:/bin" "$SCRIPT" --help)
	assert_contains "$output" 'Usage: gashell.sh'
	printf 'ok - help works before dependency and vault checks\n'
}

test_create_add_and_preserve_spaces() {
	local config="$TEST_ROOT/spaces/config"
	local output
	local oath_log="$TEST_ROOT/spaces/oath.log"

	mkdir -p "$(dirname "$config")"
	printf 'test-pass\ntest-pass\nJBSW Y3DP EHPK 3PXP\nMy Account\n' | run_gashell "$config" --add >/dev/null
	assert_mode 700 "$config"
	assert_mode 600 "$config/secrets"
	assert_contains "$(sed -n '1p' "$config/secrets")" 'BEGIN PGP MESSAGE'
	[[ ! -e "$config/salt" ]] || fail 'new vault unexpectedly created a legacy salt file'

	output=$(GASHELL_PASSPHRASE=test-pass GASHELL_TEST_OATH_LOG="$oath_log" run_gashell "$config" --once)
	assert_contains "$output" 'My Account : 111111'
	assert_contains "$(< "$oath_log")" '--totp=sha1 --digits=6 --time-step-size=30s -'
	assert_not_contains "$(< "$oath_log")" 'JBSWY3DPEHPK3PXP'
	printf 'ok - fresh setup is secure and labels preserve spaces\n'
}

test_invalid_removal_does_not_delete() {
	local config="$TEST_ROOT/spaces/config"
	local output

	printf 'KRUGS4ZANFZSAYJA\nBeta\n' | GASHELL_PASSPHRASE=test-pass run_gashell "$config" --add >/dev/null
	output=$(printf '0\n2\n' | GASHELL_PASSPHRASE=test-pass run_gashell "$config" --remove 2>&1)
	assert_contains "$output" 'Please enter a number from 1 to 2.'
	output=$(GASHELL_PASSPHRASE=test-pass run_gashell "$config" --once)
	assert_contains "$output" 'Beta : 222222'
	assert_not_contains "$output" 'My Account'
	printf 'ok - removal rejects zero and out-of-range values\n'
}

test_qr_parameters_and_decoding() {
	local config="$TEST_ROOT/qr/config"
	local image="$TEST_ROOT/qr/image with spaces.png"
	local output
	local oath_log="$TEST_ROOT/qr/oath.log"
	local qr='otpauth://totp/Acme%20Inc%3Aalice%40example.com?secret=ONXW4ZDFOQ%3D%3D%3D%3D%3D%3D&algorithm=SHA256&digits=8&period=45'

	mkdir -p "$(dirname "$image")"
	: > "$image"
	printf 'qr-pass\nqr-pass\n' | GASHELL_TEST_QR_DATA="$qr" run_gashell "$config" --import "$image" >/dev/null
	output=$(GASHELL_PASSPHRASE=qr-pass GASHELL_TEST_OATH_LOG="$oath_log" run_gashell "$config" --once)
	assert_contains "$output" 'Acme Inc:alice@example.com : 33333333'
	assert_contains "$(< "$oath_log")" '--totp=sha256 --digits=8 --time-step-size=45s -'
	printf 'ok - QR import validates and retains TOTP parameters\n'
}

test_downloaded_qr_is_cleaned_up() {
	local config="$TEST_ROOT/qr-url/config"
	local curl_log="$TEST_ROOT/qr-url/curl.log"
	local qr='otpauth://totp/Downloaded?secret=JBSWY3DPEHPK3PXP'
	local temporary_image

	mkdir -p "$(dirname "$config")"
	printf 'url-pass\nurl-pass\n' | \
		GASHELL_TEST_QR_DATA="$qr" GASHELL_TEST_CURL_LOG="$curl_log" \
		run_gashell "$config" --import 'https://example.invalid/code.png' >/dev/null
	temporary_image=$(< "$curl_log")
	[[ ! -e "$temporary_image" ]] || fail 'downloaded QR temporary file was not removed'
	printf 'ok - downloaded QR images are removed after import\n'
}

test_failed_encryption_is_atomic() {
	local config="$TEST_ROOT/spaces/config"
	local backup="$TEST_ROOT/spaces/secrets.backup"

	cp "$config/secrets" "$backup"
	if printf 'ONXW4ZDFOQ======\nShould Not Save\n' | \
		GASHELL_PASSPHRASE=test-pass GASHELL_TEST_FAIL_ENCRYPT=1 run_gashell "$config" --add >/dev/null 2>&1; then
		fail 'simulated encryption failure unexpectedly succeeded'
	fi
	cmp -s "$backup" "$config/secrets" || fail 'vault changed after encryption failure'
	printf 'ok - encryption failure leaves the live vault unchanged\n'
}

test_wrong_password_is_non_destructive() {
	local config="$TEST_ROOT/spaces/config"
	local backup="$TEST_ROOT/spaces/wrong-password.backup"

	cp "$config/secrets" "$backup"
	if GASHELL_PASSPHRASE=wrong run_gashell "$config" --once >/dev/null 2>&1; then
		fail 'wrong password unexpectedly succeeded'
	fi
	cmp -s "$backup" "$config/secrets" || fail 'vault changed after wrong password'
	printf 'ok - wrong passwords are non-destructive\n'
}

test_legacy_migration() {
	local config="$TEST_ROOT/legacy/config"
	local output

	create_legacy_vault "$config" legacy-pass
	printf 'KRUGS4ZANFZSAYJA\nNew Account\n' | GASHELL_PASSPHRASE=legacy-pass run_gashell "$config" --add >/dev/null
	assert_contains "$(sed -n '1p' "$config/secrets")" 'BEGIN PGP MESSAGE'
	[[ ! -e "$config/salt" ]] || fail 'legacy salt remained after successful migration'
	output=$(GASHELL_PASSPHRASE=legacy-pass run_gashell "$config" --once)
	assert_contains "$output" 'Legacy Account : 111111'
	assert_contains "$output" 'New Account : 222222'
	printf 'ok - legacy vault migrates only after a successful write\n'
}

test_password_change() {
	local config="$TEST_ROOT/spaces/config"

	printf 'new-pass\nnew-pass\n' | GASHELL_PASSPHRASE=test-pass run_gashell "$config" --password >/dev/null
	if GASHELL_PASSPHRASE=test-pass run_gashell "$config" --once >/dev/null 2>&1; then
		fail 'old password still unlocked the changed vault'
	fi
	GASHELL_PASSPHRASE=new-pass run_gashell "$config" --once >/dev/null
	printf 'ok - password changes re-encrypt the vault\n'
}

test_unknown_option_fails() {
	if "$SCRIPT" --definitely-invalid >/dev/null 2>&1; then
		fail 'unknown option unexpectedly succeeded'
	fi
	printf 'ok - unknown options fail before prompting\n'
}

test_help_without_runtime_dependencies
test_create_add_and_preserve_spaces
test_invalid_removal_does_not_delete
test_qr_parameters_and_decoding
test_downloaded_qr_is_cleaned_up
test_failed_encryption_is_atomic
test_wrong_password_is_non_destructive
test_legacy_migration
test_password_change
test_unknown_option_fails

printf 'All GAShell tests passed.\n'
