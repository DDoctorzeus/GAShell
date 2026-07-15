#!/usr/bin/env bash

# SPDX-License-Identifier: GPL-3.0-only

#Shell safety settings
set -o pipefail
umask 077

#Path Vars
readonly CONFIGDIR="${GASHELL_CONFIG_DIR:-$HOME/.config/gashell}"
readonly CODESFILE="$CONFIGDIR/secrets"
readonly LEGACY_SALTFILE="$CONFIGDIR/salt"
readonly GPGHOME="$CONFIGDIR/.gnupg"

#Changeable Vars
PASSWORD=""
PASSWORD_CONFIRM=""
NEW_VAULT=0
QR_TEMP=""
TEMP_FILES=()

#Auth Code Arrays
AUTHCODES=()
AUTHCODES_NAMES=()
AUTHCODES_ALGORITHMS=()
AUTHCODES_DIGITS=()
AUTHCODES_PERIODS=()

#Help output function
ShowHelp() {
	cat <<'EOF'
Usage: gashell.sh [option]

  no option       Show codes continuously.
  -a, --add       Add a key manually.
  -i, --import QR Add a key from a QR-code image path or HTTP(S) URL.
  -r, --remove    Remove a key.
  -o, --once      Output codes once.
  -p, --password  Change the vault password.
  -h, --help      Show this help screen.

For non-interactive use, GASHELL_PASSPHRASE may contain the vault password.
Treat that environment variable as sensitive and unset it when no longer needed.
EOF
}
#//ShowHelp()_END

#Error output function
Die() {
	printf 'ERROR: %s\n' "$*" >&2
	exit 1
}
#//Die()_END

#Temporary file and password cleanup function
Cleanup() {
	local file

	#Remove all registered temporary files
	for file in "${TEMP_FILES[@]}"; do
		if [[ -n "$file" && -e "$file" ]]; then
			rm -f -- "$file"
		fi
	done

	#Clear passwords held by the shell
	PASSWORD=""
	PASSWORD_CONFIRM=""
}
#//Cleanup()_END

#Register cleanup and signal handlers
trap Cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

#Temporary file registration function
RegisterTemp() {
	TEMP_FILES+=("$1")
}
#//RegisterTemp()_END

#Temporary file deregistration function
ForgetTemp() {
	local target=$1
	local file
	local remaining=()

	#Rebuild the list without the completed file
	for file in "${TEMP_FILES[@]}"; do
		if [[ "$file" != "$target" ]]; then
			remaining+=("$file")
		fi
	done
	TEMP_FILES=("${remaining[@]}")
}
#//ForgetTemp()_END

#Required executable check function
RequireCommands() {
	local command_name

	#Check each executable required by the selected operation
	for command_name in "$@"; do
		if ! command -v "$command_name" >/dev/null 2>&1; then
			Die "Missing required executable: $command_name"
		fi
	done
}
#//RequireCommands()_END

#Configuration directory setup function
EnsureConfig() {
	#Reject configuration paths that could redirect file operations
	if [[ -L "$CONFIGDIR" ]]; then
		Die "Refusing to use a symlink as the configuration directory: $CONFIGDIR"
	fi
	if [[ -L "$GPGHOME" ]]; then
		Die "Refusing to use a symlink as the GnuPG directory: $GPGHOME"
	fi

	#Create and secure the configuration directories
	mkdir -p -- "$CONFIGDIR" || Die "Could not create $CONFIGDIR"
	chmod 700 -- "$CONFIGDIR" || Die "Could not secure $CONFIGDIR"
	mkdir -p -- "$GPGHOME" || Die "Could not create $GPGHOME"
	chmod 700 -- "$GPGHOME" || Die "Could not secure $GPGHOME"
}
#//EnsureConfig()_END

#Hidden input reader function
ReadSecretLine() {
	local prompt=$1
	local variable_name=$2
	local value

	#Read without terminal echo and fail cleanly on end-of-input
	printf '%s' "$prompt" >&2
	if ! IFS= read -r -s value; then
		printf '\n' >&2
		Die "Input ended before a password was read"
	fi
	printf '\n' >&2
	printf -v "$variable_name" '%s' "$value"
}
#//ReadSecretLine()_END

#New password input and confirmation function
NewPass() {
	#Keep asking until a non-blank matching password is supplied
	while true; do
		ReadSecretLine "Enter new vault password: " PASSWORD
		ReadSecretLine "Confirm new vault password: " PASSWORD_CONFIRM

		if [[ -z "$PASSWORD" ]]; then
			printf 'Password cannot be blank.\n' >&2
		elif [[ "$PASSWORD" != "$PASSWORD_CONFIRM" ]]; then
			printf 'Passwords do not match.\n' >&2
		else
			PASSWORD_CONFIRM=""
			return
		fi
	done
}
#//NewPass()_END

#Existing password input function
AskForPassword() {
	#Use the documented environment override when provided
	if [[ -n "${GASHELL_PASSPHRASE:-}" ]]; then
		PASSWORD=$GASHELL_PASSPHRASE
		return
	fi

	#Otherwise request a non-blank password interactively
	while [[ -z "$PASSWORD" ]]; do
		ReadSecretLine "Enter vault password: " PASSWORD
		if [[ -z "$PASSWORD" ]]; then
			printf 'Password cannot be blank.\n' >&2
		fi
	done
}
#//AskForPassword()_END

#Auth code name validation function
ValidateName() {
	local name=$1

	[[ -n "$name" ]] || return 1
	[[ "$name" != *$'\t'* ]] || return 1
	[[ "$name" != *$'\r'* ]] || return 1
	[[ "$name" != *$'\n'* ]] || return 1
}
#//ValidateName()_END

#Base32 secret normalisation function
NormaliseSecret() {
	local secret=$1

	#Base32 values are stored uppercase without whitespace
	secret=${secret^^}
	secret=${secret//[[:space:]]/}
	printf '%s' "$secret"
}
#//NormaliseSecret()_END

#Base32 secret validation function
ValidateSecret() {
	local secret=$1

	[[ "$secret" =~ ^[A-Z2-7]+=*$ ]]
}
#//ValidateSecret()_END

#TOTP parameter validation function
ValidateOTPParameters() {
	local algorithm=$1
	local digits=$2
	local period=$3

	[[ "$algorithm" == "SHA1" || "$algorithm" == "SHA256" || "$algorithm" == "SHA512" ]] || return 1
	[[ "$digits" =~ ^[0-9]+$ ]] || return 1
	(( 10#$digits >= 6 && 10#$digits <= 8 )) || return 1
	[[ "$period" =~ ^[0-9]+$ ]] || return 1
	(( 10#$period >= 1 && 10#$period <= 300 )) || return 1
}
#//ValidateOTPParameters()_END

#Auth code array append function
AppendCode() {
	local secret=$1
	local name=$2
	local algorithm=$3
	local digits=$4
	local period=$5

	AUTHCODES+=("$secret")
	AUTHCODES_NAMES+=("$name")
	AUTHCODES_ALGORITHMS+=("$algorithm")
	AUTHCODES_DIGITS+=("$digits")
	AUTHCODES_PERIODS+=("$period")
}
#//AppendCode()_END

#Auth code alphanumeric sorting function
SortCodes() {
	local size=${#AUTHCODES[@]}
	local i
	local j
	local next
	local temp

	#Sort names and every matching metadata array together
	for ((i = 0; i < size - 1; i++)); do
		for ((j = 0; j < size - i - 1; j++)); do
			next=$((j + 1))
			if [[ "${AUTHCODES_NAMES[j]}" > "${AUTHCODES_NAMES[next]}" ]]; then
				temp=${AUTHCODES_NAMES[j]}
				AUTHCODES_NAMES[j]=${AUTHCODES_NAMES[next]}
				AUTHCODES_NAMES[next]=$temp

				temp=${AUTHCODES[j]}
				AUTHCODES[j]=${AUTHCODES[next]}
				AUTHCODES[next]=$temp

				temp=${AUTHCODES_ALGORITHMS[j]}
				AUTHCODES_ALGORITHMS[j]=${AUTHCODES_ALGORITHMS[next]}
				AUTHCODES_ALGORITHMS[next]=$temp

				temp=${AUTHCODES_DIGITS[j]}
				AUTHCODES_DIGITS[j]=${AUTHCODES_DIGITS[next]}
				AUTHCODES_DIGITS[next]=$temp

				temp=${AUTHCODES_PERIODS[j]}
				AUTHCODES_PERIODS[j]=${AUTHCODES_PERIODS[next]}
				AUTHCODES_PERIODS[next]=$temp
			fi
		done
	done
}
#//SortCodes()_END

#Vault record serialization function
SerializeCodes() {
	local i

	#Write the payload format marker first
	printf 'GASHELL\t2\n'

	#Write one tab-delimited record per auth code
	for ((i = 0; i < ${#AUTHCODES[@]}; i++)); do
		printf '%s\t%s\t%s\t%s\t%s\n' \
			"${AUTHCODES[i]}" \
			"${AUTHCODES_NAMES[i]}" \
			"${AUTHCODES_ALGORITHMS[i]}" \
			"${AUTHCODES_DIGITS[i]}" \
			"${AUTHCODES_PERIODS[i]}"
	done
}
#//SerializeCodes()_END

#Current vault payload parsing function
ParseV2Payload() {
	local payload=$1
	local line
	local line_number=0
	local secret
	local name
	local algorithm
	local digits
	local period
	local extra

	#Reset all code arrays before loading records
	AUTHCODES=()
	AUTHCODES_NAMES=()
	AUTHCODES_ALGORITHMS=()
	AUTHCODES_DIGITS=()
	AUTHCODES_PERIODS=()

	#Validate the format header and then parse each stored record
	while IFS= read -r line || [[ -n "$line" ]]; do
		line_number=$((line_number + 1))
		if (( line_number == 1 )); then
			[[ "$line" == $'GASHELL\t2' ]] || Die "Unsupported or damaged vault payload"
			continue
		fi

		[[ -n "$line" ]] || Die "Damaged vault: blank record at line $line_number"
		IFS=$'\t' read -r secret name algorithm digits period extra <<< "$line"
		[[ -z "$extra" ]] || Die "Damaged vault: too many fields at line $line_number"
		ValidateSecret "$secret" || Die "Damaged vault: invalid secret at line $line_number"
		ValidateName "$name" || Die "Damaged vault: invalid name at line $line_number"
		ValidateOTPParameters "$algorithm" "$digits" "$period" || \
			Die "Damaged vault: invalid OTP parameters at line $line_number"
		AppendCode "$secret" "$name" "$algorithm" "$digits" "$period"
	done <<< "$payload"

	(( line_number > 0 )) || Die "Vault payload is empty"
}
#//ParseV2Payload()_END

#Current GnuPG vault loading function
LoadV2Vault() {
	local payload

	#Decrypt the authenticated vault with the password on a file descriptor
	RequireCommands gpg
	if ! payload=$(gpg \
		--batch \
		--quiet \
		--no-options \
		--homedir "$GPGHOME" \
		--pinentry-mode loopback \
		--passphrase-fd 3 \
		--decrypt "$CODESFILE" \
		3< <(printf '%s\n' "$PASSWORD") 2>/dev/null); then
		Die "Could not decrypt the vault; the password may be wrong or the file may be damaged"
	fi

	#Only parse plaintext after GnuPG verifies the complete message
	ParseV2Payload "$payload"
}
#//LoadV2Vault()_END

#Legacy OpenSSL vault loading function
LoadLegacyVault() {
	local salt
	local escaped_payload
	local payload
	local line
	local line_number=0
	local secret
	local name
	local extra

	#Check and secure the separate salt used by the original format
	RequireCommands openssl
	[[ ! -L "$LEGACY_SALTFILE" ]] || Die "Refusing to read a symlinked legacy salt"
	[[ -f "$LEGACY_SALTFILE" ]] || Die "Legacy vault salt file is missing"
	chmod 600 -- "$LEGACY_SALTFILE" || Die "Could not secure the legacy salt file"
	salt=$(tr -d '\n' < "$LEGACY_SALTFILE") || Die "Could not read the legacy salt"
	[[ -n "$salt" ]] || Die "Legacy vault salt is blank"

	#Decrypt through a file descriptor so the password is not in process arguments
	if ! escaped_payload=$(openssl enc \
		-d \
		-pbkdf2 \
		-aes-256-cbc \
		-a \
		-nosalt \
		-pass fd:3 \
		-in "$CODESFILE" \
		3< <(printf '%s\n' "$salt$PASSWORD$salt") 2>/dev/null); then
		Die "Could not decrypt the legacy vault; the password may be wrong or the file may be damaged"
	fi

	#Reset all code arrays before importing legacy records
	AUTHCODES=()
	AUTHCODES_NAMES=()
	AUTHCODES_ALGORITHMS=()
	AUTHCODES_DIGITS=()
	AUTHCODES_PERIODS=()

	#An empty legacy vault is valid
	[[ -n "$escaped_payload" ]] || {
		return
	}

	#Translate only the delimiters written by the original serializer
	payload=${escaped_payload//\\n/$'\n'}
	payload=${payload//\\t/$'\t'}

	#Validate and append each legacy record with its original defaults
	while IFS= read -r line || [[ -n "$line" ]]; do
		line_number=$((line_number + 1))
		IFS=$'\t' read -r secret name extra <<< "$line"
		[[ -z "$extra" ]] || Die "Damaged legacy vault record at line $line_number"
		secret=$(NormaliseSecret "$secret")
		ValidateSecret "$secret" || Die "Invalid secret in legacy vault at line $line_number"
		ValidateName "$name" || Die "Invalid name in legacy vault at line $line_number"
		AppendCode "$secret" "$name" "SHA1" "6" "30"
	done <<< "$payload"
}
#//LoadLegacyVault()_END

#Vault format detection and loading function
LoadVault() {
	local first_line

	#Secure and inspect the live vault without following symlinks
	[[ ! -L "$CODESFILE" ]] || Die "Refusing to read a symlinked vault"
	[[ -f "$CODESFILE" ]] || Die "Vault path is not a regular file"
	chmod 600 -- "$CODESFILE" || Die "Could not secure the vault"
	IFS= read -r first_line < "$CODESFILE" || true

	#Select the authenticated format or the supported legacy format
	if [[ "$first_line" == "-----BEGIN PGP MESSAGE-----" ]]; then
		LoadV2Vault
	elif [[ -e "$LEGACY_SALTFILE" ]]; then
		LoadLegacyVault
	else
		Die "Vault format is unrecognized or damaged"
	fi
}
#//LoadVault()_END

#Atomic authenticated vault saving function
SaveVault() {
	local temp_file
	local i

	#Validate every parallel array entry before creating ciphertext
	RequireCommands gpg
	for ((i = 0; i < ${#AUTHCODES[@]}; i++)); do
		ValidateSecret "${AUTHCODES[i]}" || Die "Refusing to save an invalid secret"
		ValidateName "${AUTHCODES_NAMES[i]}" || Die "Refusing to save an invalid name"
		ValidateOTPParameters \
			"${AUTHCODES_ALGORITHMS[i]}" \
			"${AUTHCODES_DIGITS[i]}" \
			"${AUTHCODES_PERIODS[i]}" || Die "Refusing to save invalid OTP parameters"
	done

	#Sort and create a mode-0600 temporary file beside the live vault
	SortCodes
	temp_file=$(mktemp "$CONFIGDIR/.secrets.tmp.XXXXXX") || Die "Could not create a temporary vault"
	RegisterTemp "$temp_file"

	#Encrypt with password-based AEAD and keep plaintext on a pipe
	if ! SerializeCodes | gpg \
		--batch \
		--yes \
		--quiet \
		--no-options \
		--homedir "$GPGHOME" \
		--pinentry-mode loopback \
		--passphrase-fd 3 \
		--symmetric \
		--armor \
		--force-aead \
		--aead-algo OCB \
		--cipher-algo AES256 \
		--s2k-mode 3 \
		--s2k-digest-algo SHA512 \
		--s2k-count 65011712 \
		--compress-algo none \
		--output "$temp_file" \
		3< <(printf '%s\n' "$PASSWORD") 2>/dev/null; then
		Die "Could not encrypt the new vault; the existing vault was not changed"
	fi

	#Replace the live vault only after encryption completed successfully
	[[ -s "$temp_file" ]] || Die "Encryption produced an empty vault; the existing vault was not changed"
	chmod 600 -- "$temp_file" || Die "Could not secure the new vault"
	mv -f -- "$temp_file" "$CODESFILE" || Die "Could not atomically replace the vault"
	#Retire the legacy salt only after the new vault is safely installed
	ForgetTemp "$temp_file"
	rm -f -- "$LEGACY_SALTFILE"
}
#//SaveVault()_END

#TOTP code output function
ShowCodes() {
	local i
	local code
	local status=0
	local algorithm

	#Return early when there is nothing to generate
	if (( ${#AUTHCODES[@]} == 0 )); then
		printf 'No authentication codes are stored. Use --add or --import to add one.\n'
		return
	fi

	#Generate each code with its stored TOTP parameters
	for ((i = 0; i < ${#AUTHCODES[@]}; i++)); do
		algorithm=${AUTHCODES_ALGORITHMS[i],,}
		if code=$(printf '%s\n' "${AUTHCODES[i]}" | oathtool \
			--base32 \
			"--totp=$algorithm" \
			"--digits=${AUTHCODES_DIGITS[i]}" \
			"--time-step-size=${AUTHCODES_PERIODS[i]}s" \
			- 2>/dev/null); then
			printf '%d. %s : %s\n' "$((i + 1))" "${AUTHCODES_NAMES[i]}" "$code"
		else
			printf '%d. %s : [generation failed]\n' "$((i + 1))" "${AUTHCODES_NAMES[i]}" >&2
			status=1
		fi
	done

	return "$status"
}
#//ShowCodes()_END

#Manual auth code input function
AddManualCode() {
	local secret
	local name

	#Read the secret and display name without word splitting
	printf 'Enter new auth secret: '
	IFS= read -r secret || Die "Input ended before a secret was read"
	printf 'Enter new name/description: '
	IFS= read -r name || Die "Input ended before a name was read"

	#Normalise and validate both input values
	secret=$(NormaliseSecret "$secret")
	ValidateSecret "$secret" || Die "The secret must be a Base32 value using A-Z and 2-7"
	ValidateName "$name" || Die "The name cannot be blank or contain tabs/newlines"

	#Add with standard TOTP defaults and save atomically
	AppendCode "$secret" "$name" "SHA1" "6" "30"
	SaveVault
	printf 'New code added successfully.\n'
}
#//AddManualCode()_END

#URL percent-decoding function
URLDecode() {
	local data=${1//+/ }
	local output=""
	local prefix
	local hex
	local character

	#Decode each percent-encoded byte and reject malformed/NUL values
	while [[ "$data" == *%* ]]; do
		prefix=${data%%\%*}
		output+=$prefix
		data=${data#*%}
		[[ "$data" =~ ^([[:xdigit:]]{2})(.*)$ ]] || return 1
		hex=${BASH_REMATCH[1]}
		data=${BASH_REMATCH[2]}
		[[ "$hex" != "00" ]] || return 1
		printf -v character '%b' "\\x$hex"
		output+=$character
	done

	URL_DECODED=$output$data
}
#//URLDecode()_END

#OTPAuth URI parsing function
ParseOTPAuthURI() {
	local uri=$1
	local remainder
	local encoded_label
	local query
	local label
	local pair
	local raw_key
	local raw_value
	local key
	local value
	local secret=""
	local algorithm="SHA1"
	local digits="6"
	local period="30"
	local query_parts=()

	#Require a TOTP URI and split its label from its query string
	[[ "$uri" == otpauth://totp/*\?* ]] || Die "QR code is not an otpauth TOTP URI"
	remainder=${uri#otpauth://totp/}
	encoded_label=${remainder%%\?*}
	query=${remainder#*\?}
	URLDecode "$encoded_label" || Die "QR label contains invalid percent encoding"
	label=$URL_DECODED
	ValidateName "$label" || Die "QR code has an invalid or blank label"

	#Extract the supported OTPAuth query parameters
	IFS='&' read -r -a query_parts <<< "$query"
	for pair in "${query_parts[@]}"; do
		[[ "$pair" == *=* ]] || continue
		raw_key=${pair%%=*}
		raw_value=${pair#*=}
		URLDecode "$raw_key" || Die "QR query contains invalid percent encoding"
		key=${URL_DECODED,,}
		URLDecode "$raw_value" || Die "QR query contains invalid percent encoding"
		value=$URL_DECODED

		case "$key" in
			secret) secret=$value ;;
			algorithm) algorithm=${value^^} ;;
			digits) digits=$value ;;
			period) period=$value ;;
		esac
	done

	#Normalise and validate all imported values
	secret=$(NormaliseSecret "$secret")
	ValidateSecret "$secret" || Die "QR code contains no valid Base32 secret"
	ValidateOTPParameters "$algorithm" "$digits" "$period" || \
		Die "QR code contains unsupported algorithm, digits or period parameters"

	#Return parsed fields through the script's global import variables
	AUTHCODE=$secret
	AUTHCODE_NAME=$label
	AUTHCODE_ALGORITHM=$algorithm
	AUTHCODE_DIGITS=$digits
	AUTHCODE_PERIOD=$period
}
#//ParseOTPAuthURI()_END

#QR code import function
ImportQRCode() {
	local location=$1
	local qr_data

	#Download remote images to a registered mode-0600 temporary file
	RequireCommands zbarimg
	if [[ "$location" =~ ^https?:// ]]; then
		RequireCommands curl
		QR_TEMP=$(mktemp "${TMPDIR:-/tmp}/gashell-qr.XXXXXX") || Die "Could not create a QR temporary file"
		RegisterTemp "$QR_TEMP"
		chmod 600 -- "$QR_TEMP"
		if ! curl \
			--fail \
			--silent \
			--show-error \
			--location \
			--proto '=http,https' \
			--proto-redir '=http,https' \
			--max-filesize 10485760 \
			--output "$QR_TEMP" \
			-- "$location"; then
			Die "Could not download the QR image"
		fi
		location=$QR_TEMP
	fi

	#Decode exactly one QR value from a readable image
	[[ -f "$location" && -r "$location" ]] || Die "Could not read QR image: $location"
	if ! qr_data=$(zbarimg --quiet --raw -- "$location" 2>/dev/null); then
		Die "Could not decode a QR code from $location"
	fi
	[[ -n "$qr_data" ]] || Die "QR image did not contain any data"
	[[ "$qr_data" != *$'\n'* ]] || Die "QR image must contain exactly one code"

	#Parse, append and atomically save the imported record
	ParseOTPAuthURI "$qr_data"
	AppendCode "$AUTHCODE" "$AUTHCODE_NAME" "$AUTHCODE_ALGORITHM" "$AUTHCODE_DIGITS" "$AUTHCODE_PERIOD"
	SaveVault
	printf 'New code imported successfully.\n'
}
#//ImportQRCode()_END

#Auth code removal function
RemoveCode() {
	local selection
	local index

	#Show the current list before requesting a selection
	(( ${#AUTHCODES[@]} > 0 )) || Die "There are no codes to remove"
	ShowCodes || true

	#Keep prompting until a numeric in-range selection is supplied
	while true; do
		printf '\nEnter code to delete (1-%d): ' "${#AUTHCODES[@]}"
		IFS= read -r selection || Die "Input ended before a selection was read"
		if [[ "$selection" =~ ^[0-9]+$ ]] && \
			(( 10#$selection >= 1 && 10#$selection <= ${#AUTHCODES[@]} )); then
			break
		fi
		printf 'Please enter a number from 1 to %d.\n' "${#AUTHCODES[@]}" >&2
	done

	#Remove the selected entry from every parallel metadata array
	index=$((10#$selection - 1))
	unset "AUTHCODES[$index]"
	unset "AUTHCODES_NAMES[$index]"
	unset "AUTHCODES_ALGORITHMS[$index]"
	unset "AUTHCODES_DIGITS[$index]"
	unset "AUTHCODES_PERIODS[$index]"
	#Repack sparse arrays before saving
	AUTHCODES=("${AUTHCODES[@]}")
	AUTHCODES_NAMES=("${AUTHCODES_NAMES[@]}")
	AUTHCODES_ALGORITHMS=("${AUTHCODES_ALGORITHMS[@]}")
	AUTHCODES_DIGITS=("${AUTHCODES_DIGITS[@]}")
	AUTHCODES_PERIODS=("${AUTHCODES_PERIODS[@]}")

	#Save the updated arrays atomically
	SaveVault
	printf 'Code removed successfully.\n'
}
#//RemoveCode()_END

#Command Vars
ACTION="loop"
IMPORT_LOCATION=""

#Parse and validate the requested command
case "${1:-}" in
	"")
		#No option starts continuous display mode
		(( $# == 0 )) || Die "Unexpected arguments"
		;;
	-h|--help)
		#Help exits before dependency or vault checks
		(( $# == 1 )) || Die "--help does not accept additional arguments"
		ShowHelp
		exit 0
		;;
	-a|--add)
		#Manual add accepts no additional arguments
		(( $# == 1 )) || Die "--add does not accept additional arguments"
		ACTION="add"
		;;
	-i|--import)
		#QR import requires one path or URL
		(( $# == 2 )) || Die "--import requires one image path or URL"
		ACTION="import"
		IMPORT_LOCATION=$2
		;;
	-r|--remove)
		#Remove accepts no additional arguments
		(( $# == 1 )) || Die "--remove does not accept additional arguments"
		ACTION="remove"
		;;
	-o|--once)
		#One-time output accepts no additional arguments
		(( $# == 1 )) || Die "--once does not accept additional arguments"
		ACTION="once"
		;;
	-p|--password)
		#Password change accepts no additional arguments
		(( $# == 1 )) || Die "--password does not accept additional arguments"
		ACTION="password"
		;;
	*)
		#Unknown options fail before any password prompt
		Die "Unknown option: $1 (use --help for usage)"
		;;
esac

#Check feature-specific dependencies before prompting for a password
case "$ACTION" in
	loop|once|remove)
		#Code display operations require OATH Toolkit
		RequireCommands oathtool
		;;
	import)
		#QR imports require ZBar and URL imports additionally require curl
		RequireCommands zbarimg
		if [[ "$IMPORT_LOCATION" =~ ^https?:// ]]; then
			RequireCommands curl
		fi
		;;
esac

#Create and secure configuration paths
EnsureConfig
[[ ! -L "$CODESFILE" ]] || Die "Refusing to use a symlinked vault"

#All new or modifying operations require the authenticated GnuPG format
if [[ ! -e "$CODESFILE" || "$ACTION" == "add" || "$ACTION" == "import" || \
	"$ACTION" == "remove" || "$ACTION" == "password" ]]; then
	RequireCommands gpg
fi

#Unlock an existing vault or collect a password for a new vault
if [[ -e "$CODESFILE" ]]; then
	AskForPassword
	LoadVault
else
	NEW_VAULT=1
	NewPass
fi

#Run the selected operation
case "$ACTION" in
	add)
		#Add a manually entered code
		AddManualCode
		;;
	import)
		#Import a code from a QR image
		ImportQRCode "$IMPORT_LOCATION"
		;;
	remove)
		#Create a new empty vault if needed, then remove a code
		RequireCommands oathtool
		if (( NEW_VAULT )); then
			SaveVault
		fi
		RemoveCode
		;;
	once)
		#Create a new empty vault if needed, then output once
		RequireCommands oathtool
		if (( NEW_VAULT )); then
			SaveVault
		fi
		ShowCodes
		;;
	password)
		#Initialize a new vault or re-encrypt an existing vault
		if (( NEW_VAULT )); then
			SaveVault
			printf 'Vault initialized successfully.\n'
		else
			NewPass
			SaveVault
			printf 'Password changed successfully.\n'
		fi
		;;
	loop)
		#Create a new empty vault if needed before continuous output
		RequireCommands oathtool
		if (( NEW_VAULT )); then
			SaveVault
		fi
		if (( ${#AUTHCODES[@]} == 0 )); then
			ShowCodes
			exit 0
		fi

		#Refresh the terminal until interrupted by the user
		[[ -t 1 ]] || Die "Continuous output requires a terminal; use --once instead"
		while true; do
			printf '\033[H\033[2J'
			ShowCodes || true
			printf '\nCtrl-C to exit.\n'
			sleep 1
		done
		;;
esac
