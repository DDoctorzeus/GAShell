# GAShell

GAShell is a Bash-based TOTP authenticator and encrypted secret manager. It can
add secrets manually, import `otpauth://totp` QR codes and generate codes in a
terminal.

## Security and storage

GAShell stores its vault at `~/.config/gashell/secrets` by default. New vaults
use GnuPG password-based AEAD encryption with AES-256, an iterated SHA-512
string-to-key function and an atomic same-directory file replacement. The
configuration directory is mode `0700` and the vault is mode `0600`.

Vaults created by GAShell 0.922 and earlier remain readable. They are migrated
from the legacy OpenSSL/salt format after the next successful add, import,
remove or password change. The original vault is left untouched if migration
or encryption fails.

Keep an independent backup of your TOTP recovery keys. Losing both the vault
password and the original recovery keys cannot be reversed. Anyone who can
read your unlocked terminal can also read the generated one-time codes.

## Requirements

- Bash 4.3 or newer
- GnuPG 2.4 or newer
- `oathtool` from OATH Toolkit for displaying codes
- `zbarimg` from ZBar for QR imports
- `curl` for QR imports from HTTP(S) URLs
- OpenSSL only when reading a legacy GAShell vault

Help is available without any runtime dependency and optional commands are
checked only when their feature is used.

## Usage

```text
Usage: gashell.sh [option]

  no option       Show codes continuously.
  -a, --add       Add a key manually.
  -i, --import QR Add a key from a QR-code image path or HTTP(S) URL.
  -r, --remove    Remove a key.
  -o, --once      Output codes once.
  -p, --password  Change the vault password.
  -h, --help      Show this help screen.
```

Examples:

```bash
./gashell.sh --add
./gashell.sh --import ~/Downloads/auth-qr.png
./gashell.sh --once
./gashell.sh --remove
./gashell.sh --password
```

QR imports accept TOTP URIs and retain their `algorithm`, `digits` and `period`
parameters. HOTP URIs are rejected because GAShell does not store counters.

For automation, an existing vault can be unlocked with
`GASHELL_PASSPHRASE`. Environment variables may be visible to other processes
running as the same user, so interactive password entry is preferable:

```bash
GASHELL_PASSPHRASE='vault password' ./gashell.sh --once
unset GASHELL_PASSPHRASE
```

Set `GASHELL_CONFIG_DIR` to use a different configuration directory, which is
particularly useful for testing or portable setups.

## Development

Run the regression suite with:

```bash
./tests/test_gashell.sh
```

The tests use isolated temporary vaults and mocked OTP/QR tools. They exercise
fresh setup, labels with spaces, QR metadata, removal validation, password
changes, legacy migration, wrong passwords and interrupted/failed encryption.

CI also runs `bash -n`, ShellCheck and `git diff --check`.

## License

GAShell is licensed under the GNU General Public License version 3. See
[`LICENSE`](LICENSE). It comes with absolutely no warranty.
