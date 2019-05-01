# GAShell
A bash script that generates and securely manages Google Authenticator codes

Techtonic Software 2019 - http://www.techtonicsoftware.com/

This Program/Script Is Lisenced Under GNU V3 (https://www.gnu.org/licenses/gpl-3.0.en.html) and comes with ABSOLUTELY NO WARRANTY. You may distribute, modify and run it however you must not claim it as your own nor sublisence it.

Any distribution must include this readme file.

Please note this was a script that was done in my spare time and while it has had substational testing, I recommend you have additonal backups for your google auth private keys. I welcome any suggestions for improving this script, especially suggestions to improve security. I have only tested this on Linux but may work under other *nix or Linux-based systems by changing the "BINPREFIX" variable accordingly.

GAShell acts as Google Authenticator code generator and manager allowing you to generate, add and remove your Google Authenticator codes inside your bash shell/terminal. GAShell stores your codes on your filesystem encrypted by a private passphrase (that you set yourself) with aes-256 under ~/.config/gashell. It also has the ability to read in google auth QR codes either via URL or through a local image.

You will require the following applications/binaries to use this script: sed, oathtool, openssl, zbar, curl. As well as a basic set of *nix system commands.

    Usage: ./gashell.sh args

    none:   Show codes on loop.
    -a: Add a new key.
    -i: Add a new key via QR code (url or file path).
    -r: Remove a key.
    -o: Output codes once only.
    -p: Set a new password.
    -h: Show this help screen.

    You can remove the need to enter the password on output operations by specifying it in the following variable: GASHELL_PASSPHRASE. Please note that this script will automatically take the password from this variable if defined.

    Note: Cannot currently stack flags.