#!/bin/bash

#Techtonic Software 2019 - http://www.techtonicsoftware.com/

#This Program/Script Is Lisenced Under GNU V3 (https://www.gnu.org/licenses/gpl-3.0.en.html) and comes with ABSOLUTELY NO WARRANTY. You may distribute, modify and run it however you must not claim it as your own nor sublisence it.

#CHANGE THIS IF NOT CORRECT ON YOUR SYSTEM
BINPREFIX="/bin";

#Path Vars
REQBINS=("sed" "oathtool" "openssl" "zbarimg" "curl");
CONFIGDIR="/home/$USER/.config/gashell";
SALTFILE="$CONFIGDIR/salt";
SALTLENGTH=1024;
CODESFILE="$CONFIGDIR/secrets"
QRWEBOUTPUT="/tmp/gashellqr.file";
ERROROUTFILE="/tmp/gashellerr.txt";

#Help Vars
HELPTEXT="
	Usage: ./command args

	none:\tShow codes on loop.
	-a:\tAdd a new key.
	-i:\tAdd a new key via QR code (url or file path).
	-r:\tRemove a key.
	-o:\tOutput codes once only.
	-p:\tSet a new password.
	-h:\tShow this help screen.

	You can remove the need to enter the password on output operations by specifying it in the following variable: GASHELL_PASSPHRASE. Please note that this script will automatically take the password from this variable if defined.

	Note: Cannot currently stack flags.
";

#Changeable vars
PASSWORDSMATCH=0;
PASSWORD="";
PASSWORD_CONFIRM="";
SALT="";
CODESSTR="";
AUTHCODE="";
AUTHCODE_NAME="";
AUTHCODES=();
AUTHCODES_NAMES=();
TEMPARR=();
SLEEPTIME=1;
EXIT=0;
REMSELECTION=-1;
QRLOC="";

#New Salt function
NewSALT() {
	#New Salt
	SALT=$(openssl rand -base64 $SALTLENGTH);

	#Output to file
	echo $SALT > $SALTFILE;

	#Remove spaces from string for use
	SALT="$(echo $SALT | tr -d '\n')";

	#Set Salt file Security
	chmod 600 $SALTFILE;
}

NewPass() {

	PASSWORDSMATCH=0;
	while [ $PASSWORDSMATCH -ne 1 ]; do

		echo "Enter New Codes File Password: ";
		read -s PASSWORD;
		echo "Confirm New Codes File Password: ";
		read -s PASSWORD_CONFIRM;

		#Do Checks
		if [ "$PASSWORD" != "$PASSWORD_CONFIRM" ]; then
			echo "Passwords do not match!";
		elif [ "$PASSWORD" == "" ]; then
			echo "Password cannot be blank!";
		else
			PASSWORDSMATCH=1;
		fi

	done
}

AskForPassword() {
	#Ask For Password
	while [ $PASSWORDSMATCH -ne 1 ]; do
		echo "Enter Codes File Password: ";
		read -s PASSWORD;

		#Do Checks
		if [ "$PASSWORD" == "" ]; then
			echo "Password cannot be blank!";
		else
			PASSWORDSMATCH=1;
		fi
	done
}
#//AskForPassword()_END

#Function to decrypt codes
DecCodes() {

	#Read Codes Str
	CODESSTR=$(cat $CODESFILE);

	#Attempt decrypt using provided password (no salt as added manually)
	CODESSTR=$(echo $CODESSTR | openssl enc -d -pbkdf2 -aes-256-cbc -a -nosalt -pass "pass:$SALT$PASSWORD$SALT" 2>$ERROROUTFILE);

	#Check that we got something that is parsible
	if [ -s $ERROROUTFILE ]; then
		#If we output an error during decrypt
		echo "ERROR! Failed to decrypt file (maybe wrong password?).";
		exit 1;
	elif [ "$CODESSTR" != "" ]; then
		#Store Codes In Arrays (as long as code file is not blank)
		AUTHCODES=();
		AUTHCODES_NAMES=();
		for codedet in $(echo -e $CODESSTR); do

			#If an auth code
			if [ ${#AUTHCODES[@]} -eq ${#AUTHCODES_NAMES[@]} ]; then
				#Add To List
				AUTHCODES+=($codedet);
			else
				AUTHCODES_NAMES+=($codedet);
			fi
		done
	fi
}
#//DecCodes()_END

#Function to encrypt codes
EncCodes() {

	CODESLENGTH=0;
	CODESSTR="";

	#If AutCodes length is not the same as names something went wrong
	if [ ${#AUTHCODES[@]} -ne ${#AUTHCODES_NAMES[@]} ]; then
		echo -e "ERROR! Auth codes list not match and will not be saved! Exiting!";
		exit 1;
	fi

	#Create new salt, overkill but still
	NewSALT;

	#Create string to save codes as
	CODESLENGTH=${#AUTHCODES[@]};
	for (( i=0; i<$CODESLENGTH; i++ )); do
		if [ $i -gt 0 ]; then
			CODESSTR="$CODESSTR\n";
		fi
		CODESSTR="$CODESSTR${AUTHCODES[i]}\t${AUTHCODES_NAMES[i]}";
	done

	#Encrypt String (no salt as added manually)
	CODESSTR=$(echo $CODESSTR | openssl enc -e -pbkdf2 -aes-256-cbc -a -nosalt -pass "pass:$SALT$PASSWORD$SALT" 2>/dev/null);
}
#//EncCodes()_END

ShowCodes() {
	#Loop Through Each Code
	for (( i=0; i<$CODESLENGTH; i++ )); do
		AUTHCODE=$(oathtool -c 30 --base32 --totp ${AUTHCODES[i]});
		echo "$(($i+1)). ${AUTHCODES_NAMES[i]} : $AUTHCODE";
	done
}
#//ShowCodes()_END

#Check all required binaries are present
for bin in "${REQBINS[@]}"; do
	if [ ! -f "$BINPREFIX/$bin" ]; then
		echo "Missing required executable $bin! Please ensure the application is installed and that the BINPREFIX variable is correct.";
		exit 1;
	fi
done

#If user asking for help, show help text and exit
if [ "$1" == "--help" ] || [ "$1" == "-h" ]; then
	echo -e "$HELPTEXT";
	exit 0;
fi

#Create directory if doesn't exist
if [ ! -d $CONFIGDIR ]; then
	mkdir $CONFIGDIR;

	#Set Directory Security
	chmod 700 $CONFIGDIR;
fi

#Read in salt if file exists
if [ -f $SALTFILE ]; then
	#Read in salt
	SALT="$(cat $SALTFILE | tr -d '\n')";
fi

#Determine if a new code file or existing and ask for password accordingly
if [ -f $CODESFILE ]; then
	#If found

	#Check if password was defined as a variable beforehand
	if [ "$GASHELL_PASSPHRASE" != "" ]; then
		PASSWORD=$GASHELL_PASSPHRASE;
		PASSWORDSMATCH=1;
	fi

	#Ask For Password
	AskForPassword;

	#Decrypt Codes and get code length
	DecCodes;
	CODESLENGTH=${#AUTHCODES[@]};
else
	#If Creating a new codes file, get new pass and confirm.
	NewPass;

	#Encrypt Codes with blank
	EncCodes;
	echo $CODESSTR > $CODESFILE;
fi

#If argument specified
if [ $# -gt 0 ]; then
	if [ "$1" == "-p" ]; then

		#If setting a new password (would have exited if password was wrong)
		if [ "$PASSWORD_CONFIRM" != "" ]; then
			echo "Password change requested but you just set it.. Ignoring..";
			exit 0;
		fi

		NewPass;

		#Encrypt codes
		EncCodes;

		#Save To File
		echo $CODESSTR > $CODESFILE;
		echo "Password Changed Successfully.";

		#Set Codes File Security
		chmod 600 $CODESFILE;

	elif [ "$1" == "-a" ]; then

		#If Adding
		echo "Enter New Auth Code: ";
		read AUTHCODE;
		echo "Enter New Name/Desc: ";
		read AUTHCODE_NAME;

		#Remove any spaces in the authcode
		AUTHCODE="$(echo -e "${AUTHCODE}" | tr -d '[:space:]')"

		if [ "$AUTHCODE" == "" ] || [ "$AUTHCODE_NAME" == "" ]; then
			echo "Auth code and name cannot be blank!";
			exit 1;
		fi

		#Add To Arrays
		AUTHCODES+=($AUTHCODE);
		AUTHCODES_NAMES+=($AUTHCODE_NAME);

		#Encrypt Codes
		EncCodes;

		#Save To File
		echo $CODESSTR > $CODESFILE;
		echo "New Code Added Successfully.";

		#Set Codes File Security
		chmod 600 $CODESFILE;
	elif [ "$1" == "-i" ]; then

		QRLOC="$2";

		#If file exists, remove it
		if [ -f $QRWEBOUTPUT ]; then
			rm $QRWEBOUTPUT;
		fi

		#If QR Code contains http or https download it
		if [[ "$QRLOC" == *"http://"* ]] || [[ "$QRLOC" == *"https://"* ]]; then
			curl -L $QRLOC -o $QRWEBOUTPUT;
			QRLOC=$QRWEBOUTPUT;
		fi

		#Make sure we have a valid location
		if [ "$QRLOC" == "" ]; then
			echo "Could not get code from QRCode! If a web address was specified check $QRWEBOUTPUT for log details.";
			exit 1;
		elif [ ! -f $QRLOC ]; then
			echo "Could not find file at $QRLOC";
			exit 1;
		fi

		#Get secret and name from zbar
		AUTHCODE=$(zbarimg -q --raw $QRLOC | sed "s/.*secret=//" | sed "s/&issuer=.*//");
		AUTHCODE_NAME=$(zbarimg -q --raw $QRLOC | sed "s/.*&issuer=//");

		#If file exists, remove it
		if [ -f $QRWEBOUTPUT ]; then
			rm $QRWEBOUTPUT;
		fi

		#Add To Arrays
		AUTHCODES+=($AUTHCODE);
		AUTHCODES_NAMES+=($AUTHCODE_NAME);

		#Encrypt Codes
		EncCodes;

		#Save To File
		echo $CODESSTR > $CODESFILE;
		echo "New Code Added Successfully.";

		#Set Codes File Security
		chmod 600 $CODESFILE;
	elif [ "$1" == "-r" ]; then
		REMSELECTION=-1;

		#Show Codes
		ShowCodes;

		#Ask Which one User wants to delete
		echo -e "\nEnter code to delete 1-$CODESLENGTH:";
		read REMSELECTION;

		#Lower index by 1 and delete the item from both arrays.
		REMSELECTION=$(($REMSELECTION-1));
		unset AUTHCODES[$REMSELECTION];
		unset AUTHCODES_NAMES[$REMSELECTION];

		#Enc New Codes
		EncCodes;

		#Save To File
		echo $CODESSTR > $CODESFILE;
		echo "Code Removed Successfully.";
		
		#Set Codes File Security
		chmod 600 $CODESFILE;
	elif [ "$1" == "-o" ]; then
		#Output once only
		ShowCodes;
	fi
else
	
	#If no codes found
	if [ ${#AUTHCODES[@]} -eq 0 ]; then
		echo "Auth codes file is blank, use -a or -i flag to add one.";
		exit 0;
	fi

	#Keep looping codes
	while [ $EXIT -eq 0 ]; do

		#Clear Terminal
		clear;

		#Show codes and details
		ShowCodes;
		echo -e "\nctrl-c to exit.";

		#Wait for specified time
		sleep $SLEEPTIME;
	done
fi
