#!/bin/bash
# based on http://lists.gnupg.org/pipermail/gnupg-users/2003-March/017376.html
GPG="gpg"
GPGHOME="--homedir ."
GPGPARAM="$GPGHOME --no-options --batch --no-default-keyring --keyring ./auto-pubring.gpg \
		   --secret-keyring ./auto-secring.gpg"
INPUTFILE=".gen"

#########################################
# Function				#
# generate PGPkey for username	 	#
# $1: username				#
#	          			#
#########################################
Gen_key() {
    if [ -e $INPUTFILE ] ; then
		return 0
	# ok, someone else is created the key
    fi

# WE are the one who generates the new key!
    touch $INPUTFILE

#######################
# Test if we already have a user with this name
#######################
    echo "searching for secret key"
    $GPG $GPGPARAM --status-fd 2 --list-keys $1 2> /dev/null

    if [ $? -eq 0 ] ; then
	echo "$1 already in public keyring!"
	return
    fi

##################
# Build Input file
##################

    echo "creating inputfile for key generation"
    echo

# based on description in doc/DETAILS

    echo "# input file to generate GnuPG keys automatically" > $INPUTFILE 
    echo >> $INPUTFILE
    echo "%echo Generating a standard key" >> $INPUTFILE 
    echo >> $INPUTFILE
    echo "#######################################" >> $INPUTFILE 
    echo "# parameters for the key" >> $INPUTFILE 
    echo >> $INPUTFILE
    echo "Key-Type: DSA" >> $INPUTFILE 
    echo "Key-Length: 1024" >> $INPUTFILE 
    echo "Subkey-Type: ELG-E" >> $INPUTFILE 
    echo "Subkey-Length: 2048" >> $INPUTFILE 
    echo >> $INPUTFILE
    echo "Name-Real: $1" >> $INPUTFILE 
    echo "Name-Comment: Debian Release Staging Key" >> $INPUTFILE 
    echo "Name-Email: $1@$EMAIL" >> $INPUTFILE 
    echo >> $INPUTFILE
    echo "Expire-Date: 0" >> $INPUTFILE 
    echo >> $INPUTFILE
    echo "######################################" >> $INPUTFILE 
    echo >> $INPUTFILE
    echo "# the keyring files" >> $INPUTFILE 
    echo "%pubring $TMPPUBRING" >> $INPUTFILE 
    echo "%secring $TMPSECRING" >> $INPUTFILE 
    echo >> $INPUTFILE
    echo "# perform key generation" >> $INPUTFILE 
    echo "%commit" >> $INPUTFILE 
    echo >> $INPUTFILE
    echo "%echo done" >> $INPUTFILE 
    echo "#EOF" >> $INPUTFILE 
    echo >> $INPUTFILE

#######################
# Call Key generation
#######################
    $GPG $GPGPARAM --gen-key $INPUTFILE

    if [ $? -ne 0 ] ; then
	echo "error calling $GPG; non-zero code $?, ignoring"
#	exit -1
    fi

#######################
# import the new key to the regular keyrings
#######################
    echo "importing new key"
    echo

    $GPG $GPGPARAM --status-fd 2 --logger-fd 2 --verbose \
		   --import $TMPPUBRING $TMPSECRING 

    if [ $? -ne 0 ] ; then
	echo "error calling $GPG"
	exit -1
    fi

#######################
# export the new keys for backup
#######################

    set -x
    $GPG $GPGPARAM --armor --output $1.pub.asc --export $1
    $GPG $GPGPARAM --armor --output $1.sec.asc --export-secret-key $1
    set +x
}

######################################
# MAIN
######################################
TMPSECRING=revsw.secring.pgp
TMPPUBRING=revsw.pubring.pgp
EMAIL=revsw.com
USER=revsw
Gen_key $USER


######################################
# Import
######################################
$GPG --status-fd 2 --list-keys $USER 2> /dev/null
if [ $? -eq 0 ] ; then
    echo "$USER already in host public keyring!"
    exit 0
fi

echo "Importing keys"
GPGHOME=""
GPGPARAM=" --no-options --import revsw.pub.asc"
$GPG $GPGPARAM
GPGPARAM=" --no-options --import revsw.sec.asc"
$GPG $GPGPARAM
