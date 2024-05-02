#!/bin/bash

DEF1="DEF1=${3}"
DEF2="DEF2=${4}"

SSL_LIB="openssl"
if [ "$2" == "wolfssl" ]; then
    SSL_LIB="wolfssl"
    echo "Building with wolfSSL"
else
    echo "Building with OpenSSL"
fi

if [ $1 == "udp" ] ; then
    make SN=UDP $DEF1 $DEF2
elif [ $1 == "udp6" ] ; then 
    make SN=UDP6 $DEF1 $DEF2
elif [ $1 == "rfcomm" ] ; then 
	export LDADDBLT=-lbluetooth
    make SN=RFCOMM $DEF1 $DEF2
elif [ $1 == "dtls" ] ; then
    make SN=DTLS SSL_LIB="$SSL_LIB" $DEF1 $DEF2
elif [ $1 == "dtls6" ] ; then
    make SN=DTLS6 SSL_LIB="$SSL_LIB" $DEF1 $DEF2
elif [ $1 == "clean" ] ; then
    make clean
else
    echo "Usage: build.sh  [ udp | udp6 | rfcomm | dtls | dtls6 | clean]"
fi