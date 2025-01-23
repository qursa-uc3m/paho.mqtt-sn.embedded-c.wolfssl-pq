#!/bin/bash

WORK_DIR=$(realpath $(dirname "$0")/..)
BDIR=build.gateway
ODIR=bin/

build () {
    SSL_LIB=${4:-openssl}
    if [ "$SSL_LIB" != "openssl" ] && [ "$SSL_LIB" != "wolfssl" ]; then
        echo "Invalid SSL library: $SSL_LIB. Valid values are 'openssl', 'wolfssl'."
        exit 1
    fi
    echo "Start building MQTT-SN Gateway with SensorNet: $1, SSL: $SSL_LIB"

    pushd "$WORK_DIR"
    if [ ! -d ./$BDIR ]; then
        mkdir $BDIR
    fi
    cd $BDIR
    cmake .. -DSENSORNET=$1 -DSSL_LIB=${4:-openssl} -DDEFS="${2} ${3}"
    make MQTTSNPacket
    make MQTT-SNGateway
    make MQTT-SNLogmonitor
    popd
    cp *.conf ./$ODIR
}

if [ $1 == "udp" ] ; then
    build $1 $2 $3
elif [ $1 == "udp6" ] ; then 
    build $1 $2 $3
elif [ $1 == "xbee" ] ; then
    build $1 $2 $3
elif [ $1 == "loralink" ]; then
    build $1 $2 $3
elif [ $1 == "rfcomm" ] ; then 
    build $1 $2 $3
elif [ $1 == "dtls" ] ; then
    build $1 $2 $3 $4
elif [ $1 == "dtls6" ] ; then
    build dtls "${2} ${3} -DDTLS6" $4
elif [ $1 == "clean" ] ; then
    pushd "$WORK_DIR"
    rm -rf ./$BDIR
    popd
    rm -rf ./$ODIR
else
    echo "Usage: build.sh  [ udp | udp6 | xbee | loralink | rfcomm | dtls | dtls6 | clean]"
fi