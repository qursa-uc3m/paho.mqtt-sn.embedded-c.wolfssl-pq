/**************************************************************************************
 * Copyright (c) 2016, Tomoaki Yamaguchi
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 *
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *   http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * Contributors:
 *    Tomoaki Yamaguchi - initial API and implementation and/or initial documentation
 **************************************************************************************/
#ifdef DTLS

#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <termios.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/openssl/ssl.h>
#include "BioMethods.h"

#include "LMqttsnClientApp.h"
#include "LNetworkDtls.h"
#include "LTimer.h"
#include "LScreen.h"

using namespace std;
using namespace linuxAsyncClient;

extern uint16_t getUint16(const uint8_t* pos);
extern uint32_t getUint32(const uint8_t* pos);
extern LScreen* theScreen;
extern bool theClientMode;

#define DTLS_TIMEOUT      5

#define BIO_CTRL_DGRAM_SET_CONNECTED 32
#define BIO_CTRL_DGRAM_SET_RECV_TIMEOUT 33
#define MQTT_BIO_TYPE_DGRAM 0x90    // The type is not necessary. This is a custom type code to avoid conflict with the existing types.

#define MQTT_WOLFSSL_CIPHERS "TLS13-AES128-GCM-SHA256"

/* Certificate verification. Returns 1 if trusted, else 0 */
int verify_cert(int ok, WOLFSSL_X509_STORE_CTX *ctx);

/*=========================================
       Class LNetwork
 =========================================*/
LNetwork::LNetwork()
{
    _sleepflg = false;
    resetGwAddress();
}

LNetwork::~LNetwork()
{
}

int LNetwork::broadcast(const uint8_t *xmitData, uint16_t dataLen)
{
    return LDtlsPort::multicast(xmitData, (uint32_t) dataLen);
}

int LNetwork::unicast(const uint8_t *xmitData, uint16_t dataLen)
{
    return LDtlsPort::unicast(xmitData, dataLen);
}


uint8_t* LNetwork::getMessage(int *len)
{
    *len = 0;
    uint16_t recvLen = 0;
    if (checkRecvBuf())
    {
        recvLen = LDtlsPort::recv(_rxDataBuf, MQTTSN_MAX_PACKET_SIZE, false, &_ipAddress, &_portNo);
        if (_gwIpAddress && isUnicast() && (_ipAddress != _gwIpAddress) && (_portNo != _gwPortNo))
        {
            return 0;
        }

        if (recvLen < 0)
        {
            *len = recvLen;
            return 0;
        }
        else
        {
            if (_rxDataBuf[0] == 0x01)
            {
                *len = getUint16(_rxDataBuf + 1);
            }
            else
            {
                *len = _rxDataBuf[0];
            }
            return _rxDataBuf;
        }
    }
    return 0;
}

void LNetwork::setGwAddress(void)
{
    _gwPortNo = _portNo;
    _gwIpAddress = _ipAddress;
}

void LNetwork::resetGwAddress(void)
{
    _gwIpAddress = 0;
    _gwPortNo = 0;
}


bool LNetwork::initialize(LUdpConfig *config)
{
    return LDtlsPort::open(config);
}

void LNetwork::setSleep()
{
    _sleepflg = true;
}

bool LNetwork::isBroadcastable()
{
    return true;
}

int LNetwork::sslConnect(void)
{
    return LDtlsPort::sslConnect(_gwIpAddress, _gwPortNo);
}

/*=========================================
 Class DtlsPort
 =========================================*/
LDtlsPort::LDtlsPort()
{
    _disconReq = false;
    _sockfdMcast = 0;
    _sockfdSsl = 0;
    _castStat = 0;
}

LDtlsPort::~LDtlsPort()
{
    close();
}


void LDtlsPort::close()
{
    if (_sockfdMcast > 0)
    {
        ::close(_sockfdMcast);
        _sockfdMcast = 0;
        if (_sockfdSsl > 0)
        {
            ::close(_sockfdSsl);
            _sockfdSsl = 0;
        }
    }
}

bool LDtlsPort::open(LUdpConfig *config)
{
    char errmsg[256];
    int optval = 0;

    uint8_t sav = config->ipAddress[3];
    config->ipAddress[3] = config->ipAddress[0];
    config->ipAddress[0] = sav;
    sav = config->ipAddress[2];
    config->ipAddress[2] = config->ipAddress[1];
    config->ipAddress[1] = sav;

    _gIpAddr = getUint32((const uint8_t*) config->ipAddress);
    _gPortNo = htons(config->gPortNo);
    _uPortNo = htons(config->uPortNo);

    if (_gPortNo == 0 || _gIpAddr == 0 || _uPortNo == 0)
    {
        return false;
    }

    wolfSSL_load_error_strings();
    wolfSSL_library_init();

    #ifdef DEBUG_TESTER
        wolfSSL_Debugging_ON();
    #endif
    
    if (IS_DTLS13) {
        _ctx = wolfSSL_CTX_new(wolfDTLS_method());
    } else {
        _ctx = wolfSSL_CTX_new(wolfDTLSv1_2_method());
    }

    if (_ctx == 0)
    {
        ERR_error_string_n(ERR_get_error(), errmsg, sizeof(errmsg));
        DISPLAY("wolfSSL_CTX_new() %s\n", errmsg);
        return false;
    }

    /* Client certification and cookie are not required */
    wolfSSL_CTX_set_verify(_ctx, SSL_VERIFY_PEER, verify_cert);

    wolfSSL_CTX_set_cipher_list(_ctx, MQTT_WOLFSSL_CIPHERS);

    #ifdef MQTT_WOLFSSL_GROUPS
        if (wolfSSL_CTX_set1_groups_list(_ctx, (char *) MQTT_WOLFSSL_GROUPS) != WOLFSSL_SUCCESS) {
            D_NWSTACK("Error setting groups\n");
        }
    #endif

    /* setup Multicast socket */
    _sockfdMcast = socket(AF_INET, SOCK_DGRAM, 0);
    if (_sockfdMcast < 0)
    {
        return false;
    }

    struct sockaddr_in addrm;
    addrm.sin_family = AF_INET;
    addrm.sin_port = _gPortNo;
    addrm.sin_addr.s_addr = INADDR_ANY;

    optval = 1;
    setsockopt(_sockfdMcast, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    if (::bind(_sockfdMcast, (struct sockaddr*) &addrm, sizeof(addrm)) < 0)
    {
        return false;
    }

    optval = 1;
    if (setsockopt(_sockfdMcast, IPPROTO_IP, IP_MULTICAST_LOOP,  &optval, sizeof(optval)) < 0)
    {
        D_NWLOG("\033[0m\033[0;31merror IP_MULTICAST_LOOP in LDtlsPort::open\033[0m\033[0;37m\n");
        close();
        return false;
    }

    ip_mreq mreq;
    mreq.imr_interface.s_addr = INADDR_ANY;
    mreq.imr_multiaddr.s_addr = _gIpAddr;

    if (setsockopt(_sockfdMcast, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0)
    {
        D_NWLOG("\033[0m\033[0;31merror IP_ADD_MEMBERSHIP in LDtlsPort::open\033[0m\033[0;37m\n");
        close();
        return false;
    }
    return true;
}

bool LDtlsPort::isUnicast()
{
    return (_castStat == STAT_UNICAST);
}

int LDtlsPort::unicast(const uint8_t *buf, uint32_t length)
{
    int status = wolfSSL_write(_ssl, buf, length);
    if (status <= 0)
    {
        int rc = 0;
        wolfSSL_get_error(_ssl, rc);
        DISPLAY("errno == %d in LDtlsPort::unicast\n", rc);
    }
    else
    {
        D_NWLOG("sendto gateway via DTLS ");
        for (uint16_t i = 0; i < length; i++)
        {
            D_NWLOG(" %02x", *(buf + i));
        }
        D_NWLOG("\n");

        if (!theClientMode)
        {
            char sbuf[SCREEN_BUFF_SIZE];
            int pos = 0;
            sprintf(sbuf, "\033[0;34msendto the gateway via SSL  ");
            pos = strlen(sbuf);
            for (uint16_t i = 0; i < length; i++)
            {
                sprintf(sbuf + pos, " %02x", *(buf + i));
                if (strlen(sbuf) > SCREEN_BUFF_SIZE - 20)  // -20 for Escape sequence
                {
                    break;
                }
                pos += 3;
            }
            sprintf(sbuf + strlen(sbuf), "\033[0;37m\n");
            theScreen->display(sbuf);
        }
    }

    return status;
}


int LDtlsPort::multicast(const uint8_t *buf, uint32_t length)
{
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = _gPortNo;
    dest.sin_addr.s_addr = _gIpAddr;

    int status = ::sendto(_sockfdMcast, buf, length, 0, (const sockaddr*) &dest, sizeof(dest));
    if (status < 0)
    {
        D_NWLOG("\033[0m\033[0;31merrno == %d in LDtlsPort::multicast\033[0m\033[0;37m\n", errno);
        DISPLAY("\033[0m\033[0;31merrno == %d in LDtlsPort::multicast\033[0m\033[0;37m\n", errno);
        return errno;
    }
    else
    {
        D_NWLOG("sendto %-15s:%-6u", inet_ntoa(dest.sin_addr), htons(_gPortNo));

        for (uint16_t i = 0; i < length; i++)
        {
            D_NWLOG(" %02x", *(buf + i));
            DISPLAY(" %02x", *(buf + i));
        }
        D_NWLOG("\n");

        if (!theClientMode)
        {
            char sbuf[SCREEN_BUFF_SIZE];
            int pos = 0;
            sprintf(sbuf, "\033[0;34msendto %-15s:%-6u", inet_ntoa(dest.sin_addr), htons(_gPortNo));
            pos = strlen(sbuf);
            for (uint16_t i = 0; i < length; i++)
            {
                sprintf(sbuf + pos, " %02x", *(buf + i));
                if (strlen(sbuf) > SCREEN_BUFF_SIZE - 20)
                {
                    break;
                }
                pos += 3;
            }
            sprintf(sbuf + strlen(sbuf), "\033[0;37m\n");
            theScreen->display(sbuf);
        }
        return status;
    }

}

bool LDtlsPort::checkRecvBuf()
{
    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 50000;    // 50 msec

    uint8_t buf[2];
    fd_set recvfds;
    int maxSock = 0;

    FD_ZERO(&recvfds);
    if (_sockfdMcast)
    {
        FD_SET(_sockfdMcast, &recvfds);
    }
    if (_sockfdSsl)
    {
        FD_SET(_sockfdSsl, &recvfds);
    }

    if (_sockfdMcast > _sockfdSsl)
    {
        maxSock = _sockfdMcast;
    }
    else
    {
        maxSock = _sockfdSsl;
    }

    select(maxSock + 1, &recvfds, 0, 0, &timeout);

    if (FD_ISSET(_sockfdMcast, &recvfds))
    {
        if (::recv(_sockfdMcast, buf, 1, MSG_DONTWAIT | MSG_PEEK) > 0)
        {
            _castStat = STAT_MULTICAST;
            return true;
        }
    }
    else if (FD_ISSET(_sockfdSsl, &recvfds))
    {
        if (::recv(_sockfdSsl, buf, 1, MSG_DONTWAIT | MSG_PEEK) > 0)
        {
            _castStat = STAT_SSL;
            return true;
        }
    }
    _castStat = STAT_NONE;
    return false;
}

int LDtlsPort::recv(uint8_t *buf, uint16_t len, bool flg, uint32_t *ipAddressPtr, in_port_t *portPtr)
{
    int flags = flg ? MSG_DONTWAIT : 0;
    return recvfrom(buf, len, flags, ipAddressPtr, portPtr);
}

int LDtlsPort::recvfrom(uint8_t *buf, uint16_t length, int flags, uint32_t *ipAddressPtr, in_port_t *portPtr)
{
    struct sockaddr_in sender;
    int status = 0;
    socklen_t addrlen = sizeof(sender);
    memset(&sender, 0, addrlen);

    if (_castStat == STAT_SSL)
    {
        D_NWLOG("Ucast ");
        if (wolfSSL_read(_ssl, buf, length) == 0)
        {
            return 0;
        }
    }
    else if (_castStat == STAT_MULTICAST)
    {
        D_NWLOG("Mcast ");
        status = ::recvfrom(_sockfdMcast, buf, length, flags, (struct sockaddr*) &sender, &addrlen);
    }
    else
    {
        return 0;
    }

    if (status < 0 && errno != EAGAIN)
    {
        D_NWLOG("\033[0m\033[0;31merrno == %d in LDtlsPort::recvfrom \033[0m\033[0;37m\n", errno);
        DISPLAY("\033[0m\033[0;31merrno == %d in LDtlsPort::recvfrom \033[0m\033[0;37m\n", errno);
    }
    else if (status > 0)
    {
        *ipAddressPtr = sender.sin_addr.s_addr;
        *portPtr = sender.sin_port;

        D_NWLOG("recved %-15s:%-6u", inet_ntoa(sender.sin_addr), ntohs(*portPtr));

        for (uint16_t i = 0; i < status; i++)
        {
            D_NWLOG(" %02x", *(buf + i));
        }
        D_NWLOG("\n");

        if (!theClientMode)
        {
            char sbuf[SCREEN_BUFF_SIZE];
            int pos = 0;
            sprintf(sbuf, "\033[0;34mrecved %-15s:%-6u", inet_ntoa(sender.sin_addr), ntohs(*portPtr));
            pos = strlen(sbuf);
            for (uint16_t i = 0; i < status; i++)
            {
                sprintf(sbuf + pos, " %02x", *(buf + i));
                if (strlen(sbuf) > SCREEN_BUFF_SIZE - 20)
                {
                    break;
                }
                pos += 3;
            }
            sprintf(sbuf + strlen(sbuf), "\033[0;37m\n");
            theScreen->display(sbuf);
        }
        return status;
    }
    else
    {
        return 0;
    }
    return status;
}

int LDtlsPort::sslConnect(uint32_t ipAddress, in_port_t portNo)
{
    int reuse = 1;
    if (_ssl != 0)
    {
        D_NWLOG("LDtlsPort::sslConnect SSL exists.\n");
        wolfSSL_set_quiet_shutdown(_ssl, 1);
        wolfSSL_shutdown(_ssl);
        wolfSSL_free(_ssl);
        _sockfdSsl = 0;
        _ssl = 0;
    }

    if (_sockfdSsl > 0)
    {
        D_NWLOG("LDtlsPort::sslConnect socket exists.\n");
        ::close(_sockfdSsl);
    }

    _sockfdSsl = socket(AF_INET, SOCK_DGRAM, 0);
    if (_sockfdSsl < 0)
    {
        D_NWLOG("LDtlsPort::sslConnect Can't create a socket\n");
        return -1;
    }
    setsockopt(_sockfdSsl, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = _uPortNo;
    addr.sin_addr.s_addr = INADDR_ANY;
    if (::bind(_sockfdSsl, (struct sockaddr*) &addr, sizeof(addr)) < 0)
    {
        ::close(_sockfdSsl);
        _sockfdSsl = 0;
        D_NWLOG("LDtlsPort::sslConnect Can't bind a socket\n");
        return -1;
    }

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = portNo;
    dest.sin_addr.s_addr = ipAddress;
    int rc = 0;
    errno = 0;
    
    WOLFSSL_BIO* cbio;
    WOLFSSL_BIO_METHOD *bio_methods;
    mqtt_dgram_data *data = NULL;
    data = (mqtt_dgram_data*)malloc(sizeof(mqtt_dgram_data));

    bio_methods = wolfSSL_BIO_meth_new(MQTT_BIO_TYPE_DGRAM,
                                            "mqtt-sn_dgram");

    cbio = wolfSSL_BIO_new(bio_methods);
    wolfSSL_BIO_set_fd(cbio, _sockfdSsl, BIO_NOCLOSE);

    wolfSSL_BIO_meth_set_write(bio_methods, mqtt_dgram_write);
    wolfSSL_BIO_meth_set_read(bio_methods, mqtt_dgram_read);
    wolfSSL_BIO_meth_set_puts(bio_methods, mqtt_dgram_puts);
    wolfSSL_BIO_meth_set_ctrl(bio_methods, mqtt_dgram_ctrl);
    wolfSSL_BIO_meth_set_create(bio_methods, mqtt_dgram_create);
    wolfSSL_BIO_meth_set_destroy(bio_methods, mqtt_dgram_destroy);

    

    connect(_sockfdSsl, (sockaddr*) &dest, sizeof(sockaddr_in));
    if (data != NULL) {
        wolfSSL_BIO_set_data(cbio, data);
    } else {
        D_NWLOG("LDtlsPort::sslConnect Failed to allocate mqtt_ssl_data\n");
        return -1;
    }
    wolfSSL_BIO_ctrl(cbio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &dest);

    if (_ctx == NULL) {
        return -1;
    }
    _ssl = wolfSSL_new(_ctx);
    wolfSSL_set_bio(_ssl, cbio, cbio);

    D_NWLOG("LDtlsPort::sslConnect connect to %-15s:%-6u\n", inet_ntoa(dest.sin_addr), htons(dest.sin_port));

    timeval timeout;
    timeout.tv_sec = DTLS_TIMEOUT;
    timeout.tv_usec = 0;
    wolfSSL_BIO_ctrl(cbio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

    if (HRR_COOKIE) {
        wolfSSL_NoKeyShares(_ssl);
    }
    #ifdef MQTT_WOLFSSL_SIGALGS
        if (wolfSSL_set1_sigalgs_list(_ssl, MQTT_WOLFSSL_SIGALGS) != WOLFSSL_SUCCESS) {
            D_NWSTACK("Error setting signature algorithms\n");
        }
    #endif
    int stat = wolfSSL_connect(_ssl);

    if (stat != 1)
    {
        rc = -1;
        D_NWLOG("SSL fail to connect\n");
    }
    else
    {
        rc = 1;
        D_NWLOG("SSL connected\n");
    }
    return rc;
}

int verify_cert(int ok, WOLFSSL_X509_STORE_CTX *ctx)
{
    return 1;
}


#endif

