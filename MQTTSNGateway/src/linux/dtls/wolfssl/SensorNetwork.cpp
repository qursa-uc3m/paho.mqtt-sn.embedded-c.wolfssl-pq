/**************************************************************************************
 * Copyright (c) 2021, Tomoaki Yamaguchi
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
 *    Javier Blanco-Romero (@fj-blanco) - wolfSSL integration (2024)
 **************************************************************************************/
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netdb.h>
#include <string.h>
#include <regex>
#include <string>
#include <stdlib.h>
#include <poll.h>
#include <assert.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/openssl/ssl.h>
#include "BioMethods.h"

#include <memory>
#include "SensorNetwork.h"
#include "MQTTSNGWProcess.h"
#include "MQTTSNGateway.h"


using namespace std;
using namespace MQTTSNGW;

extern Gateway *theGateway;

#define COOKIE_SECRET_LENGTH 16
int cookie_initialized = 0;
unsigned char cookie_secret[COOKIE_SECRET_LENGTH];

/*===========================================
 Class  SensorNetAddreess

 These 4 methods are minimum requirements for the SensorNetAddress class.
 isMatch(SensorNetAddress* )
 operator =(SensorNetAddress& )
 setAddress(string* )
 sprint(char* )

 UDPPort class requires these 3 methods.
 getIpAddress(void)
 getPortNo(void)
 setAddress(uint32_t IpAddr, uint16_t port)

 ============================================*/

// BIO Datagram Control
#define BIO_CTRL_DGRAM_SET_CONNECTED 32
#define BIO_CTRL_DGRAM_SET_RECV_TIMEOUT 33
#define BIO_CTRL_DGRAM_GET_PEER 46
#define MQTT_BIO_TYPE_DGRAM 0x90    // The type is not necessary. This is a custom type code to avoid conflict with the existing types.

#define MQTT_WOLFSSL_CIPHERS "TLS13-AES128-GCM-SHA256"

#define wolfSSL_BIO_dgram_get_peer(bio, peer) \
    wolfSSL_BIO_ctrl(bio, BIO_CTRL_DGRAM_GET_PEER, 0, (char *)(peer))

struct CallbackContext {
    sockaddr_in client_addr;
    sockaddr_in server_addr;
    SensorNetAddress* client;
};

enum {
    TEST_SELECT_FAIL,
    TEST_TIMEOUT,
    TEST_RECV_READY,
    TEST_SEND_READY,
    TEST_ERROR_READY
};

SensorNetAddress::SensorNetAddress()
{
    _portNo = 0;
    _pfdsIndex = 0;
    memset(&_ipAddr, 0, sizeof(_ipAddr));
}

SensorNetAddress::~SensorNetAddress()
{
}

void SensorNetAddress::setFamily(int type)
{
    _ipAddr.af = type;
}

int SensorNetAddress::getFamily(void)
{
    return _ipAddr.af;
}

ipAddr_t* SensorNetAddress::getIpAddress(void)
{
    return &_ipAddr;
}

in_port_t SensorNetAddress::getPort(void)
{
    return _portNo;
}

void SensorNetAddress::setAddress(ipAddr_t *IpAddr, uint16_t port)
{

    _ipAddr.addr.ad6 = IpAddr->addr.ad6;
    _portNo = htons(port);

    _ipAddr.af = IpAddr->af;
}

void SensorNetAddress::setPort(uint16_t port)
{
    _portNo = htons(port);
}

/**
 *  Set Address data to SensorNetAddress
 *
 *  @param  *ip_port is "IP_Address:PortNo" format string
 *  @return success = 0,  Invalid format = -1
 *
 *  This function is used in ClientList::authorize(const char* fileName)
 *  e.g.
 *  Authorized clients are defined by fileName = "clients.conf"
 *
 *  Client02,172.16.1.7:12002
 *  Client03,172.16.1.8:13003
 *  Client01,172.16.1.6:12001
 *          or
 *  Client01,[xxxx::xxxx]:11001
 *  Client02,[xxxx::xxxx]:12001
 *
 *  This definition is necessary when using TLS/DTLS connection.
 *  Gateway rejects clients are not in the list for security reasons.
 *
 */
int SensorNetAddress::setAddress(string *ipAddrPort)
{
    string port("");
    string ip("");
    size_t pos;
    int portNo = 0;
    _portNo = 0;
    memset(&_ipAddr.addr, 0, sizeof(_ipAddr.addr.ad6));

    if (*ipAddrPort->c_str() == '[')
    {
        // AF_INET6
        pos = ipAddrPort->find_last_of("]:");
        if (pos != string::npos)
        {
            ip = ipAddrPort->substr(1, pos - 2);
            port = ipAddrPort->substr(pos + 1);
        }
    }
    else
    {
        // AF_INET
        pos = ipAddrPort->find_last_of(':');
        if (pos != string::npos)
        {
            ip = ipAddrPort->substr(0, pos);
            port = ipAddrPort->substr(pos + 1);
        }
    }

    if (port == "" || ip == "")
    {
        return -1;
    }

    if (setIpAddress(&ip) == 0)
    {
        if ((portNo = atoi(port.c_str())) != 0)
        {
            _portNo = htons(portNo);
            return 0;
        }
    }
    return -1;
}

int SensorNetAddress::setIpAddress(string *ipAddress)
{
    if (inet_pton(AF_INET, (const char*) ipAddress->c_str(), (void*) &_ipAddr.addr) == 1)
    {
        _ipAddr.af = AF_INET;
    }
    else if (inet_pton(AF_INET6, (const char*) ipAddress->c_str(), (void*) &_ipAddr.addr) == 1)
    {
        _ipAddr.af = AF_INET6;
    }
    else
    {
        _ipAddr.af = 0;
        return -1;
    }
    return 0;
}

bool SensorNetAddress::isMatch(SensorNetAddress *addr)
{
    if (this->_portNo != addr->_portNo || this->_ipAddr.af != addr->_ipAddr.af)
    {
        return false;
    }

    if (this->_ipAddr.af == AF_INET
            && memcmp((const void*) &this->_ipAddr.addr.ad4, (const void*) &addr->_ipAddr.addr.ad4, sizeof(struct in_addr))
                    == 0)
    {
        return true;
    }

    if (this->_ipAddr.af == AF_INET6
            && memcmp((const void*) &this->_ipAddr.addr.ad6, (const void*) &addr->_ipAddr.addr.ad6, sizeof(struct in6_addr))
                    == 0)
    {
        return true;
    }
    return false;
}

SensorNetAddress& SensorNetAddress::operator =(SensorNetAddress &addr)
{
    this->_portNo = addr._portNo;
    memcpy((void*) &this->_ipAddr, (const void*) &addr._ipAddr, sizeof(_ipAddr));
    this->_pfdsIndex = addr._pfdsIndex;
    return *this;
}

void SensorNetAddress::setSockaddr4(sockaddr_in *sockaddr)
{
    _ipAddr.af = sockaddr->sin_family;
    _portNo = sockaddr->sin_port;
    memcpy((void*) &_ipAddr.addr.ad4, (void*) &sockaddr->sin_addr, sizeof(_ipAddr.addr.ad4));
}

void SensorNetAddress::setSockaddr6(sockaddr_in6 *sockaddr)
{
    _ipAddr.af = sockaddr->sin6_family;
    _portNo = sockaddr->sin6_port;
    memcpy((void*) &_ipAddr.addr.ad6, (void*) &sockaddr->sin6_addr, sizeof(_ipAddr.addr.ad6));
}

void SensorNetAddress::cpyAddr4(sockaddr_in *sockaddr)
{
    sockaddr->sin_family = _ipAddr.af;
    memcpy((void*) &sockaddr->sin_addr, (void*) &_ipAddr.addr.ad4, sizeof(_ipAddr.addr.ad4));
    sockaddr->sin_port = _portNo;
}

void SensorNetAddress::cpyAddr6(sockaddr_in6 *sockaddr)
{
    sockaddr->sin6_family = _ipAddr.af;
    sockaddr->sin6_port = _portNo;
    memcpy((void*) &sockaddr->sin6_addr, (void*) &_ipAddr.addr.ad6, sizeof(_ipAddr.addr.ad6));
}

void SensorNetAddress::cpyAddr(SensorNetAddress *addr)
{
    addr->_portNo = _portNo;
    memcpy((void*) &addr->_ipAddr, (const void*) &_ipAddr, sizeof(_ipAddr));
    addr->_pfdsIndex = _pfdsIndex;
}

char* SensorNetAddress::sprint(char *buf)
{
    char senderstr[INET6_ADDRSTRLEN];
    char *ptr = senderstr;

    if (_ipAddr.af == AF_INET)
    {
        ptr = inet_ntoa(_ipAddr.addr.ad4);
        sprintf(buf, "%s:", ptr);
    }
    else if (_ipAddr.af == AF_INET6)
    {
        inet_ntop(AF_INET6, (const void*) &_ipAddr.addr.ad6, ptr, INET6_ADDRSTRLEN);
        sprintf(buf, "[%s]:", ptr);
    }
    else
    {
        *buf = 0;
        return buf;
    }
    sprintf(buf + strlen(buf), "%d", ntohs(_portNo));
    sprintf(buf + strlen(buf), " index=%d", _pfdsIndex);
    return buf;
}

void SensorNetAddress::setIndex(int index)
{
    _pfdsIndex = index;
}
int SensorNetAddress::getIndex(void)
{
    return _pfdsIndex;
}

void SensorNetAddress::clear(void)
{
    memset(&_ipAddr, 0, sizeof(_ipAddr));
    _portNo = 0;
}

Connections::Connections()
{
    _pollfds = nullptr;
    _ssls = nullptr;
    _maxfds = 0;
    _numfds = 2;
}

Connections::~Connections()
{
    if (_ssls)
    {
        for (int i = 0; i < _numfds; i++)
        {
            if (_ssls[i] != nullptr)
            {
                wolfSSL_shutdown(_ssls[i]);
                wolfSSL_free(_ssls[i]);
            }
        }
        free(_ssls);
    }

    if (_pollfds)
    {
        for (int i = 0; i < _numfds; i++)
        {
            if (_pollfds[i].fd > 0)
            {
                ::close(_pollfds[i].fd);
            }
        }
        free(_pollfds);
    }
}

void Connections::initialize(int maxClient)
{
    _maxfds = maxClient + POLL_SSL;
    if ((_pollfds = (pollfd*) calloc(_maxfds, sizeof(pollfd))) == NULL)
    {
        throw EXCEPTION("Can't allocate pollfd.", 0);
    }
    if ((_ssls = (WOLFSSL**) calloc(_maxfds, sizeof(WOLFSSL*))) == NULL)
    {
        throw EXCEPTION("Can't allocate ssls.", 0);
    }
}

void Connections::closeSSL(int index)
{
    index += POLL_SSL;
    wolfSSL_shutdown(_ssls[index]);
    wolfSSL_free(_ssls[index]);
    _ssls[index] = (WOLFSSL*) -1;
}

int Connections::getEventUnicast(void)
{
    return _pollfds[POLL_UCAST].revents;
}

int Connections::getEventMulticast(void)
{
    return _pollfds[POLL_MCAST].revents;
}

int Connections::getEventClient(int index)
{
    return _pollfds[index + POLL_SSL].revents;
}

int Connections::getSockMulticast(void)
{
    return _pollfds[POLL_MCAST].fd;
}

void Connections::setSockMulticast(int sock)
{
    _mutex.lock();
    _pollfds[POLL_MCAST].fd = sock;
    _pollfds[POLL_MCAST].events = POLLIN;
    _mutex.unlock();
}

void Connections::setSockUnicast(int sock)
{
    _mutex.lock();
    _pollfds[POLL_UCAST].fd = sock;
    _pollfds[POLL_UCAST].events = POLLIN;
    _mutex.unlock();
}

int Connections::getSockUnicast(void)
{
    return _pollfds[POLL_UCAST].fd;
}

int Connections::getSockClient(int index)
{
    return _pollfds[index + POLL_SSL].fd;
}

void Connections::close(int index)
{
    D_NWSTACK("Connection %d closed\n", index);
    int idx = index + POLL_SSL;
    _mutex.lock();
    int sock = _pollfds[idx].fd;
    WOLFSSL *ssl = _ssls[idx];

    for (; idx < _numfds; idx++)
    {
        _ssls[idx] = _ssls[idx + 1];
        _pollfds[idx] = _pollfds[idx + 1];

        if (_ssls[idx + 1] == 0)
        {
            break;
        }
    }

    if (ssl != nullptr)
    {
        _numfds--;
        wolfSSL_shutdown(ssl);
        wolfSSL_free(ssl);
    }
    if (sock > 0)
    {
        ::close(sock);
    }
    _mutex.unlock();
}

int Connections::poll(int timeout)
{
    return ::poll(_pollfds, _numfds, timeout);
}

int Connections::addClientSSL(WOLFSSL *ssl, int sock)
{
    _mutex.lock();
    _pollfds[_numfds].fd = sock;
    _pollfds[_numfds].events = POLLIN;
    _ssls[_numfds] = ssl;
    int rc = _numfds - POLL_SSL;
    _numfds++;
    _mutex.unlock();
    D_NWSTACK("Add client connection index=%d, ssl=%ld, sock=%d\n", rc, (long int )ssl, sock);
    return rc;
}

int Connections::getNumOfConnections(void)
{
    return _numfds;
}

int Connections::getNumOfClients(void)
{
    return _numfds - POLL_SSL > 0 ? _numfds - POLL_SSL : 0;
}

WOLFSSL* Connections::getClientSSL(int index)
{
    return _ssls[index + POLL_SSL];
}

void Connections::print(void)
{
    for (int i = 0; i < _numfds; i++)
    {
        printf("index=%d  fd=%d   ssl=%ld \n", i, _pollfds[i].fd, (long int) _ssls[i]);
    }
}

/*================================================================
 Class  SensorNetwork

 getDescpription( )  is used by Gateway::initialize( )
 initialize( )       is used by Gateway::initialize( )
 getSenderAddress( ) is used by ClientRecvTask::run( )
 broadcast( )        is used by MQTTSNPacket::broadcast( )
 unicast( )          is used by MQTTSNPacket::unicast( )
 read( )             is used by MQTTSNPacket::recv( )

 ================================================================*/
#define DTLS_CLIENTHELLO  22
#define DTLS_APPL_2       47
#define DTLS_APPL         23
#define DTLS_OTHERS       100

#define DTLS_TIMEOUT      4

/* Certificate verification. Returns 1 if trusted, else 0 */
int verify_cert(int ok, WOLFSSL_X509_STORE_CTX *ctx);


SensorNetwork::SensorNetwork()
{
    _conns = new Connections();
    _dtlsctx = nullptr;
    _af = 0;
}

SensorNetwork::~SensorNetwork()
{
    if (_conns != nullptr)
    {
        delete _conns;
    }
}

int SensorNetwork::unicast(const uint8_t *payload, uint16_t payloadLength, SensorNetAddress *sendToAddr)
{
#ifdef DEBUG_NW
    char buf[256];
    _conns->print();
    sendToAddr->sprint(buf);
    D_NWSTACK("sendto %s\n", buf);
#endif

    _mutex.lock();
    WOLFSSL *ssl = _conns->getClientSSL(sendToAddr->getIndex());
    int len = wolfSSL_write(ssl, payload, payloadLength);
    int rc = wolfSSL_get_error(ssl, len);
    if (rc < 0)
    {
        D_NWSTACK("error %d in SensorNetwork::unicast\n", rc);
        len = -1;
    }
    _mutex.unlock();
    return len;
}

int SensorNetwork::broadcast(const uint8_t *payload, uint16_t payloadLength)
{
    _mutex.lock();

    int status;
#ifndef DTLS6
    sockaddr_in dest;
    _multicastAddr.cpyAddr4(&dest);
    status = ::sendto(_conns->getSockUnicast(), payload, payloadLength, 0, (const sockaddr*) &dest, sizeof(dest));
    if (status < 0)
    {
        WRITELOG("AF_INET errno = %d in UDP4_6Port::sendto\n", errno);
    }

    D_NWSTACK("sendto %s:%u length = %d\n", inet_ntoa(dest.sin_addr), ntohs(dest.sin_port), status);

#else
    sockaddr_in6 dest;
    _multicastAddr.cpyAddr6(&dest);
    status = ::sendto(_conns->getSockUnicast(), payload, payloadLength, 0, (const sockaddr*) &dest, sizeof(dest));
    if (status < 0)
    {
        WRITELOG("AF_INET6 errno = %d in SensorNetwork::broadcast\n", errno);
    }

#ifdef DEBUG_NW
    char buff[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &dest.sin6_addr, buff, INET6_ADDRSTRLEN);
    D_NWSTACK("sendto [%s]:%u length = %d\n", buff, ntohs(dest.sin6_port), status);
#endif
#endif
    _mutex.unlock();
    return status;
}

static int chGoodCb(WOLFSSL* ssl, void* arg)
{
    CallbackContext* ctx = (CallbackContext*) arg;
    if (!ctx) {
        perror("Failed to allocate CallbackContext");
        exit(EXIT_FAILURE);
    }
    // DTLS over IPv4
    int client_fd = socket(AF_INET, SOCK_DGRAM, 0);
    int optval = 1;
    setsockopt(client_fd, SOL_SOCKET, SO_REUSEADDR, (const void*) &optval, sizeof(optval));

    // Bind to Dtls PortNo
    bind(client_fd, (struct sockaddr*)&ctx->server_addr, sizeof(sockaddr_in));
    if (connect(client_fd, (struct sockaddr*)&ctx->client_addr, sizeof(sockaddr_in)) == -1) {
        perror("connect failed");
        return -1;
    }
    ctx->client->setSockaddr4(&ctx->client_addr);

    BIO *cbio = SSL_get_rbio(ssl);
    BIO_set_fd(cbio, client_fd, BIO_NOCLOSE);
    wolfSSL_set_fd(ssl, client_fd);
    wolfSSL_BIO_ctrl(cbio, BIO_CTRL_DGRAM_SET_PEER, 0, &ctx->client_addr);
    wolfSSL_BIO_ctrl(cbio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &ctx->client_addr);

    return WOLFSSL_SUCCESS;
}

int SensorNetwork::read(uint8_t *buf, uint16_t bufLen)
{
    int optval;
    int clientIndex = -1;
    int sockListen = 0;
    char errmsg[256];
    union
        {
            struct sockaddr_in s4;
            struct sockaddr_in6 s6;
    } client_addr;
    CallbackContext context;

    SensorNetAddress client;
    client.clear();
    client.setFamily(_af);

    // Check POLL_IN
    int cnt = _conns->poll(6000);  // Timeout 6secs
    if (cnt == 0)
    {
        // Timeout
        return cnt;
    }
    else if (cnt < 0)
    {
        return -1;
    }

    _mutex.lock();

    //  Check Unicast Port

    if (_conns->getEventUnicast() & POLLIN)
    {
        D_NWSTACK("RECV Unicast SSL_connect\n");

        // SSL connection request from a client
#ifdef DEBUG_NW
        int dtls = getUnicastClient(&client);
        D_NWSTACK("Packet type = %d\n", dtls);
#else
        getUnicastClient(&client);
#endif
        sockListen = _conns->getSockUnicast();

        // Listen Connection
        WOLFSSL *ssl = wolfSSL_new(_dtlsctx);
        WOLFSSL_BIO_METHOD *bio_methods;
        bio_methods = wolfSSL_BIO_meth_new(MQTT_BIO_TYPE_DGRAM,
                                                "mqtt-sn_dgram");
    
        if (!bio_methods)
            throw EXCEPTION("wolfSSL_BIO_meth_new", 0);

        wolfSSL_BIO_meth_set_write(bio_methods, mqtt_dgram_write);
        wolfSSL_BIO_meth_set_read(bio_methods, mqtt_dgram_read);
        wolfSSL_BIO_meth_set_puts(bio_methods, mqtt_dgram_puts);
        wolfSSL_BIO_meth_set_ctrl(bio_methods, mqtt_dgram_ctrl);
        wolfSSL_BIO_meth_set_create(bio_methods, mqtt_dgram_create);
        wolfSSL_BIO_meth_set_destroy(bio_methods, mqtt_dgram_destroy);

        mqtt_dgram_data *data = NULL;
        data = (mqtt_dgram_data*)malloc(sizeof(mqtt_dgram_data));
        WOLFSSL_BIO *bio = wolfSSL_BIO_new(bio_methods);

        wolfSSL_BIO_set_fd(bio, sockListen, BIO_NOCLOSE);
        wolfSSL_set_bio(ssl, bio, bio);
        wolfSSL_set_options(ssl, WOLFSSL_OP_COOKIE_EXCHANGE);

        /* We set the client address and pass it as context to the callback */
        client.cpyAddr4(&client_addr.s4); 
        context.client_addr = client_addr.s4;
        context.server_addr = _serverAddr4;
        context.client = &client;
        if (wolfDTLS_SetChGoodCb(ssl, chGoodCb, &context) != WOLFSSL_SUCCESS) {
            D_NWSTACK("Error setting ClientHello callback\n");
        }

        if (HRR_COOKIE) {
            if (wolfSSL_send_hrr_cookie(ssl, NULL, 0)
                != WOLFSSL_SUCCESS) {
                    D_NWSTACK("Error sending HRR cookie\n");
                }
        } else {
            wolfSSL_disable_hrr_cookie(ssl);
        }

        // Allow fragmented handshake messages
        if (IS_DTLS13) {
            wolfSSL_dtls13_allow_ch_frag(ssl, 1);
        }

        #ifdef MQTT_WOLFSSL_SIGALGS
            if (wolfSSL_set1_sigalgs_list(ssl, MQTT_WOLFSSL_SIGALGS) != WOLFSSL_SUCCESS) {
                D_NWSTACK("Error setting signature algorithms\n");
            }
        #endif
        int ret;
        // Do handshake
        ret = wolfSSL_accept(ssl);
        int err = wolfSSL_get_error(ssl, ret);
        if (ret <= 0)
        {
            wolfSSL_ERR_error_string_n(wolfSSL_ERR_get_error(), errmsg, sizeof(errmsg));
            WRITELOG("SSL_accept %s\n", errmsg);
            wolfSSL_shutdown(ssl);
            wolfSSL_free(ssl);
        }
        else
        {
            // Handle client connection
            int client_fd = wolfSSL_get_fd(ssl);
            // add ssl & socket to Connections instance
            int index = _conns->addClientSSL(ssl, client_fd);

            // save SensorNetworkAddress of Client
            client.setIndex(index);
            client.cpyAddr(&_senderAddr);

#ifdef DEBUG_NW
            char clientaddrBuf[128];
            _senderAddr.sprint(clientaddrBuf);
            D_NWSTACK("DTLS accepted client is %s   index=%d client_fd=%d\n", clientaddrBuf, _senderAddr.getIndex(),
                    client_fd);
#endif
        }
        _mutex.unlock();
    }

    // check Multicast
    else if (_conns->getEventMulticast() & POLLIN)
    {
        _mutex.unlock();
        return multicastRecv(buf, bufLen);
    }
    else
    {
        // Check SSL packet from clients
        int recvlen = 0; // changed to int to use wolfSSL_read instead of SSL_read_ex
        WOLFSSL *ssl = 0;
        int numfds = _conns->getNumOfConnections();

        for (int i = 0; i < numfds - POLL_SSL; i++)
        {
            if (_conns->getEventClient(i) == POLLIN)
            {
                D_NWSTACK("SSL Packet RECV\n");
                int dtls = getSendClient(i, &client);
                D_NWSTACK("Packet type = %d\n", dtls);
                if (dtls > 0)
                {
                    if (dtls == DTLS_CLIENTHELLO)
                    {
                        // Received packet is ClientHello
#ifdef DEBUG_NW
                        char clientaddrBuf[128];
                        client.sprint(clientaddrBuf);
                        D_NWSTACK("Client %s A packet is ClientHello. Client reconnected. Close connection. SSL_connection will timeout.\n", clientaddrBuf);
#endif
                        clientIndex = i;
                        _mutex.unlock();
                        _conns->close(clientIndex);
                        return 0;
                    }

                    // The packet is a MQTT-SN message
                    ssl = _conns->getClientSSL(i);

                    recvlen = wolfSSL_read(ssl, (void*) buf, (size_t) bufLen);

                    if (wolfSSL_get_error(ssl, recvlen) < 0)
                    {
                        D_NWSTACK("SSL RECV Error\n");
                        _conns->close(i);
                    }
                    else
                    {
                        client.cpyAddr(&_senderAddr);
                        _senderAddr.setIndex(i);

#ifdef DEBUG_NW
                        char clientaddrBuf[128];
                        _senderAddr.sprint(clientaddrBuf);
                        D_NWSTACK("Client %s ssl=%ld Received. idx=%d\n", clientaddrBuf, (long int )ssl, i);
#endif
                    }
                    _mutex.unlock();
                    return recvlen;
                }
            }
        }
    }
    return 0;
}

void SensorNetwork::initialize(void)
{
    char param[MQTTSNGW_PARAM_MAX];
    char errmsg[256];
    uint16_t multicastPortNo = 0;
    uint16_t unicastPortNo = 0;

    SensorNetAddress add;
    sockaddr_in6 soadd;
    add.setSockaddr6(&soadd);

#ifndef DTLS6
    string ip;
    uint32_t ttl = 1;

    if (theProcess->getParam("MulticastIP", param) == 0)
    {
        ip = param;
        _description += "IPv4 DTLS Multicast ";
        _description += param;
    }
    if (theProcess->getParam("MulticastPortNo", param) == 0)
    {
        multicastPortNo = atoi(param);
        _description += ":";
        _description += param;
    }
    if (theProcess->getParam("GatewayPortNo", param) == 0)
    {
        unicastPortNo = atoi(param);
        _description += ", Gateway PortNo:";
        _description += param;
    }
    if (theProcess->getParam("MulticastTTL", param) == 0)
    {
        ttl = atoi(param);
        _description += ", TTL:";
        _description += param;
    }
#else
    string ip6;
    uint32_t hops = 1;
    string interface;

    if (theProcess->getParam("MulticastIPv6", param) == 0)
    {
        ip6 = param;
        _description += "IPv6 DTLS Multicast [";
        _description += param;
    }
    if (theProcess->getParam("MulticastIPv6PortNo", param) == 0)
    {
        multicastPortNo = atoi(param);
        _description += "]:";
        _description += param;
    }
    if (theProcess->getParam("GatewayIPv6PortNo", param) == 0)
    {
        unicastPortNo = atoi(param);
        _description += ", Gateway PortNo:";
        _description += param;
    }
    if (theProcess->getParam("MulticastIPv6If", param) == 0)
    {
        interface = param;
        _description += ", Interface:";
        _description += param;
    }
    if (theProcess->getParam("MulticastHops", param) == 0)
    {
        hops = atoi(param);
        _description += ", Hops:";
        _description += param;
    }
#endif

    if (theGateway->getGWParams()->gwCertskey == nullptr)
    {
        throw EXCEPTION("DtlsCertsKey is required.", 0);
    }
    if (theGateway->getGWParams()->gwPrivatekey == nullptr)
    {
        throw EXCEPTION("DtlsPrivateKey is required.", 0);
    }

    /*  allocate Connections */
    _conns->initialize(theGateway->getGWParams()->maxClients);

    wolfSSL_load_error_strings();
    wolfSSL_library_init();

    #ifdef DEBUG_NW
        wolfSSL_Debugging_ON();
    #endif

    if (IS_DTLS13) {
        _dtlsctx = wolfSSL_CTX_new(wolfDTLS_method());
    } else {
        _dtlsctx = wolfSSL_CTX_new(wolfDTLSv1_2_method());
    }
    if (_dtlsctx == 0)
    {
        wolfSSL_ERR_error_string_n(wolfSSL_ERR_get_error(), errmsg, sizeof(errmsg));
        D_NWSTACK("SSL_CTX_new() %s\n", errmsg);
        throw EXCEPTION("SSL_CTX_new()", 0);
    }
    wolfSSL_CTX_set_min_proto_version(_dtlsctx, DTLS1_VERSION);

    if (wolfSSL_CTX_use_certificate_file(_dtlsctx, theGateway->getGWParams()->gwCertskey, SSL_FILETYPE_PEM) != 1)
    {
        wolfSSL_ERR_error_string_n(wolfSSL_ERR_get_error(), errmsg, sizeof(errmsg));
        D_NWSTACK("SSL_CTX_use_certificate_file() %s %s\n", theGateway->getGWParams()->gwCertskey, errmsg);
        throw EXCEPTION("SSL_CTX_use_certificate_file()", 0);
    }
    if (wolfSSL_CTX_use_PrivateKey_file(_dtlsctx, theGateway->getGWParams()->gwPrivatekey, SSL_FILETYPE_PEM) != 1)
    {
        wolfSSL_ERR_error_string_n(wolfSSL_ERR_get_error(), errmsg, sizeof(errmsg));
        D_NWSTACK("SSL_CTX_use_PrivateKey_file() %s %s\n", theGateway->getGWParams()->gwPrivatekey, errmsg);
        throw EXCEPTION("SSL_CTX_use_PrivateKey_file()", 0);
    }

    /* Client certification and cookie are not required */
    wolfSSL_CTX_set_verify(_dtlsctx, SSL_VERIFY_NONE, NULL);
    // Disabling session ticket for DTLSv1.3
    if (IS_DTLS13) {
        wolfSSL_CTX_no_ticket_TLSv13(_dtlsctx);
    }

    wolfSSL_CTX_set_cipher_list(_dtlsctx, MQTT_WOLFSSL_CIPHERS);

    #ifdef MQTT_WOLFSSL_GROUPS
        if (wolfSSL_CTX_set1_groups_list(_dtlsctx, (char *) MQTT_WOLFSSL_GROUPS) != WOLFSSL_SUCCESS) {
            D_NWSTACK("Error setting groups\n");
        }
    #endif
    /*  Prepare UDP and UDP6 sockets for Multicasting and unicasting */
#ifndef DTLS6
    if (openV4(&ip, multicastPortNo, unicastPortNo, ttl) < 0)
    {
        throw EXCEPTION("Can't open a UDP4", errno);
    }
#else
    if (openV6(&ip6, &interface, multicastPortNo, unicastPortNo, hops) < 0)
    {
        throw EXCEPTION("Can't open a UDP6", errno);
    }
#endif

}

const char* SensorNetwork::getDescription(void)
{
    return _description.c_str();
}

SensorNetAddress* SensorNetwork::getSenderAddress(void)
{
    return &_senderAddr;
}

int SensorNetwork::openV4(string *ipAddress, uint16_t multiPortNo, uint16_t uniPortNo, uint32_t ttl)
{
    int optval = 0;
    int rc = -1;
    int sock = 0;
    errno = 0;
    _af = AF_INET;

    if (uniPortNo == 0 || multiPortNo == 0)
    {
        D_NWSTACK("error portNo undefined in UDP4_6Port::openV4\n");
        return rc;
    }

    /*------ Create unicast socket --------*/
    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0)
    {
        D_NWSTACK("can't create unicast socket in UDP4_6Port::openV4 error %d %s\n", errno, strerror(errno));
        return -1;
    }

    optval = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    _serverAddr4.sin_family = AF_INET;
    _serverAddr4.sin_port = htons(uniPortNo);
    _serverAddr4.sin_addr.s_addr = INADDR_ANY;

    if (::bind(sock, (sockaddr*) &_serverAddr4, sizeof(_serverAddr4)) < 0)
    {
        D_NWSTACK("can't bind unicast socket in UDP4_6Port::openV4 error %d %s\n", errno, strerror(errno));
        return -1;
    }
    _conns->setSockUnicast(sock);

    /*------ Create Multicast socket --------*/
    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0)
    {
        D_NWSTACK("can't create multicast socket in UDP4_6Port::openV4 error %d %s\n", errno, strerror(errno));
        return -1;
    }
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    sockaddr_in addrm;
    addrm.sin_family = AF_INET;
    addrm.sin_port = htons(multiPortNo);
    addrm.sin_addr.s_addr = INADDR_ANY;

    if (::bind(sock, (sockaddr*) &addrm, sizeof(addrm)) < 0)
    {
        D_NWSTACK("can't bind multicast socket in UDP4_6Port::openV4 error %d %s\n", errno, strerror(errno));
        return -1;
    }

    ip_mreq mreq;
    memset(&mreq, 0, sizeof(mreq));
    mreq.imr_interface.s_addr = INADDR_ANY;
    mreq.imr_multiaddr.s_addr = inet_addr(ipAddress->c_str());

    if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0)
    {
        D_NWSTACK("Multicast IP_ADD_MEMBERSHIP in UDP4_6Port::openV4 error %d %s\n", errno, strerror(errno));
        return -1;
    }
    if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) < 0)
    {
        D_NWSTACK("Multicast IP_MULTICAST_TTL in UDP4_6Port::openV4 error %d %s\n", errno, strerror(errno));
        return -1;
    }

#ifdef DEBUG_NW
    optval = 1;
#else
    optval = 0;
#endif

    if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_LOOP, (char*) &optval, sizeof(optval)) < 0)
    {
        D_NWSTACK("error %d IP_MULTICAST_LOOP in UDP4_6Port::openV4 %s\n", errno, strerror(errno));
        return -1;
    }
    _multicastAddr.setFamily(AF_INET);
    _multicastAddr.setIpAddress(ipAddress);
    _multicastAddr.setPort(multiPortNo);
    _conns->setSockMulticast(sock);
    return 0;
}

int SensorNetwork::openV6(string *ipAddress, string *interface, uint16_t multiPortNo, uint16_t uniPortNo, uint32_t hops)
{
    int optval = 0;
    int sock = 0;
    uint32_t ifindex = 0;

    errno = 0;

    if (uniPortNo == 0 || multiPortNo == 0)
    {
        WRITELOG("error portNo undefined in SensorNetwork::openV6\n");
        return -1;
    }

    _multicastAddr.setPort(multiPortNo);
    _unicastAddr.setPort(uniPortNo);

    if (_multicastAddr.setIpAddress(ipAddress) < 0)
    {
        D_NWSTACK("Incorrect IPV6 address in SensorNetwork::openV6 error %s\n", strerror(errno));
        return -1;
    }

    /*------ Create unicast socket --------*/
    sock = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        D_NWSTACK("can't create unicast socket in SensorNetwork::openV6 error %s\n", strerror(errno));
        return -1;
    }
    _conns->setSockUnicast(sock);

    optval = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    optval = 1;
    if (setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &optval, sizeof(optval)) < 0)
    {
        D_NWSTACK("IPV6_ONLY in SensorNetwork::openV6 error %s\n", strerror(errno));
        return -1;
    }

    memset(&_serverAddr6, 0, sizeof(_serverAddr6));
    _serverAddr6.sin6_family = AF_INET6;
    _serverAddr6.sin6_port = htons(uniPortNo);
    _serverAddr6.sin6_addr = in6addr_any;

    if (::bind(sock, (sockaddr*) &_serverAddr6, sizeof(_serverAddr6)) < 0)
    {
        D_NWSTACK("can't bind unicast socket in SensorNetwork::openV6 error %s\n", strerror(errno));
        return -1;
    }

    if (interface->size() > 0)
    {
        ifindex = if_nametoindex(interface->c_str());
#ifdef __APPLE__
        setsockopt(sock, IPPROTO_IP, IP_BOUND_IF, &ifindex, interface->size());
#else
        setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, interface->c_str(), interface->size());
#endif
    }

    // Create Multicast socket
    sock = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        D_NWSTACK("can't create multicast socket in SensorNetwork::openV6 error %s\n", strerror(errno));
        return -1;
    }

    _conns->setSockMulticast(sock);

    optval = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    if (setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_IF, &ifindex, sizeof(ifindex)) < 0)
    {
        D_NWSTACK("IPV6_MULTICAST_IF in SensorNetwork::openV6 error %s\n", strerror(errno));
        return -1;
    }

    if (setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (char*) &optval, sizeof(optval)) < 0)
    {
        D_NWSTACK("IPV6_ONLY in SensorNetworkSensorNetwork::openV6 error %s\n", strerror(errno));
        return -1;
    }

    sockaddr_in6 addrm;
    addrm.sin6_family = AF_INET6;
    addrm.sin6_port = htons(multiPortNo);
    addrm.sin6_addr = in6addr_any;

    if (::bind(sock, (sockaddr*) &addrm, sizeof(addrm)) < 0)
    {
        D_NWSTACK("can't bind multicast socket in SensorNetwork::openV6 error %s\n", strerror(errno));
        return -1;
    }

    struct ipv6_mreq mreq;
    mreq.ipv6mr_multiaddr = _multicastAddr.getIpAddress()->addr.ad6;
    mreq.ipv6mr_interface = ifindex;

    if (setsockopt(sock, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq)) < 0)
    {
        D_NWSTACK("Multicast IPV6_JOIN_GROUP in SensorNetwork::openV6 error %s\n", strerror(errno));
        return -1;
    }

#ifdef DEBUG_NW
    optval = 1;
#else
    optval = 0;
#endif

    if (setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &optval, sizeof(optval)) < 0)
    {
        D_NWSTACK("IPV6_MULTICAST_LOOP in SensorNetwork::openV6 error %s\n", strerror(errno));
        return -1;
    }

    if (setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops, sizeof(hops)) < 0)
    {
        D_NWSTACK("Multicast IPV6_MULTICAST_HOPS in SensorNetwork::openV6 error %s\n", strerror(errno));
        return -1;
    }
    _multicastAddr.setFamily(AF_INET6);
    _multicastAddr.setIpAddress(ipAddress);
    _multicastAddr.setPort(multiPortNo);
    return 0;
}

int SensorNetwork::multicastRecv(uint8_t *buf, uint16_t len)
{
    int rc = -1;

#ifndef DTLS6
    sockaddr_in sender;
    socklen_t addrlen = sizeof(sender);
    memset(&sender, 0, addrlen);

    rc = ::recvfrom(_conns->getSockMulticast(), buf, len, 0, (sockaddr*) &sender, &addrlen);
    if (rc < 0 && errno != EAGAIN)
    {
        D_NWSTACK("errno  %s IPv4 in SensorNetwork::multicastRecv\n", strerror(errno));
        return -1;
    }

    D_NWSTACK("IPv4 multicast recved from %s:%d length = %d\n", inet_ntoa(sender.sin_addr), ntohs(sender.sin_port), rc);

#else
    sockaddr_in6 sender;
    socklen_t addrlen = sizeof(sender);
    memset(&sender, 0, addrlen);

    rc = ::recvfrom(_conns->getSockMulticast(), buf, len, 0, (sockaddr*) &sender, &addrlen);
    if (rc < 0 && errno != EAGAIN)
    {
        D_NWSTACK("errno = %d IPv6 in SensorNetwork::multicastRecv\n", errno);
        return -1;
    }
#ifdef DEBUG_NW
    char buff[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &sender.sin6_addr, buff, INET6_ADDRSTRLEN);
    D_NWSTACK("IPv6 multicast recved from %s:%u length = %d\n", buff, ntohs(sender.sin6_port), rc);
#endif
#endif

    return rc;
}

int SensorNetwork::getUnicastClient(SensorNetAddress *addr)
{
    return getSenderAddress(_conns->getSockUnicast(), addr);
}

int SensorNetwork::getSendClient(int index, SensorNetAddress *addr)
{
    return getSenderAddress(_conns->getSockClient(index), addr);
}

int SensorNetwork::getSenderAddress(int sock, SensorNetAddress *addr)
{
    int len = -1;

#ifndef DTLS6
    // AF_INET
    sockaddr_in sender4 = { 0 };
    socklen_t addrlen4 = sizeof(sender4);
    char buf[16];
    int rc = DTLS_OTHERS;

    len = ::recvfrom(sock, buf, 15, MSG_PEEK, (sockaddr*) &sender4, &addrlen4);

    if (len < 0 && errno != EAGAIN)
    {
        D_NWSTACK("errno = %d in SensorNetwork::getSenderAddress\n", errno);
        return -1;
    }

    addr->setSockaddr4(&sender4);

    D_NWSTACK("SensorNetwork::getSenderAddress recved from %s:%d length = %d fd=%d\n", inet_ntoa(sender4.sin_addr),
            ntohs(addr->getPort()), len, sock);

    if (len >= 13)
    {
        if (buf[0] == DTLS_CLIENTHELLO || buf[0] == DTLS_APPL)
        {
            rc = buf[0];
        } else if (buf[0] == DTLS_APPL_2) {
            rc = DTLS_APPL;
        }
    }
    return rc;

#else
    //AF_INET6
    sockaddr_in6 sender6 = { 0 };
    socklen_t addrlen6 = sizeof(sender6);
    char buf[16];
    int rc = DTLS_OTHERS;

    len = ::recvfrom(sock, &buf, 15, MSG_PEEK, (sockaddr*) &sender6, &addrlen6);

    if (len < 0 && errno != EAGAIN)
    {
        D_NWSTACK("errno = %d in SensorNetwork::getSenderAddress\n", errno);
        return -1;
    }

    addr->setSockaddr6(&sender6);

#ifdef DEBUG_NW
    char senderstr[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &sender6.sin6_addr,senderstr,INET6_ADDRSTRLEN);
    D_NWSTACK("recved from %s:%d length = %d fd=%d\n",senderstr ,ntohs(addr->getPort()), len, sock);
#endif
#endif

    if (len >= 13)
    {
        if (buf[0] == DTLS_CLIENTHELLO || buf[0] == DTLS_APPL)
        {
            rc = buf[0];
        } else if (buf[0] == DTLS_APPL_2) {
            rc = DTLS_APPL;
        }
    }
    return rc;
}

void SensorNetwork::clearRecvData(int sock)
{
    uint8_t buf[MQTTSNGW_MAX_PACKET_SIZE];
    ::recv(sock, buf, MQTTSNGW_MAX_PACKET_SIZE, 0);
}

Connections* SensorNetwork::getConnections(void)
{
    return _conns;
}


int verify_cert(int ok, WOLFSSL_X509_STORE_CTX *ctx)
{
    return 1;
}

