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

#include <string.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/openssl/ssl.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <regex>

#include "Network.h"
#include "MQTTSNGWDefines.h"
#include "MQTTSNGWProcess.h"

using namespace std;
using namespace MQTTSNGW;

#define SOCKET_MAXCONNECTIONS  5
char* currentDateTime();

/*========================================
 Class TCPStack
 =======================================*/
TCPStack::TCPStack()
{
	_addrinfo = 0;
	_sockfd = 0;
}

TCPStack::~TCPStack()
{
	if (_addrinfo)
	{
		freeaddrinfo(_addrinfo);
	}
}

bool TCPStack::isValid()
{
	return (_sockfd > 0);
}

void TCPStack::close()
{
	_mutex.lock();
	if (_sockfd > 0)
	{
		::close(_sockfd);
		_sockfd = 0;
		if (_addrinfo)
		{
			freeaddrinfo(_addrinfo);
			_addrinfo = 0;
		}
	}
	_mutex.unlock();

}

bool TCPStack::bind(const char* service)
{
	if (isValid())
	{
		return false;
	}
	addrinfo hints;
	memset(&hints, 0, sizeof(addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	if (_addrinfo)
	{
		freeaddrinfo(_addrinfo);
	}
	int err = getaddrinfo(0, service, &hints, &_addrinfo);
	if (err)
	{
		WRITELOG("\n%s   \x1b[0m\x1b[31merror:\x1b[0m\x1b[37mgetaddrinfo(): %s\n", currentDateTime(),
				gai_strerror(err));
		return false;
	}

	_sockfd = socket(_addrinfo->ai_family, _addrinfo->ai_socktype, _addrinfo->ai_protocol);
	if (_sockfd < 0)
	{
		return false;
	}
	int on = 1;
	if (setsockopt(_sockfd, SOL_SOCKET, SO_REUSEADDR, (const char*) &on, sizeof(on)) == -1)
	{
		return false;
	}

	if (::bind(_sockfd, _addrinfo->ai_addr, _addrinfo->ai_addrlen) < 0)
	{
		return false;
	}
	return true;
}

bool TCPStack::listen()
{
	if (!isValid())
	{
		return false;
	}
	int listen_return = ::listen(_sockfd, SOCKET_MAXCONNECTIONS);
	if (listen_return == -1)
	{
		return false;
	}
	return true;
}

bool TCPStack::accept(TCPStack& new_socket)
{
	sockaddr_storage sa;
	socklen_t len = sizeof(sa);
	new_socket._sockfd = ::accept(_sockfd, (struct sockaddr*) &sa, &len);
	if (new_socket._sockfd <= 0)
	{
		return false;
	}
	else
	{
		return true;
	}
}

int TCPStack::send(const uint8_t* buf, int length)
{
#ifdef __APPLE__
	return ::send(_sockfd, buf, length, SO_NOSIGPIPE);
#else
	return ::send(_sockfd, buf, length, MSG_NOSIGNAL);
#endif
}

int TCPStack::recv(uint8_t* buf, int len)
{
	return ::recv(_sockfd, buf, len, 0);
}

bool TCPStack::connect(const char* host, const char* service)
{
	if (isValid())
	{
		return true;
	}
	addrinfo hints;
	memset(&hints, 0, sizeof(addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	if (_addrinfo)
	{
		freeaddrinfo(_addrinfo);
	}

	int err = getaddrinfo(host, service, &hints, &_addrinfo);
	if (err)
	{
		WRITELOG("\n%s   \x1b[0m\x1b[31merror:\x1b[0m\x1b[37mgetaddrinfo(): %s\n", currentDateTime(),
				gai_strerror(err));
		return false;
	}

	int sockfd = socket(_addrinfo->ai_family, _addrinfo->ai_socktype, _addrinfo->ai_protocol);

	if (sockfd < 0)
	{
		return false;
	}
	int on = 1;

	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const char*) &on, sizeof(on)) == -1)
	{
		return false;
	}

	if (::connect(sockfd, _addrinfo->ai_addr, _addrinfo->ai_addrlen) < 0)
	{
		DEBUGLOG("Can not connect the socket. Check the PortNo! \n");
		::close(sockfd);
		return false;
	}

	_sockfd = sockfd;
	return true;
}

void TCPStack::setNonBlocking(const bool b)
{
	int opts;

	opts = fcntl(_sockfd, F_GETFL);

	if (opts < 0)
	{
		return;
	}

	if (b)
	{
		opts = (opts | O_NONBLOCK);
	}
	else
	{
		opts = (opts & ~O_NONBLOCK);
	}
	fcntl(_sockfd, F_SETFL, opts);
}

int TCPStack::getSock()
{
	return _sockfd;
}

/*========================================
 Class Network
 =======================================*/
int Network::_numOfInstance = 0;
WOLFSSL_CTX* Network::_ctx = 0;
WOLFSSL_SESSION* Network::_session = 0;

Network::Network() :
		TCPStack()
{
	_ssl = 0;
	_secureFlg = false;
	_busy = false;
	_sslValid = false;
}

Network::~Network()
{
	close();
}

bool Network::connect(const char* host, const char* port)
{
	bool rc = false;
	_mutex.lock();
	if (_secureFlg)
	{
		goto exit;
	}

	if (getSock() == 0)
	{
		if (!TCPStack::connect(host, port))
		{
			goto exit;
		}
	}
	rc = true;
exit:
	_mutex.unlock();
	return rc;
}

bool Network::connect(const char* host, const char* port, const char* caPath, const char* caFile, const char* certkey, const char* prvkey)
{
	char errmsg[256];
	char peer_CN[256];
	bool rc;
	WOLFSSL_X509* peer = nullptr;

	_mutex.lock();
	try
	{
		if (!_secureFlg)
		{
			WRITELOG("TLS is not required.\n");
			throw false;
		}

		if (_ctx == 0)
		{
			wolfSSL_load_error_strings();
			wolfSSL_library_init();

			// TODO_wolfssl: remove the DTLS13 conditional as this is just for TLS between Gateway-Network

			if (IS_DTLS13) {
            	_ctx = wolfSSL_CTX_new(wolfSSLv23_method());
			} else {
				_ctx = wolfSSL_CTX_new(wolfTLSv1_2_method());
			}

			if (_ctx == 0)
			{
				wolfSSL_ERR_error_string_n(wolfSSL_ERR_get_error(), errmsg, sizeof(errmsg));
				WRITELOG("wolfCTX_new() %s\n", errmsg);
				throw false;
			}


			if (!wolfSSL_CTX_load_verify_locations(_ctx, caFile, caPath))
			{
				wolfSSL_ERR_error_string_n(wolfSSL_ERR_get_error(), errmsg, sizeof(errmsg));
				WRITELOG("wolfSSL_CTX_load_verify_locations() %s\n", errmsg);
				throw false;
			}

			if ( certkey )
			{
				if ( wolfSSL_CTX_use_certificate_file(_ctx, certkey, WOLFSSL_FILETYPE_PEM) != 1 )
				{
					wolfSSL_ERR_error_string_n(wolfSSL_ERR_get_error(), errmsg, sizeof(errmsg));
					WRITELOG("wolfSSL_CTX_use_certificate_file() %s %s\n", certkey, errmsg);
					throw false;
				}
			}
			if ( prvkey )
			{
				if ( wolfSSL_CTX_use_PrivateKey_file(_ctx, prvkey, WOLFSSL_FILETYPE_PEM) != 1 )
				{
					wolfSSL_ERR_error_string_n(wolfSSL_ERR_get_error(), errmsg, sizeof(errmsg));
					WRITELOG("wolfSSL_use_PrivateKey_file() %s %s\n", prvkey, errmsg);
					throw false;
				}
			}
		}

		if (! TCPStack::isValid())
		{
			if ( !TCPStack::connect(host, port) )
			{
				throw false;
			}
		}

		_ssl = wolfSSL_new(_ctx);
		if (_ssl == 0)
		{
			wolfSSL_ERR_error_string_n(wolfSSL_ERR_get_error(), errmsg, sizeof(errmsg));
			WRITELOG("wolfSSL_new()  %s\n", errmsg);
			throw false;
		}

		if (!wolfSSL_set_fd(_ssl, TCPStack::getSock()))
		{
			wolfSSL_ERR_error_string_n(wolfSSL_ERR_get_error(), errmsg, sizeof(errmsg));
			WRITELOG("wolfSSL_set_fd()  %s\n", errmsg);
			wolfSSL_free(_ssl);
			_ssl = 0;
			throw false;
		}

		if (_session)
		{
			wolfSSL_set_session(_ssl, _session);
		}
		if (wolfSSL_connect(_ssl) != 1)
		{
			wolfSSL_ERR_error_string_n(wolfSSL_ERR_get_error(), errmsg, sizeof(errmsg));
			WRITELOG("wolfSSL_connect() %s\n", errmsg);
			wolfSSL_free(_ssl);
			_ssl = 0;
			throw false;
		}

		int result;
		if ( (result = wolfSSL_get_verify_result(_ssl)) != WOLFSSL_X509_V_OK)
		{
			WRITELOG("wolfSSL_get_verify_result() error: %s.\n", wolfSSL_X509_verify_cert_error_string(result));
			wolfSSL_free(_ssl);
			_ssl = 0;
			throw false;
		}

		peer = wolfSSL_get_peer_certificate(_ssl);
		wolfSSL_X509_NAME_get_text_by_NID(wolfSSL_X509_get_subject_name(peer), NID_commonName, peer_CN, 256);
		char* pos = peer_CN;
		if ( *pos == '*')
		{
			while (*host++ != '.');
			pos += 2;
		}
		if ( strcmp(host, pos))
		{
			WRITELOG("wolfSSL_get_peer_certificate() error: Broker %s dosen't match the host name %s\n", peer_CN, host);
			wolfSSL_free(_ssl);
			_ssl = 0;
			throw false;
		}

		if (_session == 0)
		{
			_session = wolfSSL_get1_session(_ssl);
		}
		_numOfInstance++;
		_sslValid = true;
		rc = true;
	}
	catch (bool x)
	{
		rc = x;
	}

	_mutex.unlock();
	if (peer != nullptr)
	{
		wolfSSL_X509_free(peer);
	}
	return rc;
}

int Network::send(const uint8_t* buf, uint16_t length)
{
	char errmsg[256];
	fd_set rset;
	fd_set wset;
	bool writeBlockedOnRead = false;
	int bpos = 0;

	if (!_secureFlg)
	{
		return TCPStack::send(buf, length);
	}
	else
	{
		_mutex.lock();

		if ( !_ssl )
		{
			_mutex.unlock();
			return -1;
		}
		_busy = true;

		while (true)
		{
			FD_ZERO(&rset);
			FD_ZERO(&wset);
			FD_SET(getSock(), &rset);
			FD_SET(getSock(), &wset);

			int activity = select(getSock() + 1, &rset, &wset, 0, 0);
			if (activity > 0)
			{
				if (FD_ISSET(getSock(), &wset) || (writeBlockedOnRead  && FD_ISSET(getSock(), &rset)))
				{

					writeBlockedOnRead = false;
					int r = wolfSSL_write(_ssl, buf + bpos, length);

					switch (wolfSSL_get_error(_ssl, r))
					{
					case WOLFSSL_ERROR_NONE:
						length -= r;
						bpos += r;
						if (length == 0)
						{
							_busy = false;
							_mutex.unlock();
							return bpos;
						}
						break;
					case WOLFSSL_ERROR_WANT_WRITE:
						break;
					case WOLFSSL_ERROR_WANT_READ:
						writeBlockedOnRead = true;
						break;
					default:
						wolfSSL_ERR_error_string_n(wolfSSL_ERR_get_error(), errmsg, sizeof(errmsg));
						WRITELOG("TLSStack::send() default %s\n", errmsg);
						_busy = false;
						_mutex.unlock();
						return -1;
					}
				}
			}
		}
	}
}

int Network::recv(uint8_t* buf, uint16_t len)
{
	char errmsg[256];
	bool writeBlockedOnRead = false;
	bool readBlockedOnWrite = false;
	bool readBlocked = false;
	int rlen = 0;
	int bpos = 0;
	fd_set rset;
	fd_set wset;

	if (!_secureFlg)
	{
		return TCPStack::recv(buf, len);
	}

	if (_busy)
	{
		return 0;
	}
	_mutex.lock();

	if ( !_ssl )
	{
		_mutex.unlock();
		return 0;
	}

	_busy = true;
loop:
	do
	{
		readBlockedOnWrite = false;
		readBlocked = false;

		rlen = wolfSSL_read(_ssl, buf + bpos, len - bpos);

		switch (wolfSSL_get_error(_ssl, rlen))
		{
		case WOLFSSL_ERROR_NONE:
			_busy = false;
			_mutex.unlock();
			return rlen + bpos;
			break;
		case WOLFSSL_ERROR_ZERO_RETURN:
			wolfSSL_shutdown(_ssl);
			_ssl = 0;
			_numOfInstance--;
			//TCPStack::close();
			_busy = false;
			_mutex.unlock();
			return -1;
			break;
		case WOLFSSL_ERROR_WANT_READ:
			readBlocked = true;
			break;
		case WOLFSSL_ERROR_WANT_WRITE:
			readBlockedOnWrite = true;
			break;
		case WOLFSSL_ERROR_SYSCALL:
			wolfSSL_free(_ssl);
			_ssl = 0;
			_numOfInstance--;
			//TCPStack::close();
			_busy = false;
			_mutex.unlock();
			return -1;
			break;
		default:
			wolfSSL_ERR_error_string_n(wolfSSL_ERR_get_error(), errmsg, sizeof(errmsg));
			WRITELOG("Network::recv() %s\n", errmsg);
			_busy = false;
			_mutex.unlock();
			return -1;
		}
	} while (wolfSSL_pending(_ssl) && !readBlocked);

	bpos += rlen;
	while (true)
	{
		FD_ZERO(&rset);
		FD_ZERO(&wset);
		FD_SET(getSock(), &rset);
		FD_SET(getSock(), &wset);

		int activity = select(getSock() + 1, &rset, &wset, 0, 0);
		if (activity > 0)
		{
			if ((FD_ISSET(getSock(),&rset) && !writeBlockedOnRead)
					|| (readBlockedOnWrite && FD_ISSET(getSock(), &wset)))
			{
				goto loop;
			}
		}
		else
		{
			wolfSSL_ERR_error_string_n(wolfSSL_ERR_get_error(), errmsg, sizeof(errmsg));
			WRITELOG("TLSStack::recv() select %s\n", errmsg);
			_busy = false;
			_mutex.unlock();
			return -1;
		}
	}
}

void Network::close(void)
{
	_mutex.lock();
	if (_secureFlg)
	{
		if (_ssl)
		{
			wolfSSL_shutdown(_ssl);
			wolfSSL_free(_ssl);
			_numOfInstance--;
			_ssl = 0;
			_sslValid = false;
			_busy = false;
		}
		if (_session && _numOfInstance == 0)
		{
			wolfSSL_SESSION_free(_session);
			_session = 0;
		}
		if (_ctx && _numOfInstance == 0)
		{
			wolfSSL_CTX_free(_ctx);
			_ctx = 0;
			wolfSSL_ERR_free_strings();
		}
	}
	TCPStack::close();
	_mutex.unlock();
}

bool Network::isValid()
{
	if ( TCPStack::isValid() )
	{
		if (_secureFlg)
		{
			if (_sslValid && !_busy)
			{
				return true;
			}
		}
		else
		{
			return true;
		}
	}
	return false;
}

int Network::getSock()
{
	return TCPStack::getSock();
}

bool Network::isSecure()
{
	return _secureFlg;
}

void Network::setSecure(bool secureFlg)
{
    _secureFlg = secureFlg;
}

