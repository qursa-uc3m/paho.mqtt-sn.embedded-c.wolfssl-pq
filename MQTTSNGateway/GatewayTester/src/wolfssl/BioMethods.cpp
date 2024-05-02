#include <sys/time.h>
#include "BioMethods.h"

int wolfSSL_BIO_dgram_non_fatal_error(int err)
{
    switch (err) {
# ifdef EWOULDBLOCK
#  ifdef WSAEWOULDBLOCK
#   if WSAEWOULDBLOCK != EWOULDBLOCK
    case EWOULDBLOCK:
#   endif
#  else
    case EWOULDBLOCK:
#  endif
# endif

# ifdef EINTR
    case EINTR:
# endif

# ifdef EAGAIN
#  if EWOULDBLOCK != EAGAIN
    case EAGAIN:
#  endif
# endif

# ifdef EPROTO
    case EPROTO:
# endif

# ifdef EINPROGRESS
    case EINPROGRESS:
# endif

# ifdef EALREADY
    case EALREADY:
# endif

        return 1;
    default:
        break;
    }
    return 0;
}

static int wolfSSL_BIO_dgram_should_retry(int i)
{
    int err;

    if ((i == 0) || (i == -1)) {
        err = errno;

        return wolfSSL_BIO_dgram_non_fatal_error(err);
    }
    return 0;
}

void wolfSSL_BIO_ADDR_clear(WOLFSSL_BIO_ADDR *ap)
{
    memset(ap, 0, sizeof(*ap));
    ap->sa.sa_family = AF_UNSPEC;
}

socklen_t wolfssl_BIO_ADDR_sockaddr_size(const WOLFSSL_BIO_ADDR *ap) {
    if (ap->sa.sa_family == AF_INET) {
        return sizeof(ap->s_in);
    }
#if defined(AF_INET6)
    if (ap->sa.sa_family == AF_INET6) {
        return sizeof(ap->s_in6);
    }
#endif
    return sizeof(*ap);
}

int wolfSSL_BIO_ADDR_make(WOLFSSL_BIO_ADDR *ap, const struct sockaddr *sa) {

    if (sa->sa_family == AF_INET) {
        memcpy(&(ap->s_in), sa, sizeof(struct sockaddr_in));
        return 1;
    }
#if defined(AF_INET6)
    if (sa->sa_family == AF_INET6) {
        memcpy(&(ap->s_in6), sa, sizeof(struct sockaddr_in6));
        return 1;
    }
#endif
    return 0;
}

int
mqtt_dgram_create(WOLFSSL_BIO *bio) {
  mqtt_dgram_data *data = NULL;
  data = (mqtt_dgram_data*)malloc(sizeof(mqtt_dgram_data));
  if (data == NULL) {
    return 0;
  }

  bio->init = 1;
  wolfSSL_BIO_set_data(bio, data);
  memset(data, 0x00, sizeof(mqtt_dgram_data));
  return 1;
}

int
mqtt_dgram_destroy(WOLFSSL_BIO *bio) {
  if (bio == NULL)
    return 0;

  int ret = wolfSSL_BIO_free(bio);

  return (ret == WOLFSSL_SUCCESS) ? 1 : 0;
}

int
mqtt_dgram_read(WOLFSSL_BIO *bio, char *out, int outl) {
  int ret = 0;
  int flags = 0;
  mqtt_dgram_data *data = (mqtt_dgram_data *)wolfSSL_BIO_get_data(bio);

  WOLFSSL_BIO_ADDR peer;
  socklen_t len = sizeof(peer);

  if (out != NULL) {
    if (data != NULL) {
      errno = 0;
      int socket_fd;
      wolfSSL_BIO_get_fd(bio, &socket_fd);
      wolfSSL_BIO_ADDR_clear(&peer);

      struct sockaddr *peer_addr = (struct sockaddr *)&(peer.sa);
      // TODO_wolfssl: implement adjustment of receive timeout of datagram socket in BIO
      //dgram_adjust_rcv_timeout(bio);

      if (data->peekmode) {
        flags = MSG_PEEK;
      }
      ret = recvfrom(socket_fd, out, outl, flags, peer_addr, &len);

      if (!data->connected && ret >= 0) {
        wolfSSL_BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_PEER, 0, &peer);
      }

      wolfSSL_BIO_clear_retry_flags(bio);
      if (ret < 0) {
        if (wolfSSL_BIO_dgram_should_retry(ret)) {
          wolfSSL_BIO_set_retry_read(bio);
          data->_errno = errno;
        }
      }

    } else {
      ret = -1;
    }

    //dgram_reset_rcv_timeout(bio);
  } else {
    ret = -1;
  }

  return ret;
}

int
mqtt_dgram_write(WOLFSSL_BIO *bio, const char *in, int inl) {
  int ret = 0;
  int socket_fd;
  wolfSSL_BIO_get_fd(bio, &socket_fd);

  mqtt_dgram_data *data = (mqtt_dgram_data *)wolfSSL_BIO_get_data(bio);

  errno = 0;

  if (data == NULL) {
      return -1;
  }

  if (data->connected) {
    if (wolfSSL_BIO_get_fd(bio, &socket_fd) == WOLFSSL_BIO_ERROR) {
        return -1;
    }
    ret = write(socket_fd, in, inl); // Linux
  }
  else {
    int peerlen = wolfssl_BIO_ADDR_sockaddr_size(&data->peer);
    const struct sockaddr *peer_addr = (const struct sockaddr *)&(data->peer.sa);

    if(peer_addr->sa_family == AF_INET) {
        struct sockaddr_in *addr_in = (struct sockaddr_in *)peer_addr;
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(addr_in->sin_addr), ip, INET_ADDRSTRLEN);
    } else if(peer_addr->sa_family == AF_INET6) {
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)peer_addr;
        char ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &(addr_in6->sin6_addr), ip, INET6_ADDRSTRLEN);
    }

    wolfSSL_BIO_get_fd(bio, &socket_fd);
    ret = sendto(socket_fd, in, inl, 0, peer_addr, peerlen);
  }

  wolfSSL_BIO_clear_retry_flags(bio);
  if (ret <= 0) {
    if (wolfSSL_BIO_dgram_should_retry(ret)) {
      wolfSSL_BIO_set_retry_write(bio);
      data->_errno = errno;
    }
    exit(EXIT_FAILURE);
  }
  return ret;
}

int
mqtt_dgram_puts(WOLFSSL_BIO *a, const char *pstr) {
  return mqtt_dgram_write(a, pstr, (int)strlen(pstr));
}

long
mqtt_dgram_ctrl(WOLFSSL_BIO *bio, int cmd, long num, void *ptr) {
  long ret = 1;
  mqtt_dgram_data *data = NULL;

  data = (mqtt_dgram_data *)wolfSSL_BIO_get_data(bio);

  const struct sockaddr *peer_addr = NULL;
  int result = 0;

  switch (cmd) {
  case BIO_CTRL_DGRAM_SET_CONNECTED:
    if (ptr != NULL) {
      data->connected = 1;
      peer_addr = (const struct sockaddr *)ptr;
      result = wolfSSL_BIO_ADDR_make(&data->peer, peer_addr);
      if (result == 0) {
        ret = -1;
      }
    } else {
      data->connected = 0;
      wolfSSL_BIO_ADDR_clear(&data->peer);
    }
    break;
case BIO_CTRL_DGRAM_GET_PEER:
    ret = wolfssl_BIO_ADDR_sockaddr_size(&data->peer);

    if (num < ret) {
      ret = -1;
    } else {

      if (num == 0 || num > ret)
        num = ret;
      memcpy(ptr, &data->peer, (ret = num));
    }
    break;
case BIO_CTRL_DGRAM_SET_PEER:
    peer_addr = (const struct sockaddr *)ptr;
    result = wolfSSL_BIO_ADDR_make(&data->peer, peer_addr);
    if (result == 0) {
      ret = -1;
    }
    break;
# if defined(SO_RCVTIMEO)
    case BIO_CTRL_DGRAM_SET_RECV_TIMEOUT:
        int socket_fd;
        wolfSSL_BIO_get_fd(bio, &socket_fd);
        if ((ret = setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, ptr,
                              sizeof(struct timeval))) < 0)

        break;
# endif
  default:
    ret = 0;
    break;
  }
  return ret;
}