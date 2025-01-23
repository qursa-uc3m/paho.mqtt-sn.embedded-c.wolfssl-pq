#ifndef MQTT_NETIF_H
#define MQTT_NETIF_H


#include <sys/socket.h>
#include <netinet/in.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/openssl/ssl.h>

// Macros
#define MQTT_LAYER_TLS_VALUE 2
#define MQTT_SOCKET_EMPTY 0x0000

#define wolfSSL_BIO_set_retry_read(a) wolfSSL_BIO_set_flags((a), WOLFSSL_BIO_FLAG_RETRY | WOLFSSL_BIO_FLAG_READ)
#define wolfSSL_BIO_set_retry_write(a) wolfSSL_BIO_set_flags((a), WOLFSSL_BIO_FLAG_RETRY | WOLFSSL_BIO_FLAG_WRITE)

#define BIO_CTRL_DGRAM_SET_CONNECTED      32
#define BIO_CTRL_DGRAM_SET_RECV_TIMEOUT   33
#define BIO_CTRL_DGRAM_GET_PEER           46
#define BIO_CTRL_DGRAM_SET_PEER           44

// Typedefs
typedef uint64_t mqtt_tick_t;

typedef union wolfssl_bio_addr_st {
    struct sockaddr sa;
#if defined(AF_INET6)
    struct sockaddr_in6 s_in6;
#endif
    struct sockaddr_in s_in;
} WOLFSSL_BIO_ADDR;

// Structure declarations
typedef struct mqtt_dtls_context_t {
  WOLFSSL_CTX *ctx;
  WOLFSSL *ssl;
  WOLFSSL_HMAC_CTX *cookie_hmac;
  WOLFSSL_BIO_METHOD *meth;
} mqtt_dtls_context_t;

typedef struct mqtt_dgram_data_st {
  WOLFSSL_BIO_ADDR peer;
  WOLFSSL_BIO_ADDR local_addr;
  unsigned int connected;
  unsigned int _errno;
  uint64_t next_timeout;
  uint64_t socket_timeout;
  unsigned peekmode;
  mqtt_tick_t timeout;
} mqtt_dgram_data;

// Function prototypes
int mqtt_dgram_create(WOLFSSL_BIO *a);
int mqtt_dgram_destroy(WOLFSSL_BIO *a);
int mqtt_dgram_read(WOLFSSL_BIO *a, char *out, int outl);
int mqtt_dgram_write(WOLFSSL_BIO *a, const char *in, int inl);
int mqtt_dgram_puts(WOLFSSL_BIO *a, const char *pstr);
long mqtt_dgram_ctrl(WOLFSSL_BIO *a, int cmd, long num, void *ptr);

void wolfSSL_BIO_ADDR_clear(WOLFSSL_BIO_ADDR *ap);

#endif // MQTT_NETIF_H