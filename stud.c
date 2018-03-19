/**
  * Copyright 2011 Bump Technologies, Inc. All rights reserved.
  *
  * Redistribution and use in source and binary forms, with or without modification, are
  * permitted provided that the following conditions are met:
  *
  *    1. Redistributions of source code must retain the above copyright notice, this list of
  *       conditions and the following disclaimer.
  *
  *    2. Redistributions in binary form must reproduce the above copyright notice, this list
  *       of conditions and the following disclaimer in the documentation and/or other materials
  *       provided with the distribution.
  *
  * THIS SOFTWARE IS PROVIDED BY BUMP TECHNOLOGIES, INC. ``AS IS'' AND ANY EXPRESS OR IMPLIED
  * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
  * FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL BUMP TECHNOLOGIES, INC. OR
  * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
  * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
  * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
  * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
  * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
  *
  * The views and conclusions contained in the software and documentation are those of the
  * authors and should not be interpreted as representing official policies, either expressed
  * or implied, of Bump Technologies, Inc.
  *
  **/

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netdb.h>
#include <sys/wait.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <getopt.h>
#include <pwd.h>
#include <limits.h>
#include <syslog.h>
#include <stdarg.h>

#include <ctype.h>
#include <sched.h>
#include <signal.h>

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif
#include <openssl/asn1.h>
#include <ev.h>

#include "foreign/uthash.h"

#include "ringbuffer.h"
#include "shctx.h"
#include "configuration.h"
#include "bufferchain.h"

#ifndef TAILQ_FOREACH_SAFE
# define TAILQ_FOREACH_SAFE(var, head, field, tvar)\
    for ((var) = TAILQ_FIRST(head); \
        (var) && ((tvar) = TAILQ_NEXT((var), field), 1); \
        (var) = (tvar))
#endif

#ifndef MSG_NOSIGNAL
# define MSG_NOSIGNAL 0
#endif
#ifndef AI_ADDRCONFIG
# define AI_ADDRCONFIG 0
#endif

/* For Mac OS X */
#ifndef TCP_KEEPIDLE
# ifdef TCP_KEEPALIVE
#  define TCP_KEEPIDLE TCP_KEEPALIVE
# endif
#endif
#ifndef SOL_TCP
# define SOL_TCP IPPROTO_TCP
#endif

/* Do we have SNI support? */
#ifndef OPENSSL_NO_TLSEXT
#ifndef SSL_CTRL_SET_TLSEXT_HOSTNAME
#define OPENSSL_NO_TLSEXT
#endif
#endif

static volatile unsigned n_sigchld;
static volatile unsigned n_sighup;

struct sni_name;
TAILQ_HEAD(sni_name_head, sni_name);

struct sslctx {
    char *filename;
    SSL_CTX *ctx;
    X509 *x509;
    struct sni_name_head sni_list;
    double mtim;
    UT_hash_handle hh;
};

struct sni_name {
    char *servername;
    struct sslctx* sctx;
    int is_wildcard;
    TAILQ_ENTRY(sni_name) list;
    UT_hash_handle hh;
};

struct worker_proc {
    pid_t pid;
    int pfd;
    unsigned generation;
    int core;
    TAILQ_ENTRY(worker_proc) list;
};

struct frontend {
    int sock;
    ev_io listener;
    int backend_index;
    char* pspec;
    TAILQ_ENTRY(frontend) list;
};

TAILQ_HEAD(frontend_head, frontend);
static struct frontend_head frontends;

enum txn_type {
    TXN_FRONTEND,
    TXN_CERT,
};

enum txn_handling {
    TXN_KEEP,
    TXN_NEW,
    TXN_DROP,
};

struct txn_obj;
typedef void txn_rollback_f(struct txn_obj* o);
typedef void txn_commit_f(struct txn_obj* o);

struct txn_obj {
    enum txn_type type;
    enum txn_handling handling;
    void *ctx[2];
    txn_rollback_f *rollback;
    txn_commit_f *commit;
    TAILQ_ENTRY(txn_obj) list;
};

TAILQ_HEAD(txn_obj_head, txn_obj);

/* Globals */
static struct ev_loop *loop;
static struct addrinfo **backaddrs;
static pid_t master_pid;
static int child_core;
TAILQ_HEAD(worker_proc_head, worker_proc);
static struct worker_proc_head worker_procs;
static struct sslctx *default_ctx;
static SSL_SESSION *client_session;

/* current number of active client connections */
static uint64_t n_conns;

static unsigned worker_generation;

enum worker_state_e {
    WORKER_ACTIVE,
    WORKER_EXITING,
};

static enum worker_state_e worker_state;

#ifdef USE_SHARED_CACHE
static ev_io shcupd_listener;
static int shcupd_socket;
struct addrinfo *shcupd_peers[MAX_SHCUPD_PEERS+1];
static unsigned char shared_secret[SHA_DIGEST_LENGTH];
#endif /*USE_SHARED_CACHE*/

long openssl_version;
int create_workers;
stud_config *CONFIG;

static ev_io mgmt_rd;

static char tcp_proxy_line[128] = "";

#define MAXIMUM_QUEUED_DATA (32*1024)


/* What agent/state requests the shutdown--for proper half-closed
 * handling */
typedef enum _SHUTDOWN_REQUESTOR {
    SHUTDOWN_HARD,
    SHUTDOWN_CLEAR,
    SHUTDOWN_SSL
} SHUTDOWN_REQUESTOR;

#ifndef OPENSSL_NO_TLSEXT
static struct sni_name *sni_names;
static struct sslctx *ssl_ctxs;
#endif /* OPENSSL_NO_TLSEXT */


union ha_proxy_v2_addr {
    struct {        /* for TCP/UDP over IPv4, len = 12 */
        uint32_t src_addr;
        uint32_t dst_addr;
        uint16_t src_port;
        uint16_t dst_port;
    } ipv4_addr;
    struct {        /* for TCP/UDP over IPv6, len = 36 */
         uint8_t  src_addr[16];
         uint8_t  dst_addr[16];
         uint16_t src_port;
         uint16_t dst_port;
    } ipv6_addr;
    struct {        /* for AF_UNIX sockets, len = 216 */
         uint8_t src_addr[108];
         uint8_t dst_addr[108];
    } unix_addr;
};


struct ha_proxy_v2_hdr {
    uint8_t sig[12]; // = {0x0D, 0x0A, 0x0D,0x0A,0x00,0x0D,0x0A,0x51,0x55,0x49,0x54,0x0A};
    uint8_t ver_cmd;    // = 0x21;      /* hex 02 */ /* We only support PROXY Command*/
    uint8_t fam;      /* protocol family and address */
    uint16_t len;      /* number of following bytes part of the header */
};

static struct ha_proxy_v2_hdr header_proxy_v2;
static union ha_proxy_v2_addr frontend_addr;
/*
 * Proxied State
 *
 * All state associated with one proxied connection
 */
typedef struct proxystate {
    struct bufferchain bc_ssl2clear;          /* Pushing bytes from secure to clear stream */
    struct bufferchain bc_clear2ssl;    /* Pushing bytes from clear to secure stream */

    ev_io ev_r_ssl;                     /* Secure stream write event */
    ev_io ev_w_ssl;                     /* Secure stream read event */

    ev_io ev_r_handshake;               /* Secure stream handshake write event */
    ev_io ev_w_handshake;               /* Secure stream handshake read event */

    ev_io ev_w_connect;                 /* Backend connect event */

    ev_io ev_r_clear;                   /* Clear stream write event */
    ev_io ev_w_clear;                   /* Clear stream read event */

    ev_io ev_proxy;                     /* proxy read event */

    int index;                          /* Index of the connection */
    int fd_up;                          /* Upstream (client) socket */
    int fd_down;                        /* Downstream (backend) socket */

    int want_shutdown:1;                /* Connection is half-shutdown */
    int handshaked:1;                   /* Initial handshake happened */
    int clear_connected:1;              /* Clear stream is connected  */
    int renegotiation:1;                /* Renegotation is occuring */

    SSL *ssl;                           /* OpenSSL SSL state */

    struct sockaddr_storage remote_ip;  /* Remote ip returned from `accept` */

    union ha_proxy_v2_addr proxy_addr;           /* proxy v2 protocol struct */
} proxystate;

#define LOG(...)                                            \
    do {                                                    \
      if (!CONFIG->QUIET) fprintf(stdout, __VA_ARGS__);     \
      if (CONFIG->SYSLOG) syslog(LOG_INFO, __VA_ARGS__);    \
    } while(0)

#define ERR(...)                                            \
    do {                                                    \
      fprintf(stderr, __VA_ARGS__);                         \
      if (CONFIG->SYSLOG) syslog(LOG_ERR, __VA_ARGS__);     \
    } while(0)

#define NULL_DEV "/dev/null"

/* Set a file descriptor (socket) to non-blocking mode */
static void setnonblocking(int fd) {
    int flag = 1;

    assert(ioctl(fd, FIONBIO, &flag) == 0);
}

/* set a tcp socket to use TCP Keepalive */
static void settcpkeepalive(int fd) {
    int optval = 1;
    socklen_t optlen = sizeof(optval);

    if(setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &optval, optlen) < 0) {
        ERR("Error activating SO_KEEPALIVE on client socket: %s", strerror(errno));
    }

    optval = CONFIG->TCP_KEEPALIVE_TIME;
    optlen = sizeof(optval);
#ifdef TCP_KEEPIDLE
    if(setsockopt(fd, SOL_TCP, TCP_KEEPIDLE, &optval, optlen) < 0) {
        ERR("Error setting TCP_KEEPIDLE on client socket: %s", strerror(errno));
    }
#endif
}

static void fail(const char* s) {
    perror(s);
    exit(1);
}

void die (char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);

    exit(1);
}

#ifndef OPENSSL_NO_DH
static int init_dh(SSL_CTX *ctx, const char *cert) {
    DH *dh;
    BIO *bio;

    assert(cert);

    bio = BIO_new_file(cert, "r");
    if (!bio) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!dh) {
        ERR("{core} Note: no DH parameters found in %s\n", cert);
        return -1;
    }

    LOG("{core} Using DH parameters from %s\n", cert);
    SSL_CTX_set_tmp_dh(ctx, dh);
    LOG("{core} DH initialized with %d bit key\n", 8*DH_size(dh));
    DH_free(dh);

#ifndef OPENSSL_NO_EC
#ifdef NID_X9_62_prime256v1
    EC_KEY *ecdh = NULL;
    ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    SSL_CTX_set_tmp_ecdh(ctx, ecdh);
    EC_KEY_free(ecdh);
    LOG("{core} ECDH Initialized with NIST P-256\n");
#endif /* NID_X9_62_prime256v1 */
#endif /* OPENSSL_NO_EC */

    return 0;
}
#endif /* OPENSSL_NO_DH */

/* This callback function is executed while OpenSSL processes the SSL
 * handshake and does SSL record layer stuff.  It's used to trap
 * client-initiated renegotiations.
 */
static void info_callback(const SSL *ssl, int where, int ret) {
    (void)ret;
    if (where & SSL_CB_HANDSHAKE_START) {
        proxystate *ps = (proxystate *)SSL_get_app_data(ssl);
        if (ps->handshaked) {
            ps->renegotiation = 1;
            LOG("{core} SSL renegotiation asked by client\n");
        }
    }
}

#ifdef USE_SHARED_CACHE

/* Handle incoming message updates */
static void handle_shcupd(struct ev_loop *loop, ev_io *w, int revents) {
    (void) revents;
    unsigned char msg[SHSESS_MAX_ENCODED_LEN], hash[EVP_MAX_MD_SIZE];
    ssize_t r;
    unsigned int hash_len;
    uint32_t encdate;
    long now = (time_t)ev_now(loop);

    while ( ( r = recv(w->fd, msg, sizeof(msg), 0) ) > 0 ) {

        /* msg len must be greater than 1 Byte of data + sig length */
        if (r < (int)(1+sizeof(shared_secret)))
           continue;

        /* compute sig */
        r -= sizeof(shared_secret);
        HMAC(EVP_sha1(), shared_secret, sizeof(shared_secret), msg, r, hash, &hash_len);

        if (hash_len != sizeof(shared_secret)) /* should never append */
           continue;

        /* check sign */
        if(memcmp(msg+r, hash, hash_len))
           continue;

        /* msg len must be greater than 1 Byte of data + encdate length */
        if (r < (int)(1+sizeof(uint32_t)))
           continue;

        /* drop too unsync updates */
        r -= sizeof(uint32_t);
        encdate = *((uint32_t *)&msg[r]);
        if (!(abs((int)(int32_t)now-ntohl(encdate)) < SSL_CTX_get_timeout(default_ctx)))
           continue;

        shctx_sess_add(msg, r, now);
    }
}

/* Send remote updates messages callback */
void shcupd_session_new(unsigned char *msg, unsigned int len, long cdate) {
    unsigned int hash_len;
    struct addrinfo **pai = shcupd_peers;
    uint32_t ncdate;

    /* add session creation encoded date to footer */
    ncdate = htonl((uint32_t)cdate);
    memcpy(msg+len, &ncdate, sizeof(ncdate));
    len += sizeof(ncdate);

    /* add msg sign */
    HMAC(EVP_sha1(), shared_secret, sizeof(shared_secret),
                     msg, len, msg+len, &hash_len);
    len += hash_len;

    /* send msg to peers */
    while (*pai) {
        sendto(shcupd_socket, msg, len, 0, (*pai)->ai_addr, (*pai)->ai_addrlen);
        pai++;
    }
}

/* Compute a sha1 secret from an ASN1 rsa private key */
static int compute_secret(RSA *rsa, unsigned char *secret) {
    unsigned char *buf,*p;
    unsigned int length;

    length = i2d_RSAPrivateKey(rsa, NULL);
    if (length <= 0)
        return -1;

    p = buf = (unsigned char *)malloc(length*sizeof(unsigned char));
    if (!buf)
        return -1;

    i2d_RSAPrivateKey(rsa,&p);

    SHA1(buf, length, secret);

    free(buf);

    return 0;
}

/* Create udp socket to receive and send updates */
static int create_shcupd_socket() {
    struct addrinfo *ai, hints;
    struct addrinfo **pai = shcupd_peers;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;
    const int gai_err = getaddrinfo(CONFIG->SHCUPD_IP, CONFIG->SHCUPD_PORT,
                                    &hints, &ai);
    if (gai_err != 0) {
        ERR("{getaddrinfo}: [%s]\n", gai_strerror(gai_err));
        exit(1);
    }

    /* check if peers inet family addresses match */
    while (*pai) {
        if ((*pai)->ai_family != ai->ai_family) {
            ERR("Share host and peers inet family differs\n");
            exit(1);
        }
        pai++;
    }

    int s = socket(ai->ai_family, SOCK_DGRAM, IPPROTO_UDP);

    if (s == -1)
      fail("{socket: shared cache updates}");

    int t = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &t, sizeof(int));
#ifdef SO_REUSEPORT
    setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &t, sizeof(int));
#endif

    setnonblocking(s);

    if (ai->ai_addr->sa_family == AF_INET) {
        struct ip_mreqn mreqn;

        memset(&mreqn, 0, sizeof(mreqn));
        mreqn.imr_multiaddr.s_addr = ((struct sockaddr_in *)ai->ai_addr)->sin_addr.s_addr;

        if (CONFIG->SHCUPD_MCASTIF) {
            if (isalpha(*CONFIG->SHCUPD_MCASTIF)) { /* appears to be an iface name */
                struct ifreq ifr;

                memset(&ifr, 0, sizeof(ifr));
                if (strlen(CONFIG->SHCUPD_MCASTIF) > IFNAMSIZ) {
                    ERR("Error iface name is too long [%s]\n",CONFIG->SHCUPD_MCASTIF);
                    exit(1);
                }

                memcpy(ifr.ifr_name, CONFIG->SHCUPD_MCASTIF, strlen(CONFIG->SHCUPD_MCASTIF));
                if (ioctl(s, SIOCGIFINDEX, &ifr)) {
                    fail("{ioctl: SIOCGIFINDEX}");
                }

                mreqn.imr_ifindex = ifr.ifr_ifindex;
            }
            else if (strchr(CONFIG->SHCUPD_MCASTIF,'.')) { /* appears to be an ipv4 address */
                mreqn.imr_address.s_addr = inet_addr(CONFIG->SHCUPD_MCASTIF);
            }
            else { /* appears to be an iface index */
                mreqn.imr_ifindex = atoi(CONFIG->SHCUPD_MCASTIF);
            }
        }

        if (setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreqn, sizeof(mreqn)) < 0) {
            if (errno != EINVAL) { /* EINVAL if it is not a multicast address,
                                                not an error we consider unicast */
                fail("{setsockopt: IP_ADD_MEMBERSIP}");
            }
        }
        else { /* this is a multicast address */
            unsigned char loop = 0;

            if(setsockopt(s, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop)) < 0) {
               fail("{setsockopt: IP_MULTICAST_LOOP}");
            }
        }

        /* optional set sockopts for sending to multicast msg */
        if (CONFIG->SHCUPD_MCASTIF &&
            setsockopt(s, IPPROTO_IP, IP_MULTICAST_IF, &mreqn, sizeof(mreqn)) < 0) {
            fail("{setsockopt: IP_MULTICAST_IF}");
        }

        if (CONFIG->SHCUPD_MCASTTTL) {
             unsigned char ttl;

             ttl = (unsigned char)atoi(CONFIG->SHCUPD_MCASTTTL);
             if (setsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) < 0) {
                 fail("{setsockopt: IP_MULTICAST_TTL}");
             }
        }

     }
#ifdef IPV6_ADD_MEMBERSHIP
     else if (ai->ai_addr->sa_family == AF_INET6) {
        struct ipv6_mreq mreq;

        memset(&mreq, 0, sizeof(mreq));
        memcpy(&mreq.ipv6mr_multiaddr, &((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr,
                                       sizeof(mreq.ipv6mr_multiaddr));

        if (CONFIG->SHCUPD_MCASTIF) {
            if (isalpha(*CONFIG->SHCUPD_MCASTIF)) { /* appears to be an iface name */
                struct ifreq ifr;

                memset(&ifr, 0, sizeof(ifr));
                if (strlen(CONFIG->SHCUPD_MCASTIF) > IFNAMSIZ) {
                    ERR("Error iface name is too long [%s]\n",CONFIG->SHCUPD_MCASTIF);
                    exit(1);
                }

                memcpy(ifr.ifr_name, CONFIG->SHCUPD_MCASTIF, strlen(CONFIG->SHCUPD_MCASTIF));
                if (ioctl(s, SIOCGIFINDEX, &ifr)) {
                    fail("{ioctl: SIOCGIFINDEX}");
                }

                mreq.ipv6mr_interface = ifr.ifr_ifindex;
            }
            else { /* option appears to be an iface index */
                mreq.ipv6mr_interface = atoi(CONFIG->SHCUPD_MCASTIF);
            }
        }

        if (setsockopt(s, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
            if (errno != EINVAL) { /* EINVAL if it is not a multicast address,
                                                not an error we consider unicast */
                fail("{setsockopt: IPV6_ADD_MEMBERSIP}");
            }
        }
        else { /* this is a multicast address */
            unsigned int loop = 0;

            if(setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &loop, sizeof(loop)) < 0) {
               fail("{setsockopt: IPV6_MULTICAST_LOOP}");
            }
        }

        /* optional set sockopts for sending to multicast msg */
        if (setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_IF,
                               &mreq.ipv6mr_interface, sizeof(mreq.ipv6mr_interface)) < 0) {
            fail("{setsockopt: IPV6_MULTICAST_IF}");
        }

        if (CONFIG->SHCUPD_MCASTTTL) {
            int hops;

            hops = atoi(CONFIG->SHCUPD_MCASTTTL);
            if (setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops, sizeof(hops)) < 0) {
                fail("{setsockopt: IPV6_MULTICAST_HOPS}");
            }
        }
    }
#endif /* IPV6_ADD_MEMBERSHIP */

    if (bind(s, ai->ai_addr, ai->ai_addrlen)) {
        fail("{bind-socket}");
    }

    freeaddrinfo(ai);

    return s;
}

#endif /*USE_SHARED_CACHE */

EVP_PKEY *load_privatekey(SSL_CTX *ctx, const char *file) {
    BIO *bio;
    EVP_PKEY *pkey;

    bio = BIO_new_file(file, "r");
    if (!bio) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    pkey = PEM_read_bio_PrivateKey(bio, NULL,
          ctx->default_passwd_callback, ctx->default_passwd_callback_userdata);
    BIO_free(bio);

    return pkey;
}

#ifndef OPENSSL_NO_TLSEXT

static int sni_match(const struct sni_name* sn, const char *srvname) {
    if (!sn->is_wildcard) {
        return strcasecmp(srvname, sn->servername) == 0;
    } else {
        const char *s = strchr(srvname, '.');
        if (s == NULL) {
            return 0;
        }

        return strcasecmp(s, sn->servername + 1) == 0;
    }
}

static struct sslctx *sni_lookup(const char* servername, const struct sni_name *sn_tab) {
    const struct sni_name *sn;

    HASH_FIND_STR(sn_tab, servername, sn);
    if (sn == NULL) {
        char *s;
        /* attemp another lookup for wildcard matches */
        s = strchr(servername, '.');
        if (s != NULL) {
            HASH_FIND_STR(sn_tab, s, sn);
        }
    }

    if (sn != NULL) {
        if (sni_match(sn, servername)) {
            return sn->sctx;
        }
    }

    return NULL;
}

/*
 * Switch the context of the current SSL object to the most appropriate one
 * based on the SNI header
 */
int sni_switch_ctx(SSL *ssl, int *al, void *data) {
    (void)data;
    (void)al;
    const char *servername;
    const struct sslctx *so;

    servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (!servername) return SSL_TLSEXT_ERR_NOACK;

#define TRY_SNI_MATCH(sn_tab) \
    do { \
        so = sni_lookup(servername, (sn_tab)); \
        if (so != NULL) { \
            SSL_set_SSL_CTX(ssl, so->ctx); \
            return SSL_TLSEXT_ERR_OK; \
        } \
    } while (0)

    TRY_SNI_MATCH(sni_names);

    /* No matching certs */
    return SSL_TLSEXT_ERR_NOACK;
}
#endif /* OPENSSL_NO_TLSEXT */

static void sctx_free(struct sslctx* sc, struct sni_name **sn_tab) {
    struct sni_name *sn, *tsn;

    if (sc == NULL) {
        return;
    }

    if (sc->x509) {
        X509_free(sc->x509);
    }

    TAILQ_FOREACH_SAFE(sn, &sc->sni_list, list, tsn) {
        TAILQ_REMOVE(&sc->sni_list, sn, list);
        if (sn_tab != NULL) {
            HASH_DEL(*sn_tab, sn);
        }
        free(sn->servername);
        free(sn);
    }

    free(sc->filename);
    SSL_CTX_free(sc->ctx);
    free(sc);
}

#ifndef OPENSSL_NO_TLSEXT
static void insert_sni_names(struct sslctx *so, struct sni_name **sn_tab) {
    struct sni_name *sn, *sn2;
    char* key;

    TAILQ_FOREACH(sn, &so->sni_list, list) {
        key = sn->servername;
        if (sn->is_wildcard) {
            key = sn->servername + 1;
        }

        HASH_FIND_STR(*sn_tab, key, sn2);
        if (sn2 != NULL) {
            ERR("Warning: SNI name '%s' from '%s' overridden by '%s'\n", key, sn2->sctx->filename, so->filename);
        }
        HASH_ADD_KEYPTR(hh, *sn_tab, key, strlen(key), sn);
    }
}

static int load_cert_ctx(struct sslctx* so) {
    X509 *x509;
    X509_NAME *x509_name;
    X509_NAME_ENTRY *x509_entry;
    BIO *f;
    STACK_OF(GENERAL_NAME) *names = NULL;
    GENERAL_NAME *name;
    int i;

#define PUSH_CTX(asn1_str) \
    do { \
        struct sni_name *sn; \
        sn = calloc(1, sizeof(struct sni_name)); \
        ASN1_STRING_to_UTF8((unsigned char**)&sn->servername, asn1_str); \
        sn->is_wildcard = (strstr(sn->servername, "*.") == sn->servername); \
        sn->sctx = so; \
        TAILQ_INSERT_TAIL(&so->sni_list, sn, list); \
    } while (0)

    f = BIO_new(BIO_s_file());

    if (!BIO_read_filename(f, so->filename)) {
        BIO_free(f);
        ERR("Could not read certificate '%s'\n", so->filename);
        return 1;
    }

    x509 = PEM_read_bio_X509_AUX(f, NULL, NULL, NULL);
    BIO_free(f);

    so->x509 = x509;

    /* First, look for Subject Alternative Names. */
    names = X509_get_ext_d2i(x509, NID_subject_alt_name, NULL, NULL);
    for (i = 0; i < sk_GENERAL_NAME_num(names); ++i) {
        name = sk_GENERAL_NAME_value(names, i);
        if (name->type == GEN_DNS) {
            PUSH_CTX(name->d.dNSName);
        }
    }

    if (sk_GENERAL_NAME_num(names) > 0) {
        sk_GENERAL_NAME_pop_free(names, GENERAL_NAME_free);
        /* If we found some, don't bother looking any further. */
        return 0;
    } else if (names != NULL) {
        sk_GENERAL_NAME_pop_free(names, GENERAL_NAME_free);
    }

    /* Now we're left looking at the CN on the cert */
    x509_name = X509_get_subject_name(x509);
    i = X509_NAME_get_index_by_NID(x509_name, NID_commonName, -1);
    if (i < 0) {
        ERR("Could not find Subject Alternative Names or a CN on cert %s\n", so->filename);
        return 1;
    }

    x509_entry = X509_NAME_get_entry(x509_name, i);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define X509_NAME_ENTRY_get_data(e) (e->value)
#endif
    PUSH_CTX(X509_NAME_ENTRY_get_data(x509_entry));

    return 0;
}

/*
 * Initialize an SSL context
 */

struct sslctx *make_ctx(const struct config_cert_file *cert) {
    SSL_CTX *ctx;
    struct sslctx* sc;
    EVP_PKEY *pkey;

    long ssloptions = SSL_OP_NO_SSLv2 | SSL_OP_ALL |
            SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;

#ifdef SSL_OP_NO_COMPRESSION
    ssloptions |= SSL_OP_NO_COMPRESSION;
#endif

    if (CONFIG->ETYPE == ENC_TLS) {
        ssloptions |= SSL_OP_NO_SSLv3;
    } else if (CONFIG->ETYPE != ENC_SSL) {
        assert(CONFIG->ETYPE == ENC_TLS || CONFIG->ETYPE == ENC_SSL);
        return NULL; // Won't happen, but gcc was complaining
    }

    ctx = SSL_CTX_new((CONFIG->PMODE == SSL_CLIENT) ?
            SSLv23_client_method() : SSLv23_server_method());
    SSL_CTX_set_options(ctx, ssloptions);
    SSL_CTX_set_info_callback(ctx, info_callback);

    if (CONFIG->CIPHER_SUITE) {
        if (SSL_CTX_set_cipher_list(ctx, CONFIG->CIPHER_SUITE) != 1) {
            ERR_print_errors_fp(stderr);
        }
    }

    if (CONFIG->PREFER_SERVER_CIPHERS) {
        SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
    }

    sc = calloc(1, sizeof(struct sslctx));
    sc->filename = strdup(cert->CERT_FILE);
    sc->ctx = ctx;
    sc->x509 = NULL;
    sc->mtim = cert->mtim;
    TAILQ_INIT(&sc->sni_list);

    if (CONFIG->PMODE == SSL_CLIENT) {
        return sc;
    }

    /* SSL_SERVER Mode stuff */
    if (SSL_CTX_use_certificate_chain_file(ctx, cert->CERT_FILE) <= 0) {
        ERR_print_errors_fp(stderr);
        sctx_free(sc, NULL);
        return NULL;
    }

    pkey = load_privatekey(ctx, cert->CERT_FILE);
    if (!pkey) {
        ERR("Error loading private key '%s'\n", cert->CERT_FILE);
        sctx_free(sc, NULL);
        return NULL;
    }

    if (SSL_CTX_use_PrivateKey(ctx, pkey) <= 0) {
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(pkey);
        sctx_free(sc, NULL);
        return NULL;
    }

#ifndef OPENSSL_NO_DH
    init_dh(ctx, cert->CERT_FILE);
#endif /* OPENSSL_NO_DH */

#ifndef OPENSSL_NO_TLSEXT
    if (!SSL_CTX_set_tlsext_servername_callback(ctx, sni_switch_ctx)) {
        ERR("Error setting up SNI support\n");
    }

    if (load_cert_ctx(sc) != 0) {
        EVP_PKEY_free(pkey);
        sctx_free(sc, NULL);
        return NULL;
    }
#endif /* OPENSSL_NO_TLSEXT */

#ifdef USE_SHARED_CACHE
    if (CONFIG->SHARED_CACHE) {
        if (shared_context_init(ctx, CONFIG->SHARED_CACHE) < 0) {
            ERR("Unable to alloc memory for shared cache.\n");
            EVP_PKEY_free(pkey);
            sctx_free(sc, NULL);
            return NULL;
        }
        if (CONFIG->SHCUPD_PORT) {
            if (compute_secret(rsa, shared_secret) < 0) {
                ERR("Unable to compute shared secret.\n");
                EVP_PKEY_free(pkey);
                sctx_free(sc, NULL);
                return NULL;
            }

            /* Force tls tickets cause keys differs */
            SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);

            if (*shcupd_peers) {
                shsess_set_new_cbk(shcupd_session_new);
            }
        }
    }
#endif

    EVP_PKEY_free(pkey);
    return sc;
}

static struct sslctx* find_ctx(const char* file) {
    struct sslctx *so;
    HASH_FIND_STR(ssl_ctxs, file, so);
    return so;
}

#endif /* OPENSSL_NO_TLSEXT */

/* Init library and load specified certificate.
 * Establishes a SSL_ctx, to act as a template for
 * each connection */
void init_openssl() {
    SSL_library_init();
    SSL_load_error_strings();

#ifndef OPENSSL_NO_ENGINE
    if (CONFIG->ENGINE) {
        ENGINE *e = NULL;
        ENGINE_load_builtin_engines();
        if (!strcmp(CONFIG->ENGINE, "auto"))
            ENGINE_register_all_complete();
        else {
            if ((e = ENGINE_by_id(CONFIG->ENGINE)) == NULL ||
                !ENGINE_init(e) ||
                !ENGINE_set_default(e, ENGINE_METHOD_ALL)) {
                ERR_print_errors_fp(stderr);
                exit(1);
            }
            LOG("{core} will use OpenSSL engine %s.\n", ENGINE_get_id(e));
            ENGINE_finish(e);
            ENGINE_free(e);
        }
    }
#endif
}

static void init_certs() {
    struct config_cert_file *cf, *tcf;
    struct sslctx* so;

    if (CONFIG->CERT_DEFAULT != NULL) {
        default_ctx = make_ctx(CONFIG->CERT_DEFAULT);
        if (default_ctx == NULL) {
            exit(1);
        }
#ifndef OPENSSL_NOTLSEXT
        insert_sni_names(default_ctx, &sni_names);
#endif /* OPENSSL_NO_TLSEXT */
    }

    // Go through the list of PEMs and make some SSL contexts for them. We also
    // keep track of the names associated with each cert so we can do SNI on
    // them later
    HASH_ITER(hh, CONFIG->CERT_FILES, cf, tcf) {
        if (find_ctx(cf->CERT_FILE) == NULL) {
            so = make_ctx(cf);
            if (so == NULL) {
                exit(1);
            }

            HASH_ADD_KEYPTR(hh, ssl_ctxs, cf->CERT_FILE, strlen(cf->CERT_FILE), so);
#ifndef OPENSSL_NO_TLSEXT
            insert_sni_names(so, &sni_names);
#endif /* OPENSSL_NO_TLSEXT */
        }
    }
}

static void prepare_proxy_line(struct sockaddr* ai_addr) {
    tcp_proxy_line[0] = 0;
    char tcp6_address_string[INET6_ADDRSTRLEN];

    memcpy(&header_proxy_v2.sig,"\r\n\r\n\0\r\nQUIT\n", 12);
    header_proxy_v2.ver_cmd = 0x21;
    header_proxy_v2.fam = ai_addr->sa_family == AF_INET ? 0x11 : 0x21;
    header_proxy_v2.len = ai_addr->sa_family == AF_INET ? 12 : 36;

    if (ai_addr->sa_family == AF_INET) {
        struct sockaddr_in* addr = (struct sockaddr_in*)ai_addr;
        size_t res = snprintf(tcp_proxy_line,
                sizeof(tcp_proxy_line),
                "PROXY %%s %%s %s %%hu %hu\r\n",
                inet_ntoa(addr->sin_addr),
                ntohs(addr->sin_port));

        memcpy(&frontend_addr.ipv4_addr.dst_addr, &addr->sin_addr, sizeof(struct in_addr));
        frontend_addr.ipv4_addr.dst_port = addr->sin_port;

        assert(res < sizeof(tcp_proxy_line));
    }
    else if (ai_addr->sa_family == AF_INET6 ) {
      struct sockaddr_in6* addr = (struct sockaddr_in6*)ai_addr;
      inet_ntop(AF_INET6,&(addr->sin6_addr),tcp6_address_string,INET6_ADDRSTRLEN);
      size_t res = snprintf(tcp_proxy_line,
                            sizeof(tcp_proxy_line),
                            "PROXY %%s %%s %s %%hu %hu\r\n",
                            tcp6_address_string,
                            ntohs(addr->sin6_port));

      memcpy(&frontend_addr.ipv6_addr.dst_addr,&addr->sin6_addr, sizeof(struct in6_addr));
      frontend_addr.ipv6_addr.dst_port = addr->sin6_port;

      assert(res < sizeof(tcp_proxy_line));
    }
    else {
        ERR("The --write-proxy mode is not implemented for this address family.\n");
        exit(1);
    }
}

/* Create the bound socket in the parent process */
static int create_main_socket(int index) {
    struct addrinfo *ai, hints;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;
    const int gai_err = getaddrinfo(CONFIG->FRONT[index].host, CONFIG->FRONT[index].port,
                                    &hints, &ai);
    if (gai_err != 0) {
        ERR("{getaddrinfo}: [%s]\n", gai_strerror(gai_err));
        exit(1);
    }

    int s = socket(ai->ai_family, SOCK_STREAM, IPPROTO_TCP);

    if (s == -1)
      fail("{socket: main}");

    int t = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &t, sizeof(int));
#ifdef SO_REUSEPORT
    setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &t, sizeof(int));
#endif
    setnonblocking(s);

    if (bind(s, ai->ai_addr, ai->ai_addrlen)) {
        fail("{bind-socket}");
    }

#ifndef NO_DEFER_ACCEPT
#if TCP_DEFER_ACCEPT
    int timeout = 1;
    setsockopt(s, IPPROTO_TCP, TCP_DEFER_ACCEPT, &timeout, sizeof(int) );
#endif /* TCP_DEFER_ACCEPT */
#endif

    prepare_proxy_line(ai->ai_addr);

    freeaddrinfo(ai);
    listen(s, CONFIG->BACKLOG);

    return s;
}

static struct frontend* create_frontend(int index) {
    struct frontend* fe;

    fe = calloc(1, sizeof(struct frontend));
    fe->pspec = strdup(CONFIG->FRONT[index].pspec);
    fe->sock = create_main_socket(index);
    fe->backend_index = index;

    return fe;
}

static void destroy_frontend(struct frontend* fe) {
    close(fe->sock);
    free(fe->pspec);
    free(fe);
}

/* Initiate a clear-text nonblocking connect() to the backend IP on behalf
 * of a newly connected upstream (encrypted) client*/
static int create_back_socket(const struct addrinfo* ai) {
    int s = socket(ai->ai_family, SOCK_STREAM, ai->ai_family == AF_INET ? IPPROTO_TCP : 0);

    if (s == -1)
      return -1;

	if (ai->ai_family == AF_INET) {
        int flag = 1;
        int ret = setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(flag));
        if (ret == -1) {
            perror("Couldn't setsockopt to backend (TCP_NODELAY)\n");
        }
    }

    setnonblocking(s);

    return s;
}

/* Only enable a libev ev_io event if the proxied connection still
 * has both up and down connected */
static void safe_enable_io(proxystate *ps, ev_io *w) {
    if (!ps->want_shutdown)
        ev_io_start(loop, w);
}

static void check_exit_state() {
    if (worker_state == WORKER_EXITING && n_conns == 0) {
        LOG("{core} Worker %d (gen: %d) in state EXITING is now exiting.\n", child_core, worker_generation);
        exit(0);
    }
}

/* Only enable a libev ev_io event if the proxied connection still
 * has both up and down connected */
static void shutdown_proxy(proxystate *ps, SHUTDOWN_REQUESTOR req) {
    if (ps->want_shutdown || req == SHUTDOWN_HARD) {
        ev_io_stop(loop, &ps->ev_w_ssl);
        ev_io_stop(loop, &ps->ev_r_ssl);
        ev_io_stop(loop, &ps->ev_w_handshake);
        ev_io_stop(loop, &ps->ev_r_handshake);
        ev_io_stop(loop, &ps->ev_w_connect);
        ev_io_stop(loop, &ps->ev_w_clear);
        ev_io_stop(loop, &ps->ev_r_clear);
        ev_io_stop(loop, &ps->ev_proxy);

        close(ps->fd_up);
        close(ps->fd_down);

        ERR_clear_error();

        SSL_set_shutdown(ps->ssl, SSL_SENT_SHUTDOWN);
        SSL_free(ps->ssl);

        bufferchain_destroy(&ps->bc_clear2ssl);
        bufferchain_destroy(&ps->bc_ssl2clear);
        free(ps);

        --n_conns;
        check_exit_state();
    }
    else {
        ps->want_shutdown = 1;
        if (req == SHUTDOWN_CLEAR && 0 == bufferchain_readable(&ps->bc_clear2ssl))
            shutdown_proxy(ps, SHUTDOWN_HARD);
        else if (req == SHUTDOWN_SSL && 0 == bufferchain_readable(&ps->bc_ssl2clear))
            shutdown_proxy(ps, SHUTDOWN_HARD);
    }
}

/* Handle various socket errors */
static void handle_socket_errno(proxystate *ps, int backend) {
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
        return;

    if (errno == ECONNRESET)
        ERR("{%s} Connection reset by peer\n", backend ? "backend" : "client");
    else if (errno == ETIMEDOUT)
        ERR("{%s} Connection to backend timed out\n", backend ? "backend" : "client");
    else if (errno == EPIPE)
        ERR("{%s} Broken pipe to backend (EPIPE)\n", backend ? "backend" : "client");
    else
        perror("{backend} [errno]");
    shutdown_proxy(ps, SHUTDOWN_CLEAR);
}
/* Start connect to backend */
static int start_connect(const struct addrinfo* ai, proxystate *ps) {
    int t = 1;
    t = connect(ps->fd_down, ai->ai_addr, ai->ai_addrlen);
    if (t == 0 || errno == EINPROGRESS || errno == EINTR) {
        ev_io_start(loop, &ps->ev_w_connect);
        return 0;
    }
    perror("{backend-connect}");
    shutdown_proxy(ps, SHUTDOWN_HARD);
    return -1;
}

/* Read some data from the backend when libev says data is available--
 * write it into the upstream buffer and make sure the write event is
 * enabled for the upstream socket */
static void clear_read(struct ev_loop *loop, ev_io *w, int revents) {
    (void) revents;
    int t;
    proxystate *ps = (proxystate *)w->data;
    if (ps->want_shutdown) {
        ev_io_stop(loop, &ps->ev_r_clear);
        return;
    }
    int fd = w->fd;
    int sz;
    void* buf = bufferchain_get_writeptr(&ps->bc_clear2ssl, &sz);
    t = recv(fd, buf, sz, 0);

    if (t > 0) {
        bufferchain_commit_write(&ps->bc_clear2ssl, t);
        if (bufferchain_readable(&ps->bc_clear2ssl) >= MAXIMUM_QUEUED_DATA)
            ev_io_stop(loop, &ps->ev_r_clear);
        if (ps->handshaked)
            safe_enable_io(ps, &ps->ev_w_ssl);
    }
    else if (t == 0) {
        LOG("{%s} Connection closed\n", fd == ps->fd_down ? "backend" : "client");
        shutdown_proxy(ps, SHUTDOWN_CLEAR);
    }
    else {
        assert(t == -1);
        handle_socket_errno(ps, fd == ps->fd_down ? 1 : 0);
    }
}
/* Write some data, previously received on the secure upstream socket,
 * out of the downstream buffer and onto the backend socket */
static void clear_write(struct ev_loop *loop, ev_io *w, int revents) {
    (void) revents;
    int t;
    proxystate *ps = (proxystate *)w->data;
    int fd = w->fd;

    int sz = bufferchain_readable(&ps->bc_ssl2clear);
    assert(sz != 0);

    const void* next = bufferchain_get_readptr(&ps->bc_ssl2clear);
    t = send(fd, next, sz, MSG_NOSIGNAL);

    if (t > 0) {
        bufferchain_commit_read(&ps->bc_ssl2clear, t);
        if (t == sz) {
            if (ps->handshaked)
                safe_enable_io(ps, &ps->ev_r_ssl);
            if (0 == bufferchain_readable(&ps->bc_ssl2clear)) {
                if (ps->want_shutdown) {
                    shutdown_proxy(ps, SHUTDOWN_HARD);
                    return; // dealloc'd
                }
                ev_io_stop(loop, &ps->ev_w_clear);
            }
        }
    }
    else {
        assert(t == -1);
        handle_socket_errno(ps, fd == ps->fd_down ? 1 : 0);
    }
}

static void start_handshake(proxystate *ps, int err);

/* Continue/complete the asynchronous connect() before starting data transmission
 * between front/backend */
static void handle_connect(struct ev_loop *loop, ev_io *w, int revents) {
    (void) revents;
    int t;
    proxystate *ps = (proxystate *)w->data;
    t = connect(ps->fd_down, backaddrs[ps->index]->ai_addr, backaddrs[ps->index]->ai_addrlen);
    if (!t || errno == EISCONN || !errno) {
        ev_io_stop(loop, &ps->ev_w_connect);

        if (!ps->clear_connected) {
            ps->clear_connected = 1;

            /* if incoming buffer is not full */
            if (bufferchain_readable(&ps->bc_clear2ssl) < MAXIMUM_QUEUED_DATA)
                safe_enable_io(ps, &ps->ev_r_clear);

            /* if outgoing buffer is not empty */
            if (0 != bufferchain_readable(&ps->bc_ssl2clear))
                // not safe.. we want to resume stream even during half-closed
                ev_io_start(loop, &ps->ev_w_clear);
        }
        else {
            /* Clear side already connected so connect is on secure side: perform handshake */
            start_handshake(ps, SSL_ERROR_WANT_WRITE);
        }
    }
    else if (errno == EINPROGRESS || errno == EINTR || errno == EALREADY) {
        /* do nothing, we'll get phoned home again... */
    }
    else {
        perror("{backend-connect}");
        shutdown_proxy(ps, SHUTDOWN_HARD);
    }
}

/* Upon receiving a signal from OpenSSL that a handshake is required, re-wire
 * the read/write events to hook up to the handshake handlers */
static void start_handshake(proxystate *ps, int err) {
    ev_io_stop(loop, &ps->ev_r_ssl);
    ev_io_stop(loop, &ps->ev_w_ssl);

    ps->handshaked = 0;

    if (err == SSL_ERROR_WANT_READ)
        ev_io_start(loop, &ps->ev_r_handshake);
    else if (err == SSL_ERROR_WANT_WRITE)
        ev_io_start(loop, &ps->ev_w_handshake);
}

/* After OpenSSL is done with a handshake, re-wire standard read/write handlers
 * for data transmission */
static void end_handshake(int index, proxystate *ps) {
    char tcp6_address_string[INET6_ADDRSTRLEN];
    size_t written = 0;
    ev_io_stop(loop, &ps->ev_r_handshake);
    ev_io_stop(loop, &ps->ev_w_handshake);

    /* Disable renegotiation (CVE-2009-3555) */
    if (ps->ssl->s3) {
        ps->ssl->s3->flags |= SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS;
    }
    ps->handshaked = 1;

    /* Check if clear side is connected */
    if (!ps->clear_connected) {

        if (CONFIG->WRITE_PROXY_LINE_V2) {

            assert(ps->remote_ip.ss_family == AF_INET ||
                   ps->remote_ip.ss_family == AF_INET6);


            bufferchain_write(&ps->bc_ssl2clear, &header_proxy_v2, sizeof(header_proxy_v2));
            bufferchain_write(&ps->bc_ssl2clear, &ps->proxy_addr, header_proxy_v2.len);
        }
        else if (CONFIG->WRITE_PROXY_LINE) {
            assert(ps->remote_ip.ss_family == AF_INET ||
                   ps->remote_ip.ss_family == AF_INET6);
            if(ps->remote_ip.ss_family == AF_INET) {
               char buffer[128];
               struct sockaddr_in* addr = (struct sockaddr_in*)&ps->remote_ip;
               written = snprintf(buffer,
                                  sizeof(buffer),
                                  tcp_proxy_line,
                                  "TCP4",
                                  inet_ntoa(addr->sin_addr),
                                  ntohs(addr->sin_port));
               bufferchain_write(&ps->bc_ssl2clear, buffer, written);
               }
               else if (ps->remote_ip.ss_family == AF_INET6) {
                        char buffer[128];
                        struct sockaddr_in6* addr = (struct sockaddr_in6*)&ps->remote_ip;
                        inet_ntop(AF_INET6,&(addr->sin6_addr),tcp6_address_string,INET6_ADDRSTRLEN);
                        written = snprintf(buffer,
                                  sizeof(buffer),
                                  tcp_proxy_line,
                                  "TCP6",
                                  tcp6_address_string,
                                  ntohs(addr->sin6_port));
                        bufferchain_write(&ps->bc_ssl2clear, buffer, written);
            }
        }
        else if (CONFIG->WRITE_IP_OCTET) {
            const unsigned char sock_family = (unsigned char) ps->remote_ip.ss_family;
            assert(ps->remote_ip.ss_family == AF_INET ||
                   ps->remote_ip.ss_family == AF_INET6);
            bufferchain_write(&ps->bc_ssl2clear, &sock_family, 1);
            if (ps->remote_ip.ss_family == AF_INET6) {
                bufferchain_write(&ps->bc_ssl2clear, &((struct sockaddr_in6 *) &ps->remote_ip)
                       ->sin6_addr.s6_addr, 16U);
            }
            else {
                bufferchain_write(&ps->bc_ssl2clear, &((struct sockaddr_in *) &ps->remote_ip)
                       ->sin_addr.s_addr, 4U);
            }
        }
        /* start connect now */
        if (0 != start_connect(backaddrs[index], ps)) {
            return;
        }
    }
    else {
        /* stud used in client mode, keep client session ) */
        if (!SSL_session_reused(ps->ssl)) {
            if (client_session)
                SSL_SESSION_free(client_session);
            client_session = SSL_get1_session(ps->ssl);
        }
    }

    /* if incoming buffer is not full */
    if (bufferchain_readable(&ps->bc_ssl2clear) < MAXIMUM_QUEUED_DATA)
        safe_enable_io(ps, &ps->ev_r_ssl);

    /* if outgoing buffer is not empty */
    if (0 != bufferchain_readable(&ps->bc_clear2ssl))
        // not safe.. we want to resume stream even during half-closed
        ev_io_start(loop, &ps->ev_w_ssl);
}

static void client_proxy_proxy(struct ev_loop *loop, ev_io *w, int revents) {
    (void) revents;
    int t;
    char *proxy = tcp_proxy_line, *end = tcp_proxy_line + sizeof(tcp_proxy_line);
    proxystate *ps = (proxystate *)w->data;
    BIO *b = SSL_get_rbio(ps->ssl);

    // Copy characters one-by-one until we hit a \n or an error
    while (proxy != end && (t = BIO_read(b, proxy, 1)) == 1) {
        if (*proxy++ == '\n') break;
    }

    if (proxy == end) {
        LOG("{client} Unexpectedly long PROXY line. Perhaps a malformed request?");
        shutdown_proxy(ps, SHUTDOWN_SSL);
    }
    else if (t == 1) {
        if (bufferchain_readable(&ps->bc_ssl2clear) >= MAXIMUM_QUEUED_DATA) {
            LOG("{client} Error writing PROXY line");
            shutdown_proxy(ps, SHUTDOWN_SSL);
            return;
        }

        bufferchain_write(&ps->bc_ssl2clear, tcp_proxy_line, proxy - tcp_proxy_line);

        // Finished reading the PROXY header
        if (*(proxy - 1) == '\n') {
            ev_io_stop(loop, &ps->ev_proxy);

            // Start the real handshake
            start_handshake(ps, SSL_ERROR_WANT_READ);
        }
    }
    else if (!BIO_should_retry(b)) {
        LOG("{client} Unexpected error reading PROXY line");
        shutdown_proxy(ps, SHUTDOWN_SSL);
    }
}

/* The libev I/O handler during the OpenSSL handshake phase.  Basically, just
 * let OpenSSL do what it likes with the socket and obey its requests for reads
 * or writes */
static void client_handshake(struct ev_loop *loop, ev_io *w, int revents) {
    (void) revents;
    int t;
    proxystate *ps = (proxystate *)w->data;

    t = SSL_do_handshake(ps->ssl);
    if (t == 1) {
        end_handshake(ps->index, ps);
    }
    else {
        int err = SSL_get_error(ps->ssl, t);
        if (err == SSL_ERROR_WANT_READ) {
            ev_io_stop(loop, &ps->ev_w_handshake);
            ev_io_start(loop, &ps->ev_r_handshake);
        }
        else if (err == SSL_ERROR_WANT_WRITE) {
            ev_io_stop(loop, &ps->ev_r_handshake);
            ev_io_start(loop, &ps->ev_w_handshake);
        }
        else if (err == SSL_ERROR_ZERO_RETURN) {
            LOG("{%s} Connection closed (in handshake)\n", w->fd == ps->fd_up ? "client" : "backend");
            shutdown_proxy(ps, SHUTDOWN_SSL);
        }
        else {
            LOG("{%s} Unexpected SSL error (in handshake): %d\n", w->fd == ps->fd_up ? "client" : "backend", err);
            shutdown_proxy(ps, SHUTDOWN_SSL);
        }
    }
}

/* Handle a socket error condition passed to us from OpenSSL */
static void handle_fatal_ssl_error(proxystate *ps, int err, int backend) {
    BIO* bio;
    char remote_addr_str[INET6_ADDRSTRLEN+1+5+1];
    int port;
    char *bioErr;
    int bioErrLen;

    switch (ps->remote_ip.ss_family) {
    case AF_INET:
        inet_ntop(AF_INET, &((const struct sockaddr_in*)&ps->remote_ip)->sin_addr, remote_addr_str, sizeof(remote_addr_str));
        port  = htons(ps->proxy_addr.ipv4_addr.src_port);
        break;

    case AF_INET6:
        inet_ntop(AF_INET6, &((const struct sockaddr_in6*)&ps->remote_ip)->sin6_addr, remote_addr_str, sizeof(remote_addr_str));
        port = htons(ps->proxy_addr.ipv6_addr.src_port);
        break;

    default:
        strcpy(remote_addr_str, "unknown");
        port = 0;
        break;
    }

    sprintf(remote_addr_str + strlen(remote_addr_str), ":%d", port);

    bio = BIO_new(BIO_s_mem());
    ERR_print_errors(bio);

    bioErr = "unknown";
    bioErrLen = (int)BIO_get_mem_data(bio, &bioErr);

    if (err == SSL_ERROR_ZERO_RETURN)
        LOG("{%s} [%s] Connection closed (in data)\n", backend ? "backend" : "client", remote_addr_str);
    else if (err == SSL_ERROR_SYSCALL)
        if (errno == 0)
            LOG("{%s} [%s] Connection closed (in data): %.*s\n", backend ? "backend" : "client", remote_addr_str, bioErrLen, bioErr);
        else
            ERR("{%s} [%s] %s [errno] %.*s\n", backend ? "backend" : "client", remote_addr_str, strerror(errno), bioErrLen, bioErr);
    else
        ERR("{%s} [%s] Unexpected SSL_read error: %d: %.*s\n", backend ? "backend" : "client", remote_addr_str, err, bioErrLen, bioErr);

    BIO_free(bio);
    shutdown_proxy(ps, SHUTDOWN_SSL);
}

/* Read some data from the upstream secure socket via OpenSSL,
 * and buffer anything we get for writing to the backend */
static void ssl_read(struct ev_loop *loop, ev_io *w, int revents) {
    (void) revents;
    int sz;
    int t;
    proxystate *ps = (proxystate *)w->data;
    if (ps->want_shutdown) {
        ev_io_stop(loop, &ps->ev_r_ssl);
        return;
    }
    void * buf = bufferchain_get_writeptr(&ps->bc_ssl2clear, &sz);
    t = SSL_read(ps->ssl, buf, sz);

    if (SSL_pending(ps->ssl))
        ev_feed_event(loop, w, EV_READ);

    /* Fix CVE-2009-3555. Disable reneg if started by client. */
    if (ps->renegotiation) {
        shutdown_proxy(ps, SHUTDOWN_SSL);
        return;
    }

    if (t > 0) {
        bufferchain_commit_write(&ps->bc_ssl2clear, t);
        if (bufferchain_readable(&ps->bc_ssl2clear) >= MAXIMUM_QUEUED_DATA) {
            ev_io_stop(loop, &ps->ev_r_ssl);
        }
        if (ps->clear_connected) {
            safe_enable_io(ps, &ps->ev_w_clear);
        }
    }
    else {
        int err = SSL_get_error(ps->ssl, t);
        if (err == SSL_ERROR_WANT_WRITE) {
            start_handshake(ps, err);
        }
        else if (err == SSL_ERROR_WANT_READ) { } /* incomplete SSL data */
        else
            handle_fatal_ssl_error(ps, err, w->fd == ps->fd_up ? 0 : 1);
    }
}

/* Write some previously-buffered backend data upstream on the
 * secure socket using OpenSSL */
static void ssl_write(struct ev_loop *loop, ev_io *w, int revents) {
    (void) revents;
    int t;
    proxystate *ps = (proxystate *)w->data;

    int sz = bufferchain_readable(&ps->bc_clear2ssl);
    assert(0 != sz);

    void* next = bufferchain_get_readptr(&ps->bc_clear2ssl);
    t = SSL_write(ps->ssl, next, sz);
    if (t > 0) {
        bufferchain_commit_read(&ps->bc_clear2ssl, t);
        if (t == sz) {
            if (ps->clear_connected)
                safe_enable_io(ps, &ps->ev_r_clear); // can be re-enabled b/c we've popped
            if (0 == bufferchain_readable(&ps->bc_clear2ssl)) {
                if (ps->want_shutdown) {
                    shutdown_proxy(ps, SHUTDOWN_HARD);
                    return;
                }
                ev_io_stop(loop, &ps->ev_w_ssl);
            }
        }
    }
    else {
        int err = SSL_get_error(ps->ssl, t);
        if (err == SSL_ERROR_WANT_READ) {
            start_handshake(ps, err);
        }
        else if (err == SSL_ERROR_WANT_WRITE) {} /* incomplete SSL data */
        else
            handle_fatal_ssl_error(ps, err,  w->fd == ps->fd_up ? 0 : 1);
    }
}

/* libev read handler for the bound socket.  Socket is accepted,
 * the proxystate is allocated and initalized, and we're off the races
 * connecting to the backend */
static void handle_accept(struct ev_loop *loop, ev_io *w, int revents) {
    (void) revents;
    (void) loop;
    struct frontend *fe = (struct frontend*)w->data;

    struct sockaddr_storage addr;
    socklen_t sl = sizeof(addr);
    int client = accept(w->fd, (struct sockaddr *) &addr, &sl);
    if (client == -1) {
        switch (errno) {
        case EMFILE:
            ERR("{client} accept() failed; too many open files for this process\n");
            break;

        case ENFILE:
            ERR("{client} accept() failed; too many open files for this system\n");
            break;

        default:
            assert(errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN);
            break;
        }
        return;
    }

    struct sockaddr_storage peeraddr;
    if (-1 == getsockname(client, (struct sockaddr *)&peeraddr, &sl))
    {
        perror("Couldn't get local address on client socket\n");
    }

    int flag = 1;
    int ret = setsockopt(client, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(flag) );
    if (ret == -1) {
      perror("Couldn't setsockopt on client (TCP_NODELAY)\n");
    }
#ifdef TCP_CWND
    int cwnd = 10;
    ret = setsockopt(client, IPPROTO_TCP, TCP_CWND, &cwnd, sizeof(cwnd));
    if (ret == -1) {
      perror("Couldn't setsockopt on client (TCP_CWND)\n");
    }
#endif

    setnonblocking(client);
    settcpkeepalive(client);

    int back = create_back_socket(backaddrs[fe->backend_index]);

    if (back == -1) {
        close(client);
        perror("{backend-socket}");
        return;
    }

    SSL *ssl = SSL_new(default_ctx->ctx);
    long mode = SSL_MODE_ENABLE_PARTIAL_WRITE;
#ifdef SSL_MODE_RELEASE_BUFFERS
    mode |= SSL_MODE_RELEASE_BUFFERS;
#endif
    SSL_set_mode(ssl, mode);
    SSL_set_accept_state(ssl);
    SSL_set_fd(ssl, client);

    proxystate *ps = (proxystate *)malloc(sizeof(proxystate));

    ps->index = fe->backend_index;
    ps->fd_up = client;
    ps->fd_down = back;
    ps->ssl = ssl;
    ps->want_shutdown = 0;
    ps->clear_connected = 0;
    ps->handshaked = 0;
    ps->renegotiation = 0;
    ps->remote_ip = addr;
    bufferchain_init(&ps->bc_clear2ssl);
    bufferchain_init(&ps->bc_ssl2clear);

    /* set up events */
    ev_io_init(&ps->ev_r_ssl, ssl_read, client, EV_READ);
    ev_io_init(&ps->ev_w_ssl, ssl_write, client, EV_WRITE);

    ev_io_init(&ps->ev_r_handshake, client_handshake, client, EV_READ);
    ev_io_init(&ps->ev_w_handshake, client_handshake, client, EV_WRITE);

    ev_io_init(&ps->ev_proxy, client_proxy_proxy, client, EV_READ);

    ev_io_init(&ps->ev_w_connect, handle_connect, back, EV_WRITE);

    ev_io_init(&ps->ev_w_clear, clear_write, back, EV_WRITE);
    ev_io_init(&ps->ev_r_clear, clear_read, back, EV_READ);

    ps->ev_r_ssl.data = ps;
    ps->ev_w_ssl.data = ps;
    ps->ev_r_clear.data = ps;
    ps->ev_w_clear.data = ps;
    ps->ev_proxy.data = ps;
    ps->ev_w_connect.data = ps;
    ps->ev_r_handshake.data = ps;
    ps->ev_w_handshake.data = ps;

    if(addr.ss_family == AF_INET) {
        struct sockaddr_in* paddr = (struct sockaddr_in*)&peeraddr;
        memcpy(&ps->proxy_addr.ipv4_addr.dst_addr, &paddr->sin_addr, sizeof(struct in_addr));
        ps->proxy_addr.ipv4_addr.dst_port =  paddr->sin_port;
        struct sockaddr_in* saddr = (struct sockaddr_in*)&addr;
        memcpy(&ps->proxy_addr.ipv4_addr.src_addr, &saddr->sin_addr, sizeof(struct in_addr));
        ps->proxy_addr.ipv4_addr.src_port = saddr->sin_port;
    } else if(addr.ss_family == AF_INET6) {
        struct sockaddr_in6* paddr = (struct sockaddr_in6*)&paddr;
        memcpy(&ps->proxy_addr.ipv6_addr.dst_addr, &paddr->sin6_addr, sizeof(struct in6_addr));
        ps->proxy_addr.ipv6_addr.dst_port = paddr->sin6_port;
        struct sockaddr_in6* saddr = (struct sockaddr_in6*)&addr;
        memcpy(&ps->proxy_addr.ipv6_addr.src_addr, &saddr->sin6_addr, sizeof(struct in6_addr));
        ps->proxy_addr.ipv6_addr.src_port = saddr->sin6_port;
    }


    /* Link back proxystate to SSL state */
    SSL_set_app_data(ssl, ps);

    ++n_conns;

    if (CONFIG->PROXY_PROXY_LINE) {
        ev_io_start(loop, &ps->ev_proxy);
    }
    else {
        start_handshake(ps, SSL_ERROR_WANT_READ); /* for client-first handshake */
    }
}


static void check_ppid(struct ev_loop *loop, ev_timer *w, int revents) {
    struct frontend *fe;

    (void) revents;
    pid_t ppid = getppid();
    if (ppid != master_pid) {
        ERR("{core} Process %d detected parent death, closing listener socket.\n", child_core);
        ev_timer_stop(loop, w);
        TAILQ_FOREACH(fe, &frontends, list) {
            ev_io_stop(loop, &fe->listener);
            close(fe->sock);
        }
    }
}

static void handle_mgmt_rd(struct ev_loop *loop, ev_io *w, int revents) {
    ssize_t r;
    unsigned current_generation;
    struct frontend *fe;

    (void)revents;

    /* Read parent's current generation. */
    r = read(w->fd, &current_generation, sizeof(current_generation));
    if (r == -1) {
        if (errno == EWOULDBLOCK || errno == EAGAIN) {
            return;
        }

        /* rely on parent process to restart us */
        ERR("{mgmt} Error in read process. Restarting.");
        exit(1);
    } else if (r == 0) {
        /* parent died */
        exit(1);
    }

    if (worker_generation != current_generation) {
        /* process is being retired by the parent */
        worker_state = WORKER_EXITING;

        /* stop accepting new connections */
        TAILQ_FOREACH(fe, &frontends, list) {
            ev_io_stop(loop, &fe->listener);
            close(fe->sock);
        }

        check_exit_state();
    }

    LOG("{mgmt} Worker %d (gen: %d): State %s\n", child_core, worker_generation,
        (worker_state == WORKER_EXITING) ? "EXITING" : "ACTIVE");
}

static void handle_clear_accept(struct ev_loop *loop, ev_io *w, int revents) {
    (void) revents;
    (void) loop;
    struct frontend *fe = (struct frontend*)w->data;
    struct sockaddr_storage addr;
    socklen_t sl = sizeof(addr);
    int client = accept(w->fd, (struct sockaddr *) &addr, &sl);
    if (client == -1) {
        switch (errno) {
        case EMFILE:
            ERR("{client} accept() failed; too many open files for this process\n");
            break;

        case ENFILE:
            ERR("{client} accept() failed; too many open files for this system\n");
            break;

        default:
            assert(errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN);
            break;
        }
        return;
    }

    int flag = 1;
    int ret = setsockopt(client, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(flag) );
    if (ret == -1) {
      perror("Couldn't setsockopt on client (TCP_NODELAY)\n");
    }
#ifdef TCP_CWND
    int cwnd = 10;
    ret = setsockopt(client, IPPROTO_TCP, TCP_CWND, &cwnd, sizeof(cwnd));
    if (ret == -1) {
      perror("Couldn't setsockopt on client (TCP_CWND)\n");
    }
#endif

    setnonblocking(client);
    settcpkeepalive(client);

    int back = create_back_socket(backaddrs[fe->backend_index]);

    if (back == -1) {
        close(client);
        perror("{backend-socket}");
        return;
    }

    SSL *ssl = SSL_new(default_ctx->ctx);
    long mode = SSL_MODE_ENABLE_PARTIAL_WRITE;
#ifdef SSL_MODE_RELEASE_BUFFERS
    mode |= SSL_MODE_RELEASE_BUFFERS;
#endif
    SSL_set_mode(ssl, mode);
    SSL_set_connect_state(ssl);
    SSL_set_fd(ssl, back);
    if (client_session)
        SSL_set_session(ssl, client_session);

    proxystate *ps = (proxystate *)malloc(sizeof(proxystate));

    ps->fd_up = client;
    ps->fd_down = back;
    ps->ssl = ssl;
    ps->want_shutdown = 0;
    ps->clear_connected = 1;
    ps->handshaked = 0;
    ps->renegotiation = 0;
    ps->remote_ip = addr;
    bufferchain_init(&ps->bc_clear2ssl);
    bufferchain_init(&ps->bc_ssl2clear);

    /* set up events */
    ev_io_init(&ps->ev_r_clear, clear_read, client, EV_READ);
    ev_io_init(&ps->ev_w_clear, clear_write, client, EV_WRITE);

    ev_io_init(&ps->ev_w_connect, handle_connect, back, EV_WRITE);

    ev_io_init(&ps->ev_r_handshake, client_handshake, back, EV_READ);
    ev_io_init(&ps->ev_w_handshake, client_handshake, back, EV_WRITE);


    ev_io_init(&ps->ev_w_ssl, ssl_write, back, EV_WRITE);
    ev_io_init(&ps->ev_r_ssl, ssl_read, back, EV_READ);

    ps->ev_r_ssl.data = ps;
    ps->ev_w_ssl.data = ps;
    ps->ev_r_clear.data = ps;
    ps->ev_w_clear.data = ps;
    ps->ev_w_connect.data = ps;
    ps->ev_r_handshake.data = ps;
    ps->ev_w_handshake.data = ps;

    /* Link back proxystate to SSL state */
    SSL_set_app_data(ssl, ps);

    ++n_conns;

    ev_io_start(loop, &ps->ev_r_clear);
    start_connect(backaddrs[fe->backend_index], ps); /* start connect */
}

/* Set up the child (worker) process including libev event loop, read event
 * on the bound socket, etc */
static void handle_connections(int mgmt_fd) {
    struct frontend *fe;

    worker_state = WORKER_ACTIVE;
    LOG("{core} Process %d online\n", child_core);

    /* child cannot create new children... */
    create_workers = 0;

#if defined(CPU_ZERO) && defined(CPU_SET)
    cpu_set_t cpus;

    CPU_ZERO(&cpus);
    CPU_SET(child_core, &cpus);

    int res = sched_setaffinity(0, sizeof(cpus), &cpus);
    if (!res)
        LOG("{core} Successfully attached to CPU #%d\n", child_core);
    else
        ERR("{core-warning} Unable to attach to CPU #%d; do you have that many cores?\n", child_core);
#endif

    loop = ev_default_loop(EVFLAG_AUTO);

    ev_timer timer_ppid_check;
    ev_timer_init(&timer_ppid_check, check_ppid, 1.0, 1.0);
    ev_timer_start(loop, &timer_ppid_check);

    setnonblocking(mgmt_fd);
    ev_io_init(&mgmt_rd, handle_mgmt_rd, mgmt_fd, EV_READ);
    ev_io_start(loop, &mgmt_rd);

    TAILQ_FOREACH(fe, &frontends, list) {
        ev_io_init(&fe->listener, (CONFIG->PMODE == SSL_CLIENT) ? handle_clear_accept : handle_accept, fe->sock, EV_READ);
        fe->listener.data = fe;
        ev_io_start(loop, &fe->listener);
    }

    ev_loop(loop, 0);
    ERR("{core} Child %d (gen: %d) exiting.\n", child_core, worker_generation);
    exit(1);
}

void change_root() {
    if (chroot(CONFIG->CHROOT) == -1)
        fail("chroot");
    if (chdir("/"))
        fail("chdir");
}

void drop_privileges() {
    if (setgid(CONFIG->GID))
        fail("setgid failed");
    if (setuid(CONFIG->UID))
        fail("setuid failed");
}


void init_globals() {
    /* backaddr */

    TAILQ_INIT(&frontends);
    TAILQ_INIT(&worker_procs);

    backaddrs = (struct addrinfo **)malloc(CONFIG->NUM_BACK*sizeof(struct addrinfo*));
    for (int ii = 0; ii < CONFIG->NUM_BACK; ++ii) {
        struct addrinfo hints;
        memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = 0;

        if (CONFIG->BACK[ii].mode == CONN_PIPE) {
            struct addrinfo* backaddr = (struct addrinfo *)malloc(sizeof(struct addrinfo));
            if (backaddr == 0) {
                ERR("{malloc}: [%s]", "allocate sockaddr_un failed");
                exit(1);
            }

            memset(backaddr, 0, sizeof(struct addrinfo));

            backaddr->ai_socktype = SOCK_STREAM;
            backaddr->ai_addrlen = sizeof(sa_family_t) + strlen(CONFIG->BACK[ii].host) + 1;
            backaddr->ai_addr = (struct sockaddr*)malloc(backaddr->ai_addrlen);
            struct sockaddr_un* addr = (struct sockaddr_un*)backaddr->ai_addr;
            backaddr->ai_family = addr->sun_family = AF_UNIX;

            memcpy(addr->sun_path, CONFIG->BACK[ii].host, backaddr->ai_addrlen - sizeof(sa_family_t));

            if (addr->sun_path[0] == '@') {
                addr->sun_path[0] = '\0';
                --backaddr->ai_addrlen;
            }

            backaddrs[ii] = backaddr;
        }
        else {

            const int gai_err = getaddrinfo(CONFIG->BACK[ii].host, CONFIG->BACK[ii].port,
                                            &hints, &backaddrs[ii]);
            if (gai_err != 0) {
                ERR("{getaddrinfo}: [%s]", gai_strerror(gai_err));
                exit(1);
            }
        }
    }

#ifdef USE_SHARED_CACHE
    if (CONFIG->SHARED_CACHE) {
        /* cache update peers addresses */
        shcupd_peer_opt *spo = CONFIG->SHCUPD_PEERS;
        struct addrinfo **pai = shcupd_peers;

        while (spo->ip) {
            memset(&hints, 0, sizeof hints);
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = SOCK_DGRAM;
            hints.ai_flags = 0;
            const int gai_err = getaddrinfo(spo->ip,
                                spo->port ? spo->port : CONFIG->SHCUPD_PORT, &hints, pai);
            if (gai_err != 0) {
                ERR("{getaddrinfo}: [%s]", gai_strerror(gai_err));
                exit(1);
            }
            spo++;
            pai++;
        }
    }
#endif

    if (CONFIG->SYSLOG)
        openlog("stud", LOG_CONS | LOG_PID | LOG_NDELAY, CONFIG->SYSLOG_FACILITY);

    bufferchain_startup();
}

/* Forks COUNT children starting with START_INDEX.
 * Each child's index is stored in child_num and its pid is stored in child_pids[child_num]
 * so the parent can manage it later. */
void start_children(int start_index, int count) {
    struct worker_proc *worker;
    int pfd[2];

    /* don't do anything if we're not allowed to create new children */
    if (!create_workers) return;

    for (child_core = start_index; child_core < start_index + count; child_core++) {
        worker = calloc(1, sizeof(struct worker_proc));
        if (pipe(pfd) != 0) {
            ERR("{core} pipe() failed: %s\n", strerror(errno));
            exit(1);
        }
        worker->pfd = pfd[1];
        worker->pid = fork();
        worker->generation = worker_generation;
        worker->core = child_core;
        if (worker->pid == -1) {
            ERR("{core} fork() failed: %s; Goodbye cruel world!\n", strerror(errno));
            exit(1);
        }
        else if (worker->pid == 0) { /* child */
            close(pfd[1]);
            free(worker);
            handle_connections(pfd[0]);
            exit(0);
        }
        else { /* parent. Track new child. */
            close(pfd[0]);
            TAILQ_INSERT_TAIL(&worker_procs, worker, list);
        }
    }
}

/* Forks a new child to replace the old, dead, one with the given PID.*/
void replace_child_with_pid(pid_t pid) {
    struct worker_proc *worker;

    /* find old child's slot and put a new child there */
    TAILQ_FOREACH(worker, &worker_procs, list) {
        if (worker->pid == pid) {
            TAILQ_REMOVE(&worker_procs, worker, list);
            /* Only replace if it matched the current generation */
            if (worker->generation == worker_generation) {
                start_children(worker->core, 1);
            }
            free(worker);
            return;
        }
    }

    ERR("Cannot find index for child pid %d", pid);
}

/* Manage status changes in child processes */
static void do_wait() {

    struct worker_proc *worker, *tworker;
    int status;
    int pid;

#define WAIT_PID(p, action) do { \
    pid = waitpid(p, &status , WNOHANG); \
    if (pid == 0) { \
        /* child has not exited */ \
        break; \
    } \
    else if (pid == -1) { \
        if (errno == EINTR) \
            ERR("{core} Interrupter waitpid\n"); \
        else \
            ERR("waitpid"); \
    } else { \
        if (WIFEXITED(status)) { \
            LOG("{core} Child %d exited with status %d.\n", pid, WEXITSTATUS(status)); \
            action; \
        } else if (WIFSIGNALED(status)) { \
            LOG("{core} Child %d was terminated by signal %d.\n", pid, WTERMSIG(status)); \
            action; \
        } \
    } \
    } while (0)

    TAILQ_FOREACH_SAFE(worker, &worker_procs, list, tworker) {
        WAIT_PID(worker->pid, replace_child_with_pid(pid));
    }

}

static void sigh_child(int signum) {
    (void)signum;
    ++n_sigchld;
}

static void sigh_hup(int signum) {
    (void)signum;
    ++n_sighup;
}

static void sigh_terminate (int __attribute__ ((unused)) signo) {
    struct worker_proc* worker;

    /* don't create any more children */
    create_workers = 0;

    /* are we the master? */
    if (getpid() == master_pid) {
        LOG("{core} Received signal %d, shutting down.\n", signo);

        /* kill all children */
        TAILQ_FOREACH(worker, &worker_procs, list) {
            if (worker->pid > 1 && kill(worker->pid, SIGTERM) != 0) {
                ERR("{core} Unable to send SIGTERM to worker pid %d: %s\n", worker->pid, strerror(errno));
            }
        }
        /* LOG("Shutdown complete.\n"); */
    }

    /* this is it, we're done... */
    exit(0);
}

void init_signals() {
    struct sigaction act;

    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    act.sa_handler = SIG_IGN;

    /* Avoid getting PIPE signal when writing to a closed file descriptor */
    if (sigaction(SIGPIPE, &act, NULL) < 0)
        fail("sigaction - sigpipe");

    /* We don't care if someone stops and starts a child process with kill (1) */
    act.sa_flags = SA_NOCLDSTOP;
    act.sa_handler = sigh_child;

    /* We do care when child processes change status */
    if (sigaction(SIGCHLD, &act, NULL) < 0)
        fail("sigaction - sigchld");

    /* catch INT and TERM signals */
    act.sa_flags = 0;
    act.sa_handler = sigh_terminate;
    if (sigaction(SIGINT, &act, NULL) < 0) {
        ERR("Unable to register SIGINT signal handler: %s\n", strerror(errno));
        exit(1);
    }
    if (sigaction(SIGTERM, &act, NULL) < 0) {
        ERR("Unable to register SIGTERM signal handler: %s\n", strerror(errno));
        exit(1);
    }

    act.sa_flags = 0;
    act.sa_handler = sigh_hup;
    if (sigaction(SIGHUP, &act, NULL) < 0) {
        ERR("Unable to register SIGHUP signal hander: %s\n", strerror(errno));
        exit(1);
    }
}

void daemonize () {
    /* go to root directory */
    if (chdir("/") != 0) {
        ERR("Unable change directory to /: %s\n", strerror(errno));
        exit(1);
    }

    /* let's make some children, baby :) */
    pid_t pid = fork();
    if (pid < 0) {
        ERR("Unable to daemonize: fork failed: %s\n", strerror(errno));
        exit(1);
    }

    /* am i the parent? */
    if (pid != 0) {
        printf("{core} Daemonized as pid %d.\n", pid);
        exit(0);
    }

    /* close standard streams */
    fclose(stdin);
    fclose(stdout);
    fclose(stderr);

    FILE* nulldev = fopen(NULL_DEV, "rw");
    if (nulldev == NULL) {
        ERR("Unable to open %s: %s\n", NULL_DEV, strerror(errno));
        exit(1);
    }

    /* reopen standard streams to null device */
    if (-1 == dup2(fileno(nulldev), STDIN_FILENO)) {
        ERR("Unable to reopen stdin to %s: %s\n", NULL_DEV, strerror(errno));
        exit(1);
    }
    if (-1 == dup2(fileno(nulldev), STDOUT_FILENO)) {
        ERR("Unable to reopen stdout to %s: %s\n", NULL_DEV, strerror(errno));
        exit(1);
    }
    if (-1 == dup2(fileno(nulldev), STDERR_FILENO)) {
        ERR("Unable to reopen stderr to %s: %s\n", NULL_DEV, strerror(errno));
        exit(1);
    }

    fclose(nulldev);

    /* this is child, the new master */
    pid_t s = setsid();
    if (s < 0) {
        ERR("Unable to create new session, setsid(2) failed: %s :: %d\n", strerror(errno), s);
        exit(1);
    }

    LOG("Successfully daemonized as pid %d.\n", getpid());
}

void openssl_check_version() {
    /* detect OpenSSL version in runtime */
    openssl_version = SSLeay();

    /* check if we're running the same openssl that we were */
    /* compiled with */
    if ((openssl_version ^ OPENSSL_VERSION_NUMBER) & ~0xff0L) {
        ERR(
            "WARNING: {core} OpenSSL version mismatch; stud was compiled with %lx, now using %lx.\n",
            (unsigned long int) OPENSSL_VERSION_NUMBER,
            (unsigned long int) openssl_version
        );
        /* now what? exit now? */
        /* exit(1); */
    }

    LOG("{core} Using OpenSSL version %lx.\n", (unsigned long int) openssl_version);
}

static struct txn_obj *make_txn_obj(enum txn_type type, enum txn_handling handling, void *ctx0, void *ctx1, txn_rollback_f *rollback, txn_commit_f *commit) {
    struct txn_obj *o;

    o = calloc(1, sizeof(*o));
    o->type = type;
    o->handling = handling;
    o->ctx[0] = ctx0;
    o->ctx[1] = ctx1;
    o->rollback = rollback;
    o->commit = commit;

    return o;
}

static void frontend_rollback(struct txn_obj *o) {
    struct frontend *fe = o->ctx[0];

    if (o->handling == TXN_NEW) {
        destroy_frontend(fe);
    }
}

static void frontend_commit(struct txn_obj *o) {
    struct frontend *fe = o->ctx[0];

    switch (o->handling) {
        case TXN_NEW:
            TAILQ_INSERT_TAIL(&frontends, fe, list);
            break;

        case TXN_DROP:
            TAILQ_REMOVE(&frontends, fe, list);
            destroy_frontend(fe);
            break;

        case TXN_KEEP:
            break; // noop
    }
}

static int frontend_query(stud_config *cfg, struct txn_obj_head *txn_objs) {
    struct frontend *fe;
    struct txn_obj *o;
    int *mark;

    mark = calloc(cfg->NUM_FRONT, sizeof(int));

    TAILQ_FOREACH(fe, &frontends, list) {
        int found = 0;
        for (int ii = 0; ii < cfg->NUM_FRONT; ++ii) {
            if (strcmp(cfg->FRONT[ii].pspec, fe->pspec) == 0) {
                mark[ii] = 1;
                found = 1;
                break;
            }
        }

        if (found) {
            o = make_txn_obj(TXN_FRONTEND, TXN_KEEP, fe, NULL, frontend_rollback, frontend_commit);
        } else {
            o = make_txn_obj(TXN_FRONTEND, TXN_DROP, fe, NULL, frontend_rollback, frontend_commit);
        }

        TAILQ_INSERT_TAIL(txn_objs, o, list);
    }

    for (int ii = 0; ii < cfg->NUM_FRONT; ++ii) {
        if (!mark[ii]) {
            fe = create_frontend(ii);
            if (fe == NULL) {
                return -1;
            }

            o = make_txn_obj(TXN_FRONTEND, TXN_NEW, fe, NULL, frontend_rollback, frontend_commit);
            TAILQ_INSERT_TAIL(txn_objs, o, list);
        }
    }

    free(mark);

    return 0;
}

static void cert_rollback(struct txn_obj *o) {
    struct sslctx *sc = o->ctx[0];

    if (o->handling == TXN_NEW) {
        sctx_free(sc, NULL);
    }
}

static void cert_commit(struct txn_obj *o) {
    struct sslctx *sc = o->ctx[0];
    struct sslctx **ctxs;
    struct sni_name **sn_tab;

    sn_tab = &sni_names;
    ctxs = &ssl_ctxs;


    switch (o->handling) {
        case TXN_NEW:
            HASH_ADD_KEYPTR(hh, *ctxs, sc->filename, strlen(sc->filename), sc);
            insert_sni_names(sc, sn_tab);
            break;

        case TXN_KEEP:
            ERR("UNREACHABLE KEEP OF CERT");
            abort();
            break;

        case TXN_DROP:
            HASH_DEL(*ctxs, sc);
            sctx_free(sc, sn_tab);
            break;
    }
}

static void dcert_rollback(struct txn_obj *o) {
    cert_rollback(o);
}

static void dcert_commit(struct txn_obj *o) {
    struct sslctx *sc = o->ctx[0];

    switch (o->handling) {
        case TXN_NEW:
            sctx_free(default_ctx, &sni_names);
            default_ctx = sc;
            insert_sni_names(sc, &sni_names);
            break;

        case TXN_KEEP:
            // fallthrough
        case TXN_DROP:
            ERR("UNREACHABLE DROP OF DEFAULT CERT");
            abort();
            break;
    }
}

static int cert_query(stud_config *cfg, struct txn_obj_head *txn_objs) {

    struct config_cert_file *cf, *tcf;
    struct sslctx *sc, *tsc;
    struct txn_obj *o;

    // drop certs no longer in the config
    HASH_ITER(hh, ssl_ctxs, sc, tsc) {
        HASH_FIND_STR(cfg->CERT_FILES, sc->filename, cf);
        if (cf != NULL && cf->mtim <= sc->mtim) {
            cf->mark = 1;
        } else {
            o = make_txn_obj(TXN_CERT, TXN_DROP, sc, NULL, cert_rollback, cert_commit);
            TAILQ_INSERT_TAIL(txn_objs, o, list);
        }
    }

    // handle default cert
    if (cfg->CERT_DEFAULT != NULL) {
        cf = cfg->CERT_DEFAULT;
        if (strcmp(default_ctx->filename, cf->CERT_FILE) != 0 || cf->mtim > default_ctx->mtim) {
            sc = make_ctx(cf);
            if (sc == NULL) {
                return -1;
            }

            o = make_txn_obj(TXN_CERT, TXN_NEW, sc, NULL, dcert_rollback, dcert_commit);
            TAILQ_INSERT_TAIL(txn_objs, o, list);
        }
    }

    // add new certs
    HASH_ITER(hh, cfg->CERT_FILES, cf, tcf) {
        if (cf->mark) {
            continue;
        }

        sc = make_ctx(cf);
        if (sc == NULL) {
            return -1;
        }

        o = make_txn_obj(TXN_CERT, TXN_NEW, sc, NULL, cert_rollback, cert_commit);
        TAILQ_INSERT_TAIL(txn_objs, o, list);
    }

    return 0;
}

static void reconfigure(int argc, char **argv) {
    int i, rv;
    struct worker_proc *worker, *tworker;
    struct timeval tv;
    stud_config *cfg_new;
    struct txn_obj_head txn_objs;
    struct txn_obj *to, *tto;
    double t0, t1;

    LOG("{core} Received SIGHUP Initializing configuration reload.\n");
    gettimeofday(&tv, NULL);
    t0 = tv.tv_sec + 1e-6 * tv.tv_usec;

    /* Reload config */
    TAILQ_INIT(&txn_objs);
    cfg_new = config_new();
    if (config_parse_cli(argc, argv, cfg_new, &rv) != 0) {
        ERR("Config reload failed: %s\n", config_error_get());
        config_destroy(cfg_new);
        return;
    }

    if (   frontend_query(cfg_new, &txn_objs) < 0
        || cert_query(cfg_new, &txn_objs) < 0) {
        TAILQ_FOREACH_SAFE(to, &txn_objs, list, tto) {
            TAILQ_REMOVE(&txn_objs, to, list);
            to->rollback(to);
            free(to);
        }
        ERR("{core} Config reload failed.\n");
        return;
    } else {
        TAILQ_FOREACH_SAFE(to, &txn_objs, list, tto) {
            TAILQ_REMOVE(&txn_objs, to, list);
            to->commit(to);
            free(to);
        }
    }

    gettimeofday(&tv, NULL);
    t1 = tv.tv_sec + 1e-6 * tv.tv_usec;

    LOG("{core} Config reloaded in %.21f seconds.  Starting new child processes.\n", t1-t0);

    /* start next worker generation */
    ++worker_generation;
    start_children(0, CONFIG->NCORES);
    TAILQ_FOREACH_SAFE(worker, &worker_procs, list, tworker) {
        if (worker->generation != worker_generation) {
            errno = 0;
            do {
                i = write(worker->pfd, &worker_generation, sizeof(worker_generation));
                if (i == -1 && errno!= EINTR) {
                    ERR("WARNING: {core} unabled to gracefully reload worker %d (%s).\n",
                        worker->pid, strerror(errno));
                    (void)kill(worker->pid, SIGTERM);
                    break;
                }
            } while (i == -1 && errno == EINTR);
        }
    }
}

/* Process command line args, create the bound socket,
 * spawn child (worker) processes, and respawn if any die */
int main(int argc, char **argv) {
    // initialize configuration
    CONFIG = config_new();

    // parse command line
    int rv;
    if (config_parse_cli(argc, argv, CONFIG, &rv) != 0) {
        fprintf(stderr, "%s\n", config_error_get());
        return rv;
    }

    create_workers = 1;

    openssl_check_version();

    init_signals();

    init_globals();

    // create frontends
    for (int ii = 0; ii < CONFIG->NUM_FRONT; ++ii) {
        struct frontend* fe = create_frontend(ii);
        if (fe == NULL) {
            exit(1);
        }
        TAILQ_INSERT_TAIL(&frontends, fe, list);
    }

#ifdef USE_SHARED_CACHE
    if (CONFIG->SHCUPD_PORT) {
        /* create socket to send(children) and
               receive(parent) cache updates */
        shcupd_socket = create_shcupd_socket();
    }
#endif /* USE_SHARED_CACHE */

    init_openssl();

    init_certs();

    if (CONFIG->CHROOT && CONFIG->CHROOT[0])
        change_root();

    if (CONFIG->UID || CONFIG->GID)
        drop_privileges();

    /* should we daemonize ?*/
    if (CONFIG->DAEMONIZE) {
        /* disable logging to stderr */
        CONFIG->QUIET = 1;
        CONFIG->SYSLOG = 1;

        /* become a daemon */
        daemonize();
    }

    master_pid = getpid();

    start_children(0, CONFIG->NCORES);
#ifdef USE_SHARED_CACHE
        if (CONFIG->SHCUPD_PORT) {
            /* start event loop to receive cache updates */

            loop = ev_default_loop(EVFLAG_AUTO);

            ev_io_init(&shcupd_listener, handle_shcupd, shcupd_socket, EV_READ);
            ev_io_start(loop, &shcupd_listener);
        }
#endif /* USE_SHARED_CACHE */

    for (;;) {
#ifdef USE_SHARED_CACHE
        if (CONFIG->SHCUPD_PORT) {
            while (0 == n_sigchld && 0 == n_sighup) {
                ev_loop(loop, EV_RUNONCE);
            }
        }
        else
#endif /* USE_SHARED_CACHE */
            /* Sleep and let the children work.
             * Parent will be woken up if a signal arrives */
            pause();

        while (n_sighup != 0) {
            n_sighup = 0;
            reconfigure(argc, argv);
        }

        while (n_sigchld != 0) {
            n_sigchld = 0;
            do_wait();
        }
    }

    exit(0); /* just a formality; we never get here */
}
