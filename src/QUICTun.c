#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#ifdef DEPLOY
#include <malloc.h>
#endif
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#include <picotls.h>
#include <picotls/openssl.h>

#include <picoquic.h>
#include <picoquic_utils.h>

#define QUICTUN_VERSION "1.0.0 " GIT_COMMIT_STR

#define SERVER_MODE 0
#define CLIENT_MODE 1

#define MAX_ERRNO 4096
#define MAX_PEERS_COUNT 32
#define SERVER_ALPN "h3"

#ifndef MAX_CNX_TTL
#define MAX_CNX_TTL 1800
#endif

#define S_TO_MICROS 1000000
#define EARLY_START 0.9
#define LATE_START 1.1

#define FFLUSH_DELAY 10

#define FIRST_BYTE_SIZE 1

#define QT_KEY_SIZE 32
#define QT_WIRE_ID_SIZE 4
#define QT_TAG_SIZE 4
#define QT_MASK_SIZE 16
#define QT_DATA_HDR_SIZE (QT_WIRE_ID_SIZE + QT_TAG_SIZE)

#define QT_RX_BATCH_SIZE 32
#define QT_TX_BATCH_SIZE 32
#define QT_TX_QUEUE_CAP 128

#define QT_PENDING_WG_MAX 64
#define QT_PENDING_WG_MAX_BYTES (256 * 1024)
#define QT_PENDING_WG_TTL_US (5 * S_TO_MICROS)

extern const char *const errno_names[MAX_ERRNO];

/* ===================== netaddr ===================== */

typedef struct {
    struct sockaddr_storage ss;
    socklen_t len;
} netaddr_t;

static void netaddr_clear(netaddr_t *a)
{
    memset(a, 0, sizeof(*a));
}

static sa_family_t netaddr_family(const netaddr_t *a)
{
    return ((const struct sockaddr *)&a->ss)->sa_family;
}

static socklen_t sockaddr_len_by_family(sa_family_t family)
{
    if (family == AF_INET) {
        return (socklen_t)sizeof(struct sockaddr_in);
    }
    if (family == AF_INET6) {
        return (socklen_t)sizeof(struct sockaddr_in6);
    }
    return 0;
}

static socklen_t sockaddr_len_from_storage(const struct sockaddr_storage *ss)
{
    return sockaddr_len_by_family(((const struct sockaddr *)ss)->sa_family);
}

static int32_t netaddr_from_sockaddr(netaddr_t *dst, const struct sockaddr *sa, socklen_t len)
{
    if (!dst || !sa) {
        return -EINVAL;
    }

    if (sa->sa_family != AF_INET && sa->sa_family != AF_INET6) {
        return -EAFNOSUPPORT;
    }

    socklen_t need = sockaddr_len_by_family(sa->sa_family);
    if (len < need) {
        return -EINVAL;
    }

    memset(dst, 0, sizeof(*dst));
    memcpy(&dst->ss, sa, need);
    dst->len = need;
    return 0;
}

static int32_t netaddr_copy(netaddr_t *dst, const netaddr_t *src)
{
    if (!dst || !src) {
        return -EINVAL;
    }
    memcpy(dst, src, sizeof(*dst));
    return 0;
}

static uint16_t netaddr_port(const netaddr_t *a)
{
    if (netaddr_family(a) == AF_INET) {
        return ntohs(((const struct sockaddr_in *)&a->ss)->sin_port);
    }
    if (netaddr_family(a) == AF_INET6) {
        return ntohs(((const struct sockaddr_in6 *)&a->ss)->sin6_port);
    }
    return 0;
}

static int netaddr_is_unspecified(const netaddr_t *a)
{
    if (netaddr_family(a) == AF_INET) {
        return ((const struct sockaddr_in *)&a->ss)->sin_addr.s_addr == htonl(INADDR_ANY);
    }
    if (netaddr_family(a) == AF_INET6) {
        static const struct in6_addr zero = IN6ADDR_ANY_INIT;
        return memcmp(&((const struct sockaddr_in6 *)&a->ss)->sin6_addr, &zero, sizeof(zero)) == 0;
    }
    return 1;
}

static int netaddr_equal(const netaddr_t *a, const netaddr_t *b)
{
    sa_family_t fa = netaddr_family(a);
    sa_family_t fb = netaddr_family(b);

    if (fa != fb) {
        return 0;
    }

    if (fa == AF_INET) {
        const struct sockaddr_in *aa = (const struct sockaddr_in *)&a->ss;
        const struct sockaddr_in *bb = (const struct sockaddr_in *)&b->ss;
        return aa->sin_port == bb->sin_port && aa->sin_addr.s_addr == bb->sin_addr.s_addr;
    }

    if (fa == AF_INET6) {
        const struct sockaddr_in6 *aa = (const struct sockaddr_in6 *)&a->ss;
        const struct sockaddr_in6 *bb = (const struct sockaddr_in6 *)&b->ss;
        return aa->sin6_port == bb->sin6_port && aa->sin6_scope_id == bb->sin6_scope_id &&
               memcmp(&aa->sin6_addr, &bb->sin6_addr, sizeof(struct in6_addr)) == 0;
    }

    return 0;
}

static const void *netaddr_addr_ptr(const netaddr_t *a)
{
    if (netaddr_family(a) == AF_INET) {
        return &((const struct sockaddr_in *)&a->ss)->sin_addr;
    }
    if (netaddr_family(a) == AF_INET6) {
        return &((const struct sockaddr_in6 *)&a->ss)->sin6_addr;
    }
    return NULL;
}

static const char *netaddr_ip_to_string(const netaddr_t *a, char *buf, size_t buflen)
{
    const void *src = netaddr_addr_ptr(a);
    if (!src) {
        return NULL;
    }
    return inet_ntop(netaddr_family(a), src, buf, (socklen_t)buflen);
}

static void netaddr_to_string(const netaddr_t *a, char *buf, size_t buflen)
{
    char ip[INET6_ADDRSTRLEN] = { 0 };
    const char *ip_s = netaddr_ip_to_string(a, ip, sizeof(ip));
    if (!ip_s) {
        snprintf(buf, buflen, "(invalid)");
        return;
    }

    if (netaddr_family(a) == AF_INET6) {
        snprintf(buf, buflen, "[%s]:%u", ip_s, (unsigned)netaddr_port(a));
    } else {
        snprintf(buf, buflen, "%s:%u", ip_s, (unsigned)netaddr_port(a));
    }
}

/* ===================== stats ===================== */

typedef struct {
    uint64_t sendto_quic[MAX_ERRNO];
    uint64_t recvfrom_quic[MAX_ERRNO];
    uint64_t sendto_new_quic[MAX_ERRNO];
    uint64_t sendto_wg[MAX_ERRNO];
    uint64_t recvfrom_wg[MAX_ERRNO];
} errors_stat_t;
static errors_stat_t errors_stat;

typedef struct {
    uint64_t recvfrom_quic_ptks;
    uint64_t recvfrom_quic_bytes;
    uint64_t recvfrom_new_quic_ptks;
    uint64_t recvfrom_new_quic_bytes;
    uint64_t recvfrom_wg_ptks;
    uint64_t recvfrom_wg_bytes;
    uint64_t recvfrom_wg_drop_ptks;
    uint64_t recvfrom_wg_drop_bytes;
    uint64_t recvfrom_wg_drop_encrypt_ptks;
    uint64_t recvfrom_wg_drop_encrypt_bytes;
    uint64_t quic_in_ptks;
    uint64_t quic_in_bytes;
    uint64_t quic_in_drop_ptks;
    uint64_t quic_in_drop_bytes;
    uint64_t sendto_quic_drop_ptks;
    uint64_t sendto_quic_drop_bytes;
    uint64_t sendto_quic_ptks;
    uint64_t sendto_quic_bytes;
    uint64_t sendto_new_quic_drop_ptks;
    uint64_t sendto_new_quic_drop_bytes;
    uint64_t sendto_new_quic_ptks;
    uint64_t sendto_new_quic_bytes;
    uint64_t sendto_wg_drop_ptks;
    uint64_t sendto_wg_drop_bytes;
    uint64_t sendto_wg_ptks;
    uint64_t sendto_wg_bytes;
} data_stat_t;
static data_stat_t data_stat;

/* ===================== config ===================== */

typedef struct {
    char *cert_hash;
    int32_t have_cert_hash;

    netaddr_t wg_endpoint_addr;
    int32_t have_wg_endpoint;
} peer_entry_t;

static peer_entry_t peers[MAX_PEERS_COUNT];
static int32_t peers_n;

typedef struct {
    int32_t have_quic_listen;
    netaddr_t listen_quic_addr;

    int32_t have_quic_endpoint;
    netaddr_t endpoint_quic_addr;

    int32_t have_wg_listen;
    netaddr_t listen_wg_addr;

    int32_t have_certs_path;
    char *certs_path;

    int32_t have_log_path;
    char *log_path;

    int32_t have_stat_path;
    char *stat_path;

    int32_t have_sni;
    char *sni;
} quictun_config_t;
static quictun_config_t cfg_global;

/* ===================== runtime ===================== */

typedef struct {
    picoquic_cnx_t *cnx;
    int32_t peer_id;
} verified_peer_t;

static verified_peer_t verified_peers[MAX_PEERS_COUNT];
static int32_t verified_peers_n;

typedef struct {
    uint8_t data[PICOQUIC_MAX_PACKET_SIZE];
    size_t len;
    netaddr_t from_wg_addr;
    uint64_t ts_us;
} pending_wg_pkt_t;

typedef struct connects_client {
    int32_t del_mark;
    int32_t timeout_mark;
    int32_t prefetch_mark;
    int32_t used_mark;

    int32_t to_server_quic_sock;
    netaddr_t to_server_quic_local_addr;
    netaddr_t to_wg_addr;

    picoquic_cnx_t *client_cnx;

    picoquic_connection_id_t remote_dcid;
    picoquic_connection_id_t local_dcid;

    uint8_t data_send_key[QT_KEY_SIZE];
    uint8_t data_recv_key[QT_KEY_SIZE];
    uint32_t data_send_ctr;

    pending_wg_pkt_t pending_wg[QT_PENDING_WG_MAX];
    int32_t pending_wg_head;
    int32_t pending_wg_tail;
    int32_t pending_wg_count;
    size_t pending_wg_bytes;
} connects_client_t;
static connects_client_t connects_client[MAX_PEERS_COUNT];
static int32_t connects_client_n;

typedef struct connects_server {
    int32_t del_mark;
    int32_t peer_id;

    int32_t to_wg_sock;
    netaddr_t to_wg_addr;
    netaddr_t to_client_quic_addr;

    picoquic_cnx_t *server_cnx;

    picoquic_connection_id_t remote_dcid;
    picoquic_connection_id_t local_dcid;

    uint8_t data_send_key[QT_KEY_SIZE];
    uint8_t data_recv_key[QT_KEY_SIZE];
    uint32_t data_send_ctr;
} connects_server_t;
static connects_server_t connects_server[MAX_PEERS_COUNT];
static int32_t connects_server_n;

static int32_t del_mark;
static volatile sig_atomic_t exit_flag = 0;

FILE *log_file;
FILE *stat_file;

static ptls_openssl_override_verify_certificate_t g_override_cb;
static ptls_openssl_verify_certificate_t g_verifier;
static X509_STORE *g_store;

/* ===================== macros ===================== */

#define PRINT_ERRNO_STAT(arr_field)                                                         \
    do {                                                                                    \
        for (int32_t e = 1; e < MAX_ERRNO; e++) {                                           \
            if (errors_stat.arr_field[e] != 0) {                                            \
                if (errno_names[e]) {                                                       \
                    fprintf(stat_file, "  " #arr_field " %s %" PRIu64 "\n", errno_names[e], \
                            errors_stat.arr_field[e]);                                      \
                } else {                                                                    \
                    fprintf(stat_file, "  " #arr_field " %d %" PRIu64 "\n", e,              \
                            errors_stat.arr_field[e]);                                      \
                }                                                                           \
            }                                                                               \
        }                                                                                   \
    } while (0)

#define ERRNO_ADD(prefix)                     \
    do {                                      \
        if (errno > 0 && errno < MAX_ERRNO) { \
            errors_stat.prefix[errno]++;      \
        }                                     \
    } while (0)

#define PRINT_DATA_STAT(prefix)                                                               \
    do {                                                                                      \
        if (data_stat.prefix##_ptks != 0) {                                                   \
            fprintf(stat_file, "  " #prefix "_ptks %" PRIu64 "\n", data_stat.prefix##_ptks);  \
        }                                                                                     \
        if (data_stat.prefix##_bytes != 0) {                                                  \
            fprintf(stat_file, "  " #prefix "_byte %" PRIu64 "\n", data_stat.prefix##_bytes); \
        }                                                                                     \
    } while (0)

#define STAT_ADD(prefix, len)                        \
    do {                                             \
        data_stat.prefix##_ptks++;                   \
        data_stat.prefix##_bytes += (uint64_t)(len); \
    } while (0)

/* ===================== batch tx/rx ===================== */

typedef enum {
    TX_STAT_SENDTO_QUIC = 0,
    TX_STAT_SENDTO_NEW_QUIC = 1,
    TX_STAT_SENDTO_WG = 2,
} tx_stat_kind_t;

typedef struct {
    int32_t fd;
    int32_t have_addr;
    struct sockaddr_storage addr;
    socklen_t addr_len;
    size_t len;
    tx_stat_kind_t stat_kind;
    uint8_t buf[PICOQUIC_MAX_PACKET_SIZE];
} tx_pkt_t;

typedef struct {
    tx_pkt_t pkts[QT_TX_QUEUE_CAP];
    int32_t n;
} tx_queue_t;

typedef struct {
    struct mmsghdr msgs[QT_RX_BATCH_SIZE];
    struct iovec iov[QT_RX_BATCH_SIZE];
    struct sockaddr_storage addrs[QT_RX_BATCH_SIZE];
    uint8_t bufs[QT_RX_BATCH_SIZE][PICOQUIC_MAX_PACKET_SIZE];
} rx_batch_t;

static void tx_queue_reset(tx_queue_t *q)
{
    q->n = 0;
}

static void tx_errno_add(tx_stat_kind_t kind)
{
    if (errno <= 0 || errno >= MAX_ERRNO) {
        return;
    }

    switch (kind) {
    case TX_STAT_SENDTO_QUIC:
        errors_stat.sendto_quic[errno]++;
        break;
    case TX_STAT_SENDTO_NEW_QUIC:
        errors_stat.sendto_new_quic[errno]++;
        break;
    case TX_STAT_SENDTO_WG:
        errors_stat.sendto_wg[errno]++;
        break;
    }
}

static void tx_stat_add(tx_stat_kind_t kind, int32_t drop, size_t len)
{
    switch (kind) {
    case TX_STAT_SENDTO_QUIC:
        if (drop) {
            STAT_ADD(sendto_quic_drop, len);
        } else {
            STAT_ADD(sendto_quic, len);
        }
        break;
    case TX_STAT_SENDTO_NEW_QUIC:
        if (drop) {
            STAT_ADD(sendto_new_quic_drop, len);
        } else {
            STAT_ADD(sendto_new_quic, len);
        }
        break;
    case TX_STAT_SENDTO_WG:
        if (drop) {
            STAT_ADD(sendto_wg_drop, len);
        } else {
            STAT_ADD(sendto_wg, len);
        }
        break;
    }
}

static int32_t tx_queue_push(tx_queue_t *q, int32_t fd, const void *data, size_t len,
                             const struct sockaddr *addr, socklen_t addr_len,
                             tx_stat_kind_t stat_kind)
{
    if (!q || fd < 0 || !data || len == 0 || len > PICOQUIC_MAX_PACKET_SIZE) {
        errno = EINVAL;
        tx_errno_add(stat_kind);
        tx_stat_add(stat_kind, 1, len);
        return -EINVAL;
    }

    if (q->n >= QT_TX_QUEUE_CAP) {
        errno = ENOBUFS;
        tx_errno_add(stat_kind);
        tx_stat_add(stat_kind, 1, len);
        return -ENOBUFS;
    }

    tx_pkt_t *p = &q->pkts[q->n++];
    memset(p, 0, sizeof(*p));
    p->fd = fd;
    p->len = len;
    p->stat_kind = stat_kind;
    memcpy(p->buf, data, len);

    if (addr && addr_len > 0) {
        p->have_addr = 1;
        p->addr_len = addr_len;
        memcpy(&p->addr, addr, addr_len);
    }

    return 0;
}

static void tx_queue_flush(tx_queue_t *q)
{
    int32_t off = 0;

    while (off < q->n) {
        int32_t fd = q->pkts[off].fd;
        struct mmsghdr msgs[QT_TX_BATCH_SIZE];
        struct iovec iov[QT_TX_BATCH_SIZE];
        int32_t cnt = 0;

        memset(msgs, 0, sizeof(msgs));

        while (off + cnt < q->n && cnt < QT_TX_BATCH_SIZE && q->pkts[off + cnt].fd == fd) {
            tx_pkt_t *pkt = &q->pkts[off + cnt];

            iov[cnt].iov_base = pkt->buf;
            iov[cnt].iov_len = pkt->len;
            msgs[cnt].msg_hdr.msg_iov = &iov[cnt];
            msgs[cnt].msg_hdr.msg_iovlen = 1;

            if (pkt->have_addr) {
                msgs[cnt].msg_hdr.msg_name = &pkt->addr;
                msgs[cnt].msg_hdr.msg_namelen = pkt->addr_len;
            }

            cnt++;
        }

        int32_t sent = sendmmsg(fd, msgs, (unsigned)cnt, MSG_DONTWAIT);
        if (sent < 0) {
            for (int32_t i = 0; i < cnt; i++) {
                tx_errno_add(q->pkts[off + i].stat_kind);
                tx_stat_add(q->pkts[off + i].stat_kind, 1, q->pkts[off + i].len);
            }
            off += cnt;
            continue;
        }

        for (int32_t i = 0; i < sent; i++) {
            tx_pkt_t *pkt = &q->pkts[off + i];
            if (msgs[i].msg_len == pkt->len) {
                tx_stat_add(pkt->stat_kind, 0, pkt->len);
            } else {
                tx_stat_add(pkt->stat_kind, 1, pkt->len);
            }
        }

        for (int32_t i = sent; i < cnt; i++) {
            tx_pkt_t *pkt = &q->pkts[off + i];
            tx_stat_add(pkt->stat_kind, 1, pkt->len);
        }

        off += cnt;
    }

    tx_queue_reset(q);
}

static int32_t rx_batch_recv(int32_t fd, rx_batch_t *b, size_t recv_offset)
{
    if (!b || recv_offset >= PICOQUIC_MAX_PACKET_SIZE) {
        return -EINVAL;
    }

    memset(b, 0, sizeof(*b));

    for (int32_t i = 0; i < QT_RX_BATCH_SIZE; i++) {
        b->iov[i].iov_base = b->bufs[i] + recv_offset;
        b->iov[i].iov_len = PICOQUIC_MAX_PACKET_SIZE - recv_offset;

        b->msgs[i].msg_hdr.msg_iov = &b->iov[i];
        b->msgs[i].msg_hdr.msg_iovlen = 1;
        b->msgs[i].msg_hdr.msg_name = &b->addrs[i];
        b->msgs[i].msg_hdr.msg_namelen = sizeof(b->addrs[i]);
    }

    int32_t n = recvmmsg(fd, b->msgs, QT_RX_BATCH_SIZE, MSG_DONTWAIT, NULL);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        return -errno;
    }

    return n;
}

static void pending_wg_clear(connects_client_t *c)
{
    if (!c) {
        return;
    }

    c->pending_wg_head = 0;
    c->pending_wg_tail = 0;
    c->pending_wg_count = 0;
    c->pending_wg_bytes = 0;
}

static void pending_wg_drop_oldest(connects_client_t *c)
{
    if (!c || c->pending_wg_count <= 0) {
        return;
    }

    pending_wg_pkt_t *p = &c->pending_wg[c->pending_wg_head];
    STAT_ADD(recvfrom_wg_drop, p->len);

    if (c->pending_wg_bytes >= p->len) {
        c->pending_wg_bytes -= p->len;
    } else {
        c->pending_wg_bytes = 0;
    }

    memset(p, 0, sizeof(*p));
    c->pending_wg_head = (c->pending_wg_head + 1) % QT_PENDING_WG_MAX;
    c->pending_wg_count--;
}

static void pending_wg_prune_expired(connects_client_t *c, uint64_t now_us)
{
    while (c && c->pending_wg_count > 0) {
        pending_wg_pkt_t *p = &c->pending_wg[c->pending_wg_head];
        if (now_us >= p->ts_us && now_us - p->ts_us <= QT_PENDING_WG_TTL_US) {
            break;
        }
        pending_wg_drop_oldest(c);
    }
}

static int32_t pending_wg_push(connects_client_t *c, const void *data, size_t len,
                               const netaddr_t *from_wg_addr, uint64_t now_us)
{
    if (!c || !data || len == 0 || len > PICOQUIC_MAX_PACKET_SIZE || !from_wg_addr) {
        return -EINVAL;
    }

    pending_wg_prune_expired(c, now_us);

    while (c->pending_wg_count >= QT_PENDING_WG_MAX ||
           c->pending_wg_bytes + len > QT_PENDING_WG_MAX_BYTES) {
        pending_wg_drop_oldest(c);
    }

    pending_wg_pkt_t *p = &c->pending_wg[c->pending_wg_tail];
    memset(p, 0, sizeof(*p));
    memcpy(p->data, data, len);
    p->len = len;
    p->ts_us = now_us;
    netaddr_copy(&p->from_wg_addr, from_wg_addr);

    c->pending_wg_tail = (c->pending_wg_tail + 1) % QT_PENDING_WG_MAX;
    c->pending_wg_count++;
    c->pending_wg_bytes += len;
    return 0;
}

/* ===================== helpers ===================== */

static void errmsg(const char *format, ...)
{
    va_list args;

    printf("Error: ");

    va_start(args, format);
    vprintf(format, args);
    va_end(args);

    fflush(stdout);
    exit(1);
}

static void main_catch_function(int32_t signo)
{
    (void)signo;
    exit_flag = 1;
}

static int32_t set_sock_nonblocking(int32_t set_sock)
{
    int32_t flags = fcntl(set_sock, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }

    if (flags & O_NONBLOCK) {
        return 0;
    }

    if (fcntl(set_sock, F_SETFL, flags | O_NONBLOCK) < 0) {
        return -1;
    }

    return 0;
}

static uint8_t make_quic_short_header_byte(uint32_t wire_id)
{
    return (uint8_t)(0x40 | ((wire_id >> 24) & 0x3f));
}

void dump_hex(const char *p, int32_t n)
{
    for (int32_t i = 0; i < n; i++) {
        if (i % 8 == 0 && i != 0) {
            printf("\n");
        }
        printf("0x%02X ", (unsigned char)p[i]);
    }
    printf("\n");
}

static char *trim(char *s)
{
    while (*s && isspace((unsigned char)*s)) {
        s++;
    }

    if (*s == 0) {
        return s;
    }

    char *e = s + strlen(s) - 1;
    while (e > s && isspace((unsigned char)*e)) {
        *e-- = 0;
    }

    return s;
}

static void strip_comment(char *s)
{
    for (; *s; s++) {
        if (*s == '#' || *s == ';') {
            *s = 0;
            return;
        }
    }
}

static int32_t set_string(char **dst, const char *src)
{
    char *p = strdup(src);
    if (!p) {
        return -ENOMEM;
    }
    free(*dst);
    *dst = p;
    return 0;
}

static int32_t set_nonempty_string(char **dst, const char *src)
{
    if (!src) {
        return -EINVAL;
    }

    const char *s = src;
    while (*s && isspace((unsigned char)*s)) {
        s++;
    }

    if (*s == 0) {
        return -EINVAL;
    }

    return set_string(dst, s);
}

static int32_t parse_addrport(const char *val, netaddr_t *out)
{
    char *tmp = strdup(val);
    if (!tmp) {
        return -ENOMEM;
    }

    char *s = trim(tmp);
    char *host = NULL;
    char *port_str = NULL;

    if (*s == '[') {
        char *rb = strchr(s, ']');
        if (!rb || rb[1] != ':') {
            free(tmp);
            return -EINVAL;
        }
        *rb = 0;
        host = s + 1;
        port_str = rb + 2;
    } else {
        char *first = strchr(s, ':');
        char *last = strrchr(s, ':');

        if (!first || first != last) {
            free(tmp);
            return -EINVAL;
        }

        *last = 0;
        host = s;
        port_str = last + 1;
    }

    host = trim(host);
    port_str = trim(port_str);

    char *endp = NULL;
    errno = 0;
    long port = strtol(port_str, &endp, 10);
    if (errno != 0 || endp == port_str || *trim(endp) != 0 || port <= 0 || port > 65535) {
        free(tmp);
        return -EINVAL;
    }

    struct in_addr ip4;
    if (inet_pton(AF_INET, host, &ip4) == 1) {
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_addr = ip4;
        sa.sin_port = htons((uint16_t)port);

        netaddr_clear(out);
        memcpy(&out->ss, &sa, sizeof(sa));
        out->len = sizeof(sa);

        free(tmp);
        return 0;
    }

    struct in6_addr ip6;
    if (inet_pton(AF_INET6, host, &ip6) == 1) {
        struct sockaddr_in6 sa6;
        memset(&sa6, 0, sizeof(sa6));
        sa6.sin6_family = AF_INET6;
        sa6.sin6_addr = ip6;
        sa6.sin6_port = htons((uint16_t)port);

        netaddr_clear(out);
        memcpy(&out->ss, &sa6, sizeof(sa6));
        out->len = sizeof(sa6);

        free(tmp);
        return 0;
    }

    free(tmp);
    return -EINVAL;
}

static int32_t make_udp_socket(sa_family_t family)
{
    int fd = socket(family, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) {
        return -errno;
    }

    if (set_sock_nonblocking(fd) < 0) {
        int rc = -errno;
        close(fd);
        return rc;
    }

    return fd;
}

static void cfg_init(quictun_config_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    netaddr_clear(&cfg->listen_quic_addr);
    netaddr_clear(&cfg->endpoint_quic_addr);
    netaddr_clear(&cfg->listen_wg_addr);
}

static void peers_free(void)
{
    for (int32_t i = 0; i < peers_n; i++) {
        free(peers[i].cert_hash);
        memset(&peers[i], 0, sizeof(peers[i]));
    }
    peers_n = 0;
}

static void cfg_free(quictun_config_t *cfg)
{
    free(cfg->certs_path);
    free(cfg->log_path);
    free(cfg->stat_path);
    free(cfg->sni);
    cfg_init(cfg);
}

/* ===================== peer binding ===================== */

static void bind_verified_peer(picoquic_cnx_t *cnx, int32_t peer_id)
{
    for (int32_t i = 0; i < verified_peers_n; i++) {
        if (verified_peers[i].cnx == cnx) {
            verified_peers[i].peer_id = peer_id;
            return;
        }
    }

    if (verified_peers_n < MAX_PEERS_COUNT) {
        verified_peers[verified_peers_n].cnx = cnx;
        verified_peers[verified_peers_n].peer_id = peer_id;
        verified_peers_n++;
    }
}

static int32_t find_verified_peer_id(picoquic_cnx_t *cnx)
{
    for (int32_t i = 0; i < verified_peers_n; i++) {
        if (verified_peers[i].cnx == cnx) {
            return verified_peers[i].peer_id;
        }
    }
    return -1;
}

static void unbind_verified_peer(picoquic_cnx_t *cnx)
{
    for (int32_t i = 0; i < verified_peers_n; i++) {
        if (verified_peers[i].cnx == cnx) {
            verified_peers_n--;
            if (i != verified_peers_n) {
                verified_peers[i] = verified_peers[verified_peers_n];
            }
            memset(&verified_peers[verified_peers_n], 0, sizeof(verified_peers[0]));
            return;
        }
    }
}

static int32_t find_peer_id_by_hash(const char *cert_hash)
{
    for (int32_t i = 0; i < peers_n; i++) {
        if (peers[i].cert_hash && strcmp(peers[i].cert_hash, cert_hash) == 0) {
            return i;
        }
    }
    return -1;
}

static int32_t peer_hash_exists(const char *cert_hash)
{
    if (!cert_hash) {
        return 0;
    }

    return find_peer_id_by_hash(cert_hash) >= 0;
}

/* ===================== logging ===================== */

static void cfg_print_addr(const char *name, int32_t have, const netaddr_t *a)
{
    if (!have) {
        printf("%s: (not set)\n", name);
        return;
    }

    char full[INET6_ADDRSTRLEN + 32];
    netaddr_to_string(a, full, sizeof(full));
    printf("%s: %s\n", name, full);
}

static void cfg_print_str(const char *name, int32_t have, const char *s)
{
    if (!have || !s) {
        printf("%s: (not set)\n", name);
        return;
    }
    printf("%s: %s\n", name, s);
}

static void quictun_config_log(const quictun_config_t *cfg)
{
    cfg_print_addr("QuicListen", cfg->have_quic_listen, &cfg->listen_quic_addr);
    cfg_print_addr("QuicEndpoint", cfg->have_quic_endpoint, &cfg->endpoint_quic_addr);
    cfg_print_addr("WgListen", cfg->have_wg_listen, &cfg->listen_wg_addr);

    cfg_print_str("CertsPath", cfg->have_certs_path, cfg->certs_path);
    cfg_print_str("SNI", cfg->have_sni, cfg->sni);
    cfg_print_str("LogPath", cfg->have_log_path, cfg->log_path);
    cfg_print_str("StatPath", cfg->have_stat_path, cfg->stat_path);

    if (peers_n > 0) {
        printf("Peers: %d\n", peers_n);
        for (int32_t i = 0; i < peers_n; i++) {
            char full[INET6_ADDRSTRLEN + 32];
            netaddr_to_string(&peers[i].wg_endpoint_addr, full, sizeof(full));
            printf("Peer[%d]: %s %s\n", i, peers[i].cert_hash ? peers[i].cert_hash : "(null)",
                   full);
        }
    }
}

static void logids(const char *format, picoquic_connection_id_t *remote_dcid,
                   picoquic_connection_id_t *local_dcid)
{
    if (!log_file) {
        return;
    }

    time_t now = time(NULL);
    struct tm tm_now;
    localtime_r(&now, &tm_now);

    fprintf(log_file, "[%02d:%02d:%02d] %s", tm_now.tm_hour, tm_now.tm_min, tm_now.tm_sec, format);

    if (remote_dcid && remote_dcid->id_len != 0) {
        for (unsigned i = 0; i < (unsigned)remote_dcid->id_len; i++) {
            fprintf(log_file, "%02x", remote_dcid->id[i]);
        }
    } else {
        fprintf(log_file, "unseted");
    }

    fprintf(log_file, " ");

    if (local_dcid && local_dcid->id_len != 0) {
        for (unsigned i = 0; i < (unsigned)local_dcid->id_len; i++) {
            fprintf(log_file, "%02x", local_dcid->id[i]);
        }
    } else {
        fprintf(log_file, "unseted");
    }

    fprintf(log_file, "\n\n");
}

static void log_peer_match(const char *prefix, int32_t peer_id, const char *cert_hash,
                           const netaddr_t *wg_addr)
{
    if (!log_file) {
        return;
    }

    time_t now = time(NULL);
    struct tm tm_now;
    localtime_r(&now, &tm_now);

    char full[INET6_ADDRSTRLEN + 32];
    netaddr_to_string(wg_addr, full, sizeof(full));

    fprintf(log_file, "[%02d:%02d:%02d] %s peer_id=%d cert_hash=%s wg=%s\n\n", tm_now.tm_hour,
            tm_now.tm_min, tm_now.tm_sec, prefix, peer_id, cert_hash ? cert_hash : "(null)", full);
}

/* ===================== cert verify ===================== */

static int cert_sha256_b64(X509 *cert, char *out, size_t out_sz)
{
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int mdlen = 0;

    if (X509_digest(cert, EVP_sha256(), md, &mdlen) != 1 || mdlen != 32) {
        return -1;
    }

    if (out_sz < 45) {
        return -1;
    }

    int n = EVP_EncodeBlock((unsigned char *)out, md, (int32_t)mdlen);
    if (n != 44) {
        return -1;
    }

    out[n] = 0;
    return 0;
}

static int on_verified_cert(ptls_openssl_override_verify_certificate_t *self, ptls_t *tls, int ret,
                            int ossl_ret, X509 *cert, STACK_OF(X509) * chain)
{
    (void)self;
    (void)ossl_ret;
    (void)chain;

    if (ret != 0) {
        return ret;
    }

    if (!cert) {
        return PTLS_ALERT_ACCESS_DENIED;
    }

    char cert_hash[45];
    if (cert_sha256_b64(cert, cert_hash, sizeof(cert_hash)) != 0) {
        return PTLS_ALERT_ACCESS_DENIED;
    }

    int32_t peer_id = find_peer_id_by_hash(cert_hash);
    if (peer_id < 0) {
        if (log_file) {
            time_t now = time(NULL);
            struct tm tm_now;
            localtime_r(&now, &tm_now);

            fprintf(log_file,
                    "[%02d:%02d:%02d] Cert verify failed: "
                    "unknown cert_hash=%s\n\n",
                    tm_now.tm_hour, tm_now.tm_min, tm_now.tm_sec, cert_hash);
        }
        return PTLS_ALERT_ACCESS_DENIED;
    }

    picoquic_cnx_t *cnx = (picoquic_cnx_t *)*ptls_get_data_ptr(tls);
    if (!cnx) {
        return PTLS_ALERT_ACCESS_DENIED;
    }

    bind_verified_peer(cnx, peer_id);

    log_peer_match("Cert matched", peer_id, cert_hash, &peers[peer_id].wg_endpoint_addr);

    return 0;
}

static X509_STORE *make_store_from_ca(const char *ca_pem)
{
    X509_STORE *store = X509_STORE_new();
    if (!store) {
        return NULL;
    }

    X509_LOOKUP *lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
    if (!lookup) {
        X509_STORE_free(store);
        return NULL;
    }

    if (X509_LOOKUP_load_file(lookup, ca_pem, X509_FILETYPE_PEM) != 1) {
        X509_STORE_free(store);
        return NULL;
    }

    return store;
}

/* ===================== config parser ===================== */

static int32_t apply_interface_kv(quictun_config_t *cfg, const char *key, const char *val)
{
    if (strcmp(key, "QuicListen") == 0) {
        if (cfg->have_quic_listen) {
            return -EEXIST;
        }

        int32_t rc = parse_addrport(val, &cfg->listen_quic_addr);
        if (rc == 0) {
            if (netaddr_is_unspecified(&cfg->listen_quic_addr)) {
                return -EINVAL;
            }
            cfg->have_quic_listen = 1;
        }
        return rc;
    } else if (strcmp(key, "QuicEndpoint") == 0) {
        if (cfg->have_quic_endpoint) {
            return -EEXIST;
        }

        int32_t rc = parse_addrport(val, &cfg->endpoint_quic_addr);
        if (rc == 0) {
            if (netaddr_is_unspecified(&cfg->endpoint_quic_addr)) {
                return -EINVAL;
            }
            cfg->have_quic_endpoint = 1;
        }
        return rc;
    } else if (strcmp(key, "WgListen") == 0) {
        if (cfg->have_wg_listen) {
            return -EEXIST;
        }

        int32_t rc = parse_addrport(val, &cfg->listen_wg_addr);
        if (rc == 0) {
            if (netaddr_is_unspecified(&cfg->listen_wg_addr)) {
                return -EINVAL;
            }
            cfg->have_wg_listen = 1;
        }
        return rc;
    } else if (strcmp(key, "CertsPath") == 0) {
        if (cfg->have_certs_path) {
            return -EEXIST;
        }

        int32_t rc = set_nonempty_string(&cfg->certs_path, val);
        if (rc == 0) {
            cfg->have_certs_path = 1;
        }
        return rc;
    } else if (strcmp(key, "LogPath") == 0) {
        if (cfg->have_log_path) {
            return -EEXIST;
        }

        int32_t rc = set_nonempty_string(&cfg->log_path, val);
        if (rc == 0) {
            cfg->have_log_path = 1;
        }
        return rc;
    } else if (strcmp(key, "StatPath") == 0) {
        if (cfg->have_stat_path) {
            return -EEXIST;
        }

        int32_t rc = set_nonempty_string(&cfg->stat_path, val);
        if (rc == 0) {
            cfg->have_stat_path = 1;
        }
        return rc;
    } else if (strcmp(key, "SNI") == 0) {
        if (cfg->have_sni) {
            return -EEXIST;
        }

        int32_t rc = set_nonempty_string(&cfg->sni, val);
        if (rc == 0) {
            cfg->have_sni = 1;
        }
        return rc;
    }

    return -EINVAL;
}

static int32_t apply_peer_kv(peer_entry_t *peer, const char *key, const char *val)
{
    if (strcmp(key, "PeerCertSHA256") == 0) {
        if (peer->have_cert_hash) {
            return -EEXIST;
        }

        int32_t rc = set_nonempty_string(&peer->cert_hash, val);
        if (rc == 0) {
            peer->have_cert_hash = 1;
        }
        return rc;
    } else if (strcmp(key, "WgEndpoint") == 0) {
        if (peer->have_wg_endpoint) {
            return -EEXIST;
        }

        int32_t rc = parse_addrport(val, &peer->wg_endpoint_addr);
        if (rc == 0) {
            if (netaddr_is_unspecified(&peer->wg_endpoint_addr)) {
                return -EINVAL;
            }
            peer->have_wg_endpoint = 1;
        }
        return rc;
    }

    return -EINVAL;
}

static int32_t finalize_peer_section(peer_entry_t *cur_peer)
{
    if (!cur_peer->have_cert_hash && !cur_peer->have_wg_endpoint && !cur_peer->cert_hash) {
        return 0;
    }

    if (!cur_peer->have_cert_hash || !cur_peer->have_wg_endpoint) {
        return -EINVAL;
    }

    if (peer_hash_exists(cur_peer->cert_hash)) {
        return -EEXIST;
    }

    if (peers_n >= MAX_PEERS_COUNT) {
        return -ENOMEM;
    }

    peers[peers_n++] = *cur_peer;
    memset(cur_peer, 0, sizeof(*cur_peer));
    return 0;
}

static int32_t quictun_config_load_file(quictun_config_t *cfg, const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        return -errno;
    }

    cfg_init(cfg);
    peers_free();

    enum { SEC_NONE = 0, SEC_INTERFACE = 1, SEC_PEER = 2 } sec = SEC_NONE;
    int32_t seen_interface = 0;

    peer_entry_t cur_peer;
    memset(&cur_peer, 0, sizeof(cur_peer));

    char line[1024];
    int32_t rc = 0;
    uint32_t lineno = 0;

    while (fgets(line, sizeof(line), f)) {
        lineno++;

        line[strcspn(line, "\r\n")] = 0;
        strip_comment(line);

        char *s = trim(line);
        if (*s == 0) {
            continue;
        }

        if (strcmp(s, "[Interface]") == 0) {
            if (seen_interface) {
                rc = -EEXIST;
                break;
            }

            if (sec == SEC_PEER) {
                rc = finalize_peer_section(&cur_peer);
                if (rc != 0) {
                    break;
                }
            }

            seen_interface = 1;
            sec = SEC_INTERFACE;
            continue;
        }

        if (strcmp(s, "[Peer]") == 0) {
            if (sec == SEC_PEER) {
                rc = finalize_peer_section(&cur_peer);
                if (rc != 0) {
                    break;
                }
            }
            memset(&cur_peer, 0, sizeof(cur_peer));
            sec = SEC_PEER;
            continue;
        }

        char *eq = strchr(s, '=');
        if (!eq) {
            rc = -EINVAL;
            break;
        }

        *eq = 0;
        char *key = trim(s);
        char *val = trim(eq + 1);

        if (*key == 0) {
            rc = -EINVAL;
            break;
        }

        if (sec == SEC_INTERFACE) {
            rc = apply_interface_kv(cfg, key, val);
        } else if (sec == SEC_PEER) {
            rc = apply_peer_kv(&cur_peer, key, val);
        } else {
            rc = -EINVAL;
        }

        if (rc != 0) {
            break;
        }
    }

    if (rc == 0 && sec == SEC_PEER) {
        rc = finalize_peer_section(&cur_peer);
    }

    fclose(f);

    if (rc != 0) {
        free(cur_peer.cert_hash);
        cfg_free(cfg);
        peers_free();

        if (rc == -EEXIST) {
            fprintf(stdout, "config parse error: %s:%u duplicate key or section\n", path, lineno);
        } else {
            fprintf(stdout, "config parse error: %s:%u rc=%d\n", path, lineno, rc);
        }
    }

    return rc;
}

/* ===================== stats print ===================== */

static void stat_print(void)
{
    if (!stat_file) {
        return;
    }

    if (ftruncate(fileno(stat_file), 0) != 0) {
        return;
    }

    fseek(stat_file, 0, SEEK_SET);

    fprintf(stat_file, "errnos:\n");
    PRINT_ERRNO_STAT(sendto_quic);
    PRINT_ERRNO_STAT(recvfrom_quic);
    PRINT_ERRNO_STAT(sendto_new_quic);
    PRINT_ERRNO_STAT(sendto_wg);
    PRINT_ERRNO_STAT(recvfrom_wg);
    fprintf(stat_file, "\n");

    fprintf(stat_file, "recvfrom_quic:\n");
    PRINT_DATA_STAT(recvfrom_quic);
    PRINT_DATA_STAT(quic_in);
    PRINT_DATA_STAT(quic_in_drop);
    PRINT_DATA_STAT(sendto_quic);
    PRINT_DATA_STAT(sendto_quic_drop);
    fprintf(stat_file, "\n");

    fprintf(stat_file, "recvfrom_wg:\n");
    PRINT_DATA_STAT(recvfrom_wg);
    PRINT_DATA_STAT(recvfrom_wg_drop);
    PRINT_DATA_STAT(recvfrom_wg_drop_encrypt);
    PRINT_DATA_STAT(sendto_new_quic);
    PRINT_DATA_STAT(sendto_new_quic_drop);
    fprintf(stat_file, "\n");

    fprintf(stat_file, "recvfrom_new_quic:\n");
    PRINT_DATA_STAT(recvfrom_new_quic);
    PRINT_DATA_STAT(sendto_wg);
    PRINT_DATA_STAT(sendto_wg_drop);
    fprintf(stat_file, "\n");
}

/* ===================== runtime lookup ===================== */

static connects_client_t *find_connect_cnx_client(picoquic_cnx_t *cnx)
{
    for (int32_t i = 0; i < connects_client_n; i++) {
        if (connects_client[i].client_cnx == cnx) {
            return &connects_client[i];
        }
    }
    return NULL;
}

static connects_client_t *find_connect_addr_client(const netaddr_t *addr)
{
    for (int32_t i = 0; i < connects_client_n; i++) {
        if (netaddr_equal(&connects_client[i].to_wg_addr, addr)) {
            uint64_t age_us = picoquic_current_time() -
                              picoquic_get_cnx_start_time(connects_client[i].client_cnx);

            if (age_us < MAX_CNX_TTL * S_TO_MICROS) {
                return &connects_client[i];
            }
        }
    }
    return NULL;
}

static connects_server_t *find_connect_cnx_server(picoquic_cnx_t *cnx)
{
    for (int32_t i = 0; i < connects_server_n; i++) {
        if (connects_server[i].server_cnx == cnx) {
            return &connects_server[i];
        }
    }
    return NULL;
}

/* ===================== data packet v2 mask/demux ===================== */

static uint32_t qt_load32_le(const void *p)
{
    const uint8_t *b = (const uint8_t *)p;
    return ((uint32_t)b[0]) | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) |
           ((uint32_t)b[3] << 24);
}

static void qt_store32_le(void *p, uint32_t v)
{
    uint8_t *b = (uint8_t *)p;
    b[0] = (uint8_t)(v);
    b[1] = (uint8_t)(v >> 8);
    b[2] = (uint8_t)(v >> 16);
    b[3] = (uint8_t)(v >> 24);
}

static uint32_t qt_mix32(uint32_t x)
{
    x ^= x >> 16;
    x *= 0x7feb352dU;
    x ^= x >> 15;
    x *= 0x846ca68bU;
    x ^= x >> 16;
    return x;
}

static uint32_t qt_key32(const uint8_t key[QT_KEY_SIZE], uint32_t idx)
{
    return qt_load32_le(key + ((idx & 7u) * 4u));
}

static uint32_t qt_dcid_mix(const picoquic_connection_id_t *dcid)
{
    uint32_t x = 0x9e3779b9U ^ (uint32_t)dcid->id_len;

    for (uint8_t i = 0; i < dcid->id_len; i++) {
        x ^= (uint32_t)dcid->id[i] << ((i & 3u) * 8u);
        x = qt_mix32(x + 0x85ebca6bU + (uint32_t)i);
    }

    return x;
}

static uint32_t qt_wire_id_from_ctr(const uint8_t key[QT_KEY_SIZE], uint32_t ctr)
{
    uint32_t k0 = qt_key32(key, 0);
    uint32_t k1 = qt_key32(key, 1);
    uint32_t k2 = qt_key32(key, 2);

    return qt_mix32(ctr ^ k0) ^ qt_mix32((ctr + k1) ^ k2);
}

static uint32_t qt_mask_word(const uint8_t key[QT_KEY_SIZE], uint32_t wire_id,
                             const picoquic_connection_id_t *dcid, uint32_t payload_len,
                             uint32_t word_idx)
{
    uint32_t x = wire_id;
    x ^= qt_key32(key, 3 + word_idx);
    x ^= qt_mix32(payload_len ^ qt_key32(key, 7 - word_idx));
    x ^= qt_dcid_mix(dcid);
    x ^= 0x517cc1b7U + word_idx * 0x9e3779b9U;
    return qt_mix32(x);
}

static void qt_xor_mask16(uint8_t *p, const uint8_t key[QT_KEY_SIZE], uint32_t wire_id,
                          const picoquic_connection_id_t *dcid, uint32_t payload_len)
{
    for (uint32_t i = 0; i < 4; i++) {
        uint32_t w = qt_load32_le(p + i * 4);
        w ^= qt_mask_word(key, wire_id, dcid, payload_len, i);
        qt_store32_le(p + i * 4, w);
    }
}

static uint32_t qt_tag32(const uint8_t key[QT_KEY_SIZE], uint32_t wire_id,
                         const picoquic_connection_id_t *dcid, uint32_t payload_len,
                         const uint8_t *masked16)
{
    uint32_t x = 0xa5b35705U;

    x ^= wire_id;
    x ^= qt_key32(key, 4);
    x ^= qt_mix32(payload_len ^ qt_key32(key, 5));
    x ^= qt_dcid_mix(dcid);

    for (uint32_t i = 0; i < 4; i++) {
        x ^= qt_mix32(qt_load32_le(masked16 + i * 4) ^ qt_key32(key, i));
        x = qt_mix32(x + 0x9e3779b9U + i);
    }

    return qt_mix32(x ^ qt_key32(key, 6));
}

static int32_t qt_data_mask(uint8_t *data_hdr, uint32_t payload_len,
                            const picoquic_connection_id_t *dcid, const uint8_t key[QT_KEY_SIZE],
                            uint32_t *send_ctr, uint32_t *wire_id_out)
{
    if (payload_len < QT_MASK_SIZE) {
        return 0;
    }

    uint32_t ctr = ++(*send_ctr);
    if (ctr == 0) {
        return 0;
    }

    uint32_t wire_id = qt_wire_id_from_ctr(key, ctr);
    uint8_t *masked16 = data_hdr + QT_DATA_HDR_SIZE;

    qt_xor_mask16(masked16, key, wire_id, dcid, payload_len);

    uint32_t tag = qt_tag32(key, wire_id, dcid, payload_len, masked16);
    qt_store32_le(data_hdr, wire_id);
    qt_store32_le(data_hdr + QT_WIRE_ID_SIZE, tag);

    if (wire_id_out) {
        *wire_id_out = wire_id;
    }

    return 1;
}

static int32_t qt_data_unmask(uint8_t *data_hdr, uint32_t payload_len,
                              const picoquic_connection_id_t *dcid, const uint8_t key[QT_KEY_SIZE])
{
    if (payload_len < QT_MASK_SIZE) {
        return 0;
    }

    uint32_t wire_id = qt_load32_le(data_hdr);
    uint32_t tag = qt_load32_le(data_hdr + QT_WIRE_ID_SIZE);
    uint8_t *masked16 = data_hdr + QT_DATA_HDR_SIZE;
    uint32_t expected = qt_tag32(key, wire_id, dcid, payload_len, masked16);

    if (tag != expected) {
        return 0;
    }

    qt_xor_mask16(masked16, key, wire_id, dcid, payload_len);
    return 1;
}

/* ===================== connection setup ===================== */

static void add_connect_client(connects_client_t *connect_c, picoquic_quic_t *quic)
{
    picoquic_connection_id_t icid = picoquic_null_connection_id;
    picoquic_connection_id_t rcid = picoquic_null_connection_id;
    uint64_t now = picoquic_current_time();

    picoquic_cnx_t *client_cnx =
        picoquic_create_cnx(quic, icid, rcid, (struct sockaddr *)&cfg_global.endpoint_quic_addr.ss,
                            now, 0, cfg_global.sni, SERVER_ALPN, 1);

    if (!client_cnx) {
        return;
    }

    picoquic_enable_keep_alive(client_cnx, 0);
    picoquic_start_client_cnx(client_cnx);

    connect_c->client_cnx = client_cnx;

    connect_c->to_server_quic_sock =
        make_udp_socket(netaddr_family(&cfg_global.endpoint_quic_addr));
    if (connect_c->to_server_quic_sock < 0) {
        return;
    }

    if (connect(connect_c->to_server_quic_sock,
                (struct sockaddr *)&cfg_global.endpoint_quic_addr.ss,
                cfg_global.endpoint_quic_addr.len) < 0) {
        return;
    }

    struct sockaddr_storage tmp_local;
    socklen_t quic_client_addr_len = sizeof(tmp_local);
    memset(&tmp_local, 0, sizeof(tmp_local));

    if (getsockname(connect_c->to_server_quic_sock, (struct sockaddr *)&tmp_local,
                    &quic_client_addr_len) == 0) {
        netaddr_from_sockaddr(&connect_c->to_server_quic_local_addr, (struct sockaddr *)&tmp_local,
                              quic_client_addr_len);
    }

    picoquic_connection_id_t remote_dcid = picoquic_get_remote_cnxid(connect_c->client_cnx);
    picoquic_connection_id_t local_dcid = picoquic_get_local_cnxid(connect_c->client_cnx);

    memcpy(&connect_c->remote_dcid, &remote_dcid, sizeof(remote_dcid));
    memcpy(&connect_c->local_dcid, &local_dcid, sizeof(local_dcid));
}

static void append_connect_client(connects_client_t *connect_c)
{
    picoquic_connection_id_t remote_dcid = picoquic_get_remote_cnxid(connect_c->client_cnx);
    picoquic_connection_id_t local_dcid = picoquic_get_local_cnxid(connect_c->client_cnx);

    memcpy(&connect_c->remote_dcid, &remote_dcid, sizeof(remote_dcid));
    memcpy(&connect_c->local_dcid, &local_dcid, sizeof(local_dcid));

    picoquic_export_secret(connect_c->client_cnx, "QUICTun data send v2", connect_c->data_send_key,
                           QT_KEY_SIZE);

    picoquic_export_secret(connect_c->client_cnx, "QUICTun data recv v2", connect_c->data_recv_key,
                           QT_KEY_SIZE);

    connect_c->data_send_ctr = 0;
}

static void add_connect_server(connects_server_t *connect_s)
{
    picoquic_connection_id_t remote_dcid = picoquic_get_remote_cnxid(connect_s->server_cnx);
    picoquic_connection_id_t local_dcid = picoquic_get_local_cnxid(connect_s->server_cnx);

    memcpy(&connect_s->remote_dcid, &remote_dcid, sizeof(remote_dcid));
    memcpy(&connect_s->local_dcid, &local_dcid, sizeof(local_dcid));

    picoquic_export_secret(connect_s->server_cnx, "QUICTun data recv v2", connect_s->data_send_key,
                           QT_KEY_SIZE);

    picoquic_export_secret(connect_s->server_cnx, "QUICTun data send v2", connect_s->data_recv_key,
                           QT_KEY_SIZE);

    connect_s->data_send_ctr = 0;

    struct sockaddr *peer = NULL;
    picoquic_get_peer_addr(connect_s->server_cnx, &peer);
    if (peer) {
        netaddr_from_sockaddr(&connect_s->to_client_quic_addr, peer,
                              sockaddr_len_by_family(peer->sa_family));
    }

    connect_s->to_wg_sock = make_udp_socket(netaddr_family(&connect_s->to_wg_addr));
    if (connect_s->to_wg_sock < 0) {
        return;
    }

    if (connect(connect_s->to_wg_sock, (struct sockaddr *)&connect_s->to_wg_addr.ss,
                connect_s->to_wg_addr.len) < 0) {
        close(connect_s->to_wg_sock);
        connect_s->to_wg_sock = -1;
        return;
    }
}

static void free_connect_client(connects_client_t *c)
{
    pending_wg_clear(c);

    if (c->to_server_quic_sock >= 0) {
        close(c->to_server_quic_sock);
    }

    if (c->client_cnx) {
        picoquic_delete_cnx(c->client_cnx);
    }

    memset(c, 0, sizeof(*c));
    c->to_server_quic_sock = -1;
}

static void free_connect_server(connects_server_t *s)
{
    if (s->to_wg_sock >= 0) {
        close(s->to_wg_sock);
    }
}

/* ===================== picoquic callbacks ===================== */

static int32_t quic_conn_event_client(picoquic_cnx_t *cnx, uint64_t stream_id, uint8_t *bytes,
                                      size_t length, picoquic_call_back_event_t event,
                                      void *callback_ctx, void *v_stream_ctx)
{
    (void)stream_id;
    (void)bytes;
    (void)length;
    (void)callback_ctx;
    (void)v_stream_ctx;

    if (event == picoquic_callback_ready) {
        connects_client_t *connect_c = find_connect_cnx_client(cnx);
        if (!connect_c) {
            return 0;
        }

        append_connect_client(connect_c);
        logids("Client connected\n", &connect_c->remote_dcid, &connect_c->local_dcid);
        return 0;
    }

    if (event == picoquic_callback_close) {
        connects_client_t *connect_c = find_connect_cnx_client(cnx);
        if (!connect_c) {
            return 0;
        }

        del_mark = 1;
        connect_c->del_mark = 1;

        logids("Client disconnected\n", &connect_c->remote_dcid, &connect_c->local_dcid);
        return 0;
    }

    return 0;
}

static int32_t quic_conn_event_server(picoquic_cnx_t *cnx, uint64_t stream_id, uint8_t *bytes,
                                      size_t length, picoquic_call_back_event_t event,
                                      void *callback_ctx, void *v_stream_ctx)
{
    (void)stream_id;
    (void)bytes;
    (void)length;
    (void)callback_ctx;
    (void)v_stream_ctx;

    if (event == picoquic_callback_ready) {
        int32_t peer_id = find_verified_peer_id(cnx);
        if (peer_id < 0) {
            picoquic_close(cnx, 0);
            return 0;
        }

        if (connects_server_n < MAX_PEERS_COUNT) {
            connects_server_t *connect_s = &connects_server[connects_server_n++];

            memset(connect_s, 0, sizeof(*connect_s));
            connect_s->to_wg_sock = -1;
            connect_s->server_cnx = cnx;
            connect_s->peer_id = peer_id;
            netaddr_copy(&connect_s->to_wg_addr, &peers[peer_id].wg_endpoint_addr);

            log_peer_match("Connection bound", peer_id, peers[peer_id].cert_hash,
                           &connect_s->to_wg_addr);

            add_connect_server(connect_s);

            logids("Client connected\n", &connect_s->remote_dcid, &connect_s->local_dcid);
        }

        return 0;
    }

    if (event == picoquic_callback_close) {
        connects_server_t *connect_s = find_connect_cnx_server(cnx);
        if (connect_s) {
            log_peer_match("Connection closing", connect_s->peer_id,
                           (connect_s->peer_id >= 0 && connect_s->peer_id < peers_n) ?
                               peers[connect_s->peer_id].cert_hash :
                               "(unknown)",
                           &connect_s->to_wg_addr);

            del_mark = 1;
            connect_s->del_mark = 1;

            logids("Client disconnected\n", &connect_s->remote_dcid, &connect_s->local_dcid);
        }

        unbind_verified_peer(cnx);
        return 0;
    }

    return 0;
}

/* ===================== packet decrypt dispatch ===================== */

static int32_t wg_hdr_try_decrypt_client(char *recv_buf, ssize_t bytes_recv, int32_t wg_client_sock,
                                         tx_queue_t *txq)
{
    connects_client_t *connect_c = NULL;

    for (int32_t i = 0; i < connects_client_n; i++) {
        connects_client_t *connect_tmp = &connects_client[i];

        if (!connect_tmp->client_cnx) {
            continue;
        }

        if (picoquic_get_cnx_state(connect_tmp->client_cnx) != picoquic_state_ready) {
            continue;
        }

        int32_t data_offset = FIRST_BYTE_SIZE + connect_tmp->local_dcid.id_len;
        int32_t payload_offset = data_offset + QT_DATA_HDR_SIZE;

        if (bytes_recv < payload_offset + QT_MASK_SIZE) {
            continue;
        }

        if (memcmp(recv_buf + FIRST_BYTE_SIZE, connect_tmp->local_dcid.id,
                   connect_tmp->local_dcid.id_len) != 0) {
            continue;
        }

        if (qt_data_unmask((uint8_t *)recv_buf + data_offset,
                           (uint32_t)(bytes_recv - payload_offset), &connect_tmp->local_dcid,
                           connect_tmp->data_recv_key)) {
            connect_c = connect_tmp;
        }

        break;
    }

    if (!connect_c) {
        return 0;
    }

    int32_t payload_offset = FIRST_BYTE_SIZE + connect_c->local_dcid.id_len + QT_DATA_HDR_SIZE;
    size_t payload_len = (size_t)(bytes_recv - payload_offset);

    tx_queue_push(txq, wg_client_sock, recv_buf + payload_offset, payload_len,
                  (struct sockaddr *)&connect_c->to_wg_addr.ss, connect_c->to_wg_addr.len,
                  TX_STAT_SENDTO_WG);

    return 1;
}

static int32_t wg_hdr_try_decrypt_server(char *recv_buf, ssize_t bytes_recv, tx_queue_t *txq)
{
    connects_server_t *connect_s = NULL;

    for (int32_t i = 0; i < connects_server_n; i++) {
        connects_server_t *connect_tmp = &connects_server[i];

        int32_t data_offset = FIRST_BYTE_SIZE + connect_tmp->local_dcid.id_len;
        int32_t payload_offset = data_offset + QT_DATA_HDR_SIZE;

        if (bytes_recv < payload_offset + QT_MASK_SIZE) {
            continue;
        }

        if (memcmp(recv_buf + FIRST_BYTE_SIZE, connect_tmp->local_dcid.id,
                   connect_tmp->local_dcid.id_len) != 0) {
            continue;
        }

        if (qt_data_unmask((uint8_t *)recv_buf + data_offset,
                           (uint32_t)(bytes_recv - payload_offset), &connect_tmp->local_dcid,
                           connect_tmp->data_recv_key)) {
            connect_s = connect_tmp;
        }

        break;
    }

    if (!connect_s) {
        return 0;
    }

    int32_t payload_offset = FIRST_BYTE_SIZE + connect_s->local_dcid.id_len + QT_DATA_HDR_SIZE;
    size_t payload_len = (size_t)(bytes_recv - payload_offset);

    tx_queue_push(txq, connect_s->to_wg_sock, recv_buf + payload_offset, payload_len, NULL, 0,
                  TX_STAT_SENDTO_WG);

    return 1;
}

/* ===================== quic rx/tx ===================== */

static void quic_rx_dispatch_client(connects_client_t *connect_c, int32_t wg_client_sock,
                                    picoquic_quic_t *quic, tx_queue_t *txq)
{
    rx_batch_t batch;
    int32_t n = rx_batch_recv(connect_c->to_server_quic_sock, &batch, 0);

    if (n < 0) {
        errno = -n;
        ERRNO_ADD(recvfrom_quic);
        return;
    }

    for (int32_t i = 0; i < n; i++) {
        char *recv_buf = (char *)batch.bufs[i];
        ssize_t bytes_recv = (ssize_t)batch.msgs[i].msg_len;
        struct sockaddr_storage *addr_from = &batch.addrs[i];

        if (wg_hdr_try_decrypt_client(recv_buf, bytes_recv, wg_client_sock, txq)) {
            STAT_ADD(recvfrom_new_quic, bytes_recv);
            continue;
        }

        STAT_ADD(recvfrom_quic, bytes_recv);

        uint64_t now = picoquic_current_time();
        int32_t rc = picoquic_incoming_packet(
            quic, (uint8_t *)recv_buf, (size_t)bytes_recv, (struct sockaddr *)addr_from,
            (struct sockaddr *)&connect_c->to_server_quic_local_addr.ss, 0, 0, now);

        if (rc != 0) {
            STAT_ADD(quic_in_drop, bytes_recv);
        } else {
            STAT_ADD(quic_in, bytes_recv);
        }
    }
}

static void quic_rx_dispatch_server(int32_t quic_sock, picoquic_quic_t *quic, tx_queue_t *txq)
{
    rx_batch_t batch;
    int32_t n = rx_batch_recv(quic_sock, &batch, 0);

    if (n < 0) {
        errno = -n;
        ERRNO_ADD(recvfrom_quic);
        return;
    }

    for (int32_t i = 0; i < n; i++) {
        char *recv_buf = (char *)batch.bufs[i];
        ssize_t bytes_recv = (ssize_t)batch.msgs[i].msg_len;
        struct sockaddr_storage *addr_from = &batch.addrs[i];

        if (wg_hdr_try_decrypt_server(recv_buf, bytes_recv, txq)) {
            STAT_ADD(recvfrom_new_quic, bytes_recv);
            continue;
        }

        STAT_ADD(recvfrom_quic, bytes_recv);

        uint64_t now = picoquic_current_time();
        int32_t rc = picoquic_incoming_packet(quic, (uint8_t *)recv_buf, (size_t)bytes_recv,
                                              (struct sockaddr *)addr_from,
                                              (struct sockaddr *)&cfg_global.listen_quic_addr.ss, 0,
                                              0, now);

        if (rc != 0) {
            STAT_ADD(quic_in_drop, bytes_recv);
        } else {
            STAT_ADD(quic_in, bytes_recv);
        }
    }
}

static int32_t quic_tx_prepare_client_once(picoquic_quic_t *quic, tx_queue_t *txq)
{
    uint8_t send_buf[PICOQUIC_MAX_PACKET_SIZE];
    struct sockaddr_storage addr_to;
    struct sockaddr_storage addr_from;
    int32_t if_index = 0;
    size_t send_length = 0;
    picoquic_cnx_t *prepared_cnx = NULL;

    memset(&addr_to, 0, sizeof(addr_to));
    memset(&addr_from, 0, sizeof(addr_from));

    uint64_t now = picoquic_current_time();
    int32_t rc = picoquic_prepare_next_packet(quic, now, send_buf, sizeof(send_buf), &send_length,
                                              &addr_to, &addr_from, &if_index, NULL, &prepared_cnx);

    if (rc != 0 || send_length == 0) {
        return 0;
    }

    connects_client_t *connect_c = find_connect_cnx_client(prepared_cnx);
    if (!connect_c) {
        return 0;
    }

    tx_queue_push(txq, connect_c->to_server_quic_sock, send_buf, send_length,
                  (struct sockaddr *)&addr_to, sockaddr_len_from_storage(&addr_to),
                  TX_STAT_SENDTO_QUIC);

    return 1;
}

static void quic_tx_fill_client(picoquic_quic_t *quic, tx_queue_t *txq)
{
    for (int32_t i = 0; i < QT_TX_BATCH_SIZE; i++) {
        if (!quic_tx_prepare_client_once(quic, txq)) {
            break;
        }
    }
}

static int32_t quic_tx_prepare_server_once(int32_t udp_sock, picoquic_quic_t *quic, tx_queue_t *txq)
{
    uint8_t send_buf[PICOQUIC_MAX_PACKET_SIZE];
    struct sockaddr_storage addr_to;
    struct sockaddr_storage addr_from;
    int32_t if_index = 0;
    size_t send_length = 0;
    picoquic_cnx_t *prepared_cnx = NULL;

    memset(&addr_to, 0, sizeof(addr_to));
    memset(&addr_from, 0, sizeof(addr_from));

    uint64_t now = picoquic_current_time();
    int32_t rc = picoquic_prepare_next_packet(quic, now, send_buf, sizeof(send_buf), &send_length,
                                              &addr_to, &addr_from, &if_index, NULL, &prepared_cnx);

    if (rc != 0 || send_length == 0) {
        return 0;
    }

    tx_queue_push(txq, udp_sock, send_buf, send_length, (struct sockaddr *)&addr_to,
                  sockaddr_len_from_storage(&addr_to), TX_STAT_SENDTO_QUIC);

    return 1;
}

static void quic_tx_fill_server(int32_t udp_sock, picoquic_quic_t *quic, tx_queue_t *txq)
{
    for (int32_t i = 0; i < QT_TX_BATCH_SIZE; i++) {
        if (!quic_tx_prepare_server_once(udp_sock, quic, txq)) {
            break;
        }
    }
}

/* ===================== wg rx -> quic ===================== */

static int32_t wg_payload_queue_quic_client(connects_client_t *connect_c, const uint8_t *payload,
                                            size_t payload_len, tx_queue_t *txq)
{
    if (!connect_c || !payload || !txq || payload_len < QT_MASK_SIZE ||
        payload_len > PICOQUIC_MAX_PACKET_SIZE) {
        return -EINVAL;
    }

    int32_t max_payload_offset =
        FIRST_BYTE_SIZE + PICOQUIC_CONNECTION_ID_MAX_SIZE + QT_DATA_HDR_SIZE;
    int32_t real_payload_offset =
        FIRST_BYTE_SIZE + connect_c->remote_dcid.id_len + QT_DATA_HDR_SIZE;

    if ((size_t)real_payload_offset + payload_len > PICOQUIC_MAX_PACKET_SIZE) {
        return -EMSGSIZE;
    }

    uint8_t send_buf[PICOQUIC_MAX_PACKET_SIZE];
    uint8_t *real_begin = send_buf + max_payload_offset - real_payload_offset;

    memcpy(real_begin + real_payload_offset, payload, payload_len);
    memcpy(real_begin + FIRST_BYTE_SIZE, connect_c->remote_dcid.id, connect_c->remote_dcid.id_len);

    uint32_t wire_id = 0;
    if (!qt_data_mask(real_begin + FIRST_BYTE_SIZE + connect_c->remote_dcid.id_len,
                      (uint32_t)payload_len, &connect_c->remote_dcid, connect_c->data_send_key,
                      &connect_c->data_send_ctr, &wire_id)) {
        return -EINVAL;
    }

    real_begin[0] = make_quic_short_header_byte(wire_id);

    return tx_queue_push(txq, connect_c->to_server_quic_sock, real_begin,
                         payload_len + (size_t)real_payload_offset, NULL, 0,
                         TX_STAT_SENDTO_NEW_QUIC);
}

static void pending_wg_flush_client(connects_client_t *c, tx_queue_t *txq)
{
    if (!c || !txq || !c->client_cnx ||
        picoquic_get_cnx_state(c->client_cnx) != picoquic_state_ready) {
        return;
    }

    uint64_t now_us = picoquic_current_time();
    pending_wg_prune_expired(c, now_us);

    while (c->pending_wg_count > 0) {
        pending_wg_pkt_t *p = &c->pending_wg[c->pending_wg_head];
        int32_t rc = wg_payload_queue_quic_client(c, p->data, p->len, txq);
        if (rc != 0) {
            break;
        }

        if (c->pending_wg_bytes >= p->len) {
            c->pending_wg_bytes -= p->len;
        } else {
            c->pending_wg_bytes = 0;
        }

        memset(p, 0, sizeof(*p));
        c->pending_wg_head = (c->pending_wg_head + 1) % QT_PENDING_WG_MAX;
        c->pending_wg_count--;
    }
}

static void pending_wg_flush_all_clients(tx_queue_t *txq)
{
    for (int32_t i = 0; i < connects_client_n; i++) {
        pending_wg_flush_client(&connects_client[i], txq);
    }
}

static void wg_rx_send_quic_client(int32_t wg_client_sock, picoquic_quic_t *quic, tx_queue_t *txq)
{
    int32_t payload_offset = FIRST_BYTE_SIZE + PICOQUIC_CONNECTION_ID_MAX_SIZE + QT_DATA_HDR_SIZE;
    rx_batch_t batch;
    int32_t n = rx_batch_recv(wg_client_sock, &batch, (size_t)payload_offset);

    if (n < 0) {
        errno = -n;
        ERRNO_ADD(recvfrom_wg);
        return;
    }

    for (int32_t i = 0; i < n; i++) {
        uint8_t *payload = batch.bufs[i] + payload_offset;
        ssize_t bytes_recv = (ssize_t)batch.msgs[i].msg_len;
        struct sockaddr_storage *from_wg_client_to_quic_server_addr = &batch.addrs[i];
        socklen_t from_wg_client_to_quic_server_addr_len = batch.msgs[i].msg_hdr.msg_namelen;

        STAT_ADD(recvfrom_wg, bytes_recv);

        netaddr_t from_wg_addr;
        if (netaddr_from_sockaddr(&from_wg_addr,
                                  (struct sockaddr *)from_wg_client_to_quic_server_addr,
                                  from_wg_client_to_quic_server_addr_len) != 0) {
            STAT_ADD(recvfrom_wg_drop, bytes_recv);
            continue;
        }

        if (bytes_recv < QT_MASK_SIZE) {
            STAT_ADD(recvfrom_wg_drop_encrypt, bytes_recv);
            continue;
        }

        connects_client_t *connect_c = find_connect_addr_client(&from_wg_addr);
        uint64_t now_us = picoquic_current_time();

        if (!connect_c) {
            if (connects_client_n < MAX_PEERS_COUNT) {
                connect_c = &connects_client[connects_client_n++];
                memset(connect_c, 0, sizeof(*connect_c));
                connect_c->to_server_quic_sock = -1;
                netaddr_copy(&connect_c->to_wg_addr, &from_wg_addr);

                add_connect_client(connect_c, quic);

                logids("Client created\n", &connect_c->remote_dcid, &connect_c->local_dcid);
            }

            if (!connect_c || !connect_c->client_cnx || connect_c->to_server_quic_sock < 0) {
                STAT_ADD(recvfrom_wg_drop, bytes_recv);
                continue;
            }

            if (pending_wg_push(connect_c, payload, (size_t)bytes_recv, &from_wg_addr, now_us) !=
                0) {
                STAT_ADD(recvfrom_wg_drop, bytes_recv);
            }
            continue;
        }

        pending_wg_prune_expired(connect_c, now_us);

        if (!connect_c->client_cnx ||
            picoquic_get_cnx_state(connect_c->client_cnx) != picoquic_state_ready) {
            if (pending_wg_push(connect_c, payload, (size_t)bytes_recv, &from_wg_addr, now_us) !=
                0) {
                STAT_ADD(recvfrom_wg_drop, bytes_recv);
            }
            continue;
        }

        connect_c->used_mark = 1;

        pending_wg_flush_client(connect_c, txq);

        if (wg_payload_queue_quic_client(connect_c, payload, (size_t)bytes_recv, txq) != 0) {
            STAT_ADD(recvfrom_wg_drop_encrypt, bytes_recv);
            continue;
        }
    }
}

static void wg_rx_send_quic_server(connects_server_t *connect_s, int32_t quic_server_sock,
                                   tx_queue_t *txq)
{
    int32_t payload_offset = FIRST_BYTE_SIZE + PICOQUIC_CONNECTION_ID_MAX_SIZE + QT_DATA_HDR_SIZE;
    rx_batch_t batch;
    int32_t n = rx_batch_recv(connect_s->to_wg_sock, &batch, (size_t)payload_offset);

    if (n < 0) {
        errno = -n;
        ERRNO_ADD(recvfrom_wg);
        return;
    }

    for (int32_t i = 0; i < n; i++) {
        char *recv_buf = (char *)batch.bufs[i];
        ssize_t bytes_recv = (ssize_t)batch.msgs[i].msg_len;

        STAT_ADD(recvfrom_wg, bytes_recv);

        if (bytes_recv < QT_MASK_SIZE) {
            STAT_ADD(recvfrom_wg_drop_encrypt, bytes_recv);
            continue;
        }

        char *real_begin = recv_buf + payload_offset - QT_DATA_HDR_SIZE -
                           connect_s->remote_dcid.id_len - FIRST_BYTE_SIZE;

        int32_t real_payload_offset =
            FIRST_BYTE_SIZE + connect_s->remote_dcid.id_len + QT_DATA_HDR_SIZE;

        memcpy(real_begin + FIRST_BYTE_SIZE, connect_s->remote_dcid.id,
               connect_s->remote_dcid.id_len);

        uint32_t wire_id = 0;
        if (!qt_data_mask((uint8_t *)real_begin + FIRST_BYTE_SIZE + connect_s->remote_dcid.id_len,
                          (uint32_t)bytes_recv, &connect_s->remote_dcid, connect_s->data_send_key,
                          &connect_s->data_send_ctr, &wire_id)) {
            STAT_ADD(recvfrom_wg_drop_encrypt, bytes_recv);
            continue;
        }

        real_begin[0] = (char)make_quic_short_header_byte(wire_id);

        tx_queue_push(txq, quic_server_sock, real_begin, (size_t)(bytes_recv + real_payload_offset),
                      (struct sockaddr *)&connect_s->to_client_quic_addr.ss,
                      connect_s->to_client_quic_addr.len, TX_STAT_SENDTO_NEW_QUIC);
    }
}

/* ===================== main ===================== */

int32_t main(int32_t argc, char *argv[])
{
    printf("--------------------------------------------\n");
    printf("QUICTun " QUICTUN_VERSION "\n");
    printf("--------------------------------------------\n");

    if (signal(SIGINT, main_catch_function) == SIG_ERR) {
        errmsg("Can't set SIGINT signal handler main\n");
    }

    if (signal(SIGTERM, main_catch_function) == SIG_ERR) {
        errmsg("Can't set SIGTERM signal handler main\n");
    }

    if (signal(SIGHUP, main_catch_function) == SIG_ERR) {
        errmsg("Can't set SIGHUP signal handler main\n");
    }

    if (argc != 2) {
        errmsg("Usage %s <config.conf>\n", argv[0]);
    }

    if (quictun_config_load_file(&cfg_global, argv[1]) != 0) {
        errmsg("Config parse failed\n");
    }

    quictun_config_log(&cfg_global);

    if (!cfg_global.have_certs_path) {
        errmsg("CertsPath is required\n");
    }

    if (!cfg_global.have_sni) {
        errmsg("SNI is required\n");
    }

    int32_t client_mode = cfg_global.have_quic_endpoint && cfg_global.have_wg_listen;
    int32_t server_mode = cfg_global.have_quic_listen;

    if (client_mode && server_mode) {
        errmsg("Choose exactly one mode\n");
    }

    if (!client_mode && !server_mode) {
        errmsg("Choose exactly one mode:\n"
               "    client: [Interface] QuicEndpoint + WgListen\n"
               "    server: [Interface] QuicListen + [Peer]...\n");
    }

    if (server_mode && peers_n == 0) {
        errmsg("Server mode requires at least one [Peer]\n");
    }

    int32_t work_mode = client_mode ? CLIENT_MODE : SERVER_MODE;
    if (work_mode == CLIENT_MODE) {
        printf("Client mode\n");
    } else {
        printf("Server mode\n");
    }

    if (cfg_global.have_log_path) {
        log_file = fopen(cfg_global.log_path, "w");
        if (!log_file) {
            errmsg("Can't open LogPath\n");
        }
    }

    if (cfg_global.have_stat_path) {
        stat_file = fopen(cfg_global.stat_path, "w");
        if (!stat_file) {
            errmsg("Can't open StatPath\n");
        }
    }

    int32_t quic_server_sock = -1;
    int32_t wg_client_sock = -1;

    if (work_mode == CLIENT_MODE) {
        wg_client_sock = make_udp_socket(netaddr_family(&cfg_global.listen_wg_addr));
        if (wg_client_sock < 0) {
            errmsg("Can't create wg socket \"%s\"\n", strerror(-wg_client_sock));
        }

        if (bind(wg_client_sock, (struct sockaddr *)&cfg_global.listen_wg_addr.ss,
                 cfg_global.listen_wg_addr.len) < 0) {
            errmsg("Can't bind to wg listen \"%s\"\n", strerror(errno));
        }
    } else {
        quic_server_sock = make_udp_socket(netaddr_family(&cfg_global.listen_quic_addr));
        if (quic_server_sock < 0) {
            errmsg("Can't create quic socket \"%s\"\n", strerror(-quic_server_sock));
        }

        if (bind(quic_server_sock, (struct sockaddr *)&cfg_global.listen_quic_addr.ss,
                 cfg_global.listen_quic_addr.len) < 0) {
            errmsg("Can't bind to quic listen \"%s\"\n", strerror(errno));
        }
    }

    char cert_path[PATH_MAX];
    snprintf(cert_path, PATH_MAX, "%s/cert.pem", cfg_global.certs_path);

    char cert_key_path[PATH_MAX];
    snprintf(cert_key_path, PATH_MAX, "%s/cert.key", cfg_global.certs_path);

    char ca_cert_path[PATH_MAX];
    snprintf(ca_cert_path, PATH_MAX, "%s/ca.pem", cfg_global.certs_path);

    uint64_t now = picoquic_current_time();
    picoquic_quic_t *quic = NULL;

    if (work_mode == CLIENT_MODE) {
        quic = picoquic_create(MAX_PEERS_COUNT, cert_path, cert_key_path, ca_cert_path, SERVER_ALPN,
                               quic_conn_event_client, NULL, NULL, NULL, NULL, now, NULL, NULL,
                               NULL, 0);
    } else {
        quic = picoquic_create(MAX_PEERS_COUNT, cert_path, cert_key_path, ca_cert_path, SERVER_ALPN,
                               quic_conn_event_server, NULL, NULL, NULL, NULL, now, NULL, NULL,
                               NULL, 0);
    }

    if (quic == NULL) {
        errmsg("Picoquic create failed\n");
    }

    picoquic_set_use_exporter(quic, 1);
    picoquic_set_default_idle_timeout(quic, 1000);

    if (work_mode == SERVER_MODE) {
        memset(&g_override_cb, 0, sizeof(g_override_cb));
        g_override_cb.cb = on_verified_cert;

        g_store = make_store_from_ca(ca_cert_path);
        if (!g_store) {
            errmsg("make_store_from_ca failed\n");
        }

        ptls_openssl_init_verify_certificate(&g_verifier, g_store);
        g_verifier.override_callback = &g_override_cb;

        picoquic_set_verify_certificate_callback(quic, &g_verifier.super, NULL);
        picoquic_set_client_authentication(quic, 1);
    } else {
        picoquic_enforce_client_only(quic, 1);
    }

    if (log_file) {
        time_t now_ts = time(NULL);
        struct tm tm_now;
        localtime_r(&now_ts, &tm_now);

        fprintf(log_file, "[%02d:%02d:%02d] Loop started\n\n", tm_now.tm_hour, tm_now.tm_min,
                tm_now.tm_sec);
    }

    time_t last_fflush_ts = time(NULL);
    static tx_queue_t txq;

#ifdef DEPLOY
    struct mallinfo2 mi = mallinfo2();
    printf("heap=%zu used=%zu\n", mi.arena, mi.uordblks);
#endif

    while (!exit_flag) {
        tx_queue_reset(&txq);
        time_t now_ts = time(NULL);
        if (now_ts != (time_t)-1 && (now_ts - last_fflush_ts) >= FFLUSH_DELAY) {
            stat_print();

            fflush(stdout);
            if (log_file) {
                fflush(log_file);
            }
            if (stat_file) {
                fflush(stat_file);
            }

            last_fflush_ts = now_ts;
        }

        if (work_mode == CLIENT_MODE) {
            struct pollfd socks[1 + MAX_PEERS_COUNT];
            int32_t nsocks = 0;

            socks[nsocks].fd = wg_client_sock;
            socks[nsocks].events = POLLIN;
            nsocks++;

            for (int32_t i = 0; i < connects_client_n; i++) {
                socks[nsocks].fd = connects_client[i].to_server_quic_sock;
                socks[nsocks].events = POLLIN;
                nsocks++;
            }

            int32_t rc = poll(socks, nsocks, 1);
            if (rc > 0) {
                if (socks[0].revents & POLLIN) {
                    wg_rx_send_quic_client(wg_client_sock, quic, &txq);
                }

                for (int32_t i = 0; i < nsocks - 1; i++) {
                    if (socks[i + 1].revents & POLLIN) {
                        quic_rx_dispatch_client(&connects_client[i], wg_client_sock, quic, &txq);
                    }
                }
            }

            quic_tx_fill_client(quic, &txq);
            pending_wg_flush_all_clients(&txq);
            tx_queue_flush(&txq);

            if (del_mark) {
                for (int32_t i = 0; i < connects_client_n;) {
                    if (!connects_client[i].del_mark) {
                        i++;
                        continue;
                    }

                    logids("Client deleted\n", &connects_client[i].remote_dcid,
                           &connects_client[i].local_dcid);

                    free_connect_client(&connects_client[i]);

                    connects_client_n--;
                    if (i != connects_client_n) {
                        connects_client[i] = connects_client[connects_client_n];
                    }
                    memset(&connects_client[connects_client_n], 0, sizeof(connects_client[0]));
                    connects_client[connects_client_n].to_server_quic_sock = -1;
                }

                del_mark = 0;
            }

            for (int32_t i = 0; i < connects_client_n; i++) {
                uint64_t age_us = picoquic_current_time() -
                                  picoquic_get_cnx_start_time(connects_client[i].client_cnx);

                if (age_us > MAX_CNX_TTL * S_TO_MICROS * EARLY_START &&
                    !connects_client[i].prefetch_mark && connects_client[i].used_mark) {
                    connects_client[i].prefetch_mark = 1;

                    if (connects_client_n < MAX_PEERS_COUNT) {
                        connects_client_t *connect_c_new = &connects_client[connects_client_n++];

                        memset(connect_c_new, 0, sizeof(*connect_c_new));
                        connect_c_new->to_server_quic_sock = -1;
                        netaddr_copy(&connect_c_new->to_wg_addr, &connects_client[i].to_wg_addr);

                        add_connect_client(connect_c_new, quic);

                        logids("Client prefetch created\n", &connect_c_new->remote_dcid,
                               &connect_c_new->local_dcid);
                    }
                }

                if (age_us > MAX_CNX_TTL * S_TO_MICROS * LATE_START &&
                    !connects_client[i].timeout_mark) {
                    connects_client[i].timeout_mark = 1;

                    logids("Client timeout\n", &connects_client[i].remote_dcid,
                           &connects_client[i].local_dcid);

                    picoquic_close(connects_client[i].client_cnx, 0);
                }
            }
        } else {
            struct pollfd socks[1 + MAX_PEERS_COUNT];
            int32_t nsocks = 0;

            socks[nsocks].fd = quic_server_sock;
            socks[nsocks].events = POLLIN;
            nsocks++;

            for (int32_t i = 0; i < connects_server_n; i++) {
                socks[nsocks].fd = connects_server[i].to_wg_sock;
                socks[nsocks].events = POLLIN;
                nsocks++;
            }

            int32_t rc = poll(socks, nsocks, 1);
            if (rc > 0) {
                if (socks[0].revents & POLLIN) {
                    quic_rx_dispatch_server(quic_server_sock, quic, &txq);
                }

                for (int32_t i = 0; i < nsocks - 1; i++) {
                    if (socks[i + 1].revents & POLLIN) {
                        wg_rx_send_quic_server(&connects_server[i], quic_server_sock, &txq);
                    }
                }
            }

            quic_tx_fill_server(quic_server_sock, quic, &txq);
            tx_queue_flush(&txq);

            if (del_mark) {
                for (int32_t i = 0; i < connects_server_n;) {
                    if (!connects_server[i].del_mark) {
                        i++;
                        continue;
                    }

                    logids("Client deleted\n", &connects_server[i].remote_dcid,
                           &connects_server[i].local_dcid);

                    free_connect_server(&connects_server[i]);

                    connects_server_n--;
                    if (i != connects_server_n) {
                        connects_server[i] = connects_server[connects_server_n];
                    }
                    memset(&connects_server[connects_server_n], 0, sizeof(connects_server[0]));
                    connects_server[connects_server_n].to_wg_sock = -1;
                }

                del_mark = 0;
            }
        }
    }

#ifdef DEPLOY
    {
        struct mallinfo2 mi = mallinfo2();
        printf("heap=%zu used=%zu\n", mi.arena, mi.uordblks);
    }
#endif

    if (log_file) {
        time_t now_ts = time(NULL);
        struct tm tm_now;
        localtime_r(&now_ts, &tm_now);

        fprintf(log_file, "[%02d:%02d:%02d] Loop finished\n\n", tm_now.tm_hour, tm_now.tm_min,
                tm_now.tm_sec);
    }

    if (g_store) {
        X509_STORE_free(g_store);
        g_store = NULL;
    }

    if (quic_server_sock >= 0) {
        close(quic_server_sock);
    }
    if (wg_client_sock >= 0) {
        close(wg_client_sock);
    }

    picoquic_free(quic);
    cfg_free(&cfg_global);
    peers_free();

    stat_print();

    if (log_file) {
        fclose(log_file);
    }
    if (stat_file) {
        fclose(stat_file);
    }

    printf("QUICTun finished\n");
    return 0;
}
