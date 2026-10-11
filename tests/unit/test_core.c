/*
 * Exercise the production internal helpers without duplicating their logic.
 * The renamed application main is never invoked; link dependencies are the
 * same as for the production executable.
 */
#define main quictun_application_main
#include "../../src/QUICTun.c"
#undef main

#define CHECK(expr)                                                         \
    do {                                                                    \
        if (!(expr)) {                                                      \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr); \
            exit(EXIT_FAILURE);                                             \
        }                                                                   \
    } while (0)

static void test_addresses(void)
{
    netaddr_t a, b;
    CHECK(parse_addrport(" 127.0.0.1:51820 ", &a) == 0);
    CHECK(netaddr_family(&a) == AF_INET);
    CHECK(netaddr_port(&a) == 51820);
    CHECK(!netaddr_is_unspecified(&a));
    CHECK(netaddr_copy(&b, &a) == 0);
    CHECK(netaddr_equal(&a, &b));
    CHECK(parse_addrport("[::1]:443", &b) == 0);
    CHECK(netaddr_family(&b) == AF_INET6);
    CHECK(netaddr_port(&b) == 443);
    CHECK(!netaddr_equal(&a, &b));
    CHECK(parse_addrport("0.0.0.0:123", &b) == 0);
    CHECK(netaddr_is_unspecified(&b));
    CHECK(parse_addrport("[::]:123", &b) == 0);
    CHECK(netaddr_is_unspecified(&b));
    const char *bad[] = { "127.0.0.1",     "127.0.0.1:0",   "127.0.0.1:65536", "127.0.0.1:-1",
                          "127.0.0.1:nan", "127.0.0.1:80x", "::1:443",         "[::1]443",
                          "[::1]:",        "999.1.1.1:53",  "[::1]:70000" };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        CHECK(parse_addrport(bad[i], &b) == -EINVAL);
    }
    printf("PASS: IPv4/IPv6 addresses, copying, equality, and invalid ports\n");
}

static void test_strings(void)
{
    char line[] = "  Value  # ignored";
    strip_comment(line);
    CHECK(strcmp(trim(line), "Value") == 0);
    char *str = NULL;
    CHECK(set_nonempty_string(&str, "  \t") == -EINVAL);
    CHECK(str == NULL);
    CHECK(set_nonempty_string(&str, "  hello") == 0);
    CHECK(strcmp(str, "hello") == 0);
    CHECK(set_string(&str, "world") == 0);
    CHECK(strcmp(str, "world") == 0);
    free(str);
    printf("PASS: config string trimming, comments, and nonempty validation\n");
}

static void test_data_mask(void)
{
    uint8_t key[QT_KEY_SIZE];
    for (size_t i = 0; i < sizeof(key); i++)
        key[i] = (uint8_t)(i * 7u + 1u);
    picoquic_connection_id_t dcid = { 0 };
    dcid.id_len = 8;
    for (unsigned i = 0; i < dcid.id_len; i++)
        dcid.id[i] = (uint8_t)(i + 10);

    const uint32_t sizes[] = { 16, 17, 64, 512, 1200 };
    uint32_t ctr = 0, wid = 0;
    for (size_t n = 0; n < sizeof(sizes) / sizeof(sizes[0]); n++) {
        uint8_t packet[QT_DATA_HDR_SIZE + 1200] = { 0 };
        uint8_t original[1200];
        uint32_t len = sizes[n];
        for (uint32_t i = 0; i < len; i++)
            original[i] = (uint8_t)(i * 13u + n);
        memcpy(packet + QT_DATA_HDR_SIZE, original, len);
        CHECK(qt_data_mask(packet, len, &dcid, key, &ctr, &wid) == 1);
        CHECK(ctr == n + 1);
        CHECK(wid == qt_load32_le(packet));
        uint8_t tampered[sizeof(packet)];
        memcpy(tampered, packet, sizeof(packet));
        tampered[QT_WIRE_ID_SIZE] ^= 1;
        CHECK(qt_data_unmask(tampered, len, &dcid, key) == 0);
        memcpy(tampered, packet, sizeof(packet));
        tampered[QT_DATA_HDR_SIZE] ^= 1;
        CHECK(qt_data_unmask(tampered, len, &dcid, key) == 0);
        uint8_t wrong_key[QT_KEY_SIZE];
        memcpy(wrong_key, key, sizeof(key));
        wrong_key[0] ^= 1;
        memcpy(tampered, packet, sizeof(packet));
        CHECK(qt_data_unmask(tampered, len, &dcid, wrong_key) == 0);
        picoquic_connection_id_t wrong_dcid = dcid;
        wrong_dcid.id[0] ^= 1;
        memcpy(tampered, packet, sizeof(packet));
        CHECK(qt_data_unmask(tampered, len, &wrong_dcid, key) == 0);
        CHECK(qt_data_unmask(packet, len, &dcid, key) == 1);
        CHECK(memcmp(packet + QT_DATA_HDR_SIZE, original, len) == 0);
    }
    uint8_t small[QT_DATA_HDR_SIZE + 15] = { 0 };
    CHECK(qt_data_mask(small, 15, &dcid, key, &ctr, NULL) == 0);
    CHECK(qt_data_unmask(small, 15, &dcid, key) == 0);
    ctr = UINT32_MAX;
    CHECK(qt_data_mask(small, 16, &dcid, key, &ctr, NULL) == 0);
    CHECK(ctr == UINT32_MAX);
    CHECK(qt_data_mask(small, 16, &dcid, key, &ctr, NULL) == 0);
    CHECK(ctr == UINT32_MAX); /* No wrap and no keystream reuse. */
    printf("PASS: data mask round trips, tamper detection, and counter wrap\n");
}

static void test_tx_queue(void)
{
    tx_queue_t *q = calloc(1, sizeof(*q));
    CHECK(q != NULL);
    uint8_t payload[32] = { 42 };
    CHECK(tx_queue_push(q, -1, payload, sizeof(payload), NULL, 0, TX_STAT_SENDTO_WG) == -EINVAL);
    CHECK(tx_queue_push(q, 1, payload, 0, NULL, 0, TX_STAT_SENDTO_WG) == -EINVAL);
    CHECK(q->n == 0);
    struct sockaddr_storage addr = { 0 };
    CHECK(tx_queue_push(q, 1, payload, sizeof(payload), (struct sockaddr *)&addr, sizeof(addr) + 1,
                        TX_STAT_SENDTO_WG) == -EINVAL);
    CHECK(tx_queue_push(q, 1, payload, sizeof(payload), NULL, sizeof(struct sockaddr_in),
                        TX_STAT_SENDTO_WG) == -EINVAL);
    CHECK(q->n == 0);
    for (int i = 0; i < QT_TX_QUEUE_CAP; i++) {
        CHECK(tx_queue_push(q, 1, payload, sizeof(payload), NULL, 0, TX_STAT_SENDTO_WG) == 0);
    }
    CHECK(q->n == QT_TX_QUEUE_CAP);
    CHECK(tx_queue_push(q, 1, payload, sizeof(payload), NULL, 0, TX_STAT_SENDTO_WG) == -ENOBUFS);
    CHECK(q->n == QT_TX_QUEUE_CAP);
    CHECK(memcmp(q->pkts[0].buf, payload, sizeof(payload)) == 0);
    tx_queue_reset(q);
    CHECK(q->n == 0);
    free(q);
    printf("PASS: TX queue boundary and full-queue behavior\n");
}

static void test_tx_flush_socketpair(void)
{
    /* Exercise the actual sendmmsg path rather than only queue bookkeeping. */
    int fds[2] = { -1, -1 };
    CHECK(socketpair(AF_UNIX, SOCK_DGRAM, 0, fds) == 0);
    tx_queue_t *q = calloc(1, sizeof(*q));
    CHECK(q != NULL);
    uint64_t before = data_stat.sendto_wg_ptks;
    uint64_t before_drops = data_stat.sendto_wg_drop_ptks;
    for (uint8_t i = 0; i < 8; i++) {
        uint8_t data[32] = { 0 };
        data[0] = i;
        CHECK(tx_queue_push(q, fds[0], data, sizeof(data), NULL, 0, TX_STAT_SENDTO_WG) == 0);
    }
    tx_queue_flush(q);
    CHECK(q->n == 0);
    CHECK(data_stat.sendto_wg_ptks == before + 8);
    CHECK(data_stat.sendto_wg_drop_ptks == before_drops);
    for (uint8_t i = 0; i < 8; i++) {
        uint8_t data[32];
        CHECK(recv(fds[1], data, sizeof(data), MSG_DONTWAIT) == sizeof(data));
        CHECK(data[0] == i);
    }
    close(fds[0]);
    close(fds[1]);
    free(q);
    puts("PASS: sendmmsg batching and FIFO delivery over a real socketpair");
}

static void test_pending_queue(void)
{
    connects_client_t *c = calloc(1, sizeof(*c));
    CHECK(c != NULL);
    netaddr_t from;
    CHECK(parse_addrport("127.0.0.1:1234", &from) == 0);
    uint8_t payload[32] = { 7 };
    for (int i = 0; i < QT_PENDING_WG_MAX + 8; i++) {
        payload[0] = (uint8_t)i;
        CHECK(pending_wg_push(c, payload, sizeof(payload), &from, 1000000) == 0);
    }
    CHECK(c->pending_wg_count == QT_PENDING_WG_MAX);
    CHECK(c->pending_wg_bytes == QT_PENDING_WG_MAX * sizeof(payload));
    CHECK(c->pending_wg[c->pending_wg_head].data[0] == 8);
    pending_wg_prune_expired(c, 1000000 + QT_PENDING_WG_TTL_US + 1);
    CHECK(c->pending_wg_count == 0);
    CHECK(c->pending_wg_bytes == 0);
    CHECK(pending_wg_push(c, payload, 0, &from, 0) == -EINVAL);
    pending_wg_clear(c);
    CHECK(c->pending_wg_count == 0);
    free(c);
    printf("PASS: pending packets FIFO eviction, expiration, and accounting\n");
}

static void test_failed_client_creation(void)
{
    /* A transport/socket failure must not publish or consume a connection slot. */
    quictun_config_t original = cfg_global;
    connects_client_t c = { 0 };
    c.to_server_quic_sock = -1;
    cfg_global.endpoint_quic_addr.ss.ss_family = AF_UNSPEC;
    cfg_global.endpoint_quic_addr.len = 0;
    /* Invalid UDP family fails before touching the fake PicoQUIC handle. */
    picoquic_quic_t *unused_quic = (picoquic_quic_t *)(void *)&c;
    CHECK(add_connect_client(&c, unused_quic) < 0);
    CHECK(c.client_cnx == NULL);
    CHECK(c.to_server_quic_sock == -1);
    cfg_global = original;
    puts("PASS: failed UDP setup does not publish a partial connection");
}

int main(void)
{
    test_addresses();
    test_strings();
    test_data_mask();
    test_tx_queue();
    test_tx_flush_socketpair();
    test_pending_queue();
    test_failed_client_creation();
    puts("ALL QUICTun C UNIT TESTS PASSED");
    return 0;
}
