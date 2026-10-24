/*
 * Start rendezvous visibility (RNetSessionStats.ready_mask).
 *
 * Three UDP peers over loopback; the third guest starts late. Until it does,
 * the host must stay out of RUNNING and its stats must say which seat it is
 * waiting on: ready_mask lacks that seat and peer_rx_age_ms says nothing was
 * ever heard from it, while the seat that did join is ready and heard. This is
 * what the game logs and shows instead of a silent black screen.
 */
#include "recomp_net/recomp_net.h"

#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <process.h>
static unsigned test_pid(void) { return (unsigned)_getpid(); }
#else
#include <unistd.h>
static unsigned test_pid(void) { return (unsigned)getpid(); }
#endif

static int g_failures;
static rnet_u64 g_now_ms = 1000;

static void fail(const char *message)
{
    fprintf(stderr, "FAIL: %s\n", message);
    g_failures++;
}

static void sample_local(rnet_u32 tick, RNetInputSample *out, void *opaque)
{
    (void)tick;
    (void)opaque;
    memset(out, 0, sizeof(*out));
    out->size = 2;
    out->valid = 1;
}

static void publish(rnet_u32 tick, const RNetInputSample *by_slot, int slots, void *opaque)
{
    (void)tick; (void)by_slot; (void)slots; (void)opaque;
}

static rnet_u64 now_ms(void *opaque)
{
    (void)opaque;
    return g_now_ms;
}

int main(void)
{
    RNetConfig ca, cb, cc;
    RNetHostVTable vt;
    RNetSession *a = NULL, *b = NULL, *c = NULL;
    RNetSessionStats st;
    char bind_a[64], bind_b[64], bind_c[64];
    const unsigned base_port = 46300u + (test_pid() % 900u) * 3u;
    int i;

    memset(&vt, 0, sizeof(vt));
    vt.sample_local = sample_local; vt.publish = publish; vt.now_ms = now_ms;

    rnet_config_init_defaults(&ca);
    ca.slot_count = 3;
    ca.input_delay = 2;
    ca.host_authority = 1;
    ca.session_id = 0x57414954u ^ test_pid();
    cb = ca; cc = ca;
    ca.local_slot = 0; cb.local_slot = 1; cc.local_slot = 2;
    snprintf(bind_a, sizeof(bind_a), "127.0.0.1:%u", base_port);
    snprintf(bind_b, sizeof(bind_b), "127.0.0.1:%u", base_port + 1U);
    snprintf(bind_c, sizeof(bind_c), "127.0.0.1:%u", base_port + 2U);
    a = rnet_session_create(&ca, &vt);
    b = rnet_session_create(&cb, &vt);
    c = rnet_session_create(&cc, &vt);
    if (!a || !b || !c) { fail("session create"); goto done; }
    if (rnet_session_start_lan_hub(a, bind_a) != 0 ||
        rnet_session_start_lan(b, bind_b, bind_a) != 0)
    { fail("LAN start"); goto done; }

    for (i = 0; i < 3000; ++i)
    {
        g_now_ms++;
        rnet_session_pump(a); rnet_session_pump(b);
    }
    if (rnet_session_is_running(a)) fail("host started without seat 2");
    memset(&st, 0, sizeof(st));
    rnet_session_get_stats(a, &st);
    if (st.ready_mask != 0x3u)
    {
        fprintf(stderr, "  ready_mask=0x%x\n", (unsigned)st.ready_mask);
        fail("host should be waiting on seat 2 only");
    }
    if (st.peer_rx_age_ms[1] == RNET_PEER_RX_NEVER) fail("seat 1 should be heard");
    if (st.peer_rx_age_ms[2] != RNET_PEER_RX_NEVER) fail("seat 2 should be silent");

    if (rnet_session_start_lan(c, bind_c, bind_a) != 0) { fail("late LAN start"); goto done; }
    for (i = 0; i < 20000; ++i)
    {
        g_now_ms++;
        rnet_session_pump(a); rnet_session_pump(b); rnet_session_pump(c);
        if (rnet_session_is_running(a) && rnet_session_is_running(b) &&
            rnet_session_is_running(c))
            break;
    }
    if (!rnet_session_is_running(a)) fail("host did not start once seat 2 joined");
    memset(&st, 0, sizeof(st));
    rnet_session_get_stats(a, &st);
    if (st.ready_mask != 0x7u) fail("every seat should be ready once running");

done:
    rnet_session_destroy(a);
    rnet_session_destroy(b);
    rnet_session_destroy(c);
    if (g_failures == 0)
    {
        printf("session_start_wait_test: ok\n");
        return 0;
    }
    fprintf(stderr, "session_start_wait_test: %d failure(s)\n", g_failures);
    return 1;
}
