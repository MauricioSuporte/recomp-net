/*
 * Host-authoritative delay-sync (RNetConfig.host_authority).
 *
 * Three real UDP peers over loopback: the host hubs two guests, and one guest
 * is slow (it only gets to run one tick in three). What this proves:
 *   1. the host never stalls -- it admits every tick it is offered, however
 *      far behind the slow guest is;
 *   2. every peer publishes the same resolved row for every tick it plays,
 *      so the match stays deterministic;
 *   3. guest input reaches the match (the host folds in what has arrived).
 */
#include "recomp_net/recomp_net.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <process.h>
static unsigned test_pid(void) { return (unsigned)_getpid(); }
#else
#include <unistd.h>
static unsigned test_pid(void) { return (unsigned)getpid(); }
#endif

enum { kTicks = 300, kHashCapacity = 1024 };

typedef struct HostCtx
{
    rnet_u8 slot;
    int published;
    int guest_bytes_seen;
    rnet_u32 hashes[kHashCapacity];
} HostCtx;

static int g_failures;
static rnet_u64 g_now_ms = 1000;

static void fail(const char *message)
{
    fprintf(stderr, "FAIL: %s\n", message);
    g_failures++;
}

static void sample_local(rnet_u32 tick, RNetInputSample *out, void *opaque)
{
    HostCtx *ctx = (HostCtx *)opaque;
    memset(out, 0, sizeof(*out));
    out->size = 4;
    out->bytes[0] = (rnet_u8)(0x10u + ctx->slot);
    out->bytes[1] = (rnet_u8)tick;
    out->bytes[2] = (rnet_u8)(tick >> 8);
    out->bytes[3] = (rnet_u8)(0xa5u ^ ctx->slot);
    out->valid = 1;
}

static void publish(rnet_u32 tick, const RNetInputSample *by_slot, int slots,
                    void *opaque)
{
    HostCtx *ctx = (HostCtx *)opaque;
    rnet_u32 hash = rnet_checksum(&tick, sizeof(tick));
    int slot;
    for (slot = 0; slot < slots; ++slot)
    {
        hash ^= rnet_checksum(by_slot[slot].bytes, by_slot[slot].size);
        hash *= 16777619u;
        if (slot > 0 && by_slot[slot].bytes[0] == (rnet_u8)(0x10u + slot))
            ctx->guest_bytes_seen++;
    }
    if (ctx->published < kHashCapacity)
        ctx->hashes[ctx->published] = hash;
    ctx->published++;
}

static rnet_u64 now_ms(void *opaque)
{
    (void)opaque;
    return g_now_ms;
}

int main(void)
{
    RNetConfig ca, cb, cc;
    RNetHostVTable va, vb, vc;
    RNetSession *a = NULL, *b = NULL, *c = NULL;
    HostCtx ha, hb, hc;
    char bind_a[64], bind_b[64], bind_c[64];
    const unsigned base_port = 43300u + (test_pid() % 900u) * 3u;
    int i, host_offers = 0, host_refusals = 0, common;

    memset(&ha, 0, sizeof(ha));
    memset(&hb, 0, sizeof(hb));
    memset(&hc, 0, sizeof(hc));
    ha.slot = 0; hb.slot = 1; hc.slot = 2;
    memset(&va, 0, sizeof(va));
    va.sample_local = sample_local; va.publish = publish; va.now_ms = now_ms;
    va.ctx = &ha;
    vb = va; vb.ctx = &hb;
    vc = va; vc.ctx = &hc;

    rnet_config_init_defaults(&ca);
    ca.slot_count = 3;
    ca.input_delay = 2;
    ca.host_authority = 1;
    ca.session_id = 0x48415554u ^ test_pid();
    cb = ca; cc = ca;
    ca.local_slot = 0; cb.local_slot = 1; cc.local_slot = 2;

    snprintf(bind_a, sizeof(bind_a), "127.0.0.1:%u", base_port);
    snprintf(bind_b, sizeof(bind_b), "127.0.0.1:%u", base_port + 1U);
    snprintf(bind_c, sizeof(bind_c), "127.0.0.1:%u", base_port + 2U);
    a = rnet_session_create(&ca, &va);
    b = rnet_session_create(&cb, &vb);
    c = rnet_session_create(&cc, &vc);
    if (!a || !b || !c) { fail("session create"); goto done; }
    if (rnet_session_start_lan_hub(a, bind_a) != 0 ||
        rnet_session_start_lan(b, bind_b, bind_a) != 0 ||
        rnet_session_start_lan(c, bind_c, bind_a) != 0)
    { fail("LAN start"); goto done; }

    for (i = 0; i < 20000; ++i)
    {
        g_now_ms++;
        rnet_session_pump(a); rnet_session_pump(b); rnet_session_pump(c);
        if (rnet_session_is_running(a) && rnet_session_is_running(b) &&
            rnet_session_is_running(c))
            break;
    }
    if (!rnet_session_is_running(a) || !rnet_session_is_running(b) ||
        !rnet_session_is_running(c))
    { fail("peers did not reach RUNNING"); goto done; }

    /* One host tick per 16 ms; guest b keeps up, guest c runs one in three. */
    for (i = 0; i < kTicks * 16 * 4 && ha.published < kTicks; ++i)
    {
        g_now_ms++;
        rnet_session_pump(a); rnet_session_pump(b); rnet_session_pump(c);
        if (i % 16 == 0)
        {
            host_offers++;
            if (rnet_session_try_admit(a, rnet_session_sim_tick(a)))
                rnet_session_advance(a);
            else
                host_refusals++;
        }
        if (rnet_session_try_admit(b, rnet_session_sim_tick(b)))
            rnet_session_advance(b);
        if (i % 48 == 0 && rnet_session_try_admit(c, rnet_session_sim_tick(c)))
            rnet_session_advance(c);
    }

    if (ha.published < kTicks) fail("the host did not run every tick");
    if (host_refusals != 0)
    {
        fprintf(stderr, "  host refused %d of %d ticks\n", host_refusals, host_offers);
        fail("the host stalled");
    }
    fprintf(stderr, "  published host=%d b=%d c=%d\n", ha.published, hb.published, hc.published);
    if (hb.published < kTicks - 20) fail("the fast guest fell behind");
    if (hc.published == 0 || hc.published >= ha.published)
        fail("the slow guest should run, and behind the host");
    if (ha.guest_bytes_seen == 0) fail("guest input never reached the match");

    common = hb.published < ha.published ? hb.published : ha.published;
    for (i = 0; i < common && i < kHashCapacity; ++i)
        if (ha.hashes[i] != hb.hashes[i]) { fail("host and guest b diverged"); break; }
    common = hc.published < ha.published ? hc.published : ha.published;
    for (i = 0; i < common && i < kHashCapacity; ++i)
        if (ha.hashes[i] != hc.hashes[i]) { fail("host and slow guest c diverged"); break; }

done:
    rnet_session_destroy(a);
    rnet_session_destroy(b);
    rnet_session_destroy(c);
    if (g_failures == 0)
    {
        printf("session_host_authority_test: ok (host %d ticks, 0 stalls; "
               "guests %d / %d; guest inputs in %d resolved seats)\n",
               ha.published, hb.published, hc.published, ha.guest_bytes_seen);
        return 0;
    }
    fprintf(stderr, "session_host_authority_test: %d failure(s)\n", g_failures);
    return 1;
}
