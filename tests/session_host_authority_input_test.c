/*
 * Host authority: guest inputs are not lost and can be sent early.
 *
 * Two real UDP peers over loopback, host + guest. What this proves:
 *   1. taps survive bursts: the guest only gets to run every third host
 *      tick, then catches up three ticks at once, so its inputs reach the
 *      host in bursts. Every tap it sent shows up in the host's resolved rows
 *      (taking only the newest input lost most of them);
 *   2. the host still never waits, and both peers publish identical rows;
 *   3. a guest whose pad changes on every tick still matches the host row
 *      for row (the queue bound may jump to the newest, never diverge);
 *   4. rnet_session_auth_refresh_local sends a changed pad while the guest
 *      waits for the host's row, so the host's very next row carries it.
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

enum { kHashCapacity = 4096, kTapPeriod = 7 };

typedef enum { PAD_TAPS, PAD_EVERY_TICK, PAD_FIXED } PadMode;

typedef struct Ctx
{
    rnet_u8 slot;
    PadMode mode;
    rnet_u8 fixed;
    int published;
    rnet_u32 hashes[kHashCapacity];
    rnet_u8 guest_seat[kHashCapacity]; /* byte 0 of seat 1 per published tick */
} Ctx;

static int g_failures;
static rnet_u64 g_now_ms = 1000;

static void fail(const char *message)
{
    fprintf(stderr, "FAIL: %s\n", message);
    g_failures++;
}

/* Guest pad by its own sim tick: a one-tick tap every kTapPeriod ticks with
 * a distinct value (so lost and duplicated taps are both visible). */
static rnet_u8 tap_value(rnet_u32 tick)
{
    if (tick % kTapPeriod != 3u)
        return 0;
    return (rnet_u8)(1u + (tick / kTapPeriod) % 250u);
}

static void sample_local(rnet_u32 tick, RNetInputSample *out, void *opaque)
{
    Ctx *ctx = (Ctx *)opaque;
    memset(out, 0, sizeof(*out));
    out->size = 2;
    if (ctx->slot == 0)
        out->bytes[0] = 0;
    else if (ctx->mode == PAD_TAPS)
        out->bytes[0] = tap_value(tick);
    else if (ctx->mode == PAD_EVERY_TICK)
        out->bytes[0] = (rnet_u8)(1u + tick % 200u);
    else
        out->bytes[0] = ctx->fixed;
    out->valid = 1;
}

static void publish(rnet_u32 tick, const RNetInputSample *by_slot, int slots,
                    void *opaque)
{
    Ctx *ctx = (Ctx *)opaque;
    rnet_u32 hash = rnet_checksum(&tick, sizeof(tick));
    int slot;
    for (slot = 0; slot < slots; ++slot)
    {
        hash ^= rnet_checksum(by_slot[slot].bytes, by_slot[slot].size);
        hash *= 16777619u;
    }
    if (ctx->published < kHashCapacity)
    {
        ctx->hashes[ctx->published] = hash;
        ctx->guest_seat[ctx->published] = slots > 1 ? by_slot[1].bytes[0] : 0;
    }
    ctx->published++;
}

static rnet_u64 now_ms(void *opaque)
{
    (void)opaque;
    return g_now_ms;
}

typedef struct Pair
{
    RNetSession *host, *guest;
    Ctx hc, gc;
    int host_refusals;
} Pair;

static int pair_open(Pair *p, unsigned port_offset)
{
    RNetConfig ca, cb;
    RNetHostVTable va, vb;
    char bind_a[64], bind_b[64];
    const unsigned base_port = 44300u + (test_pid() % 800u) * 8u + port_offset;
    int i;

    memset(p, 0, sizeof(*p));
    p->hc.slot = 0;
    p->gc.slot = 1;
    memset(&va, 0, sizeof(va));
    va.sample_local = sample_local; va.publish = publish; va.now_ms = now_ms;
    va.ctx = &p->hc;
    vb = va; vb.ctx = &p->gc;
    rnet_config_init_defaults(&ca);
    ca.slot_count = 2;
    ca.input_delay = 2;
    ca.host_authority = 1;
    ca.session_id = (0x494E5054u ^ test_pid()) + port_offset;
    cb = ca;
    ca.local_slot = 0; cb.local_slot = 1;
    snprintf(bind_a, sizeof(bind_a), "127.0.0.1:%u", base_port);
    snprintf(bind_b, sizeof(bind_b), "127.0.0.1:%u", base_port + 1u);
    p->host = rnet_session_create(&ca, &va);
    p->guest = rnet_session_create(&cb, &vb);
    if (!p->host || !p->guest) { fail("session create"); return 0; }
    if (rnet_session_start_lan(p->host, bind_a, bind_b) != 0 ||
        rnet_session_start_lan(p->guest, bind_b, bind_a) != 0)
    { fail("LAN start"); return 0; }
    for (i = 0; i < 20000; ++i)
    {
        g_now_ms++;
        rnet_session_pump(p->host); rnet_session_pump(p->guest);
        if (rnet_session_is_running(p->host) && rnet_session_is_running(p->guest))
            return 1;
    }
    fail("peers did not reach RUNNING");
    return 0;
}

static void pair_close(Pair *p)
{
    rnet_session_destroy(p->host);
    rnet_session_destroy(p->guest);
    p->host = p->guest = NULL;
}

static void host_tick(Pair *p)
{
    if (rnet_session_try_admit(p->host, rnet_session_sim_tick(p->host)))
        rnet_session_advance(p->host);
    else
        p->host_refusals++;
}

/* The guest runs only every third host tick, then up to three at once. */
static void run_bursty(Pair *p, int host_ticks)
{
    int i, k;
    for (i = 0; p->hc.published < host_ticks && i < host_ticks * 16 * 4; ++i)
    {
        g_now_ms++;
        rnet_session_pump(p->host); rnet_session_pump(p->guest);
        if (i % 16 == 0)
            host_tick(p);
        if (i % 48 == 8)
            for (k = 0; k < 3; ++k)
            {
                rnet_session_pump(p->guest);
                if (!rnet_session_try_admit(p->guest, rnet_session_sim_tick(p->guest)))
                    break;
                rnet_session_advance(p->guest);
            }
    }
    /* Let the guest finish what the host already resolved. */
    for (i = 0; i < 2000; ++i)
    {
        g_now_ms++;
        rnet_session_pump(p->host); rnet_session_pump(p->guest);
        if (rnet_session_try_admit(p->guest, rnet_session_sim_tick(p->guest)))
            rnet_session_advance(p->guest);
    }
}

static void check_identical(const Pair *p, const char *what)
{
    int i, common = p->gc.published < p->hc.published ? p->gc.published : p->hc.published;
    if (common < 10) { fail(what); return; }
    for (i = 0; i < common && i < kHashCapacity; ++i)
        if (p->hc.hashes[i] != p->gc.hashes[i]) { fail(what); return; }
}

static void test_taps_survive_bursts(void)
{
    Pair p;
    int i, seen = 0, sent = 0;
    rnet_u8 last = 0;
    RNetSessionStats gs;
    rnet_u32 guest_ticks;

    if (!pair_open(&p, 0)) { pair_close(&p); return; }
    p.gc.mode = PAD_TAPS;
    run_bursty(&p, 600);
    if (p.host_refusals) fail("taps: the host stalled");
    check_identical(&p, "taps: host and guest rows diverged");

    /* Distinct taps the host folded in, in order. */
    for (i = 0; i < p.hc.published && i < kHashCapacity; ++i)
    {
        rnet_u8 v = p.hc.guest_seat[i];
        if (v && v != last) seen++;
        last = v;
    }
    /* Taps the guest sampled, minus the tail still in flight at the end. */
    memset(&gs, 0, sizeof(gs));
    rnet_session_get_stats(p.guest, &gs);
    guest_ticks = gs.sim_tick;
    for (i = 0; (rnet_u32)i + 8u < guest_ticks; ++i)
        if (tap_value((rnet_u32)i)) sent++;
    fprintf(stderr, "  taps: host ticks=%d guest ticks=%u taps sent=%d seen=%d\n",
            p.hc.published, (unsigned)guest_ticks, sent, seen);
    if (sent < 20) fail("taps: too few taps sampled for the test to mean anything");
    if (seen < sent) fail("taps: the host lost guest taps");
    pair_close(&p);
}

static void test_deep_burst_jumps(void)
{
    Pair p;
    RNetSessionStats hs;
    if (!pair_open(&p, 2)) { pair_close(&p); return; }
    p.gc.mode = PAD_EVERY_TICK;
    run_bursty(&p, 300);
    if (p.host_refusals) fail("burst: the host stalled");
    check_identical(&p, "burst: host and guest rows diverged");
    memset(&hs, 0, sizeof(hs));
    rnet_session_get_stats(p.host, &hs);
    fprintf(stderr, "  burst: host ticks=%d jumps=%u\n", p.hc.published,
            (unsigned)hs.auth_input_jumps);
    pair_close(&p);
}

static void test_refresh_sends_early(void)
{
    Pair p;
    int i;
    rnet_u8 first_after;
    RNetSessionStats gs;

    if (!pair_open(&p, 4)) { pair_close(&p); return; }
    p.gc.mode = PAD_FIXED;
    p.gc.fixed = 0;
    /* Lockstep-ish warm up: both run every host tick. */
    for (i = 0; i < 60 * 16; ++i)
    {
        g_now_ms++;
        rnet_session_pump(p.host); rnet_session_pump(p.guest);
        if (i % 16 == 0) host_tick(&p);
        if (rnet_session_try_admit(p.guest, rnet_session_sim_tick(p.guest)))
            rnet_session_advance(p.guest);
    }
    /* Let the host's sent rows drain: the guest now waits for the next row,
     * its own input for this tick already out. */
    for (i = 0; i < 40; ++i)
    {
        g_now_ms++;
        rnet_session_pump(p.host); rnet_session_pump(p.guest);
        if (rnet_session_try_admit(p.guest, rnet_session_sim_tick(p.guest)))
            rnet_session_advance(p.guest);
    }
    if (rnet_session_try_admit(p.guest, rnet_session_sim_tick(p.guest)))
    { fail("refresh: guest should be waiting for the host's row"); pair_close(&p); return; }
    if (rnet_session_auth_refresh_local(p.guest) != 0)
        fail("refresh: an unchanged pad must not be resent");
    p.gc.fixed = 0x42;
    if (rnet_session_auth_refresh_local(p.guest) != 1)
        fail("refresh: a changed pad was not sent");
    if (rnet_session_auth_refresh_local(p.guest) != 0)
        fail("refresh: the same change must not be sent twice");
    if (rnet_session_auth_refresh_local(p.host) != 0)
        fail("refresh: the host must never refresh");
    for (i = 0; i < 4; ++i)
    {
        g_now_ms++;
        rnet_session_pump(p.guest); rnet_session_pump(p.host);
    }
    host_tick(&p);
    first_after = p.hc.guest_seat[(p.hc.published - 1) % kHashCapacity];
    if (first_after != 0x42)
    {
        fprintf(stderr, "  refresh: host's next row carried 0x%02x\n", first_after);
        fail("refresh: the host's next row did not carry the early input");
    }
    for (i = 0; i < 200; ++i)
    {
        g_now_ms++;
        rnet_session_pump(p.host); rnet_session_pump(p.guest);
        if (i % 16 == 0) host_tick(&p);
        if (rnet_session_try_admit(p.guest, rnet_session_sim_tick(p.guest)))
            rnet_session_advance(p.guest);
    }
    check_identical(&p, "refresh: host and guest rows diverged");
    if (p.host_refusals) fail("refresh: the host stalled");
    memset(&gs, 0, sizeof(gs));
    rnet_session_get_stats(p.guest, &gs);
    if (gs.auth_presend != 1) fail("refresh: presend counter");
    pair_close(&p);
}

int main(void)
{
    test_taps_survive_bursts();
    test_deep_burst_jumps();
    test_refresh_sends_early();
    if (g_failures == 0)
    {
        printf("session_host_authority_input_test: ok\n");
        return 0;
    }
    fprintf(stderr, "session_host_authority_input_test: %d failure(s)\n", g_failures);
    return 1;
}
