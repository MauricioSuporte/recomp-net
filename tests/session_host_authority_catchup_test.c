/*
 * Host-authoritative delay-sync: a guest that falls behind catches up.
 *
 * Two real UDP peers over loopback (two seats, and five seats with three
 * empty, as an online room). The host runs one tick per 16 ms and never
 * waits. The guest hiccups -- 160 ticks once, then 40 ticks twice, 240 in
 * all; the first alone is more than one input ring -- while 10% of INPUT datagrams are dropped
 * (RNET_TEST_INPUT_LOSS_PCT). After each hiccup the guest may run up to four
 * ticks per host tick, as the desktop host's catch-up burst does.
 *
 * Before the fix the guest froze for good once it trailed by more than 64
 * rows (the host resent at most 64 rows back and the guest's live window
 * dropped rows more than 64 ahead), and with two seats a single lost host
 * row older than the redundancy window was never resent ("highest seen"
 * ACK). What this proves:
 *   1. the host admits every tick;
 *   2. the guest ends within a few ticks of the host after every hiccup;
 *   3. both publish identical rows for every tick they both played.
 */
#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200112L /* setenv */
#endif
#include "recomp_net/recomp_net.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <process.h>
static unsigned test_pid(void) { return (unsigned)_getpid(); }
static void set_loss_env(void) { _putenv_s("RNET_TEST_INPUT_LOSS_PCT", "10"); }
#else
#include <unistd.h>
static unsigned test_pid(void) { return (unsigned)getpid(); }
static void set_loss_env(void) { setenv("RNET_TEST_INPUT_LOSS_PCT", "10", 1); }
#endif

enum { kTicks = 1500, kHashCapacity = 2048, kCatchup = 4 };

typedef struct Ctx
{
    rnet_u8 slot;
    int published;
    rnet_u32 hashes[kHashCapacity];
} Ctx;

static int g_failures;
static rnet_u64 g_now_ms = 1000;

static void fail(const char *message)
{
    fprintf(stderr, "FAIL: %s\n", message);
    g_failures++;
}

static void sample_local(rnet_u32 tick, RNetInputSample *out, void *opaque)
{
    Ctx *ctx = (Ctx *)opaque;
    memset(out, 0, sizeof(*out));
    out->size = 4;
    out->bytes[0] = (rnet_u8)(0x10u + ctx->slot);
    out->bytes[1] = (rnet_u8)tick;
    out->bytes[2] = (rnet_u8)(tick >> 8);
    out->bytes[3] = (rnet_u8)(tick * 37u);
    out->valid = 1;
}

static void publish(rnet_u32 tick, const RNetInputSample *by_slot, int slots, void *opaque)
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
        ctx->hashes[ctx->published] = hash;
    ctx->published++;
}

static rnet_u64 now_ms(void *opaque)
{
    (void)opaque;
    return g_now_ms;
}

static int guest_hiccup(int host_tick)
{
    return (host_tick >= 200 && host_tick < 360) ||
           (host_tick >= 600 && host_tick < 640) ||
           (host_tick >= 900 && host_tick < 940);
}

static void run_case(int seats, unsigned port)
{
    RNetConfig ca, cb;
    RNetHostVTable va, vb;
    RNetSession *a = NULL, *b = NULL;
    static Ctx ha, hb;
    char bind_a[64], bind_b[64];
    int i, refusals = 0, worst_after = 0, common;

    memset(&ha, 0, sizeof(ha));
    memset(&hb, 0, sizeof(hb));
    ha.slot = 0;
    hb.slot = 1;
    memset(&va, 0, sizeof(va));
    va.sample_local = sample_local;
    va.publish = publish;
    va.now_ms = now_ms;
    va.ctx = &ha;
    vb = va;
    vb.ctx = &hb;

    rnet_config_init_defaults(&ca);
    ca.slot_count = (rnet_u8)seats;
    ca.input_delay = 2;
    ca.host_authority = 1;
    ca.session_id = 0x43415443u ^ test_pid() ^ (rnet_u32)seats;
    if (seats > 2)
        ca.occupied_mask = 3u;
    cb = ca;
    ca.local_slot = 0;
    cb.local_slot = 1;

    snprintf(bind_a, sizeof(bind_a), "127.0.0.1:%u", port);
    snprintf(bind_b, sizeof(bind_b), "127.0.0.1:%u", port + 1u);
    a = rnet_session_create(&ca, &va);
    b = rnet_session_create(&cb, &vb);
    if (!a || !b) { fail("session create"); goto done; }
    if (seats > 2 ? (rnet_session_start_lan_hub(a, bind_a) != 0 ||
                     rnet_session_start_lan(b, bind_b, bind_a) != 0)
                  : (rnet_session_start_lan(a, bind_a, bind_b) != 0 ||
                     rnet_session_start_lan(b, bind_b, bind_a) != 0))
    { fail("LAN start"); goto done; }

    for (i = 0; i < 20000; ++i)
    {
        g_now_ms++;
        rnet_session_pump(a);
        rnet_session_pump(b);
        if (rnet_session_is_running(a) && rnet_session_is_running(b))
            break;
    }
    if (!rnet_session_is_running(a) || !rnet_session_is_running(b))
    { fail("peers did not reach RUNNING"); goto done; }

    for (i = 0; ha.published < kTicks && i < kTicks * 16 * 2; ++i)
    {
        int n;
        g_now_ms++;
        rnet_session_pump(a);
        rnet_session_pump(b);
        if (i % 16)
            continue;
        if (rnet_session_try_admit(a, rnet_session_sim_tick(a)))
            rnet_session_advance(a);
        else
            refusals++;
        if (guest_hiccup(ha.published))
            continue;
        for (n = 0; n <= kCatchup; ++n)
        {
            if (!rnet_session_try_admit(b, rnet_session_sim_tick(b)))
                break;
            rnet_session_advance(b);
        }
        /* 100 host ticks after each hiccup the guest must be back in step. */
        if (ha.published == 460 || ha.published == 740 || ha.published == 1040 ||
            ha.published == kTicks - 1)
        {
            int behind = ha.published - hb.published;
            if (behind > worst_after)
                worst_after = behind;
        }
    }

    fprintf(stderr, "  %d seats: host=%d guest=%d worst backlog after recovery=%d\n",
            seats, ha.published, hb.published, worst_after);
    if (ha.published < kTicks) fail("the host did not run every tick");
    if (refusals) fail("the host stalled");
    if (worst_after > 6) fail("the guest did not catch up with the host");

    common = hb.published < ha.published ? hb.published : ha.published;
    for (i = 0; i < common && i < kHashCapacity; ++i)
        if (ha.hashes[i] != hb.hashes[i]) { fail("host and guest diverged"); break; }

done:
    rnet_session_destroy(a);
    rnet_session_destroy(b);
}

int main(void)
{
    const unsigned base_port = 44300u + (test_pid() % 400u) * 4u;
    set_loss_env();
    run_case(2, base_port);
    run_case(5, base_port + 2u);
    if (g_failures == 0)
    {
        printf("session_host_authority_catchup_test: ok\n");
        return 0;
    }
    fprintf(stderr, "session_host_authority_catchup_test: %d failure(s)\n", g_failures);
    return 1;
}
