/*
 * psistorm-PMAC-NN: the classic-Mac Battle.net version-check challenge, reconstructed as source.
 *
 * The originals are PowerPC CFM fragments (PEF, export "CheckRevision") served by useast as
 * psistorm-PMAC-00 ... psistorm-PMAC-19, all stamped 2006-11-08 18:34-18:44 UTC. Every one is the same
 * program; they differ only in the parameters of the hash, which the original builds spread over tiny
 * constant-returning functions (li r3,N; blr). This file is that program with the parameters pulled out into
 * a per-build header (psistorm_build_NN.h, made by gen_headers.py from ../builds/psistorm-PMAC-NN.json):
 *
 *   PS_INIT    five initial state words
 *   PS_ROT_C   the rotate-left applied to the third working variable at every step (10 in RIPEMD-160;
 *              2 in build 00, 14 in build 02, ...)
 *   PS_STEPS   160 steps {message word, boolean-function truth table, constant, rotation}
 *
 * Build:  cc -O2 -DPS_CLI -DPS_BUILD_HEADER='"psistorm_build_14.h"' psistorm.c -o ps14
 * Use:    ./ps14 FILE1 FILE2 FILE3 VALUESTRING_HEX      (prints exe version, checksum, exe info)
 *
 * Tags: [V] verified against the PowerPC code of the original fragments (Ghidra emulation of the real code, or the
 * lifted straight-line compression function, which the 20 table sets reproduce on 30 of 30 random blocks each)
 * and against a real Mac client's live answer (build 04, see the README); [I] inference.
 *
 * Differences from the original: file access uses stdio (the Mac code used FSRef/FSSpec fork reads and
 * ResolveAliasFile), and the output buffers are plain C buffers.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef PS_BUILD_HEADER
#error "define PS_BUILD_HEADER as the parameter header, e.g. -DPS_BUILD_HEADER='\"psistorm_build_14.h\"'"
#endif
#include PS_BUILD_HEADER

typedef struct {
    uint8_t  word;   /* index of the message word (0-15) added at this step */
    uint8_t  tt;     /* truth table of the boolean function f(b,c,d): bit j is the result for (x,y,z) = (j&1, j>>1&1, j>>2&1) */
    uint32_t k;      /* additive constant */
    uint8_t  rot;    /* rotate-left of the sum */
} ps_step;

static const uint32_t ps_init[5]   = PS_INIT;
static const ps_step  ps_steps[160] = PS_STEPS;

static inline uint32_t rotl32(uint32_t x, unsigned n) { n &= 31; return n ? (x << n) | (x >> (32 - n)) : x; }

/* Any three-input boolean function, applied bitwise. [V] the original calls one tiny function per round that
 * computes it from a constant; the standard RIPEMD-160 set is only a subset of the tables seen. */
static uint32_t ps_f(uint8_t tt, uint32_t x, uint32_t y, uint32_t z)
{
    uint32_t r = 0;
    for (int j = 0; j < 8; j++)
        if ((tt >> j) & 1)
            r |= ((j & 1 ? x : ~x) & (j & 2 ? y : ~y) & (j & 4 ? z : ~z));
    return r;
}

/* The compression function: the RIPEMD-160 skeleton (two lines of 80 steps on the same block, then the
 * RIPEMD-160 combination) driven by the tables. [V] reproduces the lifted PowerPC compression function of all
 * 20 builds. x is the block as 16 little-endian words. */
static void ps_compress(uint32_t h[5], const uint32_t x[16])
{
    uint32_t al = h[0], bl = h[1], cl = h[2], dl = h[3], el = h[4];
    uint32_t ar = h[0], br = h[1], cr = h[2], dr = h[3], er = h[4];
    uint32_t t;

    for (int j = 0; j < 80; j++) {            /* first line */
        const ps_step *s = &ps_steps[j];
        t  = rotl32(al + ps_f(s->tt, bl, cl, dl) + x[s->word] + s->k, s->rot) + el;
        al = el; el = dl; dl = rotl32(cl, PS_ROT_C); cl = bl; bl = t;
    }
    for (int j = 80; j < 160; j++) {          /* second line */
        const ps_step *s = &ps_steps[j];
        t  = rotl32(ar + ps_f(s->tt, br, cr, dr) + x[s->word] + s->k, s->rot) + er;
        ar = er; er = dr; dr = rotl32(cr, PS_ROT_C); cr = br; br = t;
    }

    t    = h[1] + cl + dr;                    /* RIPEMD-160 final combination */
    h[1] = h[2] + dl + er;
    h[2] = h[3] + el + ar;
    h[3] = h[4] + al + br;
    h[4] = h[0] + bl + cr;
    h[0] = t;
}

/* ---- the hash: MD framing around ps_compress. [V] 64-byte blocks, message words little-endian, 0x80, zeros,
 * 64-bit little-endian bit count, state words written little-endian. ---- */
typedef struct { uint32_t h[5]; uint8_t buf[64]; size_t n; uint64_t bits; } ps_hash;

static void ps_hash_init(ps_hash *c) { memcpy(c->h, ps_init, sizeof c->h); c->n = 0; c->bits = 0; }

static void ps_block(ps_hash *c, const uint8_t *p)
{
    uint32_t x[16];
    for (int i = 0; i < 16; i++) x[i] = p[4*i] | p[4*i+1] << 8 | p[4*i+2] << 16 | (uint32_t)p[4*i+3] << 24;
    ps_compress(c->h, x);
}

static void ps_hash_update(ps_hash *c, const uint8_t *p, size_t len)
{
    c->bits += (uint64_t)len * 8;
    while (len) {
        size_t take = 64 - c->n < len ? 64 - c->n : len;
        memcpy(c->buf + c->n, p, take); c->n += take; p += take; len -= take;
        if (c->n == 64) { ps_block(c, c->buf); c->n = 0; }
    }
}

static void ps_hash_final(ps_hash *c, uint8_t out[20])
{
    uint64_t bits = c->bits;
    uint8_t pad[72] = { 0x80 };
    size_t zeros = (size_t)((0x37 - (bits >> 3)) & 0x3f);
    uint8_t len[8];
    for (int i = 0; i < 8; i++) len[i] = (uint8_t)(bits >> (8 * i));
    ps_hash_update(c, pad, 1 + zeros);
    ps_hash_update(c, len, 8);
    for (int i = 0; i < 5; i++) for (int b = 0; b < 4; b++) out[4*i + b] = (uint8_t)(c->h[i] >> (8 * b));
}

/* ---- HMAC: textbook, 64-byte block, ipad 0x36, opad 0x5C, 20-byte inner digest, key zero-extended. [V] ---- */
typedef struct { ps_hash inner; uint8_t opad[64]; } ps_hmac;

static void ps_hmac_init(ps_hmac *m, const uint8_t key[16])
{
    uint8_t ipad[64];
    for (int i = 0; i < 64; i++) {
        uint8_t k = i < 16 ? key[i] : 0;
        ipad[i] = 0x36 ^ k; m->opad[i] = 0x5c ^ k;
    }
    ps_hash_init(&m->inner); ps_hash_update(&m->inner, ipad, 64);
}

static void ps_hmac_final(ps_hmac *m, uint8_t out[20])
{
    uint8_t d[20]; ps_hash outer;
    ps_hash_final(&m->inner, d);
    ps_hash_init(&outer); ps_hash_update(&outer, m->opad, 64); ps_hash_update(&outer, d, 20);
    ps_hash_final(&outer, out);
}

/* ---- the value-string transform (shared with the Windows Lockdown). [V] 40 of 40 random inputs against the
 * PowerPC routine. The value string is read as digits of a base-255 number, most significant first, and the
 * result is that number in a 16-byte little-endian buffer: for each input byte from the last to the first,
 * multiply the buffer by 255, then add (byte - 1). Fails (returns 0) if it does not fit in 16 bytes.
 * Written as the original loops, including truncating stores, so unusual inputs (a 0 byte adds 0xFFFF) behave as
 * the compiled code does [I]. ---- */
static int ps_shuffle_value_string(const uint8_t *vs, size_t len, uint8_t buf[16])
{
    unsigned pos = 0;
    memset(buf, 0, 16);
    for (size_t x = len; x > 0; x--) {
        uint32_t shifter = 0;
        for (unsigned i = 0; i < pos; i++) {          /* buf *= 255 */
            uint32_t t = (uint32_t)buf[i] * 255 + shifter;
            buf[i] = (uint8_t)t; shifter = (t >> 8) & 0xff;
        }
        if (shifter > 0) { if (pos >= 16) return 0; buf[pos++] = (uint8_t)shifter; }
        uint32_t adder = (uint16_t)(vs[x - 1] - 1);   /* buf += byte - 1 */
        for (unsigned i = 0; i < pos && adder > 0; i++) {
            buf[i] = (uint8_t)(buf[i] + adder);
            adder = buf[i] < adder ? 1 : 0;
        }
        if (adder > 0) { if (pos >= 16) return 0; buf[pos++] = (uint8_t)adder; }
    }
    return 1;
}

/* ---- the exe-info transform (shared with the Windows Lockdown's digest shuffle). [V] 40 of 40 random inputs.
 * The 16 digest bytes are a little-endian number; repeatedly divide it by 255 and emit remainder + 1 until it is
 * zero. (The compiled code does the division with a shift-and-add trick, `word_shifter`; it equals / and % 255
 * for every 16-bit input, checked exhaustively.) Returns the number of bytes written (at most 20). ---- */
static size_t ps_digest_shuffle(const uint8_t digest16[16], uint8_t *out)
{
    uint8_t s[16]; size_t n = 0, top = 16;
    memcpy(s, digest16, 16);
    for (;;) {
        while (top > 0 && s[top - 1] == 0) top--;
        if (top == 0) break;
        uint32_t rem = 0;
        for (size_t j = top; j-- > 0;) {
            uint32_t w = (rem << 8) + s[j];
            s[j] = (uint8_t)(w / 255); rem = w % 255;
        }
        out[n++] = (uint8_t)(rem + 1);
    }
    return n;
}

/* ---- CheckRevision. [V] signature on the Mac: (file1, file2, file3, valueString, *exeVersion, *checksum, exeInfo),
 * returns 1 on success. What each file argument is, in a real client, is unknown [?]. ----
 *   seed        = shuffle(valueString)                       (16 bytes; fails if it does not fit)
 *   exeVersion  = last 4 bytes of file1, little-endian dword
 *   digest      = HMAC(key = seed, message = file1 || file2 || file3)   (files read whole in 0x4000-byte chunks,
 *                 no padding, no interpretation; a file that cannot be opened is skipped)
 *   checksum    = digest[0..3] little-endian
 *   exeInfo     = digest_shuffle(digest[4..19])                (NUL-terminated here) */
int ps_check_revision(const char *file1, const char *file2, const char *file3, const char *value_string, size_t value_len,
                      uint32_t *exe_version, uint32_t *checksum, uint8_t exe_info[24], size_t *exe_info_len)
{
    uint8_t seed[16], digest[20];
    ps_hmac m;
    const char *files[3] = { file1, file2, file3 };

    if (!ps_shuffle_value_string((const uint8_t *)value_string, value_len, seed)) return 0;
    ps_hmac_init(&m, seed);

    for (int f = 0; f < 3; f++) {
        FILE *fp = fopen(files[f], "rb");
        if (!fp) continue;
        uint8_t chunk[0x4000]; size_t n, total = 0; uint8_t tail[4] = {0};
        while ((n = fread(chunk, 1, sizeof chunk, fp)) > 0) {
            ps_hash_update(&m.inner, chunk, n);
            total += n;
            if (f == 0) {                              /* keep the last 4 bytes of file 1 */
                if (n >= 4) memcpy(tail, chunk + n - 4, 4);
                else { memmove(tail, tail + n, 4 - n); memcpy(tail + 4 - n, chunk, n); }
            }
        }
        fclose(fp);
        if (f == 0) *exe_version = tail[0] | tail[1] << 8 | tail[2] << 16 | (uint32_t)tail[3] << 24;
        (void)total;
    }

    ps_hmac_final(&m, digest);
    *checksum = digest[0] | digest[1] << 8 | digest[2] << 16 | (uint32_t)digest[3] << 24;
    *exe_info_len = ps_digest_shuffle(digest + 4, exe_info);
    exe_info[*exe_info_len] = 0;
    return 1;
}

#ifdef PS_CLI
int main(int argc, char **argv)
{
    if (argc != 5) {
        fprintf(stderr, "usage: %s FILE1 FILE2 FILE3 VALUESTRING_HEX\n", argv[0]);
        return 2;
    }

    uint8_t vs[256];
    size_t vl = strlen(argv[4]) / 2;
    if (vl > sizeof vs) {
        return 2;
    }
    for (size_t i = 0; i < vl; i++) {
        unsigned v;
        sscanf(argv[4] + 2 * i, "%2x", &v);
        vs[i] = (uint8_t)v;
    }

    uint32_t ver = 0, sum = 0;
    uint8_t info[24];
    size_t il = 0;
    if (!ps_check_revision(argv[1], argv[2], argv[3], (const char *)vs, vl, &ver, &sum, info, &il)) {
        puts("fail");
        return 1;
    }
    printf("version=%08x checksum=%08x info=", ver, sum);
    for (size_t i = 0; i < il; i++) printf("%02x", info[i]);
    putchar('\n');
    return 0;
}
#endif
