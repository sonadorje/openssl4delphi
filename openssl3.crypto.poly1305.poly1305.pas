unit openssl3.crypto.poly1305.poly1305;

{$I config.inc}
interface
uses
 OpenSSL.Api;

function Poly1305_ctx_size:size_t;
  function U8TOU32(const p : PByte):uint32;
//  function U8TOU64(const p : PByte):uint64;
//  procedure U64TO8( p : PByte; v : uint64);
  procedure poly1305_init(ctx : Pointer;const key : PByte);
  procedure poly1305_blocks(ctx : Pointer;inp : PByte; len : size_t; padbit : uint32);
  procedure poly1305_emit(ctx : Pointer; mac : PByte;const nonce : Puint32);
  procedure U32TO8( p : PByte; v : uint32);

  procedure _Poly1305_Init(ctx : PPOLY1305;const key : PByte);
  procedure _Poly1305_Update(ctx : PPOLY1305; inp : PByte; len : size_t);
  procedure _Poly1305_Final( ctx : PPOLY1305; mac : PByte);



implementation
uses openssl3.internal.constant_time, openssl3.crypto.mem;

function Poly1305_ctx_size:size_t;
begin
    Result := sizeof(poly1305_context);
end;


function U8TOU32(const p : PByte):uint32;
begin
    Result := (uint32(p[0] and $ff) or
              (uint32(p[1] and $ff)  shl  8) or
              (uint32(p[2] and $ff)  shl  16) or
              (uint32(p[3] and $ff)  shl  24));
end;

(*
 * Implementations can be classified by amount of significant bits in
 * words making up the multi-precision value, or in other words radix
 * or base of numerical representation, e.g. base 2^64, base 2^32,
 * base 2^26. Complementary characteristic is how wide is the result of
 * multiplication of pair of digits, e.g. it would take 128 bits to
 * accommodate multiplication result in base 2^64 case. These are used
 * interchangeably. To describe implementation that is. But interface
 * is designed to isolate this so that low-level primitives implemented
 * in assembly can be self-contained/self-coherent.
 *)
{$ifndef POLY1305_ASM}
(*
 * Even though there is __int128 reference implementation targeting
 * 64-bit platforms provided below, it's not obvious that it's optimal
 * choice for every one of them. Depending on instruction set overall
 * amount of instructions can be comparable to one in __int64
 * implementation. Amount of multiplication instructions would be lower,
 * but not necessarily overall. And in out-of-order execution context,
 * it is the latter that can be crucial...
 *
 * On related note. Poly1305 author, D. J. Bernstein, discusses and
 * provides floating-point implementations of the algorithm in question.
 * It made a lot of sense by the time of introduction, because most
 * then-modern processors didn't have pipelined integer multiplier.
 * [Not to mention that some had non-constant timing for integer
 * multiplications.] Floating-point instructions on the other hand could
 * be issued every cycle, which allowed to achieve better performance.
 * Nowadays, with SIMD and/or out-or-order execution, shared or
 * even emulated FPU, it's more complicated, and floating-point
 * implementation is not necessarily optimal choice in every situation,
 * rather contrary...
 *
 *                                              <appro@openssl.org>
 *)

(*
 * poly1305_blocks processes a multiple of POLY1305_BLOCK_SIZE blocks
 * of |inp| no longer than |len|. Behaviour for |len| not divisible by
 * block size is unspecified in general case, even though in reference
 * implementation the trailing chunk is simply ignored. Per algorithm
 * specification, every input block, complete or last partial, is to be
 * padded with a bit past most significant byte. The latter kind is then
 * padded with zeros till block size. This last partial block padding
 * is caller()'s responsibility, and because of this the last partial
 * block is always processed with separate call with |len| set to
 * POLY1305_BLOCK_SIZE and |padbit| to 0. In all other cases |padbit|
 * should be set to 1 to perform implicit padding with 128th bit.
 * poly1305_blocks does not actually check for this constraint though,
  it's caller(^)'s responsibility to comply.
 *
 * (^)  In the context "caller" is not application code, but higher
 *      level Poly1305_* from this very module, so that quirks are
 *      handled locally.
 *)

 function CONSTANT_TIME_CARRY(a,b:Uint32) :Uint32;
begin
   Result :=  (a xor ((a xor b) or ((a - b) xor b))) shr (sizeof(a) * 8 - 1)
end;

{$if defined(INT64_MAX) && defined(INT128_MAX)}

typedef unsigned long u64;
typedef uint128_t u128;
typedef struct {
    u64 h[3];
    u64 r[2];
} poly1305_internal;

// pick 32-bit unsigned integer in little endian order
function U8TOU64(const p : PByte):uint64;
begin
    Exit(((uint64(p[0] and $ff)) |);
            (uint64(p[1] and $ff)  shl  8) or
            (uint64(p[2] and $ff)  shl  16) or
            (uint64(p[3] and $ff)  shl  24) or
            (uint64(p[4] and $ff)  shl  32) or
            (uint64(p[5] and $ff)  shl  40) or
            (uint64(p[6] and $ff)  shl  48) or
            (uint64(p[7] and $ff)  shl  56));
end;


procedure U64TO8( p : PByte; v : uint64);
begin
    p[0] := Byte( ((v) and $ff);
    p[1] := Byte( ((v  shr  8) and $ff);
    p[2] := Byte( ((v  shr  16) and $ff);
    p[3] := Byte( ((v  shr  24) and $ff);
    p[4] := Byte( ((v  shr  32) and $ff);
    p[5] := Byte( ((v  shr  40) and $ff);
    p[6] := Byte( ((v  shr  48) and $ff);
    p[7] := Byte( ((v  shr  56) and $ff);
end;


procedure poly1305_init(ctx : Pointer;const key : Byte);
var
  st : Ppoly1305_internal;
begin
    st := Ppoly1305_internal (  ctx;
    { h = 0 }
    st.h[0] := 0;
    st.h[1] := 0;
    st.h[2] := 0;
    { r &= $ffffffc0ffffffc0ffffffc0fffffff }
    st.r[0] := U8TOU64(&key[0]) and $0ffffffc0fffffff;
    st.r[1] := U8TOU64(&key[8]) and $0ffffffc0ffffffc;
end;


procedure poly1305_blocks(ctx : Pointer;const inp : PByte; len : size_t; padbit : uint32);
var
  st : Ppoly1305_internal;

  r0, r1, s1, h0, h1, h2, c : uint64;

  d0, d1 : u128;
begin
    st := Ppoly1305_internal ( ctx;
    r0 := st.r[0];
    r1 := st.r[1];
    s1 := r1 + (r1  shr  2);
    h0 := st.h[0];
    h1 := st.h[1];
    h2 := st.h[2];
    while len >= POLY1305_BLOCK_SIZE do  begin
        { h += m[i] }
        h0 := uint64(d0 = uint128(h0 + U8TOU64(inp + 0));
        h1 := uint64(d1 = uint128(h1 + (d0  shr  64) + U8TOU64(inp + 8));
        {
         * padbit can be zero only when original len was
         * POLY1306_BLOCK_SIZE, but we don't check
         }
        h2  := h2 + (uint64(d1  shr  64) + padbit);
        { h *= r '%" p, where "%" stands for "partial remainder' }
        d0 := (uint128(h0 * r0) +
             (uint128(h1 * s1);
        d1 := (uint128(h0 * r1) +
             (uint128(h1 * r0) +
             (h2 * s1);
        h2 := (h2 * r0);
        { last reduction step: }
        { a) h2:h0 = h2 shl 128 + d1 shl 64 + d0 }
        h0 := uint64d0;
        h1 := uint64(d1  := h1 = uint64(d1 + (d0  shr  64));
        h2  := h2 + (uint64(d1  shr  64));
        { b) (h2:h0 += (h2:h0 shr 130) * 5) %= 2^130 }
        c := (h2  shr  2) + (h2 and ~3L);
        h2 &= 3;
        h0  := h0 + c;
        h1  := h1 + ((c = CONSTANT_TIME_CARRY(h0,c)));
        h2  := h2 + (CONSTANT_TIME_CARRY(h1,c));
        {
         * Occasional overflows to 3rd bit of h2 are taken care of
         * 'naturally'. If after this point we end up at the top of
         * this loop, then the overflow bit will be accounted for
         * in next iteration. If we end up in poly1305_emit, then
         * comparison to modulus below will still count as "carry
         * into 131st bit", so that properly reduced value will be
         * picked in conditional move.
         }
        inp  := inp + POLY1305_BLOCK_SIZE;
        len  := len - POLY1305_BLOCK_SIZE;
    end;
    st.h[0] := h0;
    st.h[1] := h1;
    st.h[2] := h2;
end;


procedure poly1305_emit(ctx : Pointer; mac : Byte;const nonce : uint32);
var
  st : Ppoly1305_internal;

  h0, h1, h2, g0, g1, g2 : uint64;

  t : u128;

  mask : uint64;
begin
    st := Ppoly1305_internal (  ctx;
    h0 := st.h[0];
    h1 := st.h[1];
    h2 := st.h[2];
    { compare to modulus by computing h + -p }
    g0 := uint64(t = uint128(h0 + 5);
    g1 := uint64(t = uint128(h1 + (t  shr  64));
    g2 := h2 + uint64(t  shr  64);
    { if there was carry into 131st bit, h1:h0 = g1:g0 }
    mask := 0 - (g2  shr  2);
    g0 &= mask;
    g1 &= mask;
    mask := ~mask;
    h0 := (h0 and mask) or g0;
    h1 := (h1 and mask) or g1;
    { mac = (h + nonce) % (2^128) }
    h0 := uint64(t = uint128(h0 + nonce[0] + (uint64nonce[1] shl 32));
    h1 := uint64(t = uint128(h1 + nonce[2] + (uint64nonce[3] shl 32) + (t  shr  64));
    U64TO8(mac + 0, h0);
    U64TO8(mac + 8, h1);
end;
{$ELSE}

{$if defined(MSWINDOWS)}
type u64 = uint64;
{$elseif defined(__arch64__)}
typedef unsigned long u64;
{$else}
typedef unsigned long long u64;
{$endif}


type
  poly1305_internal = record
    h: array[0..5-1] of Uint32;
    r: array[0..4-1] of Uint32;
 end;
 Ppoly1305_internal = ^poly1305_internal;

procedure U32TO8( p : PByte; v : uint32);
begin
    p[0] := Byte((v) and $ff);
    p[1] := Byte((v  shr  8) and $ff);
    p[2] := Byte((v  shr  16) and $ff);
    p[3] := Byte((v  shr  24) and $ff);
end;


procedure poly1305_init(ctx : Pointer;const key : PByte);
var
  st : Ppoly1305_internal;
begin
{$POINTERMATH ON}
    st := Ppoly1305_internal (  ctx);
    { h = 0 }
    st.h[0] := 0;
    st.h[1] := 0;
    st.h[2] := 0;
    st.h[3] := 0;
    st.h[4] := 0;
    { r &= $ffffffc0ffffffc0ffffffc0fffffff }
    st.r[0] := U8TOU32(@key[0]) and $0fffffff;
    st.r[1] := U8TOU32(@key[4]) and $0ffffffc;
    st.r[2] := U8TOU32(@key[8]) and $0ffffffc;
    st.r[3] := U8TOU32(@key[12]) and $0ffffffc;
{$POINTERMATH ON}
end;


procedure poly1305_blocks(ctx : Pointer;inp : PByte; len : size_t; padbit : uint32);
var
  st : Ppoly1305_internal;

  r0, r1, r2, r3, s1, s2, s3, h0, h1, h2, h3, h4, c : uint32;

  d0, d1, d2, d3 : uint64;
begin
    st := Ppoly1305_internal ( ctx);
    r0 := st.r[0];
    r1 := st.r[1];
    r2 := st.r[2];
    r3 := st.r[3];
    s1 := r1 + (r1  shr  2);
    s2 := r2 + (r2  shr  2);
    s3 := r3 + (r3  shr  2);
    h0 := st.h[0];
    h1 := st.h[1];
    h2 := st.h[2];
    h3 := st.h[3];
    h4 := st.h[4];
    while len >= POLY1305_BLOCK_SIZE do
    begin
        { h += m[i] }
        d0 := uint64(h0) + U8TOU32(inp + 0);
        h0 := uint32(d0);
        d1 := uint64(h1) + (d0  shr  32) + U8TOU32(inp + 4);
        h1 := uint32(d1);
        d2 := uint64(h2) + (d1  shr  32) + U8TOU32(inp + 8);
        h2 := uint32(d2);
        d3 := uint64(h3) + (d2  shr  32) + U8TOU32(inp + 12);
        h3 := uint32(d3);
        h4  := h4 + uint32(d3  shr  32) + padbit;
        { h *= r '%" p, where "%" stands for "partial remainder' }
        d0 := (uint64(h0) * r0) +
             (uint64(h1) * s3) +
             (uint64(h2) * s2) +
             (uint64(h3) * s1);
        d1 := (uint64(h0) * r1) +
             (uint64(h1) * r0) +
             (uint64(h2) * s3) +
             (uint64(h3) * s2) +
             (h4 * s1);
        d2 := (uint64(h0) * r2) +
             (uint64(h1) * r1) +
             (uint64(h2) * r0) +
             (uint64(h3) * s3) +
             (h4 * s2);
        d3 := (uint64(h0) * r3) +
             (uint64(h1) * r2) +
             (uint64(h2) * r1) +
             (uint64(h3) * r0) +
             (h4 * s3);
        h4 := (h4 * r0);
        { last reduction step: }
        { a) h4:h0 = h4 shl 128 + d3 shl 96 + d2 shl 64 + d1 shl 32 + d0 }
        h0 := uint32(d0);
        d1  := d1 + (d0  shr  32);
        h1 := uint32(d1);

        d2  := d2 + (d1  shr  32);
        h2 := uint32(d2);

        d3  := d3 + (d2  shr  32);
        h3 := uint32(d3);
        h4  := h4 + (uint32(d3  shr  32));
        { b) (h4:h0 += (h4:h0 shr 130) * 5) %= 2^130 }
        c := (h4  shr  2) + (h4 and (not UINT32(3)));
        h4 := h4 and 3;
        h0  := h0 + c;
        c := CONSTANT_TIME_CARRY(h0,c);
        h1  := h1 + (c);
        c := CONSTANT_TIME_CARRY(h1,c);
        h2  := h2 + (c);
        c := CONSTANT_TIME_CARRY(h2,c);
        h3  := h3 + (c);
        h4  := h4 + (CONSTANT_TIME_CARRY(h3,c));
        {
         * Occasional overflows to 3rd bit of h4 are taken care of
         * 'naturally'. If after this point we end up at the top of
         * this loop, then the overflow bit will be accounted for
         * in next iteration. If we end up in poly1305_emit, then
         * comparison to modulus below will still count as "carry
         * into 131st bit", so that properly reduced value will be
         * picked in conditional move.
         }
        inp  := inp + POLY1305_BLOCK_SIZE;
        len  := len - POLY1305_BLOCK_SIZE;
    end;
    st.h[0] := h0;
    st.h[1] := h1;
    st.h[2] := h2;
    st.h[3] := h3;
    st.h[4] := h4;
end;


procedure poly1305_emit(ctx : Pointer; mac : PByte;const nonce : Puint32);
var
  st : Ppoly1305_internal;

  h0, h1, h2, h3, h4, g0, g1, g2, g3, g4 : uint32;

  t : uint64;

  mask : uint32;
begin
{$POINTERMATH ON}
    st := Ppoly1305_internal (  ctx);
    h0 := st.h[0];
    h1 := st.h[1];
    h2 := st.h[2];
    h3 := st.h[3];
    h4 := st.h[4];
    { compare to modulus by computing h + -p }
    t := uint64(h0) + 5;
    g0 := uint32(t);
    t := uint64(h1 )+ (t  shr  32);
    g1 := uint32(t);
    t := uint64(h2 )+ (t  shr  32);
    g2 := uint32(t);
    t := uint64(h3 )+ (t  shr  32);
    g3 := uint32(t);
    g4 := h4 + uint32(t  shr  32);
    { if there was carry into 131st bit, h3:h0 = g3:g0 }
    mask := 0 - (g4  shr  2);
    g0 := g0 and mask;
    g1 := g1 and mask;
    g2 := g2 and mask;
    g3 := g3 and mask;
    mask := not mask;
    h0 := (h0 and mask) or g0;
    h1 := (h1 and mask) or g1;
    h2 := (h2 and mask) or g2;
    h3 := (h3 and mask) or g3;
    { mac = (h + nonce) % (2^128) }
    t  := uint64(h0 )+ nonce[0];
    h0 := uint32(t);
    t := uint64(h1 )+ (t  shr  32) + nonce[1];
    h1 := uint32(t);
    t := uint64(h2 )+ (t  shr  32) + nonce[2];
    h2 := uint32(t);
    t := uint64(h3 )+ (t  shr  32) + nonce[3];
    h3 := uint32(t);
    U32TO8(mac + 0, h0);
    U32TO8(mac + 4, h1);
    U32TO8(mac + 8, h2);
    U32TO8(mac + 12, h3);
{$POINTERMATH OFF}
end;
{$endif}
{$else}
int poly1305_init(void *ctx, const unsigned char key[16], void *func);
void poly1305_blocks(void *ctx, const unsigned char *inp, size_t len,
                     unsigned int padbit);
void poly1305_emit(void *ctx, unsigned char mac[16],
                   const unsigned int nonce[4]);
{$endif}

procedure _Poly1305_Init(ctx : PPOLY1305;const key : PByte);
begin
    ctx.nonce[0] := U8TOU32(@key[16]);
    ctx.nonce[1] := U8TOU32(@key[20]);
    ctx.nonce[2] := U8TOU32(@key[24]);
    ctx.nonce[3] := U8TOU32(@key[28]);
{$IFNDEF POLY1305_ASM}
    poly1305_init(@ctx.opaque, @key);
{$ELSE}
     * Unlike reference poly1305_init assembly counterpart is expected
     * to return a value: non-zero if it initializes ctx.func, and zero
     * otherwise. Latter is to simplify assembly in cases when there no
     * multiple code paths to switch between.
     }
    if 0>= poly1305_init(ctx.opaque, key, &ctx.func then ) begin
        ctx.func.blocks := poly1305_blocks;
        ctx.func.emit := poly1305_emit;
    end;
{$ENDIF}
    ctx.num := 0;
end;

{$ifdef POLY1305_ASM}
(*
 * This "eclipses" poly1305_blocks and poly1305_emit, but it's
 * conscious choice imposed by -Wshadow compiler warnings.
 *)
//# define poly1305_blocks (*poly1305_blocks_p)
//# define poly1305_emit   (*poly1305_emit_p)
{$endif}

procedure _Poly1305_Update(ctx : PPOLY1305;inp : PByte; len : size_t);
var
    poly1305_blocks_p : poly1305_blocks_f;

  rem,
  num               : size_t;
begin
{$IFDEF POLY1305_ASM}
    {
     * As documented, poly1305_blocks is never called with input
     * longer than single block and padbit argument set to 0. This
     * property is fluently used in assembly modules to optimize
     * padbit handling on loop boundary.
     }
    poly1305_blocks_p := ctx.func.blocks;
{$ENDIF}
    if num = ctx.num  then
    begin
        rem := POLY1305_BLOCK_SIZE - num;
        if len >= rem then
        begin
            memcpy(PByte(@ctx.data) + num, inp, rem);
            poly1305_blocks(@ctx.opaque, @ctx.data, POLY1305_BLOCK_SIZE, 1);
            inp  := inp + rem;
            len  := len - rem;
        end
        else
        begin
            { Still not enough data to process a block. }
            memcpy(PByte(@ctx.data) + num, inp, len);
            ctx.num := num + len;
            exit;
        end;
    end;
    rem := len mod POLY1305_BLOCK_SIZE;
    len  := len - rem;
    if len >= POLY1305_BLOCK_SIZE then
    begin
        poly1305_blocks(@ctx.opaque, inp, len, 1);
        inp  := inp + len;
    end;
    if rem>0 then
       memcpy(@ctx.data, inp, rem);
    ctx.num := rem;
end;


procedure _Poly1305_Final( ctx : PPOLY1305; mac : PByte);
var
    poly1305_blocks_p : poly1305_blocks_f;

    poly1305_emit_p   : poly1305_emit_f;

    num               : size_t;
begin
{$IFDEF POLY1305_ASM}
    poly1305_blocks_p := ctx.func.blocks;
    poly1305_emit_p := ctx.func.emit;
{$ENDIF}
    if num = ctx.num then
    begin
        ctx.data[PostInc(num)] := 1;   { pad bit }
        while num < POLY1305_BLOCK_SIZE do
            ctx.data[PostInc(num)] := 0;
        poly1305_blocks(@ctx.opaque, @ctx.data, POLY1305_BLOCK_SIZE, 0);
    end;
    poly1305_emit(@ctx.opaque, @mac, @ctx.nonce);
    { zero out the state }
    OPENSSL_cleanse(ctx, sizeof( ctx^));
end;


end.
