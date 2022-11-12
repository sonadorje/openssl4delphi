unit openssl3.crypto.modes.gcm128;

interface
uses OpenSSL.Api;

{$if defined(GHASH_ASM) or not defined(OPENSSL_SMALL_FOOTPRINT)}
   {$define GHASH}
(*
 * GHASH_CHUNK is "stride parameter" missioned to mitigate cache trashing
 * effect. In other words idea is to hash data while it's still in L1 cache
 * after encryption pass...
 *)
  const GHASH_CHUNK =      (3*1024);
{$endif}

 const rem_4bit: array[0..15] of size_t = (
    (size_t($0000) shl (sizeof(size_t)*8-16)), (size_t($1C20) shl (sizeof(size_t)*8-16)), (size_t($3840) shl (sizeof(size_t)*8-16)), (size_t($2460) shl (sizeof(size_t)*8-16)),
    (size_t($7080) shl (sizeof(size_t)*8-16)), (size_t($6CA0) shl (sizeof(size_t)*8-16)), (size_t($48C0) shl (sizeof(size_t)*8-16)), (size_t($54E0) shl (sizeof(size_t)*8-16)),
    (size_t($E100) shl (sizeof(size_t)*8-16)), (size_t($FD20) shl (sizeof(size_t)*8-16)), (size_t($D940) shl (sizeof(size_t)*8-16)), (size_t($C560) shl (sizeof(size_t)*8-16)),
    (size_t($9180) shl (sizeof(size_t)*8-16)), (size_t($8DA0) shl (sizeof(size_t)*8-16)), (size_t($A9C0) shl (sizeof(size_t)*8-16)), (size_t($B5E0) shl (sizeof(size_t)*8-16))
);

  rem_8bit : array[0..255] of uint16 = (
    $0000, $01C2, $0384, $0246, $0708, $06CA, $048C, $054E, $0E10, $0FD2,
    $0D94, $0C56, $0918, $08DA, $0A9C, $0B5E, $1C20, $1DE2, $1FA4, $1E66,
    $1B28, $1AEA, $18AC, $196E, $1230, $13F2, $11B4, $1076, $1538, $14FA,
    $16BC, $177E, $3840, $3982, $3BC4, $3A06, $3F48, $3E8A, $3CCC, $3D0E,
    $3650, $3792, $35D4, $3416, $3158, $309A, $32DC, $331E, $2460, $25A2,
    $27E4, $2626, $2368, $22AA, $20EC, $212E, $2A70, $2BB2, $29F4, $2836,
    $2D78, $2CBA, $2EFC, $2F3E, $7080, $7142, $7304, $72C6, $7788, $764A,
    $740C, $75CE, $7E90, $7F52, $7D14, $7CD6, $7998, $785A, $7A1C, $7BDE,
    $6CA0, $6D62, $6F24, $6EE6, $6BA8, $6A6A, $682C, $69EE, $62B0, $6372,
    $6134, $60F6, $65B8, $647A, $663C, $67FE, $48C0, $4902, $4B44, $4A86,
    $4FC8, $4E0A, $4C4C, $4D8E, $46D0, $4712, $4554, $4496, $41D8, $401A,
    $425C, $439E, $54E0, $5522, $5764, $56A6, $53E8, $522A, $506C, $51AE,
    $5AF0, $5B32, $5974, $58B6, $5DF8, $5C3A, $5E7C, $5FBE, $E100, $E0C2,
    $E284, $E346, $E608, $E7CA, $E58C, $E44E, $EF10, $EED2, $EC94, $ED56,
    $E818, $E9DA, $EB9C, $EA5E, $FD20, $FCE2, $FEA4, $FF66, $FA28, $FBEA,
    $F9AC, $F86E, $F330, $F2F2, $F0B4, $F176, $F438, $F5FA, $F7BC, $F67E,
    $D940, $D882, $DAC4, $DB06, $DE48, $DF8A, $DDCC, $DC0E, $D750, $D692,
    $D4D4, $D516, $D058, $D19A, $D3DC, $D21E, $C560, $C4A2, $C6E4, $C726,
    $C268, $C3AA, $C1EC, $C02E, $CB70, $CAB2, $C8F4, $C936, $CC78, $CDBA,
    $CFFC, $CE3E, $9180, $9042, $9204, $93C6, $9688, $974A, $950C, $94CE,
    $9F90, $9E52, $9C14, $9DD6, $9898, $995A, $9B1C, $9ADE, $8DA0, $8C62,
    $8E24, $8FE6, $8AA8, $8B6A, $892C, $88EE, $83B0, $8272, $8034, $81F6,
    $84B8, $857A, $873C, $86FE, $A9C0, $A802, $AA44, $AB86, $AEC8, $AF0A,
    $AD4C, $AC8E, $A7D0, $A612, $A454, $A596, $A0D8, $A11A, $A35C, $A29E,
    $B5E0, $B422, $B664, $B7A6, $B2E8, $B32A, $B16C, $B0AE, $BBF0, $BA32,
    $B874, $B9B6, $BCF8, $BD3A, $BF7C, $BEBE );

procedure CRYPTO_gcm128_setiv(ctx : PGCM128_CONTEXT;{const} iv : PByte; len : size_t);
procedure gcm_gmult_4bit(Xi : Puint64;const Htable : Pu128);
function CRYPTO_gcm128_encrypt(ctx : PGCM128_CONTEXT;{const} _in : PByte; _out : PByte; len : size_t):integer;
procedure gcm_ghash_4bit(Xi : Puint64;const Htable : Pu128;{const} inp : Pbyte; len : size_t);
function CRYPTO_gcm128_aad(ctx : PGCM128_CONTEXT;{const} aad : PByte; len : size_t):integer;
function CRYPTO_gcm128_decrypt(ctx : PGCM128_CONTEXT;{const} _in : PByte; _out : PByte; len : size_t):integer;
procedure CRYPTO_gcm128_tag( ctx : PGCM128_CONTEXT; tag : PByte; len : size_t);

function CRYPTO_gcm128_finish(ctx : PGCM128_CONTEXT;const tag : PByte; len : size_t):integer;
procedure CRYPTO_gcm128_init( ctx : PGCM128_CONTEXT; key : Pointer; block : block128_f);
procedure gcm_init_4bit( Htable : Pu128; H : Puint64);
function CRYPTO_gcm128_encrypt_ctr32(ctx : PGCM128_CONTEXT;{const} _in : PByte; _out : PByte; len : size_t; stream : ctr128_f):integer;
function CRYPTO_gcm128_decrypt_ctr32(ctx : PGCM128_CONTEXT;{const} _in : PByte; _out : PByte; len : size_t; stream : ctr128_f):integer;
procedure GCM_MUL(ctx: PGCM128_CONTEXT);

implementation

uses openssl3.crypto.cpuid;

procedure GCM_MUL(ctx: PGCM128_CONTEXT);
begin
      gcm_gmult_4bit(@ctx.Xi.u, @ctx.Htable)
end;

function CRYPTO_gcm128_decrypt_ctr32(ctx : PGCM128_CONTEXT;{const} _in : PByte; _out : PByte; len : size_t; stream : ctr128_f):integer;
var
  n, ctr, mres : uint32;
  i : size_t;
  mlen : uint64;
  key : Pointer;
  c, m : uint8;
  j, k : size_t;
  ossl_is_endian: endian_st;
begin

{$IF defined(OPENSSL_SMALL_FOOTPRINT)}
    Exit(CRYPTO_gcm128_decrypt(ctx, in, out, len));
{$ELSE}
     //DECLARE_IS_ENDIAN;

    ossl_is_endian.one := 1;
    mlen := ctx.len.u[1];
    key := ctx.key;
  {$IFDEF GCM_FUNCREF_4BIT}
    void ( *gcm_gmult_p) (uint64 Xi[2], const u128 Htable[16]) = ctx.gmult;
    {$ifdef GHASH}
    void ( *gcm_ghash_p) (uint64 Xi[2], const u128 Htable[16],
                         const u8 *inp, size_t len) = ctx.ghash;
    {$endif}
  {$ENDIF}
    mlen  := mlen + len;
    if (mlen > (Uint64(1) shl 36) - 32)  or ( (sizeof(len) = 8)  and  (mlen < len)) then
        Exit(-1);
    ctx.len.u[1] := mlen;
    mres := ctx.mres;
    if ctx.ares > 0 then
    begin
        { First call to decrypt finalizes GHASH(AAD) }
  {$IF defined(GHASH)}
        if len = 0 then
        begin
            GCM_MUL(ctx);
            ctx.ares := 0;
            Exit(0);
        end;
        memcpy(@ctx.Xn, @ctx.Xi.c, sizeof(ctx.Xi));
        ctx.Xi.u[0] := 0;
        ctx.Xi.u[1] := 0;
        mres := sizeof(ctx.Xi);
  {$ELSE} GCM_MUL(ctx);
  {$ENDIF}
        ctx.ares := 0;
    end;
    if ossl_is_endian.little <> 0 then
  {$ifdef BSWAP4}
        ctr := BSWAP4(ctx.Yi.d[3]);
  {$ELSE}
        ctr := GETU32(PByte(@ctx.Yi.c) + 12)
  {$ENDIF}
    else
        ctr := ctx.Yi.d[3];
    n := mres mod 16;
    if n > 0 then begin
  {$IF defined(GHASH)}
        while (n > 0)  and  (len > 0) do
        begin
            m := PostInc(_in)^  xor  ctx.EKi.c[n];
            ctx.Xn[PostInc(mres)] := m;
            PostInc(_out)^ := m;
            PreDec(len);
            n := (n + 1) mod 16;
        end;
        if n = 0 then begin
            //GHASH(ctx, ctx.Xn, mres);
            gcm_ghash_4bit(@ctx.Xi.u, @ctx.Htable, @ctx.Xn, mres);
            mres := 0;
        end
        else
        begin
            ctx.mres := mres;
            Exit(0);
        end;
  {$ELSE}
        while n  and  len do  begin
            c := *(PostInc(in));
            *(PostInc(out)) = c  xor  ctx.EKi.c[n];
            ctx.Xi.c[n]  := ctx.Xi.c[n] xor c;
            PreDec(len);
            n := (n + 1) % 16;
        end;
        if n = 0 then begin
            GCM_MUL(ctx);
            mres := 0;
        end;
        else begin
            ctx.mres := n;
            Exit(0);
        end;
  {$ENDIF}
    end;
  {$IF defined(GHASH)}
    if (len >= 16)  and  (mres > 0) then
    begin
        //GHASH(ctx, ctx.Xn, mres);
        gcm_ghash_4bit(@ctx.Xi.u, @ctx.Htable, @ctx.Xn, mres);
        mres := 0;
    end;
    {$IF GHASH_CHUNK>0}
    while len >= GHASH_CHUNK do
    begin
        //GHASH(ctx, in, GHASH_CHUNK);
        gcm_ghash_4bit(@ctx.Xi.u, @ctx.Htable, _in, GHASH_CHUNK);
        stream(_in, _out, GHASH_CHUNK div 16, key, @ctx.Yi.c);
        ctr  := ctr + (GHASH_CHUNK div 16);
        if ossl_is_endian.little <> 0 then
     {$ifdef BSWAP4}
            ctx.Yi.d[3] := BSWAP4(ctr);
     {$ELSE}
            PUTU32(PByte(@ctx.Yi.c) + 12, ctr)
     {$ENDIF}
        else
            ctx.Yi.d[3] := ctr;
        _out  := _out + GHASH_CHUNK;
        _in  := _in + GHASH_CHUNK;
        len  := len - GHASH_CHUNK;
    end;
    {$endif}
  {$ENDIF}
    if i = (len and size_t(-16) ) then  begin
        j := i div 16;
  {$IF defined(GHASH)}
        //GHASH(ctx, in, i);
        gcm_ghash_4bit(@ctx.Xi.u, @ctx.Htable, _in, i);
  {$ELSE}
        while PostDec(j) do  begin
            for (k = 0; k < 16; PreInc(k))
                ctx.Xi.c[k]  := ctx.Xi.c[k] xor (in[k]);
            GCM_MUL(ctx);
            in  := in + 16;
        end;
        j := i / 16;
        in  := in - i;
  {$ENDIF}
        stream(_in, _out, j, key, @ctx.Yi.c);
        ctr  := ctr + uint32(j);
        if ossl_is_endian.little <> 0 then
  {$ifdef BSWAP4}
            ctx.Yi.d[3] := BSWAP4(ctr);
  {$ELSE}
            PUTU32(PByte(@ctx.Yi.c) + 12, ctr)
  {$ENDIF}
        else
            ctx.Yi.d[3] := ctr;
        _out  := _out + i;
        _in  := _in + i;
        len  := len - i;
    end;
    if len > 0 then
    begin
        ctx.block(@ctx.Yi.c, @ctx.EKi.c, key);
        Inc(ctr);
        if ossl_is_endian.little <> 0 then
  {$ifdef BSWAP4}
            ctx.Yi.d[3] := BSWAP4(ctr);
  {$ELSE}
            PUTU32(PByte(@ctx.Yi.c) + 12, ctr)
  {$ENDIF}
        else
            ctx.Yi.d[3] := ctr;
        while PostDec(len) > 0 do
        begin
  {$IF defined(GHASH)}
            ctx.Xn[PostInc(mres)] := _in[n];
            _out[n] := _in[n]  xor  ctx.EKi.c[n];
  {$ELSE}
            c := in[n];
            ctx.Xi.c[PostInc(mres)]  := ctx.Xi.c[PostInc(mres)] xor c;
            _out[n] := c  xor  ctx.EKi.c[n];
  {$ENDIF}
            Inc(n);
        end;
    end;
    ctx.mres := mres;
    Exit(0);
{$ENDIF}
end;



function CRYPTO_gcm128_encrypt_ctr32(ctx : PGCM128_CONTEXT;{const} _in : PByte; _out : PByte; len : size_t; stream : ctr128_f):integer;
var
  n, ctr, mres : uint32;
  i : size_t;
  mlen : uint64;
  key : Pointer;
  j : size_t;
  k : Byte;
  ossl_is_endian: endian_st;
begin

    ossl_is_endian.one := 1;
{$IF defined(OPENSSL_SMALL_FOOTPRINT)}
    Exit(CRYPTO_gcm128_encrypt(ctx, in, out, len));
{$ELSE DECLARE_IS_ENDIAN;}
    mlen := ctx.len.u[1];
    key := ctx.key;
  {$IFDEF GCM_FUNCREF_4BIT}
    void ( *gcm_gmult_p) (uint64 Xi[2], const u128 Htable[16]) = ctx.gmult;
    {$ifdef GHASH}
    void ( *gcm_ghash_p) (uint64 Xi[2], const u128 Htable[16],
                         const u8 *inp, size_t len) = ctx.ghash;
    {$endif}
  {$ENDIF}
    mlen  := mlen + len;
    if (mlen > (Uint64(1) shl 36) - 32)  or ( (sizeof(len) = 8)  and  (mlen < len)) then
        Exit(-1);
    ctx.len.u[1] := mlen;
    mres := ctx.mres;
    if ctx.ares > 0 then
    begin
        { First call to encrypt finalizes GHASH(AAD) }
{$IF defined(GHASH)}
        if len = 0 then
        begin
            //GCM_MUL(ctx);
            gcm_gmult_4bit(@ctx.Xi.u, @ctx.Htable);
            ctx.ares := 0;
            Exit(0);
        end;
        memcpy(@ctx.Xn, @ctx.Xi.c, sizeof(ctx.Xi));
        ctx.Xi.u[0] := 0;
        ctx.Xi.u[1] := 0;
        mres := sizeof(ctx.Xi);
{$ELSE}
        GCM_MUL(ctx);
{$ENDIF}
        ctx.ares := 0;
    end;
    if ossl_is_endian.little <> 0 then
{$ifdef BSWAP4}
        ctr := BSWAP4(ctx.Yi.d[3]);
{$ELSE}
        ctr := GETU32(Pbyte(@ctx.Yi.c) + 12)
{$ENDIF}
    else
        ctr := ctx.Yi.d[3];
    n := mres mod 16;
    if n > 0 then
    begin
  {$IF defined(GHASH)}
        while (n > 0)  and  (len > 0) do
        begin
            k := PostInc(_in)^  xor  ctx.EKi.c[n];
            PostInc(_out)^ := k;
            ctx.Xn[mres] := k;
            Inc(mres);
            Dec(len);
            n := (n + 1) mod 16;
        end;
        if n = 0 then
        begin
            //GHASH(ctx, ctx.Xn, mres);
            gcm_ghash_4bit(@ctx.Xi.u, @ctx.Htable, @ctx.Xn, mres);
            mres := 0;
        end
        else
        begin
            ctx.mres := mres;
            Exit(0);
        end;
  {$ELSE while n  and  len do  begin }
            ctx.Xi.c[n]  := ctx.Xi.c[n] xor ( *(PostInc(out)) = *(PostInc(in)) xor ctx.EKi.c[n]);
            PreDec(len);
            n := (n + 1) % 16;
        end;
        if n = 0 then begin
            GCM_MUL(ctx);
            mres := 0;
        end;
 else begin
            ctx.mres := n;
            Exit(0);
        end;
  {$ENDIF}
    end;
  {$IF defined(GHASH)}
        if (len >= 16)  and  (mres > 0) then
        begin
            //GHASH(ctx, ctx.Xn, mres);
            gcm_ghash_4bit(@ctx.Xi.u, @ctx.Htable, @ctx.Xn, mres);
            mres := 0;
        end;
    {$if GHASH_CHUNK > 0}
    while len >= GHASH_CHUNK do
    begin
        stream(_in, _out, GHASH_CHUNK div 16, key, @ctx.Yi.c);
        ctr  := ctr + (GHASH_CHUNK div 16);
        if ossl_is_endian.little <> 0 then
     {$ifdef BSWAP4}
            ctx.Yi.d[3] := BSWAP4(ctr);
     {$ELSE}
            PUTU32(PByte(@ctx.Yi.c) + 12, ctr)
     {$ENDIF}
        else
            ctx.Yi.d[3] := ctr;
        //GHASH(ctx, out, GHASH_CHUNK);
        gcm_ghash_4bit(@ctx.Xi.u, @ctx.Htable, _out, GHASH_CHUNK);
        _out  := _out + GHASH_CHUNK;
        _in  := _in + GHASH_CHUNK;
        len  := len - GHASH_CHUNK;
    end;
    {$endif}
  {$ENDIF}
    if i = (len and size_t(-16))  then
    begin
        j := i div 16;
        stream (_in, _out, j, key, @ctx.Yi.c);
        ctr  := ctr + uint32(j);
        if ossl_is_endian.little <> 0 then
  {$ifdef BSWAP4}
            ctx.Yi.d[3] := BSWAP4(ctr);
  {$ELSE}
            PUTU32(PByte(@ctx.Yi.c) + 12, ctr)
  {$ENDIF}
        else
            ctx.Yi.d[3] := ctr;
        _in  := _in + i;
        len  := len - i;
  {$IF defined(GHASH)}
        //GHASH(ctx, out, i);
        gcm_ghash_4bit(@ctx.Xi.u, @ctx.Htable, _out, i);
        _out  := _out + i;
  {$ELSE}
        while PostDec(j) > 0 do
        begin
            for (i = 0; i < 16; PreInc(i))
                ctx.Xi.c[i]  := ctx.Xi.c[i] xor (_out[i]);
            GCM_MUL(ctx);
            _out  := _out + 16;
        end;
  {$ENDIF}
    end;
    if len > 0 then
    begin
        ctx.block(@ctx.Yi.c, @ctx.EKi.c, key);
        Inc(ctr);
        if ossl_is_endian.little <> 0 then
  {$ifdef BSWAP4}
            ctx.Yi.d[3] := BSWAP4(ctr);
  {$ELSE}
            PUTU32(PByte(@ctx.Yi.c) + 12, ctr)
  {$ENDIF}
        else
            ctx.Yi.d[3] := ctr;
        while PostDec(len) > 0 do
        begin
  {$IF defined(GHASH)}
            _out[n] := _in[n]  xor  ctx.EKi.c[n];
            ctx.Xn[mres] := _out[n];
            Inc(mres);
  {$ELSE}
            ctx.Xi.c[PostInc(mres)]  := ctx.Xi.c[PostInc(mres)] xor (out[n] = in[n] xor ctx.EKi.c[n]);}
  {$ENDIF}
            Inc(n);
        end;
    end;
    ctx.mres := mres;
    Exit(0);
{$ENDIF}
end;

{$OVERFLOWCHECKS OFF}
procedure gcm_init_4bit( Htable : Pu128; H : Puint64);
var
  V : u128;
{$IF defined(OPENSSL_SMALL_FOOTPRINT)}
  i : integer;
{$ENDIF}
  Hi : Pu128;
  j : integer;
  T1, tmp1, tmp2: UInt64;
  T2, tmp3, tmp4: UInt32;
begin
{$POINTERMATH ON}
    Htable[0].hi := 0;
    Htable[0].lo := 0;
    V.hi := H[0];
    V.lo := H[1];
{$IF defined(OPENSSL_SMALL_FOOTPRINT)}
    for (Htable[8] = V, i = 4; i > 0; i  shr = 1) begin
        REDUCE1BIT(V);
        Htable[i] := V;
    end;
    for (i = 2; i < 16; i shl= 1) begin
        *Hi := Htable + i;
        for (V = *Hi, j = 1; j < i; PreInc(j)) begin
            Hi[j].hi := V.hi  xor  Htable[j].hi;
            Hi[j].lo := V.lo  xor  Htable[j].lo;
        end;
    end;
{$ELSE}
     Htable[8] := V;
     if sizeof(size_t)  =8 then
     begin
         T1 := $e100000000000000 and (0-(V.lo and 1));
         V.lo := (V.hi shl 63) or (V.lo shr 1);
         V.hi := (V.hi shr 1 ) xor T1;
     end
     else
     begin
         //4,294,967,295
         //3,774,873,600
         T2 := $e1000000 and (0- uint32(V.lo and 1));
         V.lo := (V.hi shl 63) or (V.lo shr 1);
         V.hi := (V.hi shr 1 ) xor (uint64(T2) shl 32);
     end;
     Htable[4] := V;
     if sizeof(size_t) =8  then
     begin
         T1 := $e100000000000000 and (0-(V.lo and 1));
         V.lo := (V.hi shl 63) or (V.lo shr 1);
         V.hi := (V.hi shr 1 ) xor T1;
     end
     else
     begin
         T2 := $e1000000 and (0- uint32(V.lo and 1));
         V.lo := (V.hi shl 63) or (V.lo shr 1);
         V.hi := (V.hi shr 1 ) xor (uint64(T2) shl 32);
     end;

     Htable[2] := V;
     if sizeof(size_t) =8  then
     begin
         T1 := $e100000000000000 and (0-(V.lo and 1));
         V.lo := (V.hi shl 63) or (V.lo shr 1);
         V.hi := (V.hi shr 1 ) xor T1;
     end
     else
     begin
         T2 := $e1000000 and (0- uint32(V.lo and 1));
         V.lo := (V.hi shl 63) or (V.lo shr 1);
         V.hi := (V.hi shr 1 ) xor (uint64(T2) shl 32);
     end;
    Htable[1] := V;
    Htable[3].hi := V.hi  xor  Htable[2].hi; Htable[3].lo := V.lo  xor  Htable[2].lo;
    V := Htable[4];
    Htable[5].hi := V.hi  xor  Htable[1].hi; Htable[5].lo := V.lo  xor  Htable[1].lo;
    Htable[6].hi := V.hi  xor  Htable[2].hi; Htable[6].lo := V.lo  xor  Htable[2].lo;
    Htable[7].hi := V.hi  xor  Htable[3].hi; Htable[7].lo := V.lo  xor  Htable[3].lo;
    V := Htable[8];
    Htable[9].hi := V.hi  xor  Htable[1].hi; Htable[9].lo := V.lo  xor  Htable[1].lo;
    Htable[10].hi := V.hi  xor  Htable[2].hi; Htable[10].lo := V.lo  xor  Htable[2].lo;
    Htable[11].hi := V.hi  xor  Htable[3].hi; Htable[11].lo := V.lo  xor  Htable[3].lo;
    Htable[12].hi := V.hi  xor  Htable[4].hi; Htable[12].lo := V.lo  xor  Htable[4].lo;
    Htable[13].hi := V.hi  xor  Htable[5].hi; Htable[13].lo := V.lo  xor  Htable[5].lo;
    Htable[14].hi := V.hi  xor  Htable[6].hi; Htable[14].lo := V.lo  xor  Htable[6].lo;
    Htable[15].hi := V.hi  xor  Htable[7].hi; Htable[15].lo := V.lo  xor  Htable[7].lo;
{$ENDIF}
{$IF defined(GHASH_ASM)  and  (defined(__arm__)  or  defined(__arm))}
    {
     * ARM assembler expects specific dword order in Htable.
     }
    begin
        DECLARE_IS_ENDIAN;
        if IS_LITTLE_ENDIAN then for (j = 0; j < 16; PreInc(j)) begin
                V := Htable[j];
                Htable[j].hi := V.lo;
                Htable[j].lo := V.hi;
        end;
 else
            for (j = 0; j < 16; PreInc(j)) begin
                V := Htable[j];
                Htable[j].hi := V.lo shl 32 or V.lo  shr  32;
                Htable[j].lo := V.hi shl 32 or V.hi  shr  32;
            end;
    end;
{$ENDIF}
{$POINTERMATH OFF}
end;
{$OVERFLOWCHECKS ON}

procedure CRYPTO_gcm128_init( ctx : PGCM128_CONTEXT; key : Pointer; block : block128_f);
var
   ossl_is_endian: endian_st;
   p: PByte;
   hi, lo: uint64;
   {$if    defined(GHASH)}
    procedure CTX__GHASH(f: Tghash_func);
    begin
       ctx.ghash := f;
    end;
  {$else}
    function CTX__GHASH(f): Boolean;
    begin
       Result := (ctx.ghash = nil);
    end;
  {$endif}
begin

    ossl_is_endian.one := 1;
    //DECLARE_IS_ENDIAN;

    memset(ctx, 0, sizeof(ctx^));
    ctx.block := block;
    ctx.key := key;

    block(@ctx.H.c, @ctx.H.c, key);

    if ossl_is_endian.little <> 0 then
    begin
        (* H is stored in host byte order *)
{$ifdef BSWAP8}
        ctx.H.u[0] := BSWAP8(ctx.H.u[0]);
        ctx.H.u[1] := BSWAP8(ctx.H.u[1]);
{$else}
        p := @ctx.H.c;

        hi := uint64(GETU32(p)) shl 32 or GETU32(p + 4);
        lo := uint64(GETU32(p + 8)) shl 32 or GETU32(p + 12);
        ctx.H.u[0] := hi;
        ctx.H.u[1] := lo;
{$endif}
    end;
{$if     TABLE_BITS = 8}
    gcm_init_8bit(ctx.Htable, ctx.H.u);
{$elseif   TABLE_BITS = 4}

  {$if    defined(GHASH_ASM_X86_OR_64)}
   {$if   not defined(GHASH_ASM_X86) or defined(OPENSSL_IA32_SSE2)}
    if (OPENSSL_ia32cap_P[1] & (1 shl 1)) begin /* check PCLMULQDQ bit */
        if (((OPENSSL_ia32cap_P[1] >> 22) & 0x41) :=:= 0x41) begin /* AVX+MOVBE */
            gcm_init_avx(ctx.Htable, ctx.H.u);
            ctx.gmult := gcm_gmult_avx;
            CTX__GHASH(gcm_ghash_avx);
        end; else begin
            gcm_init_clmul(ctx.Htable, ctx.H.u);
            ctx.gmult := gcm_gmult_clmul;
            CTX__GHASH(gcm_ghash_clmul);
        end;
        return;
    end;
  {$endif}
    gcm_init_4bit(ctx.Htable, ctx.H.u);
  {$if   defined(GHASH_ASM_X86)}  (* x86 only *)
    {$if  defined(OPENSSL_IA32_SSE2) }
    if (OPENSSL_ia32cap_P[0] & (1 shl 25)) begin (* check SSE bit *)
    {$else}
    if (OPENSSL_ia32cap_P[0] & (1 shl 23)) begin (* check MMX bit *)
    {$endif}
        ctx.gmult := gcm_gmult_4bit_mmx;
        CTX__GHASH(gcm_ghash_4bit_mmx);
    end
    else
    begin
        ctx.gmult := gcm_gmult_4bit_x86;
        CTX__GHASH(gcm_ghash_4bit_x86);
    end;
   {$else}
    ctx.gmult := gcm_gmult_4bit;
    CTX__GHASH(gcm_ghash_4bit);
   {$endif}
  {$elseif  defined(GHASH_ASM_ARM) }
   {$ifdef PMULL_CAPABLE}
    if (PMULL_CAPABLE) begin
        gcm_init_v8(ctx.Htable, ctx.H.u);
        ctx.gmult := gcm_gmult_v8;
        CTX__GHASH(gcm_ghash_v8);
    end; else
  {$endif}
  {$ifdef NEON_CAPABLE}
    if (NEON_CAPABLE)
    begin
        gcm_init_neon(ctx.Htable, ctx.H.u);
        ctx.gmult := gcm_gmult_neon;
        CTX__GHASH(gcm_ghash_neon);
    end
    else
  {$endif}
    begin
        gcm_init_4bit(ctx.Htable, ctx.H.u);
        ctx.gmult := gcm_gmult_4bit;
        CTX__GHASH(gcm_ghash_4bit);
    end;
  {$elseif  defined(GHASH_ASM_SPARC)}
    if (OPENSSL_sparcv9cap_P[0] & SPARCV9_VIS3) begin
        gcm_init_vis3(ctx.Htable, ctx.H.u);
        ctx.gmult := gcm_gmult_vis3;
        CTX__GHASH(gcm_ghash_vis3);
    end
    else
    begin
        gcm_init_4bit(ctx.Htable, ctx.H.u);
        ctx.gmult := gcm_gmult_4bit;
        CTX__GHASH(gcm_ghash_4bit);
    end;
  {$elseif  defined(GHASH_ASM_PPC)}
    if (OPENSSL_ppccap_P & PPC_CRYPTO207) begin
        gcm_init_p8(ctx.Htable, ctx.H.u);
        ctx.gmult := gcm_gmult_p8;
        CTX__GHASH(gcm_ghash_p8);
    end; else begin
        gcm_init_4bit(ctx.Htable, ctx.H.u);
        ctx.gmult := gcm_gmult_4bit;
        CTX__GHASH(gcm_ghash_4bit);
    end;
  {$else}
    gcm_init_4bit(@ctx.Htable, @ctx.H.u);
  {$endif}

{$endif}

end;

function CRYPTO_gcm128_finish(ctx : PGCM128_CONTEXT;const tag : PByte; len : size_t):integer;
var
  alen, clen : uint64;
  bitlen : u128;
  mres : uint32;
  blocks : uint32;
  p : PByte;
  ossl_is_endian: endian_st;
begin
{$POINTERMATH ON}
    ossl_is_endian.one := 1;
    //DECLARE_IS_ENDIAN;
    alen := ctx.len.u[0] shl 3;
    clen := ctx.len.u[1] shl 3;
{$IFDEF GCM_FUNCREF_4BIT}
    void ( *gcm_gmult_p) (uint64 Xi[2], const u128 Htable[16]) = ctx.gmult;
  {$if defined(GHASH)  and  not defined(OPENSSL_SMALL_FOOTPRINT)}
    void ( *gcm_ghash_p) (uint64 Xi[2], const u128 Htable[16],
                         const u8 *inp, size_t len) = ctx.ghash;
  {$endif}
{$ENDIF}
{$IF defined(GHASH)  and  not defined(OPENSSL_SMALL_FOOTPRINT)}
    mres := ctx.mres;
    if mres > 0 then
    begin
        blocks := (mres + 15) and -16;
        memset(PByte(@ctx.Xn) + mres, 0, blocks - mres);
        mres := blocks;
        if mres = sizeof(ctx.Xn) then
        begin
            //GHASH(ctx, ctx.Xn, mres);
            gcm_ghash_4bit(@ctx.Xi.u, @ctx.Htable, @ctx.Xn, mres);
            mres := 0;
        end;
    end
    else if (ctx.ares > 0) then
    begin
        //GCM_MUL(ctx);
        gcm_gmult_4bit(@ctx.Xi.u, @ctx.Htable)
    end;
{$ELSE}
    if ctx.mres  or  ctx.ares then GCM_MUL(ctx);
{$ENDIF}
    if ossl_is_endian.little <> 0 then begin
{$IFDEF BSWAP8}
        alen := BSWAP8(alen);
        clen := BSWAP8(clen);
{$ELSE}
        p := @ctx.len.c;
        ctx.len.u[0] := alen;
        ctx.len.u[1] := clen;
        alen := uint64(GETU32(p)) shl 32 or GETU32(p + 4);
        clen := uint64(GETU32(p + 8)) shl 32 or GETU32(p + 12);
{$ENDIF}
    end;
{$IF defined(GHASH)  and  not defined(OPENSSL_SMALL_FOOTPRINT)}
    bitlen.hi := alen;
    bitlen.lo := clen;
    memcpy(PByte(@ctx.Xn) + mres, @bitlen, sizeof(bitlen));
    mres  := mres + (sizeof(bitlen));
    //GHASH(ctx, ctx.Xn, mres);
    gcm_ghash_4bit(@ctx.Xi.u, @ctx.Htable, @ctx.Xn, mres);
{$ELSE} ctx.Xi.u[0]  := ctx.Xi.u[0] xor alen;
    ctx.Xi.u[1]  := ctx.Xi.u[1] xor clen;
    GCM_MUL(ctx);
{$ENDIF}
    ctx.Xi.u[0]  := ctx.Xi.u[0] xor (ctx.EK0.u[0]);
    ctx.Xi.u[1]  := ctx.Xi.u[1] xor (ctx.EK0.u[1]);
    if (tag <> nil)  and  (len <= sizeof(ctx.Xi)) then
        Exit(CRYPTO_memcmp(@ctx.Xi.c, tag, len))
    else
        Result := -1;
{$POINTERMATH OFF}
end;


procedure CRYPTO_gcm128_tag( ctx : PGCM128_CONTEXT; tag : PByte; len : size_t);
begin
    CRYPTO_gcm128_finish(ctx, nil, 0);
    memcpy(tag, @ctx.Xi.c,
          get_result(len <= sizeof(ctx.Xi.c) , len , sizeof(ctx.Xi.c)));
end;



function CRYPTO_gcm128_decrypt(ctx : PGCM128_CONTEXT;{const} _in : PByte; _out : PByte; len : size_t):integer;
var
  n, ctr, mres : uint32;
  i : size_t;
  mlen : uint64;
  block : block128_f;
  key : Pointer;
  c1 : uint8;
  j : size_t;
  out_t, in_t : Psize_t_aX;
  c2 : size_t;
  k: Byte;
  ossl_is_endian: endian_st;
begin
{$POINTERMATH ON}
    ossl_is_endian.one := 1;
    //DECLARE_IS_ENDIAN;
    mlen := ctx.len.u[1];
    block := ctx.block;
    key := ctx.key;
{$IFDEF GCM_FUNCREF_4BIT}
    void ( *gcm_gmult_p) (uint64 Xi[2], const u128 Htable[16]) = ctx.gmult;
{$IF defined(GHASH)  and  not defined(OPENSSL_SMALL_FOOTPRINT)}
    void ( *gcm_ghash_p) (uint64 Xi[2], const u128 Htable[16],
                         const u8 *inp, size_t len) = ctx.ghash;
{$ENDIF}
{$ENDIF}
    mlen  := mlen + len;
    if (mlen > (Uint64(1) shl 36) - 32)  or ( (sizeof(len) = 8)  and  (mlen < len)) then
        Exit(-1);
    ctx.len.u[1] := mlen;
    mres := ctx.mres;
    if ctx.ares > 0 then
    begin
        { First call to decrypt finalizes GHASH(AAD) }
{$IF defined(GHASH)  and  not defined(OPENSSL_SMALL_FOOTPRINT)}
        if len = 0 then
        begin
            //GCM_MUL(ctx);
            gcm_gmult_4bit(@ctx.Xi.u, @ctx.Htable);
            ctx.ares := 0;
            Exit(0);
        end;
        memcpy(@ctx.Xn, @ctx.Xi.c, sizeof(ctx.Xi));
        ctx.Xi.u[0] := 0;
        ctx.Xi.u[1] := 0;
        mres := sizeof(ctx.Xi);
{$ELSE} GCM_MUL(ctx);
{$ENDIF}
        ctx.ares := 0;
    end;
    if ossl_is_endian.little <> 0 then
{$ifdef BSWAP4}
        ctr := BSWAP4(ctx.Yi.d[3]);
{$ELSE}
        ctr := GETU32(PByte(@ctx.Yi.c) + 12)
{$ENDIF}
    else
        ctr := ctx.Yi.d[3];
    n := mres mod 16;
{$IF not defined(OPENSSL_SMALL_FOOTPRINT)}
    if 16 mod sizeof(size_t) = 0 then
    begin  { always true actually }
        while Boolean(0) do
        begin
            if n > 0 then
            begin
{$IF defined(GHASH)}
                while (n > 0)  and  (len > 0) do
                begin
                    k := PostInc(_in)^  xor  ctx.EKi.c[n];
                    PostInc(_out)^ := k;
                    ctx.Xn[mres] := k;
                    Inc(mres);
                    Dec(len);
                    n := (n + 1) mod 16;
                end;
                if n = 0 then begin
                    //GHASH(ctx, ctx.Xn, mres);
                    gcm_ghash_4bit(@ctx.Xi.u, @ctx.Htable, @ctx.Xn, mres);
                    mres := 0;
                end
                else
                begin
                    ctx.mres := mres;
                    Exit(0);
                end;
{$ELSE }        while n  and  len do
                begin
                    c := *(PostInc(in));
                    *(PostInc(out)) = c  xor  ctx.EKi.c[n];
                    ctx.Xi.c[n]  := ctx.Xi.c[n] xor c;
                    PreDec(len);
                    n := (n + 1) % 16;
                end;
                if n = 0 then begin
                    GCM_MUL(ctx);
                    mres := 0;
                end;
 else begin
                    ctx.mres := n;
                    Exit(0);
                end;
{$ENDIF}
            end;
{$IF defined(STRICT_ALIGNMENT)}
            if size_t(in or size_t(out then % sizeofsize_t( <> 0 then
                break;
{$ENDIF}
{$IF defined(GHASH)}
            if len >= 16  and  mres then
            begin
                //GHASH(ctx, ctx.Xn, mres);
                gcm_ghash_4bit(@ctx.Xi.u, @ctx.Htable, @ctx.Xn, mres);
                mres := 0;
            end;
{$IF GHASH_CHUNK > 0}
            while len >= GHASH_CHUNK do
            begin
                j := GHASH_CHUNK;
                //GHASH(ctx, _in, GHASH_CHUNK);
                gcm_ghash_4bit(@ctx.Xi.u, @ctx.Htable, _in, GHASH_CHUNK);
                while j > 0 do
                begin
                    out_t := Psize_t_aX(_out);
                    block(@ctx.Yi.c, @ctx.EKi.c, key);
                    Inc(ctr);
                    if ossl_is_endian.little <> 0 then
{$ifdef BSWAP4}
                        ctx.Yi.d[3] := BSWAP4(ctr);
{$ELSE}                 PUTU32(PByte(@ctx.Yi.c) + 12, ctr)
{$ENDIF}
                    else
                        ctx.Yi.d[3] := ctr;
                    for i := 0 to 16 div sizeof(size_t)-1 do
                        out_t[i] := in_t[i]  xor  ctx.EKi.t[i];
                    _out  := _out + 16;
                    _in  := _in + 16;
                    j  := j - 16;
                end;
                len  := len - GHASH_CHUNK;
            end;
{$ENDIF}
            if i = (len and size_t(-16)) then
            begin
                //GHASH(ctx, in, i);
                gcm_ghash_4bit(@ctx.Xi.u, @ctx.Htable, _in, i);
                while len >= 16 do
                begin
                    out_t := Psize_t_aX(_out);
                    block(@ctx.Yi.c, @ctx.EKi.c, key);
                    Inc(ctr);
                    if ossl_is_endian.little <> 0 then
{$ifdef BSWAP4}
                        ctx.Yi.d[3] := BSWAP4(ctr);
{$ELSE}                 PUTU32(PByte(@ctx.Yi.c) + 12, ctr)
{$ENDIF}
                    else
                        ctx.Yi.d[3] := ctr;
                    for i := 0 to 16 div sizeof(size_t) - 1 do
                        out_t[i] := in_t[i]  xor  ctx.EKi.t[i];
                    _out  := _out + 16;
                    _in  := _in + 16;
                    len  := len - 16;
                end;
            end;
{$ELSE}     while len >= 16 do  begin
                out_t := (Psize_t  )out;
                ( *block) (ctx.Yi.c, ctx.EKi.c, key);
                PreInc(ctr);
                if IS_LITTLE_ENDIAN then
{$ifdef BSWAP4}
                    ctx.Yi.d[3] := BSWAP4(ctr);
{$ELSE} PUTU32(ctx.Yi.c + 12, ctr);
{$ENDIF}
                else
                    ctx.Yi.d[3] := ctr;
                for (i = 0; i < 16 div sizeofsize_t(; PreInc(i)) begin
                    c := in_t[i];
                    out_t[i] := c  xor  ctx.EKi.t[i];
                    ctx.Xi.t[i]  := ctx.Xi.t[i] xor c;
                end;
                GCM_MUL(ctx);
                out  := out + 16;
                in  := in + 16;
                len  := len - 16;
            end;
{$ENDIF}
            if len > 0 then
            begin
                block (@ctx.Yi.c, @ctx.EKi.c, key);
                Inc(ctr);
                if ossl_is_endian.little <> 0 then
{$ifdef BSWAP4}
                    ctx.Yi.d[3] := BSWAP4(ctr);
{$ELSE}             PUTU32(PByte(@ctx.Yi.c) + 12, ctr)
{$ENDIF}
                else
                    ctx.Yi.d[3] := ctr;
{$IF defined(GHASH)}
                while PostDec(len) > 0 do
                begin
                    ctx.Xn[mres] := _in[n]  xor  ctx.EKi.c[n];
                    _out[n] := ctx.Xn[mres];
                    Inc(mres);
                    Inc(n);
                end;
{$ELSE} while PostDec(len) do  begin
                    c := in[n];
                    ctx.Xi.c[n]  := ctx.Xi.c[n] xor c;
                    out[n] := c  xor  ctx.EKi.c[n];
                    PreInc(n);
                end;
                mres := n;
{$ENDIF}
            end;
            ctx.mres := mres;
            Exit(0);
        end;

    end;
{$ENDIF}
    for i := 0 to len-1 do
    begin
        if n = 0 then begin
            block(@ctx.Yi.c, @ctx.EKi.c, key);
            Inc(ctr);
            if ossl_is_endian.little <> 0 then
{$ifdef BSWAP4}
                ctx.Yi.d[3] := BSWAP4(ctr);
{$ELSE}         PUTU32(PByte(@ctx.Yi.c) + 12, ctr)
{$ENDIF}
            else
                ctx.Yi.d[3] := ctr;
        end;
{$IF defined(GHASH)  and  not defined(OPENSSL_SMALL_FOOTPRINT)}
        c1 := _in[i];
        ctx.Xn[mres] := c1;
        Inc(mres);
        _out[i] := c1  xor  ctx.EKi.c[n];
        n := (n + 1) mod 16;
        if mres = sizeof(ctx.Xn) then
        begin
            //GHASH(ctx,ctx.Xn,sizeof(ctx.Xn));
            gcm_ghash_4bit(@ctx.Xi.u, @ctx.Htable, @ctx.Xn,sizeof(ctx.Xn));
            mres := 0;
        end;
{$ELSE} c = in[i];
        out[i] := c  xor  ctx.EKi.c[n];
        ctx.Xi.c[n]  := ctx.Xi.c[n] xor c;
        mres := n = (n + 1) % 16;
        if n = 0 then GCM_MUL(ctx);
{$ENDIF}
    end;
    ctx.mres := mres;
    Result := 0;
end;

function CRYPTO_gcm128_aad(ctx : PGCM128_CONTEXT;{const} aad : PByte; len : size_t):integer;
var
  i : size_t;
  n : uint32;
  alen : uint64;
begin
    alen := ctx.len.u[0];
{$IFDEF GCM_FUNCREF_4BIT}
    void ( *gcm_gmult_p) (uint64 Xi[2], const u128 Htable[16]) = ctx.gmult;
# ifdef GHASH
    void ( *gcm_ghash_p) (uint64 Xi[2], const u128 Htable[16],
                         const u8 *inp, size_t len) = ctx.ghash;
# endif
{$ENDIF}
    if ctx.len.u[1] > 0 then Exit(-2);
    alen  := alen + len;
    if (alen > Uint64(1) shl 61)  or ( (sizeof(len) = 8)  and  (alen < len)) then
        Exit(-1);
    ctx.len.u[0] := alen;
    n := ctx.ares;
    if n > 0 then
    begin
        while (n > 0) and  (len > 0) do
        begin
            ctx.Xi.c[n]  := ctx.Xi.c[n] xor (PostInc(aad)^);
            Dec(len);
            n := (n + 1) mod 16;
        end;
        if n = 0 then
           //GCM_MUL(ctx);
           gcm_gmult_4bit(@ctx.Xi.u, @ctx.Htable)
        else begin
            ctx.ares := n;
            Exit(0);
        end;
    end;
{$IFDEF GHASH}
    if i = (len and size_t(-16)) then
    begin
        //GHASH(ctx, aad, i);
        gcm_ghash_4bit(@ctx.Xi.u, @ctx.Htable, aad, i);
        aad  := aad + i;
        len  := len - i;
    end;
{$ELSE}
    while len >= 16 do
    begin
        for (i = 0; i < 16; PreInc(i))
            ctx.Xi.c[i]  := ctx.Xi.c[i] xor (aad[i]);
        //GCM_MUL(ctx);
        gcm_gmult_4bit(@ctx.Xi.u, @ctx.Htable);
        aad  := aad + 16;
        len  := len - 16;
    end;
{$ENDIF}
    if len > 0 then
    begin
        n := uint32(len);
        for i := 0 to len-1 do
            ctx.Xi.c[i]  := ctx.Xi.c[i] xor (aad[i]);
    end;
    ctx.ares := n;
    Result := 0;
end;


procedure gcm_ghash_4bit(Xi : Puint64;const Htable : Pu128;{const} inp : Pbyte; len : size_t);
var
  Z : u128;
  cnt : integer;
  rem, nlo, nhi : size_t;
  Hshr4 : array[0..15] of u128;
  Hshl4 : array[0..15] of uint8;
  p : PByte;
  v : uint32;
  ossl_is_endian: endian_st;
  function ok: int;
  begin
     inp := inp + 16;
     len := len - 16;
     Result := len;
  end;
begin
{$POINTERMATH ON}
    //DECLARE_IS_ENDIAN;
    ossl_is_endian.one := 1;
{$IF true}
    repeat //do begin
        cnt := 15;
        nlo := Puint8(Xi)[15];
        nlo := nlo xor (inp[15]);
        nhi := nlo  shr  4;
        nlo := nlo and $f;
        Z.hi := Htable[nlo].hi;
        Z.lo := Htable[nlo].lo;
        while Boolean(1) do
        begin
            rem := size_t(Z.lo) and $f;
            Z.lo := (Z.hi shl 60) or (Z.lo  shr  4);
            Z.hi := (Z.hi  shr  4);
            if sizeof(size_t) = 8 then
               Z.hi  := Z.hi xor (rem_4bit[rem])
            else
                Z.hi  := Z.hi xor (uint64(rem_4bit[rem]) shl 32);
            Z.hi  := Z.hi xor (Htable[nhi].hi);
            Z.lo  := Z.lo xor (Htable[nhi].lo);
            if PreDec(cnt) < 0  then
                break;
            nlo := Puint8(Xi)[cnt];
            nlo  := nlo xor (inp[cnt]);
            nhi := nlo  shr  4;
            nlo := nlo and $f;
            rem := size_t(Z.lo) and $f;
            Z.lo := (Z.hi shl 60) or (Z.lo  shr  4);
            Z.hi := (Z.hi  shr  4);
            if sizeof(size_t) = 8 then
               Z.hi  := Z.hi xor (rem_4bit[rem])
            else
                Z.hi  := Z.hi xor (uint64(rem_4bit[rem]) shl 32);
            Z.hi  := Z.hi xor (Htable[nlo].hi);
            Z.lo  := Z.lo xor (Htable[nlo].lo);
        end;
{$ELSE}
     {
     * Extra 256+16 bytes per-key plus 512 bytes shared tables
     * [should] give ~50% improvement... One could have PACK-ed
     * the rem_8bit even here, but the priority is to minimize
     * cache footprint...
     }

    {
     * This pre-processing phase slows down procedure by approximately
     * same time as it makes each loop spin faster. In other words
     * single block performance is approximately same as straightforward
     * '4-bit' implementation, and then it goes only faster...
     }
    for (cnt = 0; cnt < 16; PreInc(cnt)) begin
        Z.hi := Htable[cnt].hi;
        Z.lo := Htable[cnt].lo;
        Hshr4[cnt].lo := (Z.hi shl 60) or (Z.lo  shr  4);
        Hshr4[cnt].hi := (Z.hi  shr  4);
        Hshl4[cnt] := (u8)(Z.lo shl 4);
    end;
    do begin
        for (Z.lo = 0, Z.hi = 0, cnt = 15; cnt; PreDec(cnt)) begin
            nlo := (Puint8(Xi)[cnt];
            nlo  := nlo xor (inp[cnt]);
            nhi := nlo  shr  4;
            nlo &= $f;
            Z.hi  := Z.hi xor (Htable[nlo].hi);
            Z.lo  := Z.lo xor (Htable[nlo].lo);
            rem := size_t(Z.lo and $ff;
            Z.lo := (Z.hi shl 56) or (Z.lo  shr  8);
            Z.hi := (Z.hi  shr  8);
            Z.hi  := Z.hi xor (Hshr4[nhi].hi);
            Z.lo  := Z.lo xor (Hshr4[nhi].lo);
            Z.hi  := Z.hi xor ((uint64)rem_8bit[rem xor Hshl4[nhi]] shl 48);
        end;
        nlo := (Puint8(Xi)[0];
        nlo  := nlo xor (inp[0]);
        nhi := nlo  shr  4;
        nlo &= $f;
        Z.hi  := Z.hi xor (Htable[nlo].hi);
        Z.lo  := Z.lo xor (Htable[nlo].lo);
        rem := size_t(Z.lo and $f;
        Z.lo := (Z.hi shl 60) or (Z.lo  shr  4);
        Z.hi := (Z.hi  shr  4);
        Z.hi  := Z.hi xor (Htable[nhi].hi);
        Z.lo  := Z.lo xor (Htable[nhi].lo);
        Z.hi  := Z.hi xor (((uint64)rem_8bit[rem shl 4]) shl 48);
{$ENDIF}
        if ossl_is_endian.little <> 0 then begin
{$IFDEF BSWAP8}
            Xi[0] := BSWAP8(Z.hi);
            Xi[1] := BSWAP8(Z.lo);
{$ELSE}
            p := Puint8(Xi);
            v := uint32(Z.hi  shr  32);
            PUTU32(p, v);
            v := uint32(Z.hi);
            PUTU32(p + 4, v);
            v := uint32(Z.lo  shr  32);
            PUTU32(p + 8, v);
            v := uint32(Z.lo);
            PUTU32(p + 12, v);
{$ENDIF}
        end
        else
        begin
            Xi[0] := Z.hi;
            Xi[1] := Z.lo;
        end;
    until not (ok > 0);
 {$POINTERMATH OFF}
end;


function CRYPTO_gcm128_encrypt(ctx : PGCM128_CONTEXT;{const} _in : PByte; _out : PByte; len : size_t):integer;
var
  n, ctr, mres : uint32;
  i : size_t;
  mlen : uint64;
  block : block128_f;
  key : Pointer;
  j : size_t;
  out_t, in_t : Psize_t_aX;
  ossl_is_endian: endian_st;
  k: Byte;
begin
{$POINTERMATH ON}
    //DECLARE_IS_ENDIAN;
    ossl_is_endian.one := 1;
    mlen := ctx.len.u[1];
    block := ctx.block;
    key := ctx.key;
{$IFDEF GCM_FUNCREF_4BIT}
    void ( *gcm_gmult_p) (uint64 Xi[2], const u128 Htable[16]) = ctx.gmult;
{$IF defined(GHASH)  and  not defined(OPENSSL_SMALL_FOOTPRINT)}
    void ( *gcm_ghash_p) (uint64 Xi[2], const u128 Htable[16],
                         const u8 *inp, size_t len) = ctx.ghash;
{$ENDIF}
{$ENDIF}
    mlen  := mlen + len;
    if (mlen > (Uint64(1) shl 36) - 32)  or ( (sizeof(len) = 8)  and  (mlen < len)) then
        Exit(-1);
    ctx.len.u[1] := mlen;
    mres := ctx.mres;
    if ctx.ares > 0 then
    begin
        { First call to encrypt finalizes GHASH(AAD) }
{$IF defined(GHASH)  and  not defined(OPENSSL_SMALL_FOOTPRINT)}
        if len = 0 then
        begin
            //GCM_MUL(ctx);
            gcm_gmult_4bit(@ctx.Xi.u, @ctx.Htable);
            ctx.ares := 0;
            Exit(0);
        end;
        memcpy(@ctx.Xn, @ctx.Xi.c, sizeof(ctx.Xi));
        ctx.Xi.u[0] := 0;
        ctx.Xi.u[1] := 0;
        mres := sizeof(ctx.Xi);
{$ELSE}
       //GCM_MUL(ctx);
       gcm_gmult_4bit(@ctx.Xi.u, @ctx.Htable);
{$ENDIF}
        ctx.ares := 0;
    end;
    if ossl_is_endian.little <> 0 then
{$ifdef BSWAP4}
        ctr := BSWAP4(ctx.Yi.d[3]);
{$ELSE}
        ctr := GETU32(Pbyte(@ctx.Yi.c) + 12)
{$ENDIF}
    else
        ctr := ctx.Yi.d[3];
    n := mres mod 16;
{$IF not defined(OPENSSL_SMALL_FOOTPRINT)}
    if 16 mod sizeof(size_t) = 0 then
    begin  { always true actually }
        while Boolean(0) do
        begin
            if n > 0 then
            begin
{$IF defined(GHASH)}
                while (n > 0)  and  (len > 0) do
                begin
                    k := PostInc(_in)^  xor  ctx.EKi.c[n];
                    PostInc(_out)^ := k;
                    ctx.Xn[mres] := k;
                    Inc(mres);
                    Dec(len);
                    n := (n + 1) mod 16;
                end;
                if n = 0 then
                begin
                    //GHASH(ctx, ctx.Xn, mres);
                    gcm_ghash_4bit(@ctx.Xi.u, @ctx.Htable, @ctx.Xn, mres);
                    mres := 0;
                end
                else
                begin
                    ctx.mres := mres;
                    Exit(0);
                end;
{$ELSE}
                while (n > 0)  and  (len > 0) do
                begin
                    ctx.Xi.c[n]  := ctx.Xi.c[n] xor ( *(PostInc(out)) = *(PostInc(in)) xor ctx.EKi.c[n]);
                    PreDec(len);
                    n := (n + 1) mod 16;
                end;
                if n = 0 then
                begin
                    //GCM_MUL(ctx);
                    gcm_gmult_4bit(@ctx.Xi.u, @ctx.Htable);
                    mres := 0;
                end
                else
                begin
                    ctx.mres := n;
                    Exit(0);
                end;
{$ENDIF}
            end;
{$IF defined(STRICT_ALIGNMENT)}
            if size_t(in or size_t(out then % sizeofsize_t( <> 0 then
                break;
{$ENDIF}
{$IF defined(GHASH)}
            if (len >= 16)  and  (mres > 0) then
            begin
                //GHASH(ctx, ctx.Xn, mres);
                gcm_ghash_4bit(@ctx.Xi.u, @ctx.Htable, @ctx.Xn, mres);
                mres := 0;
            end;
{$IF GHASH_CHUNK > 0}
            while len >= GHASH_CHUNK do
            begin
                j := GHASH_CHUNK;
                while j > 0 do
                begin
                    out_t := Psize_t_aX(_out);
                    in_t := Psize_t_aX(_in);
                    block(@ctx.Yi.c, @ctx.EKi.c, key);
                    Inc(ctr);
                    if ossl_is_endian.little <> 0 then
{$ifdef BSWAP4}
                        ctx.Yi.d[3] := BSWAP4(ctr);
{$ELSE}
                        PUTU32(PByte(@ctx.Yi.c) + 12, ctr)
{$ENDIF}
                    else
                        ctx.Yi.d[3] := ctr;

                    for i := 0 to 16 div sizeof(size_t) -1 do
                        out_t[i] := in_t[i]  xor  ctx.EKi.t[i];
                    _out  := _out + 16;
                    _in  := _in + 16;
                    j  := j - 16;
                end;
                //GHASH(ctx, _out - GHASH_CHUNK, GHASH_CHUNK);
                gcm_ghash_4bit(@ctx.Xi.u, @ctx.Htable, _out - GHASH_CHUNK, GHASH_CHUNK);
                len  := len - GHASH_CHUNK;
            end;
{$ENDIF}
            if i = (len and size_t(-16)) then
            begin
                j := i;
                while len >= 16 do
                begin
                    out_t := Psize_t_aX(_out);
                    in_t := Psize_t_aX(_in);
                    block(@ctx.Yi.c, @ctx.EKi.c, key);
                    Inc(ctr);
                    if ossl_is_endian.little <> 0 then
{$ifdef BSWAP4}
                        ctx.Yi.d[3] := BSWAP4(ctr);
{$ELSE}
                        PUTU32(PByte(@ctx.Yi.c) + 12, ctr)
{$ENDIF}
                    else
                        ctx.Yi.d[3] := ctr;
                    for i := 0 to  16 div sizeof(size_t) - 1 do
                        out_t[i] := in_t[i]  xor  ctx.EKi.t[i];
                    _out  := _out + 16;
                    _in  := _in + 16;
                    len  := len - 16;
                end;
                //GHASH(ctx, out - j, j);
                gcm_ghash_4bit(@ctx.Xi.u, @ctx.Htable, _out - j, j);
            end;
{$ELSE}     while len >= 16 do
            begin
                out_t := (Psize_t  )out;
                in_t := (const Psize_t  )in;
                ( *block) (ctx.Yi.c, ctx.EKi.c, key);
                PreInc(ctr);
                if IS_LITTLE_ENDIAN then
{$ifdef BSWAP4}
                    ctx.Yi.d[3] := BSWAP4(ctr);
{$ELSE}
                    PUTU32(ctx.Yi.c + 12, ctr)
{$ENDIF}
                else
                    ctx.Yi.d[3] := ctr;
                for (i = 0; i < 16 div sizeofsize_t(; PreInc(i))
                    ctx.Xi.t[i]  := ctx.Xi.t[i] xor (out_t[i] = in_t[i] xor ctx.EKi.t[i]);
                GCM_MUL(ctx);
                _out  := _out + 16;
                _in  := _in + 16;
                len  := len - 16;
            end;
{$ENDIF}
            if len > 0 then
            begin
                block(@ctx.Yi.c, @ctx.EKi.c, key);
                Inc(ctr);
                if ossl_is_endian.little <> 0 then
{$ifdef BSWAP4}
                    ctx.Yi.d[3] := BSWAP4(ctr);
{$ELSE}
                    PUTU32(PByte(@ctx.Yi.c) + 12, ctr)
{$ENDIF}
                else
                    ctx.Yi.d[3] := ctr;
{$IF defined(GHASH)}
                while PostDec(len) > 0 do
                begin
                    _out[n] := _in[n]  xor  ctx.EKi.c[n];
                    ctx.Xn[mres] := _out[n];
                    Inc(mres);
                    Inc(n);
                end;
{$ELSE}
                while PostDec(len) do
                begin
                    ctx.Xi.c[n]  := ctx.Xi.c[n] xor (out[n] = in[n] xor ctx.EKi.c[n]);
                    PreInc(n);
                end;
                mres := n;
{$ENDIF}
            end;
            ctx.mres := mres;
            Exit(0);
        end;

    end;
{$ENDIF}
    for i := 0 to len - 1 do
    begin
        if n = 0 then
        begin
            block (@ctx.Yi.c, @ctx.EKi.c, key);
            Inc(ctr);
            if ossl_is_endian.little <> 0 then
{$ifdef BSWAP4}
                ctx.Yi.d[3] := BSWAP4(ctr);
{$ELSE}
                PUTU32(PByte(@ctx.Yi.c) + 12, ctr)
{$ENDIF}
            else
                ctx.Yi.d[3] := ctr;
        end;
{$IF defined(GHASH)  and  not defined(OPENSSL_SMALL_FOOTPRINT)}
        _out[i] := _in[i]  xor  ctx.EKi.c[n];
        ctx.Xn[mres] := _out[i];
        Inc(mres);
        n := (n + 1) mod 16;
        if mres = sizeof(ctx.Xn)  then
        begin
            //GHASH(ctx,ctx.Xn,sizeof(ctx.Xn));
            gcm_ghash_4bit(@ctx.Xi.u, @ctx.Htable, @ctx.Xn, sizeof(ctx.Xn));
            mres := 0;
        end;
{$ELSE}
        ctx.Xi.c[n]  := ctx.Xi.c[n] xor (out[i] = in[i] xor ctx.EKi.c[n]);
        mres := n = (n + 1) % 16;
        if n = 0 then
           gcm_gmult_4bit(@ctx.Xi.u, @ctx.Htable);//GCM_MUL(ctx);
{$ENDIF}
    end;
    ctx.mres := mres;
    Result := 0;
end;

procedure gcm_gmult_4bit(Xi : Puint64;const Htable : Pu128);
var
  Z : u128;
  cnt : integer;
  rem, nlo, nhi : size_t;
  p : Puint8;
  v : uint32;
  ossl_is_endian: endian_st;
begin
{$POINTERMATH ON}
    //DECLARE_IS_ENDIAN;
    ossl_is_endian.one := 1;
    cnt := 15;

    nlo := Puint8(Xi)[15];
    nhi := nlo  shr  4;
    nlo := nlo and $f;
    Z.hi := Htable[nlo].hi;
    Z.lo := Htable[nlo].lo;
    while Boolean(1) do
    begin
        rem := size_t(Z.lo) and $f;
        Z.lo := (Z.hi shl 60) or (Z.lo  shr  4);
        Z.hi := (Z.hi  shr  4);
        if sizeof(size_t) = 8 then
           Z.hi  := Z.hi xor (rem_4bit[rem])
        else
            Z.hi  := Z.hi xor (uint64(rem_4bit[rem]) shl 32);
        Z.hi  := Z.hi xor (Htable[nhi].hi);
        Z.lo  := Z.lo xor (Htable[nhi].lo);
        if PreDec(cnt) < 0  then
            break;
        nlo := Puint8(Xi)[cnt];
        nhi := nlo  shr  4;
        nlo := nlo and $f;
        rem := size_t(Z.lo) and $f;
        Z.lo := (Z.hi shl 60) or (Z.lo  shr  4);
        Z.hi := (Z.hi  shr  4);
        if sizeof(size_t) = 8 then
           Z.hi  := Z.hi xor (rem_4bit[rem])
        else
            Z.hi  := Z.hi xor (uint64(rem_4bit[rem]) shl 32);
        Z.hi  := Z.hi xor (Htable[nlo].hi);
        Z.lo  := Z.lo xor (Htable[nlo].lo);
    end;
    if ossl_is_endian.little <> 0 then begin
{$IFDEF BSWAP8}
        Xi[0] := BSWAP8(Z.hi);
        Xi[1] := BSWAP8(Z.lo);
{$ELSE} p := Puint8(Xi);
        v := uint32(Z.hi  shr  32);
        PUTU32(p, v);
        v := uint32(Z.hi);
        PUTU32(p + 4, v);
        v := uint32(Z.lo  shr  32);
        PUTU32(p + 8, v);
        v := uint32(Z.lo);
        PUTU32(p + 12, v);
{$ENDIF}
    end
    else begin
        Xi[0] := Z.hi;
        Xi[1] := Z.lo;
    end;
{$POINTERMATH OFF}
end;



procedure CRYPTO_gcm128_setiv(ctx : PGCM128_CONTEXT;{const} iv : PByte; len : size_t);
var
  ctr : uint32;
  i : size_t;
  len0 : uint64;
  ossl_is_endian: endian_st;
begin
    //DECLARE_IS_ENDIAN;
    ossl_is_endian.one := 1;
{$IFDEF GCM_FUNCREF_4BIT}
    void ( *gcm_gmult_p) (u64 Xi[2], const u128 Htable[16]) = ctx.gmult;
{$ENDIF}
    ctx.len.u[0] := 0;          { AAD length }
    ctx.len.u[1] := 0;          { message length }
    ctx.ares := 0;
    ctx.mres := 0;
    if len = 12 then
    begin
        memcpy(@ctx.Yi.c, iv, 12);
        ctx.Yi.c[12] := 0;
        ctx.Yi.c[13] := 0;
        ctx.Yi.c[14] := 0;
        ctx.Yi.c[15] := 1;
        ctr := 1;
    end
    else
    begin
        len0 := len;
        { Borrow ctx.Xi to calculate initial Yi }
        ctx.Xi.u[0] := 0;
        ctx.Xi.u[1] := 0;
        while len >= 16 do
        begin
            for i := 0 to 16-1 do
                ctx.Xi.c[i]  := ctx.Xi.c[i] xor (iv[i]);
            //GCM_MUL(ctx);
            gcm_gmult_4bit(@ctx.Xi.u, @ctx.Htable);
            iv  := iv + 16;
            len  := len - 16;
        end;
        if len > 0 then
        begin
            for i := 0 to len-1 do
                ctx.Xi.c[i]  := ctx.Xi.c[i] xor (iv[i]);
            //GCM_MUL(ctx);
            gcm_gmult_4bit(@ctx.Xi.u, @ctx.Htable);
        end;
        len0 := len0 shl 3;
        if ossl_is_endian.little <> 0 then begin
{$IFDEF BSWAP8}
            ctx.Xi.u[1]  := ctx.Xi.u[1] xor (BSWAP8(len0));
{$ELSE}     ctx.Xi.c[8]  := ctx.Xi.c[8] xor (uint8(len0  shr  56));
            ctx.Xi.c[9]  := ctx.Xi.c[9] xor (uint8(len0  shr  48));
            ctx.Xi.c[10]  := ctx.Xi.c[10] xor (uint8(len0  shr  40));
            ctx.Xi.c[11]  := ctx.Xi.c[11] xor (uint8(len0  shr  32));
            ctx.Xi.c[12]  := ctx.Xi.c[12] xor (uint8(len0  shr  24));
            ctx.Xi.c[13]  := ctx.Xi.c[13] xor (uint8(len0  shr  16));
            ctx.Xi.c[14]  := ctx.Xi.c[14] xor (uint8(len0  shr  8));
            ctx.Xi.c[15]  := ctx.Xi.c[15] xor (uint8(len0));
{$ENDIF}
        end
        else
        begin
            ctx.Xi.u[1]  := ctx.Xi.u[1] xor len0;
        end;
        //GCM_MUL(ctx);
        gcm_gmult_4bit(@ctx.Xi.u, @ctx.Htable);
        if ossl_is_endian.little <> 0 then
{$ifdef BSWAP4}
            ctr := BSWAP4(ctx.Xi.d[3]);
{$ELSE}
            ctr := GETU32(PByte(@ctx.Xi.c) + 12)
{$ENDIF}
        else
            ctr := ctx.Xi.d[3];
        { Copy borrowed Xi to Yi }
        ctx.Yi.u[0] := ctx.Xi.u[0];
        ctx.Yi.u[1] := ctx.Xi.u[1];
    end;
    ctx.Xi.u[0] := 0;
    ctx.Xi.u[1] := 0;
    ctx.block(@ctx.Yi.c, @ctx.EK0.c, ctx.key);
    Inc(ctr);
    if ossl_is_endian.little <> 0 then
{$ifdef BSWAP4}
        ctx.Yi.d[3] := BSWAP4(ctr);
{$ELSE}
        PUTU32(PByte(@ctx.Yi.c) + 12, ctr)
{$ENDIF}
    else
        ctx.Yi.d[3] := ctr;
end;


end.
