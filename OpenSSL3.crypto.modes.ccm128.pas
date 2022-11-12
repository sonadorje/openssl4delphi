unit OpenSSL3.crypto.modes.ccm128;

interface
uses OpenSSL.Api;

 function CRYPTO_ccm128_setiv(ctx : PCCM128_CONTEXT;const nonce : PByte; nlen, mlen : size_t):integer;
procedure CRYPTO_ccm128_aad(ctx : PCCM128_CONTEXT;{const} aad : PByte; alen : size_t);
function CRYPTO_ccm128_tag( ctx : PCCM128_CONTEXT; tag : PByte; len : size_t):size_t;
function CRYPTO_ccm128_encrypt_ccm64(ctx : PCCM128_CONTEXT;{const} inp : PByte; _out : PByte; len : size_t; stream : ccm128_f):integer;
 procedure ctr64_add( counter : PByte; inc : size_t);
 function CRYPTO_ccm128_encrypt(ctx : PCCM128_CONTEXT;{const} inp : PByte; _out : PByte; len : size_t):integer;
procedure ctr64_inc( counter : PByte);
 function CRYPTO_ccm128_decrypt_ccm64(ctx : PCCM128_CONTEXT;{const} inp : PByte; _out : PByte; len : size_t; stream : ccm128_f):integer;
function CRYPTO_ccm128_decrypt(ctx : PCCM128_CONTEXT;{const} inp : PByte; _out : PByte; len : size_t):integer;
procedure CRYPTO_ccm128_init( ctx : PCCM128_CONTEXT; M, L : uint32; key : Pointer; block : block128_f);

implementation






procedure CRYPTO_ccm128_init( ctx : PCCM128_CONTEXT; M, L : uint32; key : Pointer; block : block128_f);
begin
    memset(@ctx.nonce.c, 0, sizeof(ctx.nonce.c));
    ctx.nonce.c[0] := (uint8(L - 1) and 7) or uint8(((M - 2) div 2) and 7) shl 3;
    ctx.blocks := 0;
    ctx.block := block;
    ctx.key := key;
end;



function CRYPTO_ccm128_decrypt(ctx : PCCM128_CONTEXT;{const} inp : PByte; _out : PByte; len : size_t):integer;
type
  scratch_st = record
     case Integer of
     0:(u: array[0..1] of uint64 );
     1:(c: array[0..15] of uint8);
   end;

var
  n : size_t;
  i, L : uint32;
  flags0 : Byte;
  block : block128_f;
  key : Pointer;
  scratch: scratch_st;

begin
{$POINTERMATH ON}
    flags0 := ctx.nonce.c[0];
    block := ctx.block;
    key := ctx.key;
    ;
    if 0>=(flags0 and $40 ) then
        block (@ctx.nonce.c, @ctx.cmac.c, key);
    ctx.nonce.c[0] := flags0 and 7;;
    L := flags0 and 7;
    n := 0;
    for  i := 15 - L to 15-1 do
    begin
        n  := n  or (ctx.nonce.c[i]);
        ctx.nonce.c[i] := 0;
        n := n shl 8;
    end;
    n  := n  or (ctx.nonce.c[15]);
    ctx.nonce.c[15] := 1;
    if n <> len then Exit(-1);
    while len >= 16 do  begin
{$IF defined(STRICT_ALIGNMENT)}
        union begin
        end;
 temp;
{$ENDIF}
        block (@ctx.nonce.c, @scratch.c, key);
        ctr64_inc(@ctx.nonce.c);
{$IF defined(STRICT_ALIGNMENT)}
        memcpy(temp.c, inp, 16);
        ctx.cmac.u[0] xor= (scratch.u[0]  := ctx.cmac.u[0] xor= (scratch.u[0] xor (temp.u[0]));
        ctx.cmac.u[1] xor= (scratch.u[1]  := ctx.cmac.u[1] xor= (scratch.u[1] xor (temp.u[1]));
        memcpy(out, scratch.c, 16);
{$ELSE}
        Puint64(_out)[0] := scratch.u[0]  xor  Puint64(inp)[0];
        ctx.cmac.u[0]    := ctx.cmac.u[0] xor  Puint64(_out)[0];
        Puint64(_out)[1] := scratch.u[1]  xor  Puint64(inp)[1];
        ctx.cmac.u[1]    := ctx.cmac.u[1] xor  Puint64(_out)[1];
{$ENDIF}
        block (@ctx.cmac.c, @ctx.cmac.c, key);
        inp  := inp + 16;
        _out  := _out + 16;
        len  := len - 16;
    end;
    if len > 0 then
    begin
        block (@ctx.nonce.c, @scratch.c, key);
        for i := 0 to len-1 do
        begin
            _out[i] := scratch.c[i] xor inp[i];
            ctx.cmac.c[i]  := ctx.cmac.c[i] xor _out[i];
        end;
        block (@ctx.cmac.c, @ctx.cmac.c, key);
    end;
    for i := 15 - L to 16-1 do
        ctx.nonce.c[i] := 0;
    block (@ctx.nonce.c, @scratch.c, key);
    ctx.cmac.u[0]  := ctx.cmac.u[0] xor (scratch.u[0]);
    ctx.cmac.u[1]  := ctx.cmac.u[1] xor (scratch.u[1]);
    ctx.nonce.c[0] := flags0;
    Result := 0;
{$POINTERMATH OFF}
end;


function CRYPTO_ccm128_decrypt_ccm64(ctx : PCCM128_CONTEXT;{const} inp : PByte; _out : PByte; len : size_t; stream : ccm128_f):integer;
type
  scratch_st = record
     case Integer of
     0:(u: array[0..1] of uint64 );
     1:(c: array[0..15] of uint8);
   end;
var
  n : size_t;
  i, L : uint32;
  flags0 : Byte;
  block : block128_f;
  key : Pointer;
  scratch: scratch_st;
begin
    flags0 := ctx.nonce.c[0];
    block := ctx.block;
    key := ctx.key;
    if 0>=(flags0 and $40) then
        block (@ctx.nonce.c, @ctx.cmac.c, key);
    ctx.nonce.c[0] := flags0 and 7;
    L := flags0 and 7;
    n := 0;
    for  i := 15 - L to 15-1 do
    begin
        n  := n  or (ctx.nonce.c[i]);
        ctx.nonce.c[i] := 0;
        n := n shl 8;
    end;
    n  := n  or (ctx.nonce.c[15]);
    ctx.nonce.c[15] := 1;
    if n <> len then Exit(-1);
    if n = len div 16   then
    begin
        stream (inp, _out, n, key, @ctx.nonce.c, @ctx.cmac.c);
        n  := n  * 16;
        inp  := inp + n;
        _out  := _out + n;
        len  := len - n;
        if len > 0 then
           ctr64_add(@ctx.nonce.c, n div 16);
    end;
    if len > 0 then
    begin
        block (@ctx.nonce.c, @scratch.c, key);
        for i := 0 to len-1 do
        begin
            _out[i] := scratch.c[i] xor inp[i];
            ctx.cmac.c[i]  := ctx.cmac.c[i] xor _out[i];
        end;
        block (@ctx.cmac.c, @ctx.cmac.c, key);
    end;
    for i := 15 - L to 16-1 do
        ctx.nonce.c[i] := 0;
    block (@ctx.nonce.c, @scratch.c, key);
    ctx.cmac.u[0]  := ctx.cmac.u[0] xor (scratch.u[0]);
    ctx.cmac.u[1]  := ctx.cmac.u[1] xor (scratch.u[1]);
    ctx.nonce.c[0] := flags0;
    Result := 0;
end;



procedure ctr64_inc( counter : PByte);
var
  n : uint32;
  c : uint8;
begin
    n := 8;
    counter  := counter + 8;
    repeat
        Dec(n);
        c := counter[n];
        Inc(c);
        counter[n] := c;
        if c > 0 then exit;
    until not (n>0);
end;



function CRYPTO_ccm128_encrypt(ctx : PCCM128_CONTEXT;{const} inp : PByte; _out : PByte; len : size_t):integer;
type
  scratch_st = record
     case Integer of
     0:(u: array[0..1] of uint64 );
     1:(c: array[0..15] of uint8);
   end;
var
  n : size_t;
  i, L : uint32;
  flags0 : Byte;
  block : block128_f;
  key : Pointer;
  scratch: scratch_st;
begin
{$POINTERMATH ON}
    flags0 := ctx.nonce.c[0];
    block := ctx.block;
    key := ctx.key;
   
    if 0>=(flags0 and $40 )then
    begin
        block (@ctx.nonce.c, @ctx.cmac.c, key);
         Inc(ctx.blocks);
    end;
    ctx.nonce.c[0] := flags0 and 7; L := flags0 and 7;
    n := 0;
    for i := 15 - L to 15 -1 do
    begin
        n  := n  or (ctx.nonce.c[i]);
        ctx.nonce.c[i] := 0;
        n := n shl 8;
    end;
    n  := n  or (ctx.nonce.c[15]);
    ctx.nonce.c[15] := 1;
    if n <> len then Exit(-1);              { length mismatch }
    ctx.blocks  := ctx.blocks + (((len + 15)  shr  3) or 1);
    if ctx.blocks > (Uint64(1) shl 61) then Exit(-2);              { too much data }
    while len >= 16 do  begin
{$IF defined(STRICT_ALIGNMENT)}
        union begin
        end;
 temp;
        memcpy(temp.c, inp, 16);
        ctx.cmac.u[0]  := ctx.cmac.u[0] xor (temp.u[0]);
        ctx.cmac.u[1]  := ctx.cmac.u[1] xor (temp.u[1]);
{$ELSE} ctx.cmac.u[0]  := ctx.cmac.u[0] xor (Puint64(inp)[0]);
        ctx.cmac.u[1]  := ctx.cmac.u[1] xor (Puint64(inp)[1]);
{$ENDIF}
        block (@ctx.cmac.c, @ctx.cmac.c, key);
        block (@ctx.nonce.c, @scratch.c, key);
        ctr64_inc(@ctx.nonce.c);
{$IF defined(STRICT_ALIGNMENT)}
        temp.u[0]  := temp.u[0] xor (scratch.u[0]);
        temp.u[1]  := temp.u[1] xor (scratch.u[1]);
        memcpy(out, temp.c, 16);
{$ELSE} Puint64(_out)[0] := scratch.u[0]  xor  Puint64(inp)[0];
        Puint64(_out)[1] := scratch.u[1]  xor  Puint64(inp)[1];
{$ENDIF}
        inp  := inp + 16;
        _out  := _out + 16;
        len  := len - 16;
    end;
    if len > 0 then
    begin
        for i := 0 to len-1 do
            ctx.cmac.c[i]  := ctx.cmac.c[i] xor (inp[i]);
        block (@ctx.cmac.c, @ctx.cmac.c, key);
        block (@ctx.nonce.c, @scratch.c, key);
        for i := 0 to len-1 do
            _out[i] := scratch.c[i]  xor  inp[i];
    end;
    for i := 15 - L to 16-1 do
        ctx.nonce.c[i] := 0;
    block (@ctx.nonce.c, @scratch.c, key);
    ctx.cmac.u[0]  := ctx.cmac.u[0] xor (scratch.u[0]);
    ctx.cmac.u[1]  := ctx.cmac.u[1] xor (scratch.u[1]);
    ctx.nonce.c[0] := flags0;
    Result := 0;
{$POINTERMATH OFF}
end;



procedure ctr64_add( counter : PByte; inc : size_t);
var
  n, val : size_t;
begin
    n := 8; val := 0;
    counter  := counter + 8;
    repeat
        PreDec(n);
        val  := val + (counter[n] + (inc and $ff));
        counter[n] := Byte(val);
        val  := val shr 8;              { carry bit }
        inc  := inc shr 8;
    until not ( (n > 0)  and ( (inc>0)  or  (val>0)) );
end;



function CRYPTO_ccm128_encrypt_ccm64(ctx : PCCM128_CONTEXT;{const} inp : PByte; _out : PByte; len : size_t; stream : ccm128_f):integer;
type
  scratch_st = record
     case Integer of
     0:(u: array[0..1] of uint64 );
     1:(c: array[0..15] of uint8);
   end;
var
  n : size_t;
  i, L : uint32;
  flags0 : Byte;
  block : block128_f;
  key : Pointer;
  scratch: scratch_st;
begin
    flags0 := ctx.nonce.c[0];
    block := ctx.block;
    key := ctx.key;
    if 0>=(flags0 and $40 ) then
    begin
       block(@ctx.nonce.c, @ctx.cmac.c, key);
        Inc(ctx.blocks);
    end;
    L := flags0 and 7;
    ctx.nonce.c[0] := L;
    n := 0;
    for i := 15 - L to 15-1 do
    begin
        n  := n  or (ctx.nonce.c[i]);
        ctx.nonce.c[i] := 0;
        n := n shl 8;
    end;
    n  := n  or (ctx.nonce.c[15]);
    ctx.nonce.c[15] := 1;
    if n <> len then Exit(-1);              { length mismatch }
    ctx.blocks  := ctx.blocks + (((len + 15)  shr  3) or 1);
    if ctx.blocks > (Uint64(1) shl 61) then Exit(-2);              { too much data }
    if n = len div 16 then
    begin
        stream(inp, _out, n, key, @ctx.nonce.c, @ctx.cmac.c);
        n  := n  * 16;
        inp  := inp + n;
        _out  := _out + n;
        len  := len - n;
        if len > 0 then
           ctr64_add(@ctx.nonce.c, n div 16);
    end;
    if len > 0 then
    begin
        for i := 0 to len-1 do
            ctx.cmac.c[i]  := ctx.cmac.c[i] xor (inp[i]);
        block (@ctx.cmac.c, @ctx.cmac.c, key);
        block (@ctx.nonce.c, @scratch.c, key);
        for i := 0 to len-1 do
            _out[i] := scratch.c[i]  xor  inp[i];
    end;
    for i := 15 - L to 16-1 do
        ctx.nonce.c[i] := 0;
    block(@ctx.nonce.c, @scratch.c, key);
    ctx.cmac.u[0]  := ctx.cmac.u[0] xor (scratch.u[0]);
    ctx.cmac.u[1]  := ctx.cmac.u[1] xor (scratch.u[1]);
    ctx.nonce.c[0] := flags0;
    Result := 0;
end;



function CRYPTO_ccm128_tag( ctx : PCCM128_CONTEXT; tag : PByte; len : size_t):size_t;
var
  M : uint32;
begin
    M := (ctx.nonce.c[0]  shr  3) and 7;
    M  := M  * 2;
    M  := M + 2;
    if len <> M then Exit(0);
    memcpy(tag, @ctx.cmac.c, M);
    Result := M;
end;


procedure CRYPTO_ccm128_aad(ctx : PCCM128_CONTEXT;{const} aad : PByte; alen : size_t);
var
  i : uint32;
  block : block128_f;
begin
    block := ctx.block;
    if alen = 0 then exit;
    ctx.nonce.c[0]  := ctx.nonce.c[0]  or $40;
    block(@ctx.nonce.c, @ctx.cmac.c, ctx.key);
    Inc(ctx.blocks);
    if alen < ($10000 - $100) then
    begin
        ctx.cmac.c[0]  := ctx.cmac.c[0] xor (uint8(alen  shr  8));
        ctx.cmac.c[1]  := ctx.cmac.c[1] xor uint8(alen);
        i := 2;
    end
    else
    if (sizeof(alen) = 8)
                and  (alen >= size_t(1) shl (32 mod (sizeof(alen) * 8)))then
    begin
        ctx.cmac.c[0]  := ctx.cmac.c[0] xor $FF;
        ctx.cmac.c[1]  := ctx.cmac.c[1] xor $FF;
        ctx.cmac.c[2]  := ctx.cmac.c[2] xor (Uint8(alen  shr  (56 mod (sizeof(alen) * 8))));
        ctx.cmac.c[3]  := ctx.cmac.c[3] xor (Uint8(alen  shr  (48 mod (sizeof(alen) * 8))));
        ctx.cmac.c[4]  := ctx.cmac.c[4] xor (Uint8(alen  shr  (40 mod (sizeof(alen) * 8))));
        ctx.cmac.c[5]  := ctx.cmac.c[5] xor (Uint8(alen  shr  (32 mod (sizeof(alen) * 8))));
        ctx.cmac.c[6]  := ctx.cmac.c[6] xor (Uint8(alen  shr  24));
        ctx.cmac.c[7]  := ctx.cmac.c[7] xor (Uint8(alen  shr  16));
        ctx.cmac.c[8]  := ctx.cmac.c[8] xor (Uint8(alen  shr  8));
        ctx.cmac.c[9]  := ctx.cmac.c[9] xor Uint8(alen);
        i := 10;
    end
    else
    begin
        ctx.cmac.c[0]  := ctx.cmac.c[0] xor $FF;
        ctx.cmac.c[1]  := ctx.cmac.c[1] xor $FE;
        ctx.cmac.c[2]  := ctx.cmac.c[2] xor (Uint8(alen  shr  24));
        ctx.cmac.c[3]  := ctx.cmac.c[3] xor (Uint8(alen  shr  16));
        ctx.cmac.c[4]  := ctx.cmac.c[4] xor (Uint8(alen  shr  8));
        ctx.cmac.c[5]  := ctx.cmac.c[5] xor Uint8(alen);
        i := 6;
    end;
    repeat
        while (i < 16)  and  (alen > 0)  do
        begin
            ctx.cmac.c[i]  := ctx.cmac.c[i] xor aad^;
            Inc(i); Inc(aad); Dec(alen);
        end;
        block(@ctx.cmac.c, @ctx.cmac.c, ctx.key);
         Inc(ctx.blocks);
        i := 0;
    until not (alen>0);
end;



function CRYPTO_ccm128_setiv(ctx : PCCM128_CONTEXT;const nonce : PByte; nlen, mlen : size_t):integer;
var
  L : uint32;
begin
    L := ctx.nonce.c[0] and 7;
    if nlen < (14 - L) then Exit(-1);              { nonce is too short }
    if (sizeof(mlen) = 8)  and  (L >= 3) then
    begin
        ctx.nonce.c[8] := Uint8(mlen  shr  (56 mod (sizeof(mlen) * 8)));
        ctx.nonce.c[9] := Uint8(mlen  shr  (48 mod (sizeof(mlen) * 8)));
        ctx.nonce.c[10] := Uint8(mlen  shr  (40 mod (sizeof(mlen) * 8)));
        ctx.nonce.c[11] := Uint8(mlen  shr  (32 mod (sizeof(mlen) * 8)));
    end
    else
        ctx.nonce.u[1] := 0;
    ctx.nonce.c[12] := Uint8(mlen  shr  24);
    ctx.nonce.c[13] := Uint8(mlen  shr  16);
    ctx.nonce.c[14] := Uint8(mlen  shr  8);
    ctx.nonce.c[15] := Uint8(mlen);
    ctx.nonce.c[0] := ctx.nonce.c[0] and  not $40;   { clear Adata flag }
    memcpy(@ctx.nonce.c[1], nonce, 14 - L);
    Result := 0;
end;


end.
