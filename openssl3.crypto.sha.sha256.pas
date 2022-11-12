unit openssl3.crypto.sha.sha256;

{sha_local.h
#define HASH_UPDATE                     SHA1_Update
#define HASH_TRANSFORM                  SHA1_Transform
#define HASH_FINAL                      SHA1_Final
#define HASH_INIT                       SHA1_Init
#define HASH_BLOCK_DATA_ORDER           sha1_block_data_order
}
{$DEFINE DATA_ORDER_IS_BIG_ENDIAN}
interface
uses OpenSSL.Api;

  function _SHA224_Init( c : PSHA256_CTX):integer;
  function _SHA256_Init( c : PSHA256_CTX):integer;
  function _SHA224_Update(c : PSHA256_CTX;const data : Pointer; len : size_t):integer;
  function _SHA224_Final( md : PByte; c : PSHA256_CTX):integer;
  function _SHA256_Update( c : PSHA256_CTX;const data_ : Pointer; len : size_t):integer;
  procedure sha256_block_data_order(ctx : PSHA256_CTX;const _in : Pointer; num : size_t);
  function _SHA256_Final( md : PByte; c : PSHA256_CTX):integer;
  procedure SHA256_Transform(c : Pointer;const data : PByte);

const // 1d arrays
  K256 : array[0..63] of SHA_LONG = (
    $428a2f98, $71374491, $b5c0fbcf, $e9b5dba5, $3956c25b,
    $59f111f1, $923f82a4, $ab1c5ed5, $d807aa98, $12835b01,
    $243185be, $550c7dc3, $72be5d74, $80deb1fe, $9bdc06a7,
    $c19bf174, $e49b69c1, $efbe4786, $0fc19dc6, $240ca1cc,
    $2de92c6f, $4a7484aa, $5cb0a9dc, $76f988da, $983e5152,
    $a831c66d, $b00327c8, $bf597fc7, $c6e00bf3, $d5a79147,
    $06ca6351, $14292967, $27b70a85, $2e1b2138, $4d2c6dfc,
    $53380d13, $650a7354, $766a0abb, $81c2c92e, $92722c85,
    $a2bfe8a1, $a81a664b, $c24b8b70, $c76c51a3, $d192e819,
    $d6990624, $f40e3585, $106aa070, $19a4c116, $1e376c08,
    $2748774c, $34b0bcb5, $391c0cb3, $4ed8aa4a, $5b9cca4f,
    $682e6ff3, $748f82ee, $78a5636f, $84c87814, $8cc70208,
    $90befffa, $a4506ceb, $bef9a3f7, $c67178f2 );

implementation
uses
    openssl3.crypto.sha.sha_local,  openssl3.crypto.mem;

{$I openssl3.include.crypto.md32_common.inc}
{$Q-}

procedure SHA256_Transform(c : Pointer;const data : PByte);
begin
    sha256_block_data_order(PSHA256_CTX(c), data, 1);
end;

function HASH_MAKE_STRING( c : PSHA256_CTX; s : PByte): int;
var
  ll : Cardinal;
  nn : uint32;
begin
    Result := 1;
    case (c.md_len)  of
       SHA224_DIGEST_LENGTH:
            for nn := 0 to SHA224_DIGEST_LENGTH div 4-1 do
            begin
               ll :=c.h[nn];
               HOST_l2c(ll, s);
            end;
            //break;
       SHA256_DIGEST_LENGTH:
            for nn := 0 to SHA256_DIGEST_LENGTH div 4-1 do
            begin
               ll := c.h[nn];
               HOST_l2c(ll, s);
            end;
            //break;
        else
        begin
            if (c.md_len > SHA256_DIGEST_LENGTH) or (c.md_len = 0) then
               Exit(0);
            for nn := 0 to c.md_len div 4-1 do
            begin
               ll := c.h[nn];
               HOST_l2c(ll, s);
            end;
        end;
    end;
end;

function _SHA256_Final( md : PByte; c : PSHA256_CTX):integer;
var
  p : PByte;
  n : size_t;
begin
    p := PByte(@c.data);
    n := c.num;
    p[n] := $80;
    Inc(n);
    if n > (HASH_CBLOCK - 8) then
    begin
        memset(p + n, 0, (HASH_CBLOCK) - n);
        n := 0;
        sha256_block_data_order(c, p, 1);
    end;
    memset(p + n, 0, HASH_CBLOCK - 8 - n);
    Inc(p, HASH_CBLOCK - 8);
{$IF defined(DATA_ORDER_IS_BIG_ENDIAN)}
    HOST_l2c(c.Nh, p);
    HOST_l2c(c.Nl, p);
    //PostInc(p)^ := Byte(((c.Nh) shr 24) and $ff); PostInc(p)^ := Byte(((c.Nh) shr 16) and $ff); PostInc(p)^ := Byte(((c.Nh) shr  8) and $ff); PostInc(p)^ := Byte(((c.Nh) ) and $ff); //c.Nh;
    //PostInc(p)^ := Byte(((c.Nl) shr 24) and $ff); PostInc(p)^ := Byte(((c.Nl) shr 16) and $ff); PostInc(p)^ := Byte(((c.Nl) shr  8) and $ff); PostInc(p)^ := Byte(((c.Nl) ) and $ff); //c.Nl;

{$elseif defined(DATA_ORDER_IS_LITTLE_ENDIAN)}
    (void)HOST_l2c(c.Nl, p);
    (void)HOST_l2c(c.Nh, p);
{$ENDIF}
    p  := p - HASH_CBLOCK;
    sha256_block_data_order(c, p, 1);
    c.num := 0;
    OPENSSL_cleanse(p, HASH_CBLOCK);
    if 0 = HASH_MAKE_STRING(c, md) then
       Exit(0);
    Result := 1;
end;


function Maj(x,y,z: Uint32): UInt32;
begin
  Result := ((x and y) xor (x and z) xor (y and z))
end;

function Ch(x,y,z: Uint32): UInt32;
begin
   Result :=  ((x and y) xor ((not x) and z))
end;


function _Sigma0(x: uint32): UInt32;
begin
  Result := (ROTATE(x,30) xor ROTATE(x,19) xor ROTATE(x,10))
end;

function sigma0(x: uint32): UInt32;
begin
   Result :=  (ROTATE((x),25) xor ROTATE((x),14) xor ((x) shr 3))
end;

function  _Sigma1(x: uint32): UInt32;
begin
   Result :=  (ROTATE(x,26) xor ROTATE(x,21) xor ROTATE(x,7))
end;

function sigma1(x: uint32): UInt32;
begin
   Result :=  (ROTATE((x),15) xor ROTATE((x),13) xor ((x) shr 10))
end;

procedure sha256_block_data_order(ctx : PSHA256_CTX;const _in : Pointer; num : size_t);
var
  a, b, c, d, e, f, g, h, s0, s1, T1 : uint32;
  X : array[0..15] of SHA_LONG;
  i : integer;
  data : PByte;
  W : PSHA_LONG;
  ossl_is_endian: endian_st;
  l : SHA_LONG;
{$POINTERMATH ON}

  procedure ROUND_00_15(i,a,b,c: uint32; var d: uint32; e,f,g: uint32; var h : uint32);
  begin
      T1  := T1 + (h + _Sigma1(e) + Ch(e,f,g) + K256[i]);
      h := _Sigma0(a) + Maj(a,b,c);
      d := d + T1;
      h := h + T1;
  end;

  procedure ROUND_16_63( i,a,b,c,d,e,f,g,h: UInt32; X : Puint32);
  begin
      s0 := X[(i+1) and $0f];
      s0 := sigma0(s0);
      s1 := X[(i+14) and $0f];
      s1 := sigma1(s1);
      X[(i) and $0f]  := X[(i) and $0f] + (s0 + s1 + X[(i+9) and $0f]);
      T1 := X[(i) and $0f];
      ROUND_00_15(i,a,b,c,d,e,f,g,h);
  end;

begin

    ossl_is_endian.one := 1;
     data := _in;
    //DECLARE_IS_ENDIAN;
    while PostDec(num)>0 do
    begin
        a := ctx.h[0];
        b := ctx.h[1];
        c := ctx.h[2];
        d := ctx.h[3];
        e := ctx.h[4];
        f := ctx.h[5];
        g := ctx.h[6];
        h := ctx.h[7];
        if (not (ossl_is_endian.little <> 0))  and  (sizeof(SHA_LONG) = 4)
             and  (size_t( _in) mod 4 = 0)  then
        begin
            W := PSHA_LONG(data);
            T1 :=  W[0]; X[0] := W[0];

            ROUND_00_15(0, a, b, c, d, e, f, g, h);
            T1 := W[1]; X[1] := W[1];
            ROUND_00_15(1, h, a, b, c, d, e, f, g);
            T1 := W[2]; X[2] := W[2];
            ROUND_00_15(2, g, h, a, b, c, d, e, f);
            T1 := W[3]; X[3] := W[3];
            ROUND_00_15(3, f, g, h, a, b, c, d, e);
            T1 := W[4]; X[4] := W[4];
            ROUND_00_15(4, e, f, g, h, a, b, c, d);
            T1 := W[5]; X[5] := W[5];
            ROUND_00_15(5, d, e, f, g, h, a, b, c);
            T1 := W[6]; X[6] := W[6];
            ROUND_00_15(6, c, d, e, f, g, h, a, b);
            T1 := W[7]; X[7] := W[7];
            ROUND_00_15(7, b, c, d, e, f, g, h, a);
            T1 := W[8]; X[8] := W[8];
            ROUND_00_15(8, a, b, c, d, e, f, g, h);
            T1 := W[9]; X[9] := W[9];
            ROUND_00_15(9, h, a, b, c, d, e, f, g);
            T1 := W[10]; X[10] := W[10];
            ROUND_00_15(10, g, h, a, b, c, d, e, f);
            T1 := W[11]; X[11] := W[11];
            ROUND_00_15(11, f, g, h, a, b, c, d, e);
            T1 := W[12]; X[12] := W[12];
            ROUND_00_15(12, e, f, g, h, a, b, c, d);
            T1 := W[13]; X[13] := W[13];
            ROUND_00_15(13, d, e, f, g, h, a, b, c);
            T1 := W[14]; X[14] := W[14];
            ROUND_00_15(14, c, d, e, f, g, h, a, b);
            T1 :=  W[15]; X[15] := W[15];
            ROUND_00_15(15, b, c, d, e, f, g, h, a);
            data  := data + SHA256_CBLOCK;
        end
        else
        begin
            HOST_c2l(data, l);
            T1 := l; X[0] := l;
            ROUND_00_15(0, a, b, c, d, e, f, g, h);
            HOST_c2l(data, l);
            T1 := l; X[1] := l;
            ROUND_00_15(1, h, a, b, c, d, e, f, g);
            HOST_c2l(data, l);
            T1 := l; X[2] := l;
            ROUND_00_15(2, g, h, a, b, c, d, e, f);
            HOST_c2l(data, l);
            T1 := l; X[3] := l;
            ROUND_00_15(3, f, g, h, a, b, c, d, e);
            HOST_c2l(data, l);
            T1 := l; X[4] := l;
            ROUND_00_15(4, e, f, g, h, a, b, c, d);
            HOST_c2l(data, l);
            T1 := l; X[5] := l;
            ROUND_00_15(5, d, e, f, g, h, a, b, c);
            HOST_c2l(data, l);
            T1 := l; X[6] := l;
            ROUND_00_15(6, c, d, e, f, g, h, a, b);
            HOST_c2l(data, l);
            T1 := l; X[7] := l;
            ROUND_00_15(7, b, c, d, e, f, g, h, a);
            HOST_c2l(data, l);
            T1 := l; X[8] := l;
            ROUND_00_15(8, a, b, c, d, e, f, g, h);
            HOST_c2l(data, l);
            T1 := l; X[9] := l;
            ROUND_00_15(9, h, a, b, c, d, e, f, g);
            HOST_c2l(data, l);
            T1 := l; X[10] := l;
            ROUND_00_15(10, g, h, a, b, c, d, e, f);
            HOST_c2l(data, l);
            T1 := l; X[11] := l;
            ROUND_00_15(11, f, g, h, a, b, c, d, e);
            HOST_c2l(data, l);
            T1 := l; X[12] := l;
            ROUND_00_15(12, e, f, g, h, a, b, c, d);
            HOST_c2l(data, l);
            T1 := l; X[13] := l;
            ROUND_00_15(13, d, e, f, g, h, a, b, c);
            HOST_c2l(data, l);
            T1 := l; X[14] := l;
            ROUND_00_15(14, c, d, e, f, g, h, a, b);
            HOST_c2l(data, l);
            T1 := l; X[15] := l;
            ROUND_00_15(15, b, c, d, e, f, g, h, a);
        end;
        i := 16;
        while i < 64 do
        begin
            ROUND_16_63(i + 0, a, b, c, d, e, f, g, h, @X);
            ROUND_16_63(i + 1, h, a, b, c, d, e, f, g, @X);
            ROUND_16_63(i + 2, g, h, a, b, c, d, e, f, @X);
            ROUND_16_63(i + 3, f, g, h, a, b, c, d, e, @X);
            ROUND_16_63(i + 4, e, f, g, h, a, b, c, d, @X);
            ROUND_16_63(i + 5, d, e, f, g, h, a, b, c, @X);
            ROUND_16_63(i + 6, c, d, e, f, g, h, a, b, @X);
            ROUND_16_63(i + 7, b, c, d, e, f, g, h, a, @X);
            i := i+8;
        end;
        ctx.h[0]  := ctx.h[0] + a;
        ctx.h[1]  := ctx.h[1] + b;
        ctx.h[2]  := ctx.h[2] + c;
        ctx.h[3]  := ctx.h[3] + d;
        ctx.h[4]  := ctx.h[4] + e;
        ctx.h[5]  := ctx.h[5] + f;
        ctx.h[6]  := ctx.h[6] + g;
        ctx.h[7]  := ctx.h[7] + h;
    end;
 {$POINTERMATH OFF}
end;

function _SHA256_Update(c : PSHA256_CTX;const data_ : Pointer; len : size_t):integer;
var
  data, p : PByte;
  l : uint32;
  n : size_t;
begin
    data := data_;
    if len = 0 then Exit(1);
    l := (c.Nl + (uint32(  len)  shl  3)) and $ffffffff;
    if l < c.Nl then
       Inc(c.Nh);
    c.Nh  := c.Nh + uint32(  (len  shr  29));
    c.Nl := l;
    n := c.num;
    if n <> 0 then
    begin
        p := PByte( @c.data);
        if (len >= (16*4))  or  (len + n >= (16*4))  then
        begin
            memcpy(p + n, data, (16*4) - n);
            sha256_block_data_order(c, p, 1);
            n := (16*4) - n;
            data  := data + n;
            len  := len - n;
            c.num := 0;
            memset(p, 0, (16*4));
        end
        else
        begin
            memcpy(p + n, data, len);
            c.num  := c.num + uint32( len);
            Exit(1);
        end;
    end;
    n := len div (16*4);
    if n > 0 then
    begin
        sha256_block_data_order(c, data, n);
        n  := n  * ((16*4));
        data  := data + n;
        len  := len - n;
    end;
    if len <> 0 then
    begin
        p := PByte(@c.data);
        c.num := uint32( len);
        memcpy(p, data, len);
    end;
    Result := 1;
end;


function _SHA224_Init( c : PSHA256_CTX):integer;
begin
    memset(c, 0, sizeof( c^));
    c.h[0] := $c1059ed8;
    c.h[1] := $367cd507;
    c.h[2] := $3070dd17;
    c.h[3] := $f70e5939;
    c.h[4] := $ffc00b31;
    c.h[5] := $68581511;
    c.h[6] := $64f98fa7;
    c.h[7] := $befa4fa4;
    c.md_len := SHA224_DIGEST_LENGTH;
    Result := 1;
end;


function _SHA256_Init( c : PSHA256_CTX):integer;
begin
    memset(c, 0, sizeof( c^));
    c.h[0] := $6a09e667;
    c.h[1] := $bb67ae85;
    c.h[2] := $3c6ef372;
    c.h[3] := $a54ff53a;
    c.h[4] := $510e527f;
    c.h[5] := $9b05688c;
    c.h[6] := $1f83d9ab;
    c.h[7] := $5be0cd19;
    c.md_len := SHA256_DIGEST_LENGTH;
    Result := 1;
end;
{$Q+}

function _SHA224_Update(c : PSHA256_CTX;const data : Pointer; len : size_t):integer;
begin
    Result := _SHA256_Update(c, data, len);
end;


function _SHA224_Final( md : PByte; c : PSHA256_CTX):integer;
begin
    Result := _SHA256_Final(md, c);
end;



end.
