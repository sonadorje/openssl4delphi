unit openssl3.crypto.sha.sha512;
{$i     config.inc}
{sha_local.h
#define HASH_UPDATE                     SHA1_Update
#define HASH_TRANSFORM                  SHA1_Transform
#define HASH_FINAL                      SHA1_Final
#define HASH_INIT                       SHA1_Init
#define HASH_BLOCK_DATA_ORDER           sha1_block_data_order
}
interface
uses OpenSSL.Api;

  function sha512_224_init( c : PSHA512_CTX):integer;
  function sha512_256_init( c : PSHA512_CTX):integer;
  function _SHA384_Init( c : PSHA512_CTX):integer;
  function _SHA512_Init( c : PSHA512_CTX):integer;
  function _SHA512_Final( md : PByte; c : PSHA512_CTX):integer;
  function _SHA384_Final( md : PByte; c : PSHA512_CTX):integer;
  function _SHA512_Update(c : PSHA512_CTX;const _data : Pointer; len : size_t):integer;
  function _SHA384_Update(c : PSHA512_CTX;const data : Pointer; len : size_t):integer;
  procedure SHA512_Transform(c : Pointer;const data : PByte);
  procedure sha512_block_data_order(ctx : PSHA512_CTX;const _in : Pointer; num : size_t);

var // 1d arrays
  K512 : array[0..79] of SHA_LONG64 = (

    UInt64($428a2f98d728ae22), UInt64($7137449123ef65cd),
    UInt64($b5c0fbcfec4d3b2f), UInt64($e9b5dba58189dbbc),
    UInt64($3956c25bf348b538), UInt64($59f111f1b605d019),
    UInt64($923f82a4af194f9b), UInt64($ab1c5ed5da6d8118),
    UInt64($d807aa98a3030242), UInt64($12835b0145706fbe),
    UInt64($243185be4ee4b28c), UInt64($550c7dc3d5ffb4e2),
    UInt64($72be5d74f27b896f), UInt64($80deb1fe3b1696b1),
    UInt64($9bdc06a725c71235), UInt64($c19bf174cf692694),
    UInt64($e49b69c19ef14ad2), UInt64($efbe4786384f25e3),
    UInt64($0fc19dc68b8cd5b5), UInt64($240ca1cc77ac9c65),
    UInt64($2de92c6f592b0275), UInt64($4a7484aa6ea6e483),
    UInt64($5cb0a9dcbd41fbd4), UInt64($76f988da831153b5),
    UInt64($983e5152ee66dfab), UInt64($a831c66d2db43210),
    UInt64($b00327c898fb213f), UInt64($bf597fc7beef0ee4),
    UInt64($c6e00bf33da88fc2), UInt64($d5a79147930aa725),
    UInt64($06ca6351e003826f), UInt64($142929670a0e6e70),
    UInt64($27b70a8546d22ffc), UInt64($2e1b21385c26c926),
    UInt64($4d2c6dfc5ac42aed), UInt64($53380d139d95b3df),
    UInt64($650a73548baf63de), UInt64($766a0abb3c77b2a8),
    UInt64($81c2c92e47edaee6), UInt64($92722c851482353b),
    UInt64($a2bfe8a14cf10364), UInt64($a81a664bbc423001),
    UInt64($c24b8b70d0f89791), UInt64($c76c51a30654be30),
    UInt64($d192e819d6ef5218), UInt64($d69906245565a910),
    UInt64($f40e35855771202a), UInt64($106aa07032bbd1b8),
    UInt64($19a4c116b8d2d0c8), UInt64($1e376c085141ab53),
    UInt64($2748774cdf8eeb99), UInt64($34b0bcb5e19b48a8),
    UInt64($391c0cb3c5c95a63), UInt64($4ed8aa4ae3418acb),
    UInt64($5b9cca4f7763e373), UInt64($682e6ff3d6b2b8a3),
    UInt64($748f82ee5defb2fc), UInt64($78a5636f43172f60),
    UInt64($84c87814a1f0ab72), UInt64($8cc702081a6439ec),
    UInt64($90befffa23631e28), UInt64($a4506cebde82bde9),
    UInt64($bef9a3f7b2c67915), UInt64($c67178f2e372532b),
    UInt64($ca273eceea26619c), UInt64($d186b8c721c0c207),
    UInt64($eada7dd6cde0eb1e), UInt64($f57d4f7fee6ed178),
    UInt64($06f067aa72176fba), UInt64($0a637dc5a2c898a6),
    UInt64($113f9804bef90dae), UInt64($1b710b35131c471b),
    UInt64($28db77f523047d84), UInt64($32caab7b40c72493),
    UInt64($3c9ebe0a15c9bebc), UInt64($431d67c49c100d4c),
    UInt64($4cc5d4becb3e42b6), UInt64($597f299cfc657e2a),
    UInt64($5fcb6fab3ad6faec), UInt64($6c44198c4a475817) );

implementation
uses openssl3.crypto.sha.sha_local,             openssl3.crypto.mem;

{$I openssl3.include.crypto.md32_common.inc}

function B( x : SHA_LONG64; j : Byte):uint64;
begin
 result := (SHA_LONG64( ( PByte(@x)^ +j))) shl ((7-j)*8)
end;

function PULL64(x: SHA_LONG64): SHA_LONG64;
begin
   result := (B(x,0) or B(x,1) or B(x,2) or B(x,3) or B(x,4) or B(x,5) or B(x,6) or B(x,7))
end;

function Sigma1(x: SHA_LONG64):SHA_LONG64;
begin
   Result := (ROTR64((x),14) xor ROTR64((x),18) xor ROTR64((x),41))
end;

function Maj(x,y,z: SHA_LONG64): SHA_LONG64;
begin
  Result := (((x) and (y)) xor ((x) and (z)) xor ((y) and (z)))
end;

function Ch(x,y,z: SHA_LONG64): SHA_LONG64;
begin
   Result :=  (((x) and (y)) xor ((not (x)) and (z)))
end;

function Sigma0(x: SHA_LONG64): SHA_LONG64;
begin
   Result :=  (ROTR64((x),28) xor ROTR64((x),34) xor ROTR64((x),39))
end;

procedure sha512_block_data_order(ctx : PSHA512_CTX;const _in : Pointer; num : size_t);
var
  W: PSHA_LONG64;
  a, b, c, d, e, f, g, h, s0, s1, T1 : SHA_LONG64;
  X : array[0..15] of SHA_LONG64;
  i : integer;

  procedure ROUND_00_15(i,a,b,c,d,e,f,g,h: SHA_LONG64);
  begin
      T1  := T1 + (h + Sigma1(e) + Ch(e,f,g) + K512[i]);
      h := Sigma0(a) + Maj(a,b,c);
      d  := d + T1;
      h  := h + T1;
  end;

  procedure ROUND_16_80(i,j,a,b,c,d,e,f,g,h: SHA_LONG64; X: PSHA_LONG64) ;
  begin
  {$POINTERMATH ON}
      s0 := X[(j+1) and $0f];
      s0 := sigma0(s0);
      s1 := X[(j+14) and $0f];
      s1 := sigma1(s1);
      X[(j) and $0f]  := X[(j) and $0f] + (s0 + s1 + X[(j+9) and $0f]);
      T1 := X[(j) and $0f];
      ROUND_00_15(i+j,a,b,c,d,e,f,g,h);
    {$POINTERMATH OFF}
  end;

begin
{$POINTERMATH ON}
    W := _in;
    while PostDec(num) >0 do
    begin
        a := ctx.h[0];
        b := ctx.h[1];
        c := ctx.h[2];
        d := ctx.h[3];
        e := ctx.h[4];
        f := ctx.h[5];
        g := ctx.h[6];
        h := ctx.h[7];
{$IFDEF B_ENDIAN}
        T1 := X[0] = W[0];
        ROUND_00_15(0, a, b, c, d, e, f, g, h);
        T1 := X[1] = W[1];
        ROUND_00_15(1, h, a, b, c, d, e, f, g);
        T1 := X[2] = W[2];
        ROUND_00_15(2, g, h, a, b, c, d, e, f);
        T1 := X[3] = W[3];
        ROUND_00_15(3, f, g, h, a, b, c, d, e);
        T1 := X[4] = W[4];
        ROUND_00_15(4, e, f, g, h, a, b, c, d);
        T1 := X[5] = W[5];
        ROUND_00_15(5, d, e, f, g, h, a, b, c);
        T1 := X[6] = W[6];
        ROUND_00_15(6, c, d, e, f, g, h, a, b);
        T1 := X[7] = W[7];
        ROUND_00_15(7, b, c, d, e, f, g, h, a);
        T1 := X[8] = W[8];
        ROUND_00_15(8, a, b, c, d, e, f, g, h);
        T1 := X[9] = W[9];
        ROUND_00_15(9, h, a, b, c, d, e, f, g);
        T1 := X[10] = W[10];
        ROUND_00_15(10, g, h, a, b, c, d, e, f);
        T1 := X[11] = W[11];
        ROUND_00_15(11, f, g, h, a, b, c, d, e);
        T1 := X[12] = W[12];
        ROUND_00_15(12, e, f, g, h, a, b, c, d);
        T1 := X[13] = W[13];
        ROUND_00_15(13, d, e, f, g, h, a, b, c);
        T1 := X[14] = W[14];
        ROUND_00_15(14, c, d, e, f, g, h, a, b);
        T1 := X[15] = W[15];
        ROUND_00_15(15, b, c, d, e, f, g, h, a);
{$ELSE}
        T1 := PULL64(W[0]); X[0] := PULL64(W[0]);
        ROUND_00_15(0, a, b, c, d, e, f, g, h);
        T1 := PULL64(W[1]); X[1] := PULL64(W[1]);
        ROUND_00_15(1, h, a, b, c, d, e, f, g);
        T1 := PULL64(W[2]);X[2] := PULL64(W[2]);
        ROUND_00_15(2, g, h, a, b, c, d, e, f);
        T1 := PULL64(W[3]);X[3] := PULL64(W[3]);
        ROUND_00_15(3, f, g, h, a, b, c, d, e);
        T1 := PULL64(W[4]);X[4] := PULL64(W[4]);
        ROUND_00_15(4, e, f, g, h, a, b, c, d);
        T1 := PULL64(W[5]);X[5] := PULL64(W[5]);
        ROUND_00_15(5, d, e, f, g, h, a, b, c);
        T1 := PULL64(W[6]);X[6] := PULL64(W[6]);
        ROUND_00_15(6, c, d, e, f, g, h, a, b);
        T1 := PULL64(W[7]);X[7] := PULL64(W[7]);
        ROUND_00_15(7, b, c, d, e, f, g, h, a);
        T1 := PULL64(W[8]);X[8] := PULL64(W[8]);
        ROUND_00_15(8, a, b, c, d, e, f, g, h);
        T1 := PULL64(W[9]);X[9] := PULL64(W[9]);
        ROUND_00_15(9, h, a, b, c, d, e, f, g);
        T1 := PULL64(W[10]);X[10] := PULL64(W[10]);
        ROUND_00_15(10, g, h, a, b, c, d, e, f);
        T1 := PULL64(W[11]);X[11] := PULL64(W[11]);
        ROUND_00_15(11, f, g, h, a, b, c, d, e);
        T1 := PULL64(W[12]);X[12] := PULL64(W[12]);
        ROUND_00_15(12, e, f, g, h, a, b, c, d);
        T1 := PULL64(W[13]);X[13] := PULL64(W[13]);
        ROUND_00_15(13, d, e, f, g, h, a, b, c);
        T1 := PULL64(W[14]);X[14] := PULL64(W[14]);
        ROUND_00_15(14, c, d, e, f, g, h, a, b);
        T1 := PULL64(W[15]);X[15] := PULL64(W[15]);
        ROUND_00_15(15, b, c, d, e, f, g, h, a);
{$ENDIF}
        i := 16;
        while i < 80 do
        begin
            ROUND_16_80(i, 0, a, b, c, d, e, f, g, h, @X);
            ROUND_16_80(i, 1, h, a, b, c, d, e, f, g, @X);
            ROUND_16_80(i, 2, g, h, a, b, c, d, e, f, @X);
            ROUND_16_80(i, 3, f, g, h, a, b, c, d, e, @X);
            ROUND_16_80(i, 4, e, f, g, h, a, b, c, d, @X);
            ROUND_16_80(i, 5, d, e, f, g, h, a, b, c, @X);
            ROUND_16_80(i, 6, c, d, e, f, g, h, a, b, @X);
            ROUND_16_80(i, 7, b, c, d, e, f, g, h, a, @X);
            ROUND_16_80(i, 8, a, b, c, d, e, f, g, h, @X);
            ROUND_16_80(i, 9, h, a, b, c, d, e, f, g, @X);
            ROUND_16_80(i, 10, g, h, a, b, c, d, e, f, @X);
            ROUND_16_80(i, 11, f, g, h, a, b, c, d, e, @X);
            ROUND_16_80(i, 12, e, f, g, h, a, b, c, d, @X);
            ROUND_16_80(i, 13, d, e, f, g, h, a, b, c, @X);
            ROUND_16_80(i, 14, c, d, e, f, g, h, a, b, @X);
            ROUND_16_80(i, 15, b, c, d, e, f, g, h, a, @X);
            i := i+16;
        end;
        ctx.h[0]  := ctx.h[0] + a;
        ctx.h[1]  := ctx.h[1] + b;
        ctx.h[2]  := ctx.h[2] + c;
        ctx.h[3]  := ctx.h[3] + d;
        ctx.h[4]  := ctx.h[4] + e;
        ctx.h[5]  := ctx.h[5] + f;
        ctx.h[6]  := ctx.h[6] + g;
        ctx.h[7]  := ctx.h[7] + h;
        W  := W + SHA_LBLOCK;
    end;
{$POINTERMATH OFF}
end;


function sha512_224_init( c : PSHA512_CTX):integer;
begin
    c.h[0] := U64($8c3d37c819544da2);
    c.h[1] := U64($73e1996689dcd4d6);
    c.h[2] := U64($1dfab7ae32ff9c82);
    c.h[3] := U64($679dd514582f9fcf);
    c.h[4] := U64($0f6d2b697bd44da8);
    c.h[5] := U64($77e36f7304c48942);
    c.h[6] := U64($3f9d85a86a1d36c8);
    c.h[7] := U64($1112e6ad91d692a1);
    c.Nl := 0;
    c.Nh := 0;
    c.num := 0;
    c.md_len := SHA224_DIGEST_LENGTH;
    Result := 1;
end;


function sha512_256_init( c : PSHA512_CTX):integer;
begin
    c.h[0] := U64($22312194fc2bf72c);
    c.h[1] := U64($9f555fa3c84c64c2);
    c.h[2] := U64($2393b86b6f53b151);
    c.h[3] := U64($963877195940eabd);
    c.h[4] := U64($96283ee2a88effe3);
    c.h[5] := U64($be5e1e2553863992);
    c.h[6] := U64($2b0199fc2c85b8aa);
    c.h[7] := U64($0eb72ddc81c52ca2);
    c.Nl := 0;
    c.Nh := 0;
    c.num := 0;
    c.md_len := SHA256_DIGEST_LENGTH;
    Result := 1;
end;


function _SHA384_Init( c : PSHA512_CTX):integer;
begin
    c.h[0] := U64($cbbb9d5dc1059ed8);
    c.h[1] := U64($629a292a367cd507);
    c.h[2] := U64($9159015a3070dd17);
    c.h[3] := U64($152fecd8f70e5939);
    c.h[4] := U64($67332667ffc00b31);
    c.h[5] := U64($8eb44a8768581511);
    c.h[6] := U64($db0c2e0d64f98fa7);
    c.h[7] := U64($47b5481dbefa4fa4);
    c.Nl := 0;
    c.Nh := 0;
    c.num := 0;
    c.md_len := SHA384_DIGEST_LENGTH;
    Result := 1;
end;


function _SHA512_Init( c : PSHA512_CTX):integer;
begin
    c.h[0] := U64($6a09e667f3bcc908);
    c.h[1] := U64($bb67ae8584caa73b);
    c.h[2] := U64($3c6ef372fe94f82b);
    c.h[3] := U64($a54ff53a5f1d36f1);
    c.h[4] := U64($510e527fade682d1);
    c.h[5] := U64($9b05688c2b3e6c1f);
    c.h[6] := U64($1f83d9abfb41bd6b);
    c.h[7] := U64($5be0cd19137e2179);
    c.Nl := 0;
    c.Nh := 0;
    c.num := 0;
    c.md_len := SHA512_DIGEST_LENGTH;
    Result := 1;
end;


function _SHA512_Final( md : PByte; c : PSHA512_CTX):integer;
var
  p : PByte;

  n : size_t;

  t: SHA_LONG64;
begin
    p := PByte(@ c.u.p);
    n := c.num;
    p[n] := $80;
    PostInc(n);
    if n > (sizeof(c.u) - 16)  then
    begin
        memset(p + n, 0, sizeof(c.u) - n);
        n := 0;
        sha512_block_data_order(c, p, 1);
    end;
    memset(p + n, 0, sizeof(c.u) - 16 - n);
{$IFDEF B_ENDIAN}
    c.u.d[SHA_LBLOCK - 2] = c.Nh;
    c.u.d[SHA_LBLOCK - 1] = c.Nl;
{$ELSE}
    p[sizeof(c.u) - 1] := Byte( (c.Nl));
    p[sizeof(c.u) - 2] := Byte( (c.Nl  shr  8));
    p[sizeof(c.u) - 3] := Byte( (c.Nl  shr  16));
    p[sizeof(c.u) - 4] := Byte( (c.Nl  shr  24));
    p[sizeof(c.u) - 5] := Byte( (c.Nl  shr  32));
    p[sizeof(c.u) - 6] := Byte( (c.Nl  shr  40));
    p[sizeof(c.u) - 7] := Byte( (c.Nl  shr  48));
    p[sizeof(c.u) - 8] := Byte( (c.Nl  shr  56));
    p[sizeof(c.u) - 9] := Byte( (c.Nh));
    p[sizeof(c.u) - 10] := Byte( (c.Nh  shr  8));
    p[sizeof(c.u) - 11] := Byte( (c.Nh  shr  16));
    p[sizeof(c.u) - 12] := Byte( (c.Nh  shr  24));
    p[sizeof(c.u) - 13] := Byte( (c.Nh  shr  32));
    p[sizeof(c.u) - 14] := Byte( (c.Nh  shr  40));
    p[sizeof(c.u) - 15] := Byte( (c.Nh  shr  48));
    p[sizeof(c.u) - 16] := Byte( (c.Nh  shr  56));
{$ENDIF}
    sha512_block_data_order(c, p, 1);
    if md = nil then Exit(0);
    case c.md_len of
    { Let compiler decide if it's appropriate to unroll... }
    SHA224_DIGEST_LENGTH:
    begin
        for n := 0 to SHA224_DIGEST_LENGTH div 8-1 do
        begin
            t := c.h[n];
            PostInc(md)^ := Byte (t  shr  56);
            PostInc(md)^ := Byte (t  shr  48);
            PostInc(md)^ := Byte (t  shr  40);
            PostInc(md)^ := Byte (t  shr  32);
            PostInc(md)^ := Byte (t  shr  24);
            PostInc(md)^ := Byte (t  shr  16);
            PostInc(md)^ := Byte (t  shr  8);
            PostInc(md)^ := Byte (t);
        end;
        {
         * For 224 bits, there are four bytes left over that have to be
         * processed separately.
         }
        begin
            t := c.h[SHA224_DIGEST_LENGTH div 8];
            PostInc(md)^ := Byte (t  shr  56);
            PostInc(md)^ := Byte (t  shr  48);
            PostInc(md)^ := Byte (t  shr  40);
            PostInc(md)^ := Byte (t  shr  32);
        end;
    end;
    SHA256_DIGEST_LENGTH:
    begin
        for n := 0 to SHA256_DIGEST_LENGTH div 8-1 do
        begin
            t := c.h[n];
            PostInc(md)^ := Byte (t  shr  56);
            PostInc(md)^ := Byte (t  shr  48);
            PostInc(md)^ := Byte (t  shr  40);
            PostInc(md)^ := Byte (t  shr  32);
            PostInc(md)^ := Byte (t  shr  24);
            PostInc(md)^ := Byte (t  shr  16);
            PostInc(md)^ := Byte (t  shr  8);
            PostInc(md)^ := Byte (t);
        end;
    end;
    SHA384_DIGEST_LENGTH:
        for n := 0 to SHA384_DIGEST_LENGTH div 8-1 do
        begin
            t := c.h[n];
            PostInc(md)^ := Byte (t  shr  56);
            PostInc(md)^ := Byte (t  shr  48);
            PostInc(md)^ := Byte (t  shr  40);
            PostInc(md)^ := Byte (t  shr  32);
            PostInc(md)^ := Byte (t  shr  24);
            PostInc(md)^ := Byte (t  shr  16);
            PostInc(md)^ := Byte (t  shr  8);
            PostInc(md)^ := Byte (t);
        end;
        //break;
    SHA512_DIGEST_LENGTH:
        for n := 0 to SHA512_DIGEST_LENGTH div 8-1 do
        begin
            t := c.h[n];
            PostInc(md)^ := Byte (t  shr  56);
            PostInc(md)^ := Byte (t  shr  48);
            PostInc(md)^ := Byte (t  shr  40);
            PostInc(md)^ := Byte (t  shr  32);
            PostInc(md)^ := Byte (t  shr  24);
            PostInc(md)^ := Byte (t  shr  16);
            PostInc(md)^ := Byte (t  shr  8);
            PostInc(md)^ := Byte (t);
        end;
        //break;
    { ... as well as make sure md_len is not abused. }
    else
        Exit(0);
    end;
    Result := 1;
end;


function _SHA384_Final( md : PByte; c : PSHA512_CTX):integer;
begin
    Result := _SHA512_Final(md, c);
end;


function _SHA512_Update(c : PSHA512_CTX;const _data : Pointer; len : size_t):integer;
var
  l : SHA_LONG64;
  p, data : PByte;
  n : size_t;
begin
    p := @c.u.p;
     data := PByte (_data);
    if len = 0 then Exit(1);
    l := (c.Nl + ((SHA_LONG64( len))  shl  3)) and U64($ffffffffffffffff);
    if l < c.Nl then
       Inc(c.Nh);
    if sizeof(len) >= 8  then
        c.Nh  := c.Nh + (((SHA_LONG64( len))  shr  61));
    c.Nl := l;
    if c.num <> 0 then
    begin
        n := sizeof(c.u) - c.num;
        if len < n then
        begin
            memcpy(p + c.num, data, len);
            c.num  := c.num + uint32( len);
            Exit(1);
        end
        else
        begin
            memcpy(p + c.num, data, n);c.num := 0;
            len := len - n; data  := data + n;
            sha512_block_data_order(c, p, 1);
        end;
    end;
    if len >= sizeof(c.u) then
    begin
{$IFNDEF SHA512_BLOCK_CAN_MANAGE_UNALIGNED_DATA}
        if size_t( data % sizeof(c.u.d[0]) <> 0 then
            while len >= sizeof(c.u) do
                memcpy(p, data, sizeof(c.u)),
                sha512_block_data_order(c, p, 1),
                len  := len - (sizeof(c.u));
 data  := data + (sizeof(c.u));
        else
{$ENDIF}
            sha512_block_data_order(c, data, len div sizeof(c.u));
            data  := data + len;
            len  := len mod (sizeof(c.u));
            data  := data - len;
    end;
    if len <> 0 then Result := 1;
end;


function _SHA384_Update(c : PSHA512_CTX;const data : Pointer; len : size_t):integer;
begin
    Result := _SHA512_Update(c, data, len);
end;


procedure SHA512_Transform(c : Pointer;const data : PByte);
begin
{$IFNDEF SHA512_BLOCK_CAN_MANAGE_UNALIGNED_DATA}
    if size_t( data % sizeof(c.u.d[0] then <> 0)
        memcpy(c.u.p, data, sizeof(c.u.p)), data = c.u.p;
{$ENDIF}
    sha512_block_data_order(PSHA512_CTX(c), data, 1);
end;

end.
