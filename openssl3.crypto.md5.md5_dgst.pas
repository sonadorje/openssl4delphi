unit openssl3.crypto.md5.md5_dgst;
{$i     config.inc}
{md5_local.h
#define HASH_LONG               MD5_LONG
#define HASH_CTX                MD5_CTX
#define HASH_CBLOCK             MD5_CBLOCK
#define HASH_UPDATE             MD5_Update
#define HASH_TRANSFORM          MD5_Transform
#define HASH_FINAL              MD5_Final
}



interface
uses OpenSSL.Api;

const
 INIT_DATA_A  :Uint32 = uint32($67452301);
 INIT_DATA_B  :Uint32 = uint32($efcdab89);
 INIT_DATA_C  :Uint32 = uint32($98badcfe);
 INIT_DATA_D  :Uint32 = uint32($10325476);

  function MD5_Update(c : PMD5_CTX;const data_ : Pointer; len : size_t):integer;
  procedure MD5_Transform(c : Pointer;const data : PByte);
  function MD5_Final( md : PByte; c : PMD5_CTX):integer;
  procedure md5_block_data_order(_c : PMD5_CTX;const data_ : Pointer; num : size_t);
  function MD5_Init( c : PMD5_CTX):integer;

implementation
uses
   openssl3.include.crypto.md32_common, openssl3.crypto.sha.sha_local,
   openssl3.crypto.mem;

{$Q-}
function MD5_Init( c : PMD5_CTX):integer;
begin
    memset(c, 0, sizeof( c^));
    c.A := INIT_DATA_A;
    c.B := INIT_DATA_B;
    c.C := INIT_DATA_C;
    c.D := INIT_DATA_D;
    Result := 1;
end;


procedure HASH_MAKE_STRING( c : PMD5_CTX; s : PByte);
var
  ll : Cardinal;
begin
        ll := (c).A;
    HOST_l2c(ll,(s));
        ll := (c).B;
    HOST_l2c(ll,(s));
        ll := (c).C;
    HOST_l2c(ll,(s));
        ll := (c).D;
    HOST_l2c(ll,(s));
end;

function F(b,c,d: uint32): UInt32;
begin
   Result := ((((c) xor (d)) and (b)) xor (d))
end;

function G(b,c,d: uint32): UInt32;
begin
   Result := ((((b) xor (c)) and (d)) xor (c))
end;

function H(b,c,d: uint32): UInt32;
begin
   Result := ((b) xor (c) xor (d))
end;

function I(b,c,d: uint32): UInt32;
begin
   Result :=  (((not (d)) or (b)) xor (c))
end;

function R0(var a: UInt32; b,c,d,k,s,t: uint32): UInt32;
begin
  a := a + ((k)+(t)+F((b),(c),(d)));
  a := ROTATE(a,s);
  a := a+b;
end;

function R1(var a: UInt32; b,c,d,k,s,t: uint32): UInt32;
begin
  a := a + ((k)+(t)+G((b),(c),(d)));
  a := ROTATE(a,s);
  a := a + b;
end;

function R2(var a: UInt32; b,c,d,k,s,t: uint32): UInt32;
begin
  a := a+((k)+(t)+H((b),(c),(d)));
  a := ROTATE(a,s);
  a := a + b;
end;

function R3(var a: UInt32; b,c,d,k,s,t: uint32): UInt32;
begin
  a := a+((k)+(t)+I((b),(c),(d)));
  a := ROTATE(a,s);
  a := a+b;
end;

procedure md5_block_data_order(_c : PMD5_CTX;const data_ : Pointer; num : size_t);
var
  data : PByte;

  A, B, C, D, l : uint32;

{$IFNDEF MD32_XARRAY}
    { See comment in crypto/sha/sha_local.h for details. }
    XX0, XX1, XX2, XX3, XX4, XX5, XX6, XX7,
        XX8, XX9, XX10, XX11, XX12, XX13, XX14, XX15: uint32 ;

{$ELSE}
  #define X(i)   XX[i]
{$ENDIF}
begin
     data := data_;

    A := _c.A;
    B := _c.B;
    C := _c.C;
    D := _c.D;
    while PostDec(num)>0 do
    begin
        HOST_c2l(data, l);
        XX0 := l;
        HOST_c2l(data, l);
        XX1 := l;
        { Round 0 }
        R0(A, B, C, D, XX0, 7, $d76aa478);
        HOST_c2l(data, l);
        XX2 := l;
        R0(D, A, B, C, XX1, 12, $e8c7b756);
        HOST_c2l(data, l);
        XX3 := l;
        R0(C, D, A, B, XX2, 17, $242070db);
        HOST_c2l(data, l);
        XX4 := l;
        R0(B, C, D, A, XX3, 22, $c1bdceee);
        HOST_c2l(data, l);
        XX5 := l;
        R0(A, B, C, D, XX4, 7, $f57c0faf);
        HOST_c2l(data, l);
        XX6 := l;
        R0(D, A, B, C, XX5, 12, $4787c62a);
        HOST_c2l(data, l);
        XX7 := l;
        R0(C, D, A, B, XX6, 17, $a8304613);
        HOST_c2l(data, l);
        XX8 := l;
        R0(B, C, D, A, XX7, 22, $fd469501);
        HOST_c2l(data, l);
        XX9 := l;
        R0(A, B, C, D, XX8, 7, $698098d8);
        HOST_c2l(data, l);
        XX10 := l;
        R0(D, A, B, C, XX9, 12, $8b44f7af);
        HOST_c2l(data, l);
        XX11 := l;
        R0(C, D, A, B, XX10, 17, $ffff5bb1);
        HOST_c2l(data, l);
        XX12 := l;
        R0(B, C, D, A, XX11, 22, $895cd7be);
        HOST_c2l(data, l);
        XX13 := l;
        R0(A, B, C, D, XX12, 7, $6b901122);
        HOST_c2l(data, l);
        XX14 := l;
        R0(D, A, B, C, XX13, 12, $fd987193);
        HOST_c2l(data, l);
        XX15 := l;
        R0(C, D, A, B, XX14, 17, $a679438e);
        R0(B, C, D, A, XX15, 22, $49b40821);
        { Round 1 }
        R1(A, B, C, D, XX1, 5, $f61e2562);
        R1(D, A, B, C, XX6, 9, $c040b340);
        R1(C, D, A, B, XX11, 14, $265e5a51);
        R1(B, C, D, A, XX0, 20, $e9b6c7aa);
        R1(A, B, C, D, XX5, 5, $d62f105d);
        R1(D, A, B, C, XX10, 9, $02441453);
        R1(C, D, A, B, XX15, 14, $d8a1e681);
        R1(B, C, D, A, XX4, 20, $e7d3fbc8);
        R1(A, B, C, D, XX9, 5, $21e1cde6);
        R1(D, A, B, C, XX14, 9, $c33707d6);
        R1(C, D, A, B, XX3, 14, $f4d50d87);
        R1(B, C, D, A, XX8, 20, $455a14ed);
        R1(A, B, C, D, XX13, 5, $a9e3e905);
        R1(D, A, B, C, XX2, 9, $fcefa3f8);
        R1(C, D, A, B, XX7, 14, $676f02d9);
        R1(B, C, D, A, XX12, 20, $8d2a4c8a);
        { Round 2 }
        R2(A, B, C, D, XX5, 4, $fffa3942);
        R2(D, A, B, C, XX8, 11, $8771f681);
        R2(C, D, A, B, XX11, 16, $6d9d6122);
        R2(B, C, D, A, XX14, 23, $fde5380c);
        R2(A, B, C, D, XX1, 4, $a4beea44);
        R2(D, A, B, C, XX4, 11, $4bdecfa9);
        R2(C, D, A, B, XX7, 16, $f6bb4b60);
        R2(B, C, D, A, XX10, 23, $bebfbc70);
        R2(A, B, C, D, XX13, 4, $289b7ec6);
        R2(D, A, B, C, XX0, 11, $eaa127fa);
        R2(C, D, A, B, XX3, 16, $d4ef3085);
        R2(B, C, D, A, XX6, 23, $04881d05);
        R2(A, B, C, D, XX9, 4, $d9d4d039);
        R2(D, A, B, C, XX12, 11, $e6db99e5);
        R2(C, D, A, B, XX15, 16, $1fa27cf8);
        R2(B, C, D, A, XX2, 23, $c4ac5665);
        { Round 3 }
        R3(A, B, C, D, XX0, 6, $f4292244);
        R3(D, A, B, C, XX7, 10, $432aff97);
        R3(C, D, A, B, XX14, 15, $ab9423a7);
        R3(B, C, D, A, XX5, 21, $fc93a039);
        R3(A, B, C, D, XX12, 6, $655b59c3);
        R3(D, A, B, C, XX3, 10, $8f0ccc92);
        R3(C, D, A, B, XX10, 15, $ffeff47d);
        R3(B, C, D, A, XX1, 21, $85845dd1);
        R3(A, B, C, D, XX8, 6, $6fa87e4f);
        R3(D, A, B, C, XX15, 10, $fe2ce6e0);
        R3(C, D, A, B, XX6, 15, $a3014314);
        R3(B, C, D, A, XX13, 21, $4e0811a1);
        R3(A, B, C, D, XX4, 6, $f7537e82);
        R3(D, A, B, C, XX11, 10, $bd3af235);
        R3(C, D, A, B, XX2, 15, $2ad7d2bb);
        R3(B, C, D, A, XX9, 21, $eb86d391);
        _c.A  := _c.A + A;
        A := _c.A;
        _c.B  := _c.B + B;
        B := _c.B;
        _c.C  := _c.C + C;
        C := _c.C ;
        _c.D  := _c.D + D;
        D := _c.D
    end;
end;



function MD5_Update(c : PMD5_CTX;const data_ : Pointer; len : size_t):integer;
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
        p := PByte(@ c.data);
        if (len >= 64)  or  (len + n >= 64) then
        begin
            memcpy(p + n, data, 64 - n);
            md5_block_data_order(c, p, 1);
            n := 64 - n;
            data  := data + n;
            len  := len - n;
            c.num := 0;
            memset(p, 0, 64);
        end
        else
        begin
            memcpy(p + n, data, len);
            c.num  := c.num + uint32( len);
            Exit(1);
        end;
    end;
    n := len div 64;
    if n > 0 then
    begin
        md5_block_data_order(c, data, n);
        n  := n  * 64;
        data  := data + n;
        len  := len - n;
    end;
    if len <> 0 then
    begin
        p := PByte(@ c.data);
        c.num := uint32( len);
        memcpy(p, data, len);
    end;
    Result := 1;
end;


procedure MD5_Transform(c : Pointer;const data : PByte);
begin
    md5_block_data_order(PMD5_CTX(c), data, 1);
end;


function MD5_Final( md : PByte; c : PMD5_CTX):integer;
var
  p : PByte;

  n : size_t;
begin
    p := PByte(@ c.data);
    n := c.num;
    p[n] := $80;
    Inc(n);
    if n > (64 - 8) then
    begin
        memset(p + n, 0, 64 - n);
        n := 0;
        md5_block_data_order(c, p, 1);
    end;
    memset(p + n, 0, 64 - 8 - n);
    p  := p + (64 - 8);
{$IF defined(DATA_ORDER_IS_BIG_ENDIAN)}
    HOST_l2c(c.Nh, p);
    HOST_l2c(c.Nl, p);
{$elseif defined(DATA_ORDER_IS_LITTLE_ENDIAN)}
    (void)HOST_l2c(c.Nl, p);
    (void)HOST_l2c(c.Nh, p);
{$ENDIF}
    p  := p - 64;
    md5_block_data_order(c, p, 1);
    c.num := 0;
    OPENSSL_cleanse(p, 64);
    HASH_MAKE_STRING(c, md);
    Result := 1;
end;
{$Q+}


end.
