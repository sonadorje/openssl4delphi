unit openssl3.crypto.md4.md4_dgst;

interface
uses OpenSSL.Api, openssl3.crypto.md4.md4_local;

type
  PHASH_CTX = PMD4_CTX;


const
  INIT_DATA_A =ulong($67452301);
  INIT_DATA_B =ulong($efcdab89);
  INIT_DATA_C =ulong($98badcfe);
  INIT_DATA_D =ulong($10325476);

function _MD4_Init( c : PMD4_CTX):integer;
procedure md4_block_data_order(_c : PMD4_CTX;const data_ : Pointer; num : size_t);

//defined in openssl3.include.crypto.md32_common.inc
function HASH_UPDATE( c : PHASH_CTX;const data_ : Pointer; len : size_t):integer;
function HASH_FINAL( md : PByte; c : PHASH_CTX):integer;

const
   _MD4_Update: function( c : PHASH_CTX;const data_ : Pointer; len : size_t):integer = HASH_UPDATE;
   _MD4_Final : function( md : PByte; c : PHASH_CTX):integer =  HASH_FINAL;

implementation
uses openssl3.crypto.mem;

const
  HASH_BLOCK_DATA_ORDER: procedure(c : PMD4_CTX;const data_ : Pointer; num : size_t) = md4_block_data_order;

{$I openssl3.include.crypto.md32_common.inc}

procedure md4_block_data_order(_c : PMD4_CTX;const data_ : Pointer; num : size_t);
var
  data : PByte;
  A, B, C, D, l : uint32;

{$IFNDEF MD32_XARRAY}
    { See comment in crypto/sha/sha_local.h for details. }
     XX0, XX1, XX2, XX3, XX4, XX5, XX6, XX7,
        XX8, XX9, XX10, XX11, XX12, XX13, XX14, XX15: UInt32;
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
        R0(A, B, C, D, XX0, 3, 0);
        HOST_c2l(data, l);
        XX2 := l;
        R0(D, A, B, C, XX1, 7, 0);
        HOST_c2l(data, l);
        XX3 := l;
        R0(C, D, A, B, XX2, 11, 0);
        HOST_c2l(data, l);
        XX4 := l;
        R0(B, C, D, A, XX3, 19, 0);
        HOST_c2l(data, l);
        XX5 := l;
        R0(A, B, C, D, XX4, 3, 0);
        HOST_c2l(data, l);
        XX6 := l;
        R0(D, A, B, C, XX5, 7, 0);
        HOST_c2l(data, l);
        XX7 := l;
        R0(C, D, A, B, XX6, 11, 0);
        HOST_c2l(data, l);
        XX8 := l;
        R0(B, C, D, A, XX7, 19, 0);
        HOST_c2l(data, l);
        XX9 := l;
        R0(A, B, C, D, XX8, 3, 0);
        HOST_c2l(data, l);
        XX10 := l;
        R0(D, A, B, C, XX9, 7, 0);
        HOST_c2l(data, l);
        XX11 := l;
        R0(C, D, A, B, XX10, 11, 0);
        HOST_c2l(data, l);
        XX12 := l;
        R0(B, C, D, A, XX11, 19, 0);
        HOST_c2l(data, l);
        XX13 := l;
        R0(A, B, C, D, XX12, 3, 0);
        HOST_c2l(data, l);
        XX14 := l;
        R0(D, A, B, C, XX13, 7, 0);
        HOST_c2l(data, l);
        XX15 := l;
        R0(C, D, A, B, XX14, 11, 0);
        R0(B, C, D, A, XX15, 19, 0);
        { Round 1 }
        R1(A, B, C, D, XX0, 3, $5A827999);
        R1(D, A, B, C, XX4, 5, $5A827999);
        R1(C, D, A, B, XX8, 9, $5A827999);
        R1(B, C, D, A, XX12, 13, $5A827999);
        R1(A, B, C, D, XX1, 3, $5A827999);
        R1(D, A, B, C, XX5, 5, $5A827999);
        R1(C, D, A, B, XX9, 9, $5A827999);
        R1(B, C, D, A, XX13, 13, $5A827999);
        R1(A, B, C, D, XX2, 3, $5A827999);
        R1(D, A, B, C, XX6, 5, $5A827999);
        R1(C, D, A, B, XX10, 9, $5A827999);
        R1(B, C, D, A, XX14, 13, $5A827999);
        R1(A, B, C, D, XX3, 3, $5A827999);
        R1(D, A, B, C, XX7, 5, $5A827999);
        R1(C, D, A, B, XX11, 9, $5A827999);
        R1(B, C, D, A, XX15, 13, $5A827999);
        { Round 2 }
        R2(A, B, C, D, XX0, 3, $6ED9EBA1);
        R2(D, A, B, C, XX8, 9, $6ED9EBA1);
        R2(C, D, A, B, XX4, 11, $6ED9EBA1);
        R2(B, C, D, A, XX12, 15, $6ED9EBA1);
        R2(A, B, C, D, XX2, 3, $6ED9EBA1);
        R2(D, A, B, C, XX10, 9, $6ED9EBA1);
        R2(C, D, A, B, XX6, 11, $6ED9EBA1);
        R2(B, C, D, A, XX14, 15, $6ED9EBA1);
        R2(A, B, C, D, XX1, 3, $6ED9EBA1);
        R2(D, A, B, C, XX9, 9, $6ED9EBA1);
        R2(C, D, A, B, XX5, 11, $6ED9EBA1);
        R2(B, C, D, A, XX13, 15, $6ED9EBA1);
        R2(A, B, C, D, XX3, 3, $6ED9EBA1);
        R2(D, A, B, C, XX11, 9, $6ED9EBA1);
        R2(C, D, A, B, XX7, 11, $6ED9EBA1);
        R2(B, C, D, A, XX15, 15, $6ED9EBA1);
        _c.A  := _c.A + A;
        A := _c.A;
        _c.B  := _c.B + B;
        B := _c.B;
        _c.C  := _c.C + C;
        C := _c.C;
        _c.D  := _c.D + D;
        D := _c.D;
    end;
end;

function _MD4_Init( c : PMD4_CTX):integer;
begin
    memset(c, 0, sizeof( c^));
    c.A := INIT_DATA_A;
    c.B := INIT_DATA_B;
    c.C := INIT_DATA_C;
    c.D := INIT_DATA_D;
    Result := 1;
end;

end.
