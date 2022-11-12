unit openssl3.crypto.sha.sha_local;

{sha_local.h
#define HASH_UPDATE                     SHA1_Update
#define HASH_TRANSFORM                  SHA1_Transform
#define HASH_FINAL                      SHA1_Final
#define HASH_INIT                       SHA1_Init
#define HASH_BLOCK_DATA_ORDER           sha1_block_data_order
}
interface
uses OpenSSL.Api;

const
   K_00_19 =$5a827999;
   K_20_39 =$6ed9eba1;
   K_40_59 =$8f1bbcdc;
   K_60_79 =$ca62c1d6;

    INIT_DATA_h0  = $67452301;
 INIT_DATA_h1  = $efcdab89;
 INIT_DATA_h2  = $98badcfe;
 INIT_DATA_h3  = $10325476;
 INIT_DATA_h4  = $c3d2e1f0;

procedure HASH_BLOCK_DATA_ORDER(c0 : PSHA_CTX;const p : Pointer; num : size_t);
function  F_00_19(b,c,d: uint32): uint32;
procedure Xupdate( var a, ix: uint32; ia, ib, ic, id : uint32);
procedure BODY_20_31(i,a: UInt32; var b: Uint32;c,d,e: UInt32; var f: UInt32; xi,xa,xb,xc,xd: uint32);
function F_20_39(b,c,d: uint32): uint32;
procedure BODY_32_39(i,a:uint32;var b:uint32; c,d,e:uint32; var f:uint32;xa,xb,xc,xd:uint32);
procedure BODY_40_59(i,a:uint32;var b:uint32;c,d,e:uint32;var f:uint32;xa,xb,xc,xd:uint32);
function F_40_59(b,c,d: uint32): uint32;
function  F_60_79(b,c,d:uint32):uint32;
procedure BODY_60_79(i,a:uint32;var b:uint32;c,d,e:uint32;var f:uint32;xa,xb,xc,xd:uint32);

procedure HASH_MAKE_STRING(c : PHASH_CTX; s : PByte);
//function _SHA1_FINAL( md : PByte; c : PHASH_CTX):integer;
function HASH_INIT( c : PSHA_CTX):integer;


//#define HASH_BLOCK_DATA_ORDER           sha1_block_data_order
const
   sha1_block_data_order:procedure(c0 : PSHA_CTX;const p : Pointer; num : size_t) = HASH_BLOCK_DATA_ORDER;

  _SHA1_Init: function( c : PSHA_CTX):integer = HASH_INIT;

implementation

{$OVERFLOWCHECKS OFF}
function HASH_INIT( c : PSHA_CTX):integer;
begin
    memset(c, 0, sizeof( c^));
    c.h0 := INIT_DATA_h0;
    c.h1 := INIT_DATA_h1;
    c.h2 := INIT_DATA_h2;
    c.h3 := INIT_DATA_h3;
    c.h4 := INIT_DATA_h4;
    Result := 1;
end;

procedure HOST_c2l( c : PByte; var l : uint32);
begin
  l := (uint32( PostInc(c)^)) shl 24;
  l := l or ((uint32( PostInc(c)^)) shl 16);
  l := l or ((uint32( PostInc(c)^)) shl  8);
  l := l or ((uint32( PostInc(c)^))    );
end;

function HOST_l2c( l : uint32; c : PByte):uint32;
begin
   PostInc(c)^ :=Byte((l shr 24)  and $ff);
   PostInc(c)^ :=Byte((l shr 16)  and $ff);
   PostInc(c)^ :=Byte((l shr  8)  and $ff);
   PostInc(c)^ :=Byte((l    )  and $ff);
   Result := l;
end;

function ROTATE(a,n: uint32):uint32;
begin
   Result :=(((a) shl (n)) or (((a)and $ffffffff) shr (32-(n))));
end;

procedure HASH_MAKE_STRING(c : PHASH_CTX; s : PByte);
var
  ll : uint32;
begin
    ll := (c).h0;
    HOST_l2c(ll,(s));
    ll := (c).h1;
    HOST_l2c(ll,(s));
    ll := (c).h2;
    HOST_l2c(ll,(s));
    ll := (c).h3;
    HOST_l2c(ll,(s));
    ll := (c).h4;
    HOST_l2c(ll,(s));
end;



function  F_60_79(b,c,d:uint32):uint32;
begin
   Result :=  F_20_39(b,c,d)
end;

procedure BODY_60_79(i,a:uint32;var b:uint32;c,d,e:uint32;var f:uint32;xa,xb,xc,xd:uint32);
begin
  Xupdate(f,xa,xa,xb,xc,xd);
  f := xa+(e)+K_60_79+ROTATE((a),5)+F_60_79((b),(c),(d));
  b := ROTATE((b),30);
end;

procedure BODY_40_59(i,a:uint32;var b:uint32;c,d,e:uint32;var f:uint32;xa,xb,xc,xd:uint32);
begin
    Xupdate(f,xa,xa,xb,xc,xd);
    f := f + (e)+K_40_59+ROTATE((a),5)+F_40_59((b),(c),(d));
    b := ROTATE((b),30);
end;

function F_40_59(b,c,d: uint32): uint32;
begin
   Result :=  (((b) and (c)) or (((b) or (c)) and (d)))
end;

function F_20_39(b,c,d: uint32): uint32;
begin
  Result :=  ((b) xor (c) xor (d))
end;

procedure BODY_32_39(i,a:uint32;var b:uint32; c,d,e:uint32; var f:uint32;xa,xb,xc,xd:uint32);
begin
  Xupdate(f,xa,xa,xb,xc,xd);
  f := f + (e)+K_20_39+ROTATE((a),5)+F_20_39((b),(c),(d));
  b := ROTATE((b),30);
end;

procedure Xupdate( var a, ix: uint32; ia, ib, ic, id :uint32);
begin
    a := (ia xor ib xor ic xor id);
    a := ROTATE((a),1);
    ix := a;
end;

procedure BODY_16_19(i,a: UInt32;var b: UInt32; c,d,e: UInt32;var f: UInt32; xi,xa,xb,xc,xd: uint32);
begin
  Xupdate(f,xi,xa,xb,xc,xd);
  f := f + (e)+K_00_19+ROTATE((a),5)+F_00_19((b),(c),(d));
  b :=ROTATE((b),30);
end;

procedure BODY_20_31(i,a: UInt32; var b: Uint32;c,d,e: UInt32; var f: UInt32; xi,xa,xb,xc,xd: uint32);
begin
  Xupdate(f,xi,xa,xb,xc,xd);
  f := f + (e)+K_20_39+ROTATE((a),5)+F_20_39((b),(c),(d));
  b := ROTATE((b),30);
end;

function  F_00_19(b,c,d: uint32): uint32;
begin
   Result := ((((c) xor (d)) and (b)) xor (d))
end;

procedure BODY_00_15(i,a: uint32; var b: uint32; c,d,e:Uint32; var f: uint32; xi: uint32);
begin
  f := xi+(e) + K_00_19 + ROTATE((a),5) + F_00_19((b),(c),(d));
  b := ROTATE((b),30);
end;

procedure HASH_BLOCK_DATA_ORDER(c0 : PSHA_CTX;const p : Pointer; num : size_t);
var
  data : PByte;
  A, B, C, D, E, T, l : uint32;
{$IFNDEF MD32_XARRAY}
    XX0, XX1, XX2, XX3, XX4, XX5, XX6, XX7,
    XX8, XX9, XX10, XX11, XX12, XX13, XX14, XX15: Uint32 ;
{$ELSE}
   XX : array[0..15] of SHA_LONG;
{$endif}
  W : PSHA_LONG;
  ossl_is_endian: endian_st;
begin
{$POINTERMATH ON}
    ossl_is_endian.one := 1;
    data := p;

    A := c0.h0;
    B := c0.h1;
    C := c0.h2;
    D := c0.h3;
    E := c0.h4;
    while true do
    begin
        //DECLARE_IS_ENDIAN;
        if (not (ossl_is_endian.little <> 0))  and  (sizeof(SHA_LONG) = 4)
             and  (size_t( p) mod 4 = 0) then
        begin
          W := PSHA_LONG(data);
            XX0 := W[0];
            XX1 := W[1];
            BODY_00_15(0, A, B, C, D, E, T, XX0);
            XX2 := W[2];
            BODY_00_15(1, T, A, B, C, D, E, XX1);
            XX3 := W[3];
            BODY_00_15(2, E, T, A, B, C, D, XX2);
            XX4 := W[4];
            BODY_00_15(3, D, E, T, A, B, C, XX3);
            XX5 := W[5];
            BODY_00_15(4, C, D, E, T, A, B, XX4);
            XX6 := W[6];
            BODY_00_15(5, B, C, D, E, T, A, XX5);
            XX7 := W[7];
            BODY_00_15(6, A, B, C, D, E, T, XX6);
            XX8 := W[8];
            BODY_00_15(7, T, A, B, C, D, E, XX7);
            XX9 := W[9];
            BODY_00_15(8, E, T, A, B, C, D, XX8);
            XX10 := W[10];
            BODY_00_15(9, D, E, T, A, B, C, XX9);
            XX11 := W[11];
            BODY_00_15(10, C, D, E, T, A, B, XX10);
            XX12 := W[12];
            BODY_00_15(11, B, C, D, E, T, A, XX11);
            XX13 := W[13];
            BODY_00_15(12, A, B, C, D, E, T, XX12);
            XX14 := W[14];
            BODY_00_15(13, T, A, B, C, D, E, XX13);
            XX15 := W[15];
            BODY_00_15(14, E, T, A, B, C, D, XX14);
            BODY_00_15(15, D, E, T, A, B, C, XX15);
            data  := data + SHA_CBLOCK;
        end
        else
        begin
            HOST_c2l(data, l);
            XX0 := l;
            HOST_c2l(data, l);
            XX1 := l;
            BODY_00_15(0, A, B, C, D, E, T, XX0);
            HOST_c2l(data, l);
            XX2 := l;
            BODY_00_15(1, T, A, B, C, D, E, XX1);
            HOST_c2l(data, l);
            XX3 := l;
            BODY_00_15(2, E, T, A, B, C, D, XX2);
            HOST_c2l(data, l);
            XX4 := l;
            BODY_00_15(3, D, E, T, A, B, C, XX3);
            HOST_c2l(data, l);
            XX5 := l;
            BODY_00_15(4, C, D, E, T, A, B, XX4);
            HOST_c2l(data, l);
            XX6 := l;
            BODY_00_15(5, B, C, D, E, T, A, XX5);
            HOST_c2l(data, l);
            XX7 := l;
            BODY_00_15(6, A, B, C, D, E, T, XX6);
            HOST_c2l(data, l);
            XX8 := l;
            BODY_00_15(7, T, A, B, C, D, E, XX7);
            HOST_c2l(data, l);
            XX9 := l;
            BODY_00_15(8, E, T, A, B, C, D, XX8);
            HOST_c2l(data, l);
            XX10 := l;
            BODY_00_15(9, D, E, T, A, B, C, XX9);
            HOST_c2l(data, l);
            XX11 := l;
            BODY_00_15(10, C, D, E, T, A, B, XX10);
            HOST_c2l(data, l);
            XX12 := l;
            BODY_00_15(11, B, C, D, E, T, A, XX11);
            HOST_c2l(data, l);
            XX13 := l;
            BODY_00_15(12, A, B, C, D, E, T, XX12);
            HOST_c2l(data, l);
            XX14 := l;
            BODY_00_15(13, T, A, B, C, D, E, XX13);
            HOST_c2l(data, l);
            XX15 := l;
            BODY_00_15(14, E, T, A, B, C, D, XX14);
            BODY_00_15(15, D, E, T, A, B, C, XX15);
        end;
        BODY_16_19(16, C, D, E, T, A, B, XX0, XX0, XX2, XX8, XX13);
        BODY_16_19(17, B, C, D, E, T, A, XX1, XX1, XX3, XX9, XX14);
        BODY_16_19(18, A, B, C, D, E, T, XX2, XX2, XX4, XX10, XX15);
        BODY_16_19(19, T, A, B, C, D, E, XX3, XX3, XX5, XX11, XX0);
        BODY_20_31(20, E, T, A, B, C, D, XX4, XX4, XX6, XX12, XX1);
        BODY_20_31(21, D, E, T, A, B, C, XX5, XX5, XX7, XX13, XX2);
        BODY_20_31(22, C, D, E, T, A, B, XX6, XX6, XX8, XX14, XX3);
        BODY_20_31(23, B, C, D, E, T, A, XX7, XX7, XX9, XX15, XX4);
        BODY_20_31(24, A, B, C, D, E, T, XX8, XX8, XX10, XX0, XX5);
        BODY_20_31(25, T, A, B, C, D, E, XX9, XX9, XX11, XX1, XX6);
        BODY_20_31(26, E, T, A, B, C, D, XX10, XX10, XX12, XX2, XX7);
        BODY_20_31(27, D, E, T, A, B, C, XX11, XX11, XX13, XX3, XX8);
        BODY_20_31(28, C, D, E, T, A, B, XX12, XX12, XX14, XX4, XX9);
        BODY_20_31(29, B, C, D, E, T, A, XX13, XX13, XX15, XX5, XX10);
        BODY_20_31(30, A, B, C, D, E, T, XX14, XX14, XX0, XX6, XX11);
        BODY_20_31(31, T, A, B, C, D, E, XX15, XX15, XX1, XX7, XX12);
        BODY_32_39(32, E, T, A, B, C, D, XX0, XX2, XX8, XX13);
        BODY_32_39(33, D, E, T, A, B, C, XX1, XX3, XX9, XX14);
        BODY_32_39(34, C, D, E, T, A, B, XX2, XX4, XX10, XX15);
        BODY_32_39(35, B, C, D, E, T, A, XX3, XX5, XX11, XX0);
        BODY_32_39(36, A, B, C, D, E, T, XX4, XX6, XX12, XX1);
        BODY_32_39(37, T, A, B, C, D, E, XX5, XX7, XX13, XX2);
        BODY_32_39(38, E, T, A, B, C, D, XX6, XX8, XX14, XX3);
        BODY_32_39(39, D, E, T, A, B, C, XX7, XX9, XX15, XX4);
        BODY_40_59(40, C, D, E, T, A, B, XX8, XX10, XX0, XX5);
        BODY_40_59(41, B, C, D, E, T, A, XX9, XX11, XX1, XX6);
        BODY_40_59(42, A, B, C, D, E, T, XX10, XX12, XX2, XX7);
        BODY_40_59(43, T, A, B, C, D, E, XX11, XX13, XX3, XX8);
        BODY_40_59(44, E, T, A, B, C, D, XX12, XX14, XX4, XX9);
        BODY_40_59(45, D, E, T, A, B, C, XX13, XX15, XX5, XX10);
        BODY_40_59(46, C, D, E, T, A, B, XX14, XX0, XX6, XX11);
        BODY_40_59(47, B, C, D, E, T, A, XX15, XX1, XX7, XX12);
        BODY_40_59(48, A, B, C, D, E, T, XX0, XX2, XX8, XX13);
        BODY_40_59(49, T, A, B, C, D, E, XX1, XX3, XX9, XX14);
        BODY_40_59(50, E, T, A, B, C, D, XX2, XX4, XX10, XX15);
        BODY_40_59(51, D, E, T, A, B, C, XX3, XX5, XX11, XX0);
        BODY_40_59(52, C, D, E, T, A, B, XX4, XX6, XX12, XX1);
        BODY_40_59(53, B, C, D, E, T, A, XX5, XX7, XX13, XX2);
        BODY_40_59(54, A, B, C, D, E, T, XX6, XX8, XX14, XX3);
        BODY_40_59(55, T, A, B, C, D, E, XX7, XX9, XX15, XX4);
        BODY_40_59(56, E, T, A, B, C, D, XX8, XX10, XX0, XX5);
        BODY_40_59(57, D, E, T, A, B, C, XX9, XX11, XX1, XX6);
        BODY_40_59(58, C, D, E, T, A, B, XX10, XX12, XX2, XX7);
        BODY_40_59(59, B, C, D, E, T, A, XX11, XX13, XX3, XX8);
        BODY_60_79(60, A, B, C, D, E, T, XX12, XX14, XX4, XX9);
        BODY_60_79(61, T, A, B, C, D, E, XX13, XX15, XX5, XX10);
        BODY_60_79(62, E, T, A, B, C, D, XX14, XX0, XX6, XX11);
        BODY_60_79(63, D, E, T, A, B, C, XX15, XX1, XX7, XX12);
        BODY_60_79(64, C, D, E, T, A, B, XX0, XX2, XX8, XX13);
        BODY_60_79(65, B, C, D, E, T, A, XX1, XX3, XX9, XX14);
        BODY_60_79(66, A, B, C, D, E, T, XX2, XX4, XX10, XX15);
        BODY_60_79(67, T, A, B, C, D, E, XX3, XX5, XX11, XX0);
        BODY_60_79(68, E, T, A, B, C, D, XX4, XX6, XX12, XX1);
        BODY_60_79(69, D, E, T, A, B, C, XX5, XX7, XX13, XX2);
        BODY_60_79(70, C, D, E, T, A, B, XX6, XX8, XX14, XX3);
        BODY_60_79(71, B, C, D, E, T, A, XX7, XX9, XX15, XX4);
        BODY_60_79(72, A, B, C, D, E, T, XX8, XX10, XX0, XX5);
        BODY_60_79(73, T, A, B, C, D, E, XX9, XX11, XX1, XX6);
        BODY_60_79(74, E, T, A, B, C, D, XX10, XX12, XX2, XX7);
        BODY_60_79(75, D, E, T, A, B, C, XX11, XX13, XX3, XX8);
        BODY_60_79(76, C, D, E, T, A, B, XX12, XX14, XX4, XX9);
        BODY_60_79(77, B, C, D, E, T, A, XX13, XX15, XX5, XX10);
        BODY_60_79(78, A, B, C, D, E, T, XX14, XX0, XX6, XX11);
        BODY_60_79(79, T, A, B, C, D, E, XX15, XX1, XX7, XX12);
        c0.h0 := (c0.h0 + E) and $ffffffff;
        c0.h1 := (c0.h1 + T) and $ffffffff;
        c0.h2 := (c0.h2 + A) and $ffffffff;
        c0.h3 := (c0.h3 + B) and $ffffffff;
        c0.h4 := (c0.h4 + C) and $ffffffff;
        if PreDec(num) = 0  then
            break;
        A := c0.h0;
        B := c0.h1;
        C := c0.h2;
        D := c0.h3;
        E := c0.h4;
    end;
 {$POINTERMATH OFF}
end;
{$OVERFLOWCHECKS ON}
end.
