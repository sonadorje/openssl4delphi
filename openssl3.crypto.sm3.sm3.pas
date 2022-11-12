unit openssl3.crypto.sm3.sm3;

interface
uses OpenSSL.Api;

const
 SM3_A = $7380166f;
 SM3_B = $4914b2b9;
 SM3_C = $172442d7;
 SM3_D = $da8a0600;
 SM3_E = $a96f30bc;
 SM3_F = $163138aa;
 SM3_G = $e38dee4d;
 SM3_H = $b0fb0e4e;

function ossl_sm3_update(c : PSM3_CTX;const data_ : Pointer; len : size_t):integer;
function ossl_sm3_final( md : PByte; c : PSM3_CTX):integer;
procedure ossl_sm3_block_data_order(ctx : PSM3_CTX;const p : Pointer; num : size_t);
function ossl_sm3_init( c : PSM3_CTX):integer;

implementation

uses openssl3.include.crypto.md32_common, openssl3.crypto.mem;


type
  Tfun = function(X,Y,Z: UInt32): UInt32;

  //sm3_local.h
procedure HASH_MAKE_STRING(c : PSM3_CTX;s: PByte);
var
  ll : Cardinal;
begin
        ll := (c).A;
    HOST_l2c(ll, (s));
        ll := (c).B;
    HOST_l2c(ll, (s));
        ll := (c).C;
    HOST_l2c(ll, (s));
        ll := (c).D;
    HOST_l2c(ll, (s));
        ll := (c).E;
    HOST_l2c(ll, (s));
        ll := (c).F;
    HOST_l2c(ll, (s));
        ll := (c).G;
    HOST_l2c(ll, (s));
        ll := (c).H;
    HOST_l2c(ll, (s));
end;

function ossl_sm3_final( md : PByte; c : PSM3_CTX):integer;
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
        ossl_sm3_block_data_order(c, p, 1);
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
    ossl_sm3_block_data_order(c, p, 1);
    c.num := 0;
    OPENSSL_cleanse(p, 64);
    HASH_MAKE_STRING(c, md);
    Result := 1;
end;



function ossl_sm3_init( c : PSM3_CTX):integer;
begin
    memset(c, 0, sizeof( c^));
    c.A := SM3_A;
    c.B := SM3_B;
    c.C := SM3_C;
    c.D := SM3_D;
    c.E := SM3_E;
    c.F := SM3_F;
    c.G := SM3_G;
    c.H := SM3_H;
    Result := 1;
end;

function P0(X: UInt32): UInt32;
begin
   Result := (X xor ROTATE(X, 9) xor ROTATE(X, 17))
end;

function P1(X: UInt32): UInt32;
begin
  Result := (X xor ROTATE(X, 15) xor ROTATE(X, 23))
end;
function FF0(X,Y,Z: UInt32): UInt32;
begin
   Result := (X xor Y xor Z)
end;
function GG0(X,Y,Z: UInt32): UInt32;
begin
  Result := (X xor Y xor Z)
end;
function FF1(X,Y,Z: UInt32): UInt32;
begin
   Result := ((X and Y) or ((X xor Y) and Z))
end;
function GG1(X,Y,Z: UInt32): UInt32;
begin
   Result := ((Z xor (X and (Y xor Z))))
end;



procedure RND(var A, B, C, D, E, F, G, H, TJ, Wi, Wj: uint32; FF, GG:Tfun );
var
  A12, A12_SM, SS1, TT1, TT2 : SM3_WORD;
begin
        A12 := ROTATE(A, 12);
        A12_SM := A12 + E + TJ;
        SS1 := ROTATE(A12_SM, 7);
        TT1 := FF(A, B, C) + D + (SS1  xor  A12) + (Wj);
        TT2 := GG(E, F, G) + H + SS1 + Wi;
       B := ROTATE(B, 9);
       D := TT1;
       F := ROTATE(F, 19);
       H := P0(TT2);
end;

procedure R1(A,B,C,D,E,F,G,H,TJ,Wi,Wj: uint32);
begin
   RND(A,B,C,D,E,F,G,H,TJ,Wi,Wj,FF0,GG0)
end;

procedure R2(A,B,C,D,E,F,G,H,TJ,Wi,Wj: uint32);
begin
   RND(A,B,C,D,E,F,G,H,TJ,Wi,Wj,FF1,GG1)
end;

function EXPAND(W0,W7,W13,W3,W10: uint32): uint32;
begin
   Result := (P1(W0 xor W7 xor ROTATE(W13, 15)) xor ROTATE(W3, 7) xor W10)
end;

procedure ossl_sm3_block_data_order(ctx : PSM3_CTX;const p : Pointer; num : size_t);
var
  data : PByte;

  A, B, C, D, E, F, G, H : uint32;
  W00, W01, W02, W03, W04, W05, W06, W07,
  W08, W09, W10, W11, W12, W13, W14, W15: uint32;
begin
    data := p;

    while PostDec(num)>0 do
    begin
        A := ctx.A;
        B := ctx.B;
        C := ctx.C;
        D := ctx.D;
        E := ctx.E;
        F := ctx.F;
        G := ctx.G;
        H := ctx.H;
        {
        * We have to load all message bytes immediately since SM3 reads
        * them slightly out of order.
        }
        HOST_c2l(data, W00);
        HOST_c2l(data, W01);
        HOST_c2l(data, W02);
        HOST_c2l(data, W03);
        HOST_c2l(data, W04);
        HOST_c2l(data, W05);
        HOST_c2l(data, W06);
        HOST_c2l(data, W07);
        HOST_c2l(data, W08);
        HOST_c2l(data, W09);
        HOST_c2l(data, W10);
        HOST_c2l(data, W11);
        HOST_c2l(data, W12);
        HOST_c2l(data, W13);
        HOST_c2l(data, W14);
        HOST_c2l(data, W15);
        R1(A, B, C, D, E, F, G, H, $79CC4519, W00, W00  xor  W04);
        W00 := EXPAND(W00, W07, W13, W03, W10);
        R1(D, A, B, C, H, E, F, G, $F3988A32, W01, W01  xor  W05);
        W01 := EXPAND(W01, W08, W14, W04, W11);
        R1(C, D, A, B, G, H, E, F, $E7311465, W02, W02  xor  W06);
        W02 := EXPAND(W02, W09, W15, W05, W12);
        R1(B, C, D, A, F, G, H, E, $CE6228CB, W03, W03  xor  W07);
        W03 := EXPAND(W03, W10, W00, W06, W13);
        R1(A, B, C, D, E, F, G, H, $9CC45197, W04, W04  xor  W08);
        W04 := EXPAND(W04, W11, W01, W07, W14);
        R1(D, A, B, C, H, E, F, G, $3988A32F, W05, W05  xor  W09);
        W05 := EXPAND(W05, W12, W02, W08, W15);
        R1(C, D, A, B, G, H, E, F, $7311465E, W06, W06  xor  W10);
        W06 := EXPAND(W06, W13, W03, W09, W00);
        R1(B, C, D, A, F, G, H, E, $E6228CBC, W07, W07  xor  W11);
        W07 := EXPAND(W07, W14, W04, W10, W01);
        R1(A, B, C, D, E, F, G, H, $CC451979, W08, W08  xor  W12);
        W08 := EXPAND(W08, W15, W05, W11, W02);
        R1(D, A, B, C, H, E, F, G, $988A32F3, W09, W09  xor  W13);
        W09 := EXPAND(W09, W00, W06, W12, W03);
        R1(C, D, A, B, G, H, E, F, $311465E7, W10, W10  xor  W14);
        W10 := EXPAND(W10, W01, W07, W13, W04);
        R1(B, C, D, A, F, G, H, E, $6228CBCE, W11, W11  xor  W15);
        W11 := EXPAND(W11, W02, W08, W14, W05);
        R1(A, B, C, D, E, F, G, H, $C451979C, W12, W12  xor  W00);
        W12 := EXPAND(W12, W03, W09, W15, W06);
        R1(D, A, B, C, H, E, F, G, $88A32F39, W13, W13  xor  W01);
        W13 := EXPAND(W13, W04, W10, W00, W07);
        R1(C, D, A, B, G, H, E, F, $11465E73, W14, W14  xor  W02);
        W14 := EXPAND(W14, W05, W11, W01, W08);
        R1(B, C, D, A, F, G, H, E, $228CBCE6, W15, W15  xor  W03);
        W15 := EXPAND(W15, W06, W12, W02, W09);
        R2(A, B, C, D, E, F, G, H, $9D8A7A87, W00, W00  xor  W04);
        W00 := EXPAND(W00, W07, W13, W03, W10);
        R2(D, A, B, C, H, E, F, G, $3B14F50F, W01, W01  xor  W05);
        W01 := EXPAND(W01, W08, W14, W04, W11);
        R2(C, D, A, B, G, H, E, F, $7629EA1E, W02, W02  xor  W06);
        W02 := EXPAND(W02, W09, W15, W05, W12);
        R2(B, C, D, A, F, G, H, E, $EC53D43C, W03, W03  xor  W07);
        W03 := EXPAND(W03, W10, W00, W06, W13);
        R2(A, B, C, D, E, F, G, H, $D8A7A879, W04, W04  xor  W08);
        W04 := EXPAND(W04, W11, W01, W07, W14);
        R2(D, A, B, C, H, E, F, G, $B14F50F3, W05, W05  xor  W09);
        W05 := EXPAND(W05, W12, W02, W08, W15);
        R2(C, D, A, B, G, H, E, F, $629EA1E7, W06, W06  xor  W10);
        W06 := EXPAND(W06, W13, W03, W09, W00);
        R2(B, C, D, A, F, G, H, E, $C53D43CE, W07, W07  xor  W11);
        W07 := EXPAND(W07, W14, W04, W10, W01);
        R2(A, B, C, D, E, F, G, H, $8A7A879D, W08, W08  xor  W12);
        W08 := EXPAND(W08, W15, W05, W11, W02);
        R2(D, A, B, C, H, E, F, G, $14F50F3B, W09, W09  xor  W13);
        W09 := EXPAND(W09, W00, W06, W12, W03);
        R2(C, D, A, B, G, H, E, F, $29EA1E76, W10, W10  xor  W14);
        W10 := EXPAND(W10, W01, W07, W13, W04);
        R2(B, C, D, A, F, G, H, E, $53D43CEC, W11, W11  xor  W15);
        W11 := EXPAND(W11, W02, W08, W14, W05);
        R2(A, B, C, D, E, F, G, H, $A7A879D8, W12, W12  xor  W00);
        W12 := EXPAND(W12, W03, W09, W15, W06);
        R2(D, A, B, C, H, E, F, G, $4F50F3B1, W13, W13  xor  W01);
        W13 := EXPAND(W13, W04, W10, W00, W07);
        R2(C, D, A, B, G, H, E, F, $9EA1E762, W14, W14  xor  W02);
        W14 := EXPAND(W14, W05, W11, W01, W08);
        R2(B, C, D, A, F, G, H, E, $3D43CEC5, W15, W15  xor  W03);
        W15 := EXPAND(W15, W06, W12, W02, W09);
        R2(A, B, C, D, E, F, G, H, $7A879D8A, W00, W00  xor  W04);
        W00 := EXPAND(W00, W07, W13, W03, W10);
        R2(D, A, B, C, H, E, F, G, $F50F3B14, W01, W01  xor  W05);
        W01 := EXPAND(W01, W08, W14, W04, W11);
        R2(C, D, A, B, G, H, E, F, $EA1E7629, W02, W02  xor  W06);
        W02 := EXPAND(W02, W09, W15, W05, W12);
        R2(B, C, D, A, F, G, H, E, $D43CEC53, W03, W03  xor  W07);
        W03 := EXPAND(W03, W10, W00, W06, W13);
        R2(A, B, C, D, E, F, G, H, $A879D8A7, W04, W04  xor  W08);
        W04 := EXPAND(W04, W11, W01, W07, W14);
        R2(D, A, B, C, H, E, F, G, $50F3B14F, W05, W05  xor  W09);
        W05 := EXPAND(W05, W12, W02, W08, W15);
        R2(C, D, A, B, G, H, E, F, $A1E7629E, W06, W06  xor  W10);
        W06 := EXPAND(W06, W13, W03, W09, W00);
        R2(B, C, D, A, F, G, H, E, $43CEC53D, W07, W07  xor  W11);
        W07 := EXPAND(W07, W14, W04, W10, W01);
        R2(A, B, C, D, E, F, G, H, $879D8A7A, W08, W08  xor  W12);
        W08 := EXPAND(W08, W15, W05, W11, W02);
        R2(D, A, B, C, H, E, F, G, $0F3B14F5, W09, W09  xor  W13);
        W09 := EXPAND(W09, W00, W06, W12, W03);
        R2(C, D, A, B, G, H, E, F, $1E7629EA, W10, W10  xor  W14);
        W10 := EXPAND(W10, W01, W07, W13, W04);
        R2(B, C, D, A, F, G, H, E, $3CEC53D4, W11, W11  xor  W15);
        W11 := EXPAND(W11, W02, W08, W14, W05);
        R2(A, B, C, D, E, F, G, H, $79D8A7A8, W12, W12  xor  W00);
        W12 := EXPAND(W12, W03, W09, W15, W06);
        R2(D, A, B, C, H, E, F, G, $F3B14F50, W13, W13  xor  W01);
        W13 := EXPAND(W13, W04, W10, W00, W07);
        R2(C, D, A, B, G, H, E, F, $E7629EA1, W14, W14  xor  W02);
        W14 := EXPAND(W14, W05, W11, W01, W08);
        R2(B, C, D, A, F, G, H, E, $CEC53D43, W15, W15  xor  W03);
        W15 := EXPAND(W15, W06, W12, W02, W09);
        R2(A, B, C, D, E, F, G, H, $9D8A7A87, W00, W00  xor  W04);
        W00 := EXPAND(W00, W07, W13, W03, W10);
        R2(D, A, B, C, H, E, F, G, $3B14F50F, W01, W01  xor  W05);
        W01 := EXPAND(W01, W08, W14, W04, W11);
        R2(C, D, A, B, G, H, E, F, $7629EA1E, W02, W02  xor  W06);
        W02 := EXPAND(W02, W09, W15, W05, W12);
        R2(B, C, D, A, F, G, H, E, $EC53D43C, W03, W03  xor  W07);
        W03 := EXPAND(W03, W10, W00, W06, W13);
        R2(A, B, C, D, E, F, G, H, $D8A7A879, W04, W04  xor  W08);
        R2(D, A, B, C, H, E, F, G, $B14F50F3, W05, W05  xor  W09);
        R2(C, D, A, B, G, H, E, F, $629EA1E7, W06, W06  xor  W10);
        R2(B, C, D, A, F, G, H, E, $C53D43CE, W07, W07  xor  W11);
        R2(A, B, C, D, E, F, G, H, $8A7A879D, W08, W08  xor  W12);
        R2(D, A, B, C, H, E, F, G, $14F50F3B, W09, W09  xor  W13);
        R2(C, D, A, B, G, H, E, F, $29EA1E76, W10, W10  xor  W14);
        R2(B, C, D, A, F, G, H, E, $53D43CEC, W11, W11  xor  W15);
        R2(A, B, C, D, E, F, G, H, $A7A879D8, W12, W12  xor  W00);
        R2(D, A, B, C, H, E, F, G, $4F50F3B1, W13, W13  xor  W01);
        R2(C, D, A, B, G, H, E, F, $9EA1E762, W14, W14  xor  W02);
        R2(B, C, D, A, F, G, H, E, $3D43CEC5, W15, W15  xor  W03);
        ctx.A  := ctx.A xor A;
        ctx.B  := ctx.B xor B;
        ctx.C  := ctx.C xor C;
        ctx.D  := ctx.D xor D;
        ctx.E  := ctx.E xor E;
        ctx.F  := ctx.F xor F;
        ctx.G  := ctx.G xor G;
        ctx.H  := ctx.H xor H;
    end;
end;


function ossl_sm3_update(c : PSM3_CTX;const data_ : Pointer; len : size_t):integer;
var
  data, p : PByte;

  l : uint32;

  n : size_t;
begin
     data := data_;
    if len = 0 then Exit(1);
    l := (c.Nl + ((uint32(  len)  shl  3))) and $ffffffff;
    if l < c.Nl then
      Inc(c.Nh);
    c.Nh  := c.Nh + (uint32(len  shr  29));
    c.Nl := l;
    n := c.num;
    if n <> 0 then
    begin
        p := PByte(@ c.data);
        if (len >= 64)  or  (len + n >= 64) then
        begin
            memcpy(p + n, data, 64 - n);
            ossl_sm3_block_data_order(c, p, 1);
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
        ossl_sm3_block_data_order(c, data, n);
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

end.
