unit openssl3.crypto.ripemd.rmd_local;

interface
uses OpenSSL.Api;


const
 RIPEMD160_A     = $67452301;
 RIPEMD160_B     = $EFCDAB89;
 RIPEMD160_C     = $98BADCFE;
 RIPEMD160_D     = $10325476;
 RIPEMD160_E     = $C3D2E1F0;
  KL0 = $00000000;
  KL1 = $5A827999;
  KL2 = $6ED9EBA1;
  KL3 = $8F1BBCDC;
  KL4 = $A953FD4E;
  KR0 = $50A28BE6;
  KR1 = $5C4DD124;
  KR2 = $6D703EF3;
  KR3 = $7A6D76E9;
  KR4 = $00000000;
  WL00 = 0;
  SL00 = 11;
  WL01 = 1;
  SL01 = 14;
  WL02 = 2;
  SL02 = 15;
  WL03 = 3;
  SL03 = 12;
  WL04 = 4;
  SL04 = 5;
  WL05 = 5;
  SL05 = 8;
  WL06 = 6;
  SL06 = 7;
  WL07 = 7;
  SL07 = 9;
  WL08 = 8;
  SL08 = 11;
  WL09 = 9;
  SL09 = 13;
  WL10 = 10;
  SL10 = 14;
  WL11 = 11;
  SL11 = 15;
  WL12 = 12;
  SL12 = 6;
  WL13 = 13;
  SL13 = 7;
  WL14 = 14;
  SL14 = 9;
  WL15 = 15;
  SL15 = 8;
  WL16 = 7;
  SL16 = 7;
  WL17 = 4;
  SL17 = 6;
  WL18 = 13;
  SL18 = 8;
  WL19 = 1;
  SL19 = 13;
  WL20 = 10;
  SL20 = 11;
  WL21 = 6;
  SL21 = 9;
  WL22 = 15;
  SL22 = 7;
  WL23 = 3;
  SL23 = 15;
  WL24 = 12;
  SL24 = 7;
  WL25 = 0;
  SL25 = 12;
  WL26 = 9;
  SL26 = 15;
  WL27 = 5;
  SL27 = 9;
  WL28 = 2;
  SL28 = 11;
  WL29 = 14;
  SL29 = 7;
  WL30 = 11;
  SL30 = 13;
  WL31 = 8;
  SL31 = 12;
  WL32 = 3;
  SL32 = 11;
  WL33 = 10;
  SL33 = 13;
  WL34 = 14;
  SL34 = 6;
  WL35 = 4;
  SL35 = 7;
  WL36 = 9;
  SL36 = 14;
  WL37 = 15;
  SL37 = 9;
  WL38 = 8;
  SL38 = 13;
  WL39 = 1;
  SL39 = 15;
  WL40 = 2;
  SL40 = 14;
  WL41 = 7;
  SL41 = 8;
  WL42 = 0;
  SL42 = 13;
  WL43 = 6;
  SL43 = 6;
  WL44 = 13;
  SL44 = 5;
  WL45 = 11;
  SL45 = 12;
  WL46 = 5;
  SL46 = 7;
  WL47 = 12;
  SL47 = 5;
  WL48 = 1;
  SL48 = 11;
  WL49 = 9;
  SL49 = 12;
  WL50 = 11;
  SL50 = 14;
  WL51 = 10;
  SL51 = 15;
  WL52 = 0;
  SL52 = 14;
  WL53 = 8;
  SL53 = 15;
  WL54 = 12;
  SL54 = 9;
  WL55 = 4;
  SL55 = 8;
  WL56 = 13;
  SL56 = 9;
  WL57 = 3;
  SL57 = 14;
  WL58 = 7;
  SL58 = 5;
  WL59 = 15;
  SL59 = 6;
  WL60 = 14;
  SL60 = 8;
  WL61 = 5;
  SL61 = 6;
  WL62 = 6;
  SL62 = 5;
  WL63 = 2;
  SL63 = 12;
  WL64 = 4;
  SL64 = 9;
  WL65 = 0;
  SL65 = 15;
  WL66 = 5;
  SL66 = 5;
  WL67 = 9;
  SL67 = 11;
  WL68 = 7;
  SL68 = 6;
  WL69 = 12;
  SL69 = 8;
  WL70 = 2;
  SL70 = 13;
  WL71 = 10;
  SL71 = 12;
  WL72 = 14;
  SL72 = 5;
  WL73 = 1;
  SL73 = 12;
  WL74 = 3;
  SL74 = 13;
  WL75 = 8;
  SL75 = 14;
  WL76 = 11;
  SL76 = 11;
  WL77 = 6;
  SL77 = 8;
  WL78 = 15;
  SL78 = 5;
  WL79 = 13;
  SL79 = 6;
  WR00 = 5;
  SR00 = 8;
  WR01 = 14;
  SR01 = 9;
  WR02 = 7;
  SR02 = 9;
  WR03 = 0;
  SR03 = 11;
  WR04 = 9;
  SR04 = 13;
  WR05 = 2;
  SR05 = 15;
  WR06 = 11;
  SR06 = 15;
  WR07 = 4;
  SR07 = 5;
  WR08 = 13;
  SR08 = 7;
  WR09 = 6;
  SR09 = 7;
  WR10 = 15;
  SR10 = 8;
  WR11 = 8;
  SR11 = 11;
  WR12 = 1;
  SR12 = 14;
  WR13 = 10;
  SR13 = 14;
  WR14 = 3;
  SR14 = 12;
  WR15 = 12;
  SR15 = 6;
  WR16 = 6;
  SR16 = 9;
  WR17 = 11;
  SR17 = 13;
  WR18 = 3;
  SR18 = 15;
  WR19 = 7;
  SR19 = 7;
  WR20 = 0;
  SR20 = 12;
  WR21 = 13;
  SR21 = 8;
  WR22 = 5;
  SR22 = 9;
  WR23 = 10;
  SR23 = 11;
  WR24 = 14;
  SR24 = 7;
  WR25 = 15;
  SR25 = 7;
  WR26 = 8;
  SR26 = 12;
  WR27 = 12;
  SR27 = 7;
  WR28 = 4;
  SR28 = 6;
  WR29 = 9;
  SR29 = 15;
  WR30 = 1;
  SR30 = 13;
  WR31 = 2;
  SR31 = 11;
  WR32 = 15;
  SR32 = 9;
  WR33 = 5;
  SR33 = 7;
  WR34 = 1;
  SR34 = 15;
  WR35 = 3;
  SR35 = 11;
  WR36 = 7;
  SR36 = 8;
  WR37 = 14;
  SR37 = 6;
  WR38 = 6;
  SR38 = 6;
  WR39 = 9;
  SR39 = 14;
  WR40 = 11;
  SR40 = 12;
  WR41 = 8;
  SR41 = 13;
  WR42 = 12;
  SR42 = 5;
  WR43 = 2;
  SR43 = 14;
  WR44 = 10;
  SR44 = 13;
  WR45 = 0;
  SR45 = 13;
  WR46 = 4;
  SR46 = 7;
  WR47 = 13;
  SR47 = 5;
  WR48 = 8;
  SR48 = 15;
  WR49 = 6;
  SR49 = 5;
  WR50 = 4;
  SR50 = 8;
  WR51 = 1;
  SR51 = 11;
  WR52 = 3;
  SR52 = 14;
  WR53 = 11;
  SR53 = 14;
  WR54 = 15;
  SR54 = 6;
  WR55 = 0;
  SR55 = 14;
  WR56 = 5;
  SR56 = 6;
  WR57 = 12;
  SR57 = 9;
  WR58 = 2;
  SR58 = 12;
  WR59 = 13;
  SR59 = 9;
  WR60 = 9;
  SR60 = 12;
  WR61 = 7;
  SR61 = 5;
  WR62 = 10;
  SR62 = 15;
  WR63 = 14;
  SR63 = 8;
  WR64 = 12;
  SR64 = 8;
  WR65 = 15;
  SR65 = 5;
  WR66 = 10;
  SR66 = 12;
  WR67 = 4;
  SR67 = 9;
  WR68 = 1;
  SR68 = 12;
  WR69 = 5;
  SR69 = 5;
  WR70 = 8;
  SR70 = 14;
  WR71 = 7;
  SR71 = 6;
  WR72 = 6;
  SR72 = 8;
  WR73 = 2;
  SR73 = 13;
  WR74 = 13;
  SR74 = 6;
  WR75 = 14;
  SR75 = 5;
  WR76 = 0;
  SR76 = 15;
  WR77 = 3;
  SR77 = 13;
  WR78 = 9;
  SR78 = 11;
  WR79 = 11;
  SR79 = 11;

 var
    { See comment in crypto/sha/sha_local.h for details. }
     XX0, XX1, XX2, XX3, XX4, XX5, XX6, XX7,
     XX8, XX9, XX10, XX11, XX12, XX13, XX14, XX15: uint32;

 procedure HASH_MAKE_STRING(c : PRIPEMD160_CTX;s: PByte);
 procedure RIP1(var a: uint32; b: uint32; var c: uint32; d,e: uint32; w,s: Byte);
 procedure RIP2(var a: uint32; b: uint32; var c: uint32; d,e: uint32; w,s: Byte; K: uint32);
 procedure RIP3(var a: uint32; b: uint32; var c: uint32; d,e: uint32;w,s: Byte; K: uint32);
 procedure RIP4(var a: uint32; b: uint32; var c: uint32; d,e: uint32;w,s: Byte; K: uint32);
 procedure RIP5(var a: uint32; b: uint32; var c: uint32; d,e: uint32;w,s: Byte; K: uint32);

implementation

function X(w: Byte): UInt32;
begin
   case w of
     0 :Result := XX0;
     1: Result := XX1;
     2: Result := XX2;
     3: Result := XX3;
     4: Result := XX4;
     5: Result := XX5;
     6: Result := XX6;
     7: Result := XX7;
     8: Result := XX8;
     9: Result := XX9;
     10: Result := XX10;
     11: Result := XX11;
     12: Result := XX12;
     13: Result := XX13;
     14: Result := XX14;
     15: Result := XX15;
   end;
end;

function ROTATE(a,n: uint32):uint32;
begin
   Result :=(((a) shl (n)) or (((a)and $ffffffff) shr (32-(n))));
end;

function F1(x,y,z: uint32): uint32;
begin
  Result:= ((x) xor (y) xor (z))
end;

function F2(x,y,z: uint32): uint32;
begin
  Result := ((((y) xor (z)) and (x)) xor (z))
end;

function F3(x,y,z: uint32): uint32;
begin
   Result:= (((not (y)) or (x)) xor (z))
end;

function F4(x,y,z: uint32): uint32;
begin
   Result:=  ((((x) xor (y)) and (z)) xor (y))
end;

function F5(x,y,z: uint32): uint32;
begin
   Result:=  (((not (z)) or (y)) xor (x))
end;

procedure RIP1(var a: uint32; b: uint32; var c: uint32; d,e: uint32; w,s: Byte);
begin
    a := a + (F1(b,c,d)+X(w));
    a := ROTATE(a,s)+e;
    c := ROTATE(c,10);
end;

procedure RIP2(var a: uint32; b: uint32; var c: uint32; d,e: uint32;w,s: Byte; K: uint32);
begin
    a := a + (F2(b,c,d)+X(w)+K);
    a := ROTATE(a,s)+e;
    c := ROTATE(c,10);
end;

procedure RIP3(var a: uint32; b: uint32; var c: uint32; d,e: uint32;w,s: Byte; K: uint32);
begin
    a := a + (F3(b,c,d)+X(w)+K);
    a := ROTATE(a,s)+e;
    c := ROTATE(c,10);
end;

procedure RIP4(var a: uint32; b: uint32; var c: uint32; d,e: uint32;w,s: Byte; K: uint32);
begin
    a := a + (F4(b,c,d)+X(w)+K);
    a := ROTATE(a,s)+e;
    c := ROTATE(c,10);
end;

procedure RIP5(var a: uint32; b: uint32; var c: uint32; d,e: uint32;w,s: Byte; K: uint32);
begin
    a := a + (F5(b,c,d)+X(w)+K);
    a := ROTATE(a,s)+e;
    c := ROTATE(c,10);
end;

function HOST_l2c( l : uint32; c : PByte):uint32;
begin
   PostInc(c)^ :=Byte((l shr 24)  and $ff);
   PostInc(c)^ :=Byte((l shr 16)  and $ff);
   PostInc(c)^ :=Byte((l shr  8)  and $ff);
   PostInc(c)^ :=Byte((l    )     and $ff);
   Result := l;
end;

procedure HASH_MAKE_STRING(c : PRIPEMD160_CTX;s: PByte);
var
  ll : uint32;
begin
    ll := c.A;
    HOST_l2c(ll,s);
    ll := c.B;
    HOST_l2c(ll,s);
    ll := c.C;
    HOST_l2c(ll,s);
    ll := c.D;
    HOST_l2c(ll,s);
    ll := c.E;
    HOST_l2c(ll,s);
end;

end.
