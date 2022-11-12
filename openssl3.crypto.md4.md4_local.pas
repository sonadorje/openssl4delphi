unit openssl3.crypto.md4.md4_local;

interface
uses OpenSSL.Api;


procedure HASH_MAKE_STRING(c: PMD4_CTX; s: PByte);
procedure R0(var a: UInt32; b,c,d,k: UInt32; s,t: Byte);
procedure R1(var a: UInt32; b,c,d,k: UInt32; s: Byte; t: long);
procedure R2(var a: UInt32; b,c,d,k: UInt32; s: Byte; t: long);


implementation
uses openssl3.crypto.mem,                   openssl3.crypto.md4.md4_dgst;




function ROTATE(a,n: uint32):uint32;
begin
   Result :=(((a) shl (n)) or (((a) and $ffffffff) shr (32-(n))));
end;

function F(b,c,d :uint32): UInt32;
begin
   Result :=  ((((c) xor (d)) and (b)) xor (d))
end;

function G(b,c,d :uint32): UInt32;
begin
   Result := (((b) and (c)) or ((b) and (d)) or ((c) and (d)))
end;

function H(b,c,d :uint32): UInt32;
begin
  Result :=  ((b) xor (c) xor (d))
end;

procedure R0(var a: UInt32; b,c,d,k: UInt32; s,t: Byte);
begin
    a := a +((k)+(t)+F((b),(c),(d)));
    a := ROTATE(a,s);
end;

procedure R1(var a: UInt32; b,c,d,k: UInt32; s: Byte; t: long);
begin
    a := a + ((k)+(t)+G((b),(c),(d)));
    a := ROTATE(a,s);
end;

procedure R2(var a: UInt32; b,c,d,k: UInt32; s: Byte; t: long);
begin
    a := a +((k)+(t)+H((b),(c),(d)));
    a := ROTATE(a,s);
end;

function HOST_l2c( l : uint32; c : PByte):uint32;
begin
   PostInc(c)^ :=Byte((l shr 24)  and $ff);
   PostInc(c)^ :=Byte((l shr 16)  and $ff);
   PostInc(c)^ :=Byte((l shr  8)  and $ff);
   PostInc(c)^ :=Byte((l    )  and $ff);
   Result := l;
end;

procedure HASH_MAKE_STRING(c: PMD4_CTX; s: PByte) ;
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
end.
