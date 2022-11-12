unit openssl3.crypto.cpuid;

interface
uses OpenSSL.Api;

 procedure OPENSSL_cpuid_setup;
 function CRYPTO_memcmp(const in_a, in_b : Pointer; len : size_t):integer;
  function OPENSSL_rdtsc:uint32;
  function OPENSSL_instrument_bus( &out : Puint32; cnt : size_t):size_t;
  function OPENSSL_instrument_bus2( &out : Puint32; cnt, max : size_t):size_t;

implementation

{$ifndef OPENSSL_CPUID_OBJ}
 {$ifndef OPENSSL_CPUID_SETUP}
procedure OPENSSL_cpuid_setup;
begin

end;
 {$ENDIF}

function CRYPTO_memcmp(const in_a, in_b : Pointer; len : size_t):integer;
var
  i : size_t;

  a, b : PByte;

  x : Byte;
begin
   a := in_a;
   b := in_b;
    x := 0;
    for i := 0 to len-1 do
        x  := x  or (a[i] xor b[i]);
    Result := x;
end;


function OPENSSL_rdtsc:uint32;
begin
    Result := 0;
end;


function OPENSSL_instrument_bus( &out : Puint32; cnt : size_t):size_t;
begin
    Result := 0;
end;


function OPENSSL_instrument_bus2( &out : Puint32; cnt, max : size_t):size_t;
begin
    Result := 0;
end;
{$ENDIF}
end.
