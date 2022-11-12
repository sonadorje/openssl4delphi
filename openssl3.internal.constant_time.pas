unit openssl3.internal.constant_time;

interface
 uses OpenSSL.Api;

function constant_time_is_zero_32( a : uint32):uint32;
function constant_time_msb_32( a : uint32):uint32;
procedure constant_time_cond_swap_32( mask : uint32; a, b : Puint32_t);
procedure constant_time_lookup(&out : Pointer;const table : Pointer; rowsize, numrows, idx : size_t);
function constant_time_is_zero_s( a : size_t):size_t;
function constant_time_msb_s( a : size_t):size_t;
function constant_time_select_8( mask, a, b : Byte):Byte;
function constant_time_select( mask, a, b : uint32):integer;
function value_barrier( a : uint32):uint32;
function constant_time_select_32( mask, a, b : uint32):uint32;
function value_barrier_32( a : uint32):uint32;
function constant_time_eq_int( a, b : integer):uint32;
function constant_time_eq( a, b : uint32):uint32;
function constant_time_is_zero( a : uint32):uint32;
function constant_time_msb( a : uint32):uint32;
function constant_time_is_zero_8( a : uint32):Byte;
function constant_time_select_s( mask, a, b : size_t):size_t;
function value_barrier_s( a : size_t):size_t;
function constant_time_select_int( mask : uint32; a, b : integer):integer;
function constant_time_ge_s( a, b : size_t):size_t;
function constant_time_lt_s( a, b : size_t):size_t;
function constant_time_eq_s( a, b : size_t):size_t;
function constant_time_ge_8_s( a, b : size_t):Byte;
function constant_time_eq_8_s( a, b : size_t):Byte;
function constant_time_ge( a, b : uint32):uint32;
function constant_time_lt( a, b : uint32):uint32;

implementation

{$Q-}
function constant_time_lt( a, b : uint32):uint32;
begin
    Result := constant_time_msb(a  xor  ((a  xor  b) or ((a - b)  xor  b)));
end;

function constant_time_ge( a, b : uint32):uint32;
begin
    Result := not constant_time_lt(a, b);
end;

function constant_time_eq_8_s( a, b : size_t):Byte;
begin
    Result := Byte( constant_time_eq_s(a, b));
end;

function constant_time_ge_8_s( a, b : size_t):Byte;
begin
    Result := Byte( constant_time_ge_s(a, b));
end;

function constant_time_eq_s( a, b : size_t):size_t;
begin
    Result := constant_time_is_zero_s(a  xor  b);
end;

function constant_time_lt_s( a, b : size_t):size_t;
begin
    Result := constant_time_msb_s(a  xor  ((a  xor  b) or ((a - b)  xor  b)));
end;

function constant_time_ge_s( a, b : size_t):size_t;
begin
    Result := not constant_time_lt_s(a, b);
end;

function constant_time_select_int( mask : uint32; a, b : integer):integer;
begin
    Result := int (constant_time_select(mask, uint32(a), uint32(b)));
end;

function value_barrier_s( a : size_t):size_t;
var
  r : size_t;
begin
{$IF not defined(OPENSSL_NO_ASM)  and  defined(__GNUC__)}
    __asm__('" : "=r"(r) : "0'(a));
{$ELSE}
   r := a;
{$ENDIF}
    Result := r;
end;

function constant_time_select_s( mask, a, b : size_t):size_t;
begin
    Result := (value_barrier_s(mask) and a) or (value_barrier_s(not mask) and b);
end;

function constant_time_is_zero_8( a : uint32):Byte;
begin
    Result := Byte( constant_time_is_zero(a));
end;

function constant_time_msb( a : uint32):uint32;
begin
{$Q-}
    Result := 0 - (a  shr  (sizeof(a) * 8 - 1));
{$Q+}
end;

function constant_time_is_zero( a : uint32):uint32;
begin
{$Q-}
    Result := constant_time_msb((not a) and (a - 1));
{$Q+}
end;

function constant_time_eq( a, b : uint32):uint32;
begin
    Result := constant_time_is_zero(a  xor  b);
end;

function constant_time_eq_int( a, b : integer):uint32;
begin
    Result := constant_time_eq(uint32(a), uint32(b));
end;

function value_barrier_32( a : uint32):uint32;
var
  r : uint32;
begin
{$IF not defined(OPENSSL_NO_ASM)  and  defined(__GNUC__)}
    __asm__('" : "=r"(r) : "0'(a));
{$ELSE}
   r := a;
{$ENDIF}
    Result := r;
end;



function constant_time_select_32( mask, a, b : uint32):uint32;
begin
    Result := (value_barrier_32(mask) and a) or (value_barrier_32(not mask) and b);
end;


function value_barrier( a : uint32):uint32;
var
  r : uint32;
begin
{$IF not defined(OPENSSL_NO_ASM)  and  defined(__GNUC__)}
    __asm__('" : "=r"(r) : "0'(a));
{$ELSE}
    r := a;
{$ENDIF}
    Result := r;
end;


function constant_time_select( mask, a, b : uint32):integer;
begin
    Result := (value_barrier(mask) and a) or (value_barrier(not mask) and b);
end;

function constant_time_select_8( mask, a, b : Byte):Byte;
begin
    Result := Byte( constant_time_select(mask, a, b));
end;

function constant_time_msb_s( a : size_t):size_t;
begin
    Result := 0 - (a  shr  (sizeof(a) * 8 - 1));
end;

function constant_time_is_zero_s( a : size_t):size_t;
begin
    Result := constant_time_msb_s(not a and (a - 1));
end;

procedure constant_time_lookup(&out : Pointer;const table : Pointer; rowsize, numrows, idx : size_t);
var
  i, j : size_t;
  tablec, outc : PByte;
  mask : uint8;
begin
    tablec := PByte( table);
    outc := PByte( &out);
    memset(&out, 0, rowsize);
    { Note idx may underflow - but that is well defined }
    i := 0;
    while ( i < numrows) do
    begin
        mask := Byte( constant_time_is_zero_s(idx));
        for j := 0 to rowsize-1 do
        begin
            (outc + j)^ := (outc + j)^  or
                    (constant_time_select_8(mask, tablec^, 0));
            Inc(tablec);
        end;

        Inc(i);
        Dec(idx);
    end;
end;


procedure constant_time_cond_swap_32( mask : uint32; a, b : Puint32_t);
var
  _xor : uint32;
begin
    _xor := a^  xor  b^;
    _xor := _xor and mask;
    a^  := a^ xor _xor;
    b^  := b^ xor _xor;
end;



function constant_time_msb_32( a : uint32):uint32;
begin
    Result := 0 - (a  shr  31);
end;



function constant_time_is_zero_32( a : uint32):uint32;
begin
    Result := constant_time_msb_32(not a and (a - 1));
end;
{$Q+}
end.
