unit openssl3.crypto.sha.keccak1600;

interface
uses OpenSSL.Api;

{$define KECCAK_COMPLEMENTING_TRANSFORM }

function SHA3_absorb(A : PPUInt64; inp : PByte; len, r : size_t):size_t;
function BitInterleave( Ai : uint64):uint64;
 procedure KeccakF1600( A : PPUInt64);
procedure _Round( R, A : PPuint64; i : size_t);
 procedure SHA3_squeeze(A : PPuint64; _out : Pbyte; len, r : size_t);
 function BitDeinterleave( Ai : uint64):uint64;
 function BIT_INTERLEAVE: Boolean;

const // 2d arrays
  rhotates : array[0..4,0..4] of byte = (
    (0, 1, 62, 28, 27),
    (36, 44, 6, 55, 20),
    (3, 10, 43, 25, 39),
    (41, 45, 15, 21, 8),
    (18, 2, 61, 56, 14));

implementation

uses openssl3.crypto.sha.sha_local;

var
  iotas: array[0..23] of uint64;


function BitDeinterleave( Ai : uint64):uint64;
var
  hi, lo, t0, t1 : uint32;
begin
    if BIT_INTERLEAVE then
    begin
        hi := uint32 (Ai  shr  32);
        lo := uint32( Ai);
        t0 := lo and $0000ffff;
        t0  := t0  or (t0  shl  8);
        t0 := t0 and  $00ff00ff;
        t0  := t0  or (t0  shl  4);
        t0 := t0 and  $0f0f0f0f;
        t0  := t0  or (t0  shl  2);
        t0 := t0 and  $33333333;
        t0  := t0  or (t0  shl  1);
        t0 := t0 and  $55555555;
        t1 := hi  shl  16;
        t1  := t1  or (t1  shr  8);
        t1 := t1 and  $ff00ff00;
        t1  := t1  or (t1  shr  4);
        t1 := t1 and  $f0f0f0f0;
        t1  := t1  or (t1  shr  2);
        t1 := t1 and  $cccccccc;
        t1  := t1  or (t1  shr  1);
        t1 := t1 and  $aaaaaaaa;
        lo := lo shr 16;
        lo  := lo  or (lo  shl  8);
        lo := lo and  $00ff00ff;
        lo  := lo  or (lo  shl  4);
        lo := lo and  $0f0f0f0f;
        lo  := lo  or (lo  shl  2);
        lo := lo and  $33333333;
        lo  := lo  or (lo  shl  1);
        lo := lo and  $55555555;
        hi := hi and  $ffff0000;
        hi  := hi  or (hi  shr  8);
        hi := hi and  $ff00ff00;
        hi  := hi  or (hi  shr  4);
        hi := hi and  $f0f0f0f0;
        hi  := hi  or (hi  shr  2);
        hi := hi and  $cccccccc;
        hi  := hi  or (hi  shr  1);
        hi := hi and  $aaaaaaaa;
        Ai := (uint64( (hi or lo)  shl  32)) or (t1 or t0);
    end;
    Result := Ai;
end;





procedure SHA3_squeeze(A : PPuint64; _out : Pbyte; len, r : size_t);
var
  A_flat : Puint64;

  i, w : size_t;

  Ai : uint64;
begin
{$POINTERMATH ON}
    A_flat := A^;
    w := r div 8;
    assert( (r < 25 * sizeof(A[0][0]))  and  ( (r mod 8) = 0) );
    while len <> 0 do
    begin
        i := 0;
        while  (i < w) and (len <> 0) do
        begin
            Ai := BitDeinterleave(A_flat[i]);
            if len < 8 then
            begin
                for i := 0 to len-1 do
                begin
                    _out^ := _out^ + Byte(Ai);
                    Ai  := Ai shr  8;
                    Inc(_out);
                end;
                exit;
            end;
            _out[0] := Byte(Ai);
            _out[1] := Byte(Ai  shr  8);
            _out[2] := Byte(Ai  shr  16);
            _out[3] := Byte(Ai  shr  24);
            _out[4] := Byte(Ai  shr  32);
            _out[5] := Byte(Ai  shr  40);
            _out[6] := Byte(Ai  shr  48);
            _out[7] := Byte(Ai  shr  56);
            _out  := _out + 8;
            len  := len - 8;
            Inc(i);
        end;
        if len>0 then
           KeccakF1600(A);
    end;
{$POINTERMATH ON}
end;

function BIT_INTERLEAVE: Boolean;
begin
   Result := (sizeof(Pointer) < 8)
end;

function member(condition: Boolean;result1, result2: uint64):uint64;
begin
   if condition then
      Result := result1
   else
      Result := result2;
end;


function ROL32(a, offset: uint32): uint32;
begin
   Result := (((a) shl (offset)) or ((a) shr ((32 - (offset)) and 31)))
end;

function ROL64( val : uint64; offset : integer):uint64;
var
  hi, lo, tmp : uint32;
begin
    if offset = 0 then
    begin
        Exit(val);
    end
    else
    if ( not BIT_INTERLEAVE) then
    begin
        Exit((val  shl  offset) or (val  shr  (64-offset)));
    end
    else
    begin
        hi := uint32_t(val  shr  32);
        lo := uint32_t(val);
        if (offset and 1)>0 then
        begin
            tmp := hi;
            offset := offset shr  1;
            hi := ROL32(lo, offset);
            lo := ROL32(tmp, offset + 1);
        end
        else
        begin
            offset := offset shr  1;
            lo := ROL32(lo, offset);
            hi := ROL32(hi, offset);
        end;
        Exit((uint64_t(hi)  shl  32) or lo);
    end;
end;




procedure _Round( R, A : PPuint64; i : size_t);
var
  C, D : array[0..4] of uint64;
begin
{$POINTERMATH ON}
    assert(i < (sizeof(iotas) div sizeof(iotas[0])));
    C[0] := A[0][0]  xor  A[1][0]  xor  A[2][0]  xor  A[3][0]  xor  A[4][0];
    C[1] := A[0][1]  xor  A[1][1]  xor  A[2][1]  xor  A[3][1]  xor  A[4][1];
    C[2] := A[0][2]  xor  A[1][2]  xor  A[2][2]  xor  A[3][2]  xor  A[4][2];
    C[3] := A[0][3]  xor  A[1][3]  xor  A[2][3]  xor  A[3][3]  xor  A[4][3];
    C[4] := A[0][4]  xor  A[1][4]  xor  A[2][4]  xor  A[3][4]  xor  A[4][4];
    D[0] := ROL64(C[1], 1)  xor  C[4];
    D[1] := ROL64(C[2], 1)  xor  C[0];
    D[2] := ROL64(C[3], 1)  xor  C[1];
    D[3] := ROL64(C[4], 1)  xor  C[2];
    D[4] := ROL64(C[0], 1)  xor  C[3];
    C[0] := A[0][0]  xor  D[0];
    C[1] := ROL64(A[1][1]  xor  D[1], rhotates[1][1]);
    C[2] := ROL64(A[2][2]  xor  D[2], rhotates[2][2]);
    C[3] := ROL64(A[3][3]  xor  D[3], rhotates[3][3]);
    C[4] := ROL64(A[4][4]  xor  D[4], rhotates[4][4]);
{$IFDEF KECCAK_COMPLEMENTING_TRANSFORM}
    R[0][0] := C[0]  xor  ( C[1] or C[2])  xor  iotas[i];
    R[0][1] := C[1]  xor  (not C[2] or C[3]);
    R[0][2] := C[2]  xor  ( C[3] and C[4]);
    R[0][3] := C[3]  xor  ( C[4] or C[0]);
    R[0][4] := C[4]  xor  ( C[0] and C[1]);
{$ELSE R[0][0] = C[0]  xor  (not C[1] and C[2])  xor  iotas[i];}
    R[0][1] := C[1]  xor  (not C[2] and C[3]);
    R[0][2] := C[2]  xor  (not C[3] and C[4]);
    R[0][3] := C[3]  xor  (not C[4] and C[0]);
    R[0][4] := C[4]  xor  (not C[0] and C[1]);
{$ENDIF}
    C[0] := ROL64(A[0][3]  xor  D[3], rhotates[0][3]);
    C[1] := ROL64(A[1][4]  xor  D[4], rhotates[1][4]);
    C[2] := ROL64(A[2][0]  xor  D[0], rhotates[2][0]);
    C[3] := ROL64(A[3][1]  xor  D[1], rhotates[3][1]);
    C[4] := ROL64(A[4][2]  xor  D[2], rhotates[4][2]);
{$IFDEF KECCAK_COMPLEMENTING_TRANSFORM}
    R[1][0] := C[0]  xor  (C[1] or  C[2]);
    R[1][1] := C[1]  xor  (C[2] and  C[3]);
    R[1][2] := C[2]  xor  (C[3] or not C[4]);
    R[1][3] := C[3]  xor  (C[4] or  C[0]);
    R[1][4] := C[4]  xor  (C[0] and  C[1]);
{$ELSE R[1][0] = C[0]  xor  (not C[1] and C[2]);}
    R[1][1] := C[1]  xor  (not C[2] and C[3]);
    R[1][2] := C[2]  xor  (not C[3] and C[4]);
    R[1][3] := C[3]  xor  (not C[4] and C[0]);
    R[1][4] := C[4]  xor  (not C[0] and C[1]);
{$ENDIF}
    C[0] := ROL64(A[0][1]  xor  D[1], rhotates[0][1]);
    C[1] := ROL64(A[1][2]  xor  D[2], rhotates[1][2]);
    C[2] := ROL64(A[2][3]  xor  D[3], rhotates[2][3]);
    C[3] := ROL64(A[3][4]  xor  D[4], rhotates[3][4]);
    C[4] := ROL64(A[4][0]  xor  D[0], rhotates[4][0]);
{$IFDEF KECCAK_COMPLEMENTING_TRANSFORM}
    R[2][0] := C[0]  xor  ( C[1] or C[2]);
    R[2][1] := C[1]  xor  ( C[2] and C[3]);
    R[2][2] := C[2]  xor  (not C[3] and C[4]);
    R[2][3] := not C[3]  xor  ( C[4] or C[0]);
    R[2][4] := C[4]  xor  ( C[0] and C[1]);
{$ELSE R[2][0] = C[0]  xor  (not C[1] and C[2]);}
    R[2][1] := C[1]  xor  (not C[2] and C[3]);
    R[2][2] := C[2]  xor  (not C[3] and C[4]);
    R[2][3] := C[3]  xor  (not C[4] and C[0]);
    R[2][4] := C[4]  xor  (not C[0] and C[1]);
{$ENDIF}
    C[0] := ROL64(A[0][4]  xor  D[4], rhotates[0][4]);
    C[1] := ROL64(A[1][0]  xor  D[0], rhotates[1][0]);
    C[2] := ROL64(A[2][1]  xor  D[1], rhotates[2][1]);
    C[3] := ROL64(A[3][2]  xor  D[2], rhotates[3][2]);
    C[4] := ROL64(A[4][3]  xor  D[3], rhotates[4][3]);
{$IFDEF KECCAK_COMPLEMENTING_TRANSFORM}
    R[3][0] := C[0]  xor  ( C[1] and C[2]);
    R[3][1] := C[1]  xor  ( C[2] or C[3]);
    R[3][2] := C[2]  xor  (not C[3] or C[4]);
    R[3][3] := not C[3]  xor  ( C[4] and C[0]);
    R[3][4] := C[4]  xor  ( C[0] or C[1]);
{$ELSE R[3][0] = C[0]  xor  (not C[1] and C[2]);}
    R[3][1] := C[1]  xor  (not C[2] and C[3]);
    R[3][2] := C[2]  xor  (not C[3] and C[4]);
    R[3][3] := C[3]  xor  (not C[4] and C[0]);
    R[3][4] := C[4]  xor  (not C[0] and C[1]);
{$ENDIF}
    C[0] := ROL64(A[0][2]  xor  D[2], rhotates[0][2]);
    C[1] := ROL64(A[1][3]  xor  D[3], rhotates[1][3]);
    C[2] := ROL64(A[2][4]  xor  D[4], rhotates[2][4]);
    C[3] := ROL64(A[3][0]  xor  D[0], rhotates[3][0]);
    C[4] := ROL64(A[4][1]  xor  D[1], rhotates[4][1]);
{$IFDEF KECCAK_COMPLEMENTING_TRANSFORM}
    R[4][0] := C[0]  xor  (not C[1] and C[2]);
    R[4][1] := not C[1]  xor  ( C[2] or C[3]);
    R[4][2] := C[2]  xor  ( C[3] and C[4]);
    R[4][3] := C[3]  xor  ( C[4] or C[0]);
    R[4][4] := C[4]  xor  ( C[0] and C[1]);
{$ELSE R[4][0] = C[0]  xor  (not C[1] and C[2]);}
    R[4][1] := C[1]  xor  (not C[2] and C[3]);
    R[4][2] := C[2]  xor  (not C[3] and C[4]);
    R[4][3] := C[3]  xor  (not C[4] and C[0]);
    R[4][4] := C[4]  xor  (not C[0] and C[1]);
{$ENDIF}

{$POINTERMATH OFF}
end;



procedure KeccakF1600( A : PPUInt64);
var
  T : array[0..4, 0..4] of uint64;

  i : size_t;
begin
{$POINTERMATH ON}
{$IFDEF KECCAK_COMPLEMENTING_TRANSFORM}
    A[0][1] := not A[0][1];
    A[0][2] := not A[0][2];
    A[1][3] := not A[1][3];
    A[2][2] := not A[2][2];
    A[3][2] := not A[3][2];
    A[4][0] := not A[4][0];
{$ENDIF}
    i := 0;
    while i < 24 do
    begin
        _Round(@T, A, i);
        _Round(A, @T, i + 1);
        i := i+ 2;
    end;
{$IFDEF KECCAK_COMPLEMENTING_TRANSFORM}
    A[0][1] := not A[0][1];
    A[0][2] := not A[0][2];
    A[1][3] := not A[1][3];
    A[2][2] := not A[2][2];
    A[3][2] := not A[3][2];
    A[4][0] := not A[4][0];
{$ENDIF}

{$POINTERMATH ON}
end;




function BitInterleave( Ai : uint64):uint64;
var
  hi, lo, t0, t1 : uint32;
begin
    if sizeof(Pointer) < 8 then //BIT_INTERLEAVE then
    begin
        hi := uint32(Ai  shr  32); lo := uint32( Ai);
        t0 := lo and $55555555;
        t0  := t0  or (t0  shr  1);
        t0 := t0 and  $33333333;
        t0  := t0  or (t0  shr  2);
        t0 := t0 and  $0f0f0f0f;
        t0  := t0  or (t0  shr  4);
        t0 := t0 and  $00ff00ff;
        t0  := t0  or (t0  shr  8);
        t0 := t0 and  $0000ffff;
        t1 := hi and $55555555;
        t1  := t1  or (t1  shr  1);
        t1 := t1 and  $33333333;
        t1  := t1  or (t1  shr  2);
        t1 := t1 and  $0f0f0f0f;
        t1  := t1  or (t1  shr  4);
        t1 := t1 and  $00ff00ff;
        t1  := t1  or (t1  shr  8);
        t1  := t1 shl  16;
        lo := lo and  $aaaaaaaa;
        lo  := lo  or (lo  shl  1);
        lo := lo and  $cccccccc;
        lo  := lo  or (lo  shl  2);
        lo := lo and  $f0f0f0f0;
        lo  := lo  or (lo  shl  4);
        lo := lo and  $ff00ff00;
        lo  := lo  or (lo  shl  8);
        lo  := lo shr  16;
        hi := hi and  $aaaaaaaa;
        hi := hi  or (hi  shl  1);
        hi := hi and  $cccccccc;
        hi  := hi  or (hi  shl  2);
        hi := hi and  $f0f0f0f0;
        hi  := hi  or (hi  shl  4);
        hi := hi and  $ff00ff00;
        hi  := hi  or (hi  shl  8);
        hi := hi and  $ffff0000;
        Ai := (uint64( (hi or lo)  shl  32)) or (t1 or t0);
    end;
    Result := Ai;
end;


function SHA3_absorb(A : PPUInt64; inp : PByte; len, r : size_t):size_t;
var
  A_flat : Puint64_t;

  i, w : size_t;

  Ai : uint64;
begin
{$POINTERMATH ON}
    A_flat := Puint64_t ( A);
    w := r div 8;
    assert( (r < (25 * sizeof(A[0][0])))  and  ( (r mod 8) = 0));
    while len >= r do
    begin
        for i := 0 to w-1 do
        begin
             Ai := uint64( inp[0])  or         uint64( inp[1])  shl  8  or
                          uint64( inp[2])  shl  16 or uint64( inp[3])  shl  24 or
                          uint64( inp[4])  shl  32 or uint64( inp[5])  shl  40 or
                          uint64( inp[6])  shl  48 or uint64( inp[7])  shl  56;
            inp  := inp + 8;
            A_flat[i]  := A_flat[i] xor (BitInterleave(Ai));
        end;
        KeccakF1600(A);
        len  := len - r;
    end;
    Result := len;
{$POINTERMATH OFF}
end;


initialization
    iotas[0] := member(BIT_INTERLEAVE, $0000000000000001, $0000000000000001);
    iotas[1] := member(BIT_INTERLEAVE, $0000008900000000, $0000000000008082);
    iotas[2] := member(BIT_INTERLEAVE, $8000008b00000000, $800000000000808a);
    iotas[3] := member(BIT_INTERLEAVE, $8000808000000000, $8000000080008000);
    iotas[4] := member(BIT_INTERLEAVE, $0000008b00000001, $000000000000808b);
    iotas[5] := member(BIT_INTERLEAVE, $0000800000000001, $0000000080000001);
    iotas[6] := member(BIT_INTERLEAVE, $8000808800000001, $8000000080008081);
    iotas[7] := member(BIT_INTERLEAVE, $8000008200000001, $8000000000008009);
    iotas[8] := member(BIT_INTERLEAVE, $0000000b00000000, $000000000000008a);
    iotas[9] := member(BIT_INTERLEAVE, $0000000a00000000, $0000000000000088);
    iotas[10] := member(BIT_INTERLEAVE, $0000808200000001, $0000000080008009);
    iotas[11] := member(BIT_INTERLEAVE, $0000800300000000, $000000008000000a);
    iotas[12] := member(BIT_INTERLEAVE, $0000808b00000001, $000000008000808b);
    iotas[13] := member(BIT_INTERLEAVE, $8000000b00000001, $800000000000008b);
    iotas[14] := member(BIT_INTERLEAVE, $8000008a00000001, $8000000000008089);
    iotas[15] := member(BIT_INTERLEAVE, $8000008100000001, $8000000000008003);
    iotas[16] := member(BIT_INTERLEAVE, $8000008100000000, $8000000000008002);
    iotas[17] := member(BIT_INTERLEAVE, $8000000800000000, $8000000000000080);
    iotas[18] := member(BIT_INTERLEAVE, $0000008300000000, $000000000000800a);
    iotas[19] := member(BIT_INTERLEAVE, $8000800300000000, $800000008000000a);
    iotas[20] := member(BIT_INTERLEAVE, $8000808800000001, $8000000080008081);
    iotas[21] := member(BIT_INTERLEAVE, $8000008800000000, $8000000000008080);
    iotas[22] := member(BIT_INTERLEAVE, $0000800000000001, $0000000080000001);
    iotas[23] := member(BIT_INTERLEAVE, $8000808200000000, $8000000080008008);




end.
