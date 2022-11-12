unit openssl3.crypto.aes.aes_core;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;

type
  Tuni = record
    case Integer of
      0 : (b: array[0..7] of byte);
      1 : (w : array[0..1] of uint32);
      2 : (d : UInt64);
  end;
  U64 = UInt64;

procedure AES_encrypt(const _in : PByte; _out : PByte;const key : Pointer);
procedure Cipher(const _in : PByte; _out : PByte;const w : Puint64; nr : integer);
procedure AddRoundKey(state : Puint64;const w : Puint64);
procedure SubLong( w : Puint64);
procedure ShiftRows( state : Puint64);
procedure MixColumns( state : Puint64);

procedure XtimeLong( w : Puint64);
procedure AES_decrypt(const _in : PByte; _out : PByte;const key : Pointer);
procedure InvCipher(const _in : PByte; _out : PByte;const w : Puint64; nr : integer);
procedure InvShiftRows( state : Puint64);
procedure InvSubLong( w : Puint64);
procedure InvMixColumns( state : Puint64);
function AES_set_encrypt_key(const userKey : PByte; bits : integer; key : PAES_KEY):integer;
function AES_set_decrypt_key(const userKey : PByte; bits : integer; key : PAES_KEY):integer;
procedure KeyExpansion(const key : PByte; w : Puint64; nr, nk : integer);
procedure RotWord( x : Puint32);
procedure SubWord( w : Puint32);
procedure XtimeWord( w : Puint32);

implementation

{$Q-}
procedure XtimeWord( w : Puint32);
var
  a, b : uint32;
begin
    a := w^;
    b := a and $80808080;
    a  := a xor b;
    b  := b - (b  shr  7);
    b := b and $1B1B1B1B;
    b := b xor (a  shl  1);
    w^ := b;
end;



procedure SubWord( w : Puint32);
var
  x, y, a1, a2, a3, a4, a5, a6 : uint32;
begin
    x := w^;
    y := ((x and $FEFEFEFE)  shr  1) or ((x and $01010101)  shl  7);
    x := x and $DDDDDDDD;
    x  := x xor (y and $57575757);
    y := ((y and $FEFEFEFE)  shr  1) or ((y and $01010101)  shl  7);
    x  := x xor (y and $1C1C1C1C);
    y := ((y and $FEFEFEFE)  shr  1) or ((y and $01010101)  shl  7);
    x  := x xor (y and $4A4A4A4A);
    y := ((y and $FEFEFEFE)  shr  1) or ((y and $01010101)  shl  7);
    x  := x xor (y and $42424242);
    y := ((y and $FEFEFEFE)  shr  1) or ((y and $01010101)  shl  7);
    x  := x xor (y and $64646464);
    y := ((y and $FEFEFEFE)  shr  1) or ((y and $01010101)  shl  7);
    x  := x xor (y and $E0E0E0E0);
    a1 := x;
    a1  := a1 xor ((x and $F0F0F0F0)  shr  4);
    a2 := ((x and $CCCCCCCC)  shr  2) or ((x and $33333333)  shl  2);
    a3 := x and a1;
    a3  := a3 xor ((a3 and $AAAAAAAA)  shr  1);
    a3  := a3 xor ((((x  shl  1) and a1) xor ((a1  shl  1) and x)) and $AAAAAAAA);
    a4 := a2 and a1;
    a4  := a4 xor ((a4 and $AAAAAAAA)  shr  1);
    a4  := a4 xor ((((a2  shl  1) and a1) xor ((a1  shl  1) and a2)) and $AAAAAAAA);
    a5 := (a3 and $CCCCCCCC)  shr  2;
    a3  := a3 xor (((a4  shl  2) xor a4) and $CCCCCCCC);
    a4 := a5 and $22222222;
    a4  := a4  or (a4  shr  1);
    a4  := a4 xor ((a5  shl  1) and $22222222);
    a3  := a3 xor a4;
    a5 := a3 and $A0A0A0A0;
    a5  := a5  or (a5  shr  1);
    a5  := a5 xor ((a3  shl  1) and $A0A0A0A0);
    a4 := a5 and $C0C0C0C0;
    a6 := a4  shr  2;
    a4  := a4 xor ((a5  shl  2) and $C0C0C0C0);
    a5 := a6 and $20202020;
    a5  := a5  or (a5  shr  1);
    a5  := a5 xor ((a6  shl  1) and $20202020);
    a4  := a4  or a5;
    a3  := a3 xor (a4  shr  4);
    a3 := a3 and $0F0F0F0F;
    a2 := a3;
    a2  := a2 xor ((a3 and $0C0C0C0C)  shr  2);
    a4 := a3 and a2;
    a4  := a4 xor ((a4 and $0A0A0A0A0A)  shr  1);
    a4  := a4 xor ((((a3  shl  1) and a2) xor ((a2  shl  1) and a3)) and $0A0A0A0A);
    a5 := a4 and $08080808;
    a5  := a5  or (a5  shr  1);
    a5  := a5 xor ((a4  shl  1) and $08080808);
    a4  := a4 xor (a5  shr  2);
    a4 := a4 and $03030303;
    a4  := a4 xor ((a4 and $02020202)  shr  1);
    a4  := a4  or (a4  shl  2);
    a3 := a2 and a4;
    a3  := a3 xor ((a3 and $0A0A0A0A)  shr  1);
    a3  := a3 xor ((((a2  shl  1) and a4) xor ((a4  shl  1) and a2)) and $0A0A0A0A);
    a3  := a3  or (a3  shl  4);
    a2 := ((a1 and $CCCCCCCC)  shr  2) or ((a1 and $33333333)  shl  2);
    x := a1 and a3;
    x  := x xor ((x and $AAAAAAAA)  shr  1);
    x  := x xor ((((a1  shl  1) and a3) xor ((a3  shl  1) and a1)) and $AAAAAAAA);
    a4 := a2 and a3;
    a4  := a4 xor ((a4 and $AAAAAAAA)  shr  1);
    a4  := a4 xor ((((a2  shl  1) and a3) xor ((a3  shl  1) and a2)) and $AAAAAAAA);
    a5 := (x and $CCCCCCCC)  shr  2;
    x  := x xor (((a4  shl  2) xor a4) and $CCCCCCCC);
    a4 := a5 and $22222222;
    a4  := a4  or (a4  shr  1);
    a4  := a4 xor ((a5  shl  1) and $22222222);
    x  := x xor a4;
    y := ((x and $FEFEFEFE)  shr  1) or ((x and $01010101)  shl  7);
    x := x and $39393939;
    x  := x xor (y and $3F3F3F3F);
    y := ((y and $FCFCFCFC)  shr  2) or ((y and $03030303)  shl  6);
    x  := x xor (y and $97979797);
    y := ((y and $FEFEFEFE)  shr  1) or ((y and $01010101)  shl  7);
    x  := x xor (y and $9B9B9B9B);
    y := ((y and $FEFEFEFE)  shr  1) or ((y and $01010101)  shl  7);
    x  := x xor (y and $3C3C3C3C);
    y := ((y and $FEFEFEFE)  shr  1) or ((y and $01010101)  shl  7);
    x  := x xor (y and $DDDDDDDD);
    y := ((y and $FEFEFEFE)  shr  1) or ((y and $01010101)  shl  7);
    x  := x xor (y and $72727272);
    x  := x xor $63636363;
    w^ := x;
end;

procedure RotWord(x : Puint32);
var
  w0 : PByte;
  tmp : Byte;
begin
    w0 := PByte( x);
    tmp := w0[0];
    w0[0] := w0[1];
    w0[1] := w0[2];
    w0[2] := w0[3];
    w0[3] := tmp;
end;


procedure KeyExpansion(const key : PByte; w : Puint64; nr, nk : integer);
var
  rcon : uint32;
  prev : Tuni;
  temp : uint32;
  i, n : integer;
begin
{$POINTERMATH ON}
    memcpy(w, key, nk*4);
    memcpy(@rcon, PUTF8Char(#1#0#0#0), 4);//'\1\0\0\0', 4);
    n := nk div 2;
    prev.d := w[n-1];
    for i := n to (nr+1)*2-1 do
    begin
        temp := prev.w[1];
        if i mod n = 0 then
        begin
            RotWord(@temp);
            SubWord(@temp);
            temp  := temp xor rcon;
            XtimeWord(@rcon);
        end
        else
        if (nk > 6)  and  (i mod n = 2) then
        begin
            SubWord(@temp);
        end;
        prev.d := w[i-n];
        prev.w[0]  := prev.w[0] xor temp;
        prev.w[1]  := prev.w[1] xor (prev.w[0]);
        w[i] := prev.d;
    end;
 {$POINTERMATH OFF}
end;


function AES_set_encrypt_key(const userKey : PByte; bits : integer; key : PAES_KEY):integer;
var
  rk : Puint64;
begin
    if (nil = userKey)  or  (nil = key) then Exit(-1);
    if (bits <> 128)  and ( bits <> 192)  and  (bits <> 256) then
       Exit(-2);
    rk := Puint64( @key.rd_key);
    if bits = 128 then
       key.rounds := 10
    else if (bits = 192) then
        key.rounds := 12
    else
        key.rounds := 14;
    KeyExpansion(userKey, rk, key.rounds, bits div 32);
    Result := 0;
end;


function AES_set_decrypt_key(const userKey : PByte; bits : integer; key : PAES_KEY):integer;
begin
    Result := AES_set_encrypt_key(userKey, bits, key);
end;



procedure InvMixColumns( state : Puint64);
var
  s1, s : Tuni;
  c : integer;
begin
{$POINTERMATH ON}
    for c := 0 to 1 do
    begin
        s1.d := state[c];
        s.d := s1.d;
        s.d := s.d xor ( ((s.d and U64($FFFF0000FFFF0000))  shr  16)
                         or ((s.d and U64($0000FFFF0000FFFF))  shl  16) );
        s.d := s.d xor ( ((s.d and U64($FF00FF00FF00FF00))  shr  8)
                         or ((s.d and U64($00FF00FF00FF00FF))  shl  8) );
        s.d  := s.d xor s1.d;
        XtimeLong(@s1.d);
        s.d  := s.d xor s1.d;
        s.b[0]  := s.b[0] xor (s1.b[1]);
        s.b[1]  := s.b[1] xor (s1.b[2]);
        s.b[2]  := s.b[2] xor (s1.b[3]);
        s.b[3]  := s.b[3] xor (s1.b[0]);
        s.b[4]  := s.b[4] xor (s1.b[5]);
        s.b[5]  := s.b[5] xor (s1.b[6]);
        s.b[6]  := s.b[6] xor (s1.b[7]);
        s.b[7]  := s.b[7] xor (s1.b[4]);
        XtimeLong(@s1.d);
        s1.d := s1.d xor ( ((s1.d and U64($FFFF0000FFFF0000))  shr  16)
                           or ((s1.d and U64($0000FFFF0000FFFF))  shl  16) );
        s.d  := s.d xor s1.d;
        XtimeLong(@s1.d);
        s1.d := s1.d xor ( ((s1.d and U64($FF00FF00FF00FF00))  shr  8)
                           or ((s1.d and U64($00FF00FF00FF00FF))  shl  8) );
        s.d  := s.d xor s1.d;
        state[c] := s.d;
    end;
{$POINTERMATH OFF}
end;


procedure InvSubLong( w : Puint64);
var
  x, y, a1, a2, a3, a4, a5, a6 : uint64;
begin
    x := w^;
    x  := x xor (U64($6363636363636363));
    y := ((x and U64($FEFEFEFEFEFEFEFE))  shr  1) or ((x and U64($0101010101010101))  shl  7);
    x := x and U64($FDFDFDFDFDFDFDFD);
    x  := x xor (y and U64($5E5E5E5E5E5E5E5E));
    y := ((y and U64($FEFEFEFEFEFEFEFE))  shr  1) or ((y and U64($0101010101010101))  shl  7);
    x  := x xor (y and U64($F3F3F3F3F3F3F3F3));
    y := ((y and U64($FEFEFEFEFEFEFEFE))  shr  1) or ((y and U64($0101010101010101))  shl  7);
    x  := x xor (y and U64($F5F5F5F5F5F5F5F5));
    y := ((y and U64($FEFEFEFEFEFEFEFE))  shr  1) or ((y and U64($0101010101010101))  shl  7);
    x  := x xor (y and U64($7878787878787878));
    y := ((y and U64($FEFEFEFEFEFEFEFE))  shr  1) or ((y and U64($0101010101010101))  shl  7);
    x  := x xor (y and U64($7777777777777777));
    y := ((y and U64($FEFEFEFEFEFEFEFE))  shr  1) or ((y and U64($0101010101010101))  shl  7);
    x  := x xor (y and U64($1515151515151515));
    y := ((y and U64($FEFEFEFEFEFEFEFE))  shr  1) or ((y and U64($0101010101010101))  shl  7);
    x  := x xor (y and U64($A5A5A5A5A5A5A5A5));
    a1 := x;
    a1  := a1 xor ((x and U64($F0F0F0F0F0F0F0F0))  shr  4);
    a2 := ((x and U64($CCCCCCCCCCCCCCCC))  shr  2) or ((x and U64($3333333333333333))  shl  2);
    a3 := x and a1;
    a3  := a3 xor ((a3 and U64($AAAAAAAAAAAAAAAA))  shr  1);
    a3  := a3 xor ((((x  shl  1) and a1) xor ((a1  shl  1) and x)) and U64($AAAAAAAAAAAAAAAA));
    a4 := a2 and a1;
    a4  := a4 xor ((a4 and U64($AAAAAAAAAAAAAAAA))  shr  1);
    a4  := a4 xor ((((a2  shl  1) and a1) xor ((a1  shl  1) and a2)) and U64($AAAAAAAAAAAAAAAA));
    a5 := (a3 and U64($CCCCCCCCCCCCCCCC))  shr  2;
    a3  := a3 xor (((a4  shl  2) xor a4) and U64($CCCCCCCCCCCCCCCC));
    a4 := a5 and U64($2222222222222222);
    a4  := a4  or (a4  shr  1);
    a4  := a4 xor ((a5  shl  1) and U64($2222222222222222));
    a3  := a3 xor a4;
    a5 := a3 and U64($A0A0A0A0A0A0A0A0);
    a5  := a5  or (a5  shr  1);
    a5  := a5 xor ((a3  shl  1) and U64($A0A0A0A0A0A0A0A0));
    a4 := a5 and U64($C0C0C0C0C0C0C0C0);
    a6 := a4  shr  2;
    a4  := a4 xor ((a5  shl  2) and U64($C0C0C0C0C0C0C0C0));
    a5 := a6 and U64($2020202020202020);
    a5  := a5  or (a5  shr  1);
    a5  := a5 xor ((a6  shl  1) and U64($2020202020202020));
    a4  := a4  or a5;
    a3  := a3 xor (a4  shr  4);
    a3 := a3 and U64($0F0F0F0F0F0F0F0F);
    a2 := a3;
    a2  := a2 xor ((a3 and U64($0C0C0C0C0C0C0C0C))  shr  2);
    a4 := a3 and a2;
    a4  := a4 xor ((a4 and U64($0A0A0A0A0A0A0A0A))  shr  1);
    a4  := a4 xor ((((a3  shl  1) and a2) xor ((a2  shl  1) and a3)) and U64($0A0A0A0A0A0A0A0A));
    a5 := a4 and U64($0808080808080808);
    a5  := a5  or (a5  shr  1);
    a5  := a5 xor ((a4  shl  1) and U64($0808080808080808));
    a4  := a4 xor (a5  shr  2);
    a4 := a4 and U64($0303030303030303);
    a4  := a4 xor ((a4 and U64($0202020202020202))  shr  1);
    a4  := a4  or (a4  shl  2);
    a3 := a2 and a4;
    a3  := a3 xor ((a3 and U64($0A0A0A0A0A0A0A0A))  shr  1);
    a3  := a3 xor ((((a2  shl  1) and a4) xor ((a4  shl  1) and a2)) and U64($0A0A0A0A0A0A0A0A));
    a3  := a3  or (a3  shl  4);
    a2 := ((a1 and U64($CCCCCCCCCCCCCCCC))  shr  2) or ((a1 and U64($3333333333333333))  shl  2);
    x := a1 and a3;
    x  := x xor ((x and U64($AAAAAAAAAAAAAAAA))  shr  1);
    x  := x xor ((((a1  shl  1) and a3) xor ((a3  shl  1) and a1)) and U64($AAAAAAAAAAAAAAAA));
    a4 := a2 and a3;
    a4  := a4 xor ((a4 and U64($AAAAAAAAAAAAAAAA))  shr  1);
    a4  := a4 xor ((((a2  shl  1) and a3) xor ((a3  shl  1) and a2)) and U64($AAAAAAAAAAAAAAAA));
    a5 := (x and U64($CCCCCCCCCCCCCCCC))  shr  2;
    x  := x xor (((a4  shl  2) xor a4) and U64($CCCCCCCCCCCCCCCC));
    a4 := a5 and U64($2222222222222222);
    a4  := a4  or (a4  shr  1);
    a4  := a4 xor ((a5  shl  1) and U64($2222222222222222));
    x  := x xor a4;
    y := ((x and U64($FEFEFEFEFEFEFEFE))  shr  1) or ((x and U64($0101010101010101))  shl  7);
    x := x and U64($B5B5B5B5B5B5B5B5);
    x  := x xor (y and U64($4040404040404040));
    y := ((y and U64($FEFEFEFEFEFEFEFE))  shr  1) or ((y and U64($0101010101010101))  shl  7);
    x  := x xor (y and U64($8080808080808080));
    y := ((y and U64($FEFEFEFEFEFEFEFE))  shr  1) or ((y and U64($0101010101010101))  shl  7);
    x  := x xor (y and U64($1616161616161616));
    y := ((y and U64($FEFEFEFEFEFEFEFE))  shr  1) or ((y and U64($0101010101010101))  shl  7);
    x  := x xor (y and U64($EBEBEBEBEBEBEBEB));
    y := ((y and U64($FEFEFEFEFEFEFEFE))  shr  1) or ((y and U64($0101010101010101))  shl  7);
    x  := x xor (y and U64($9797979797979797));
    y := ((y and U64($FEFEFEFEFEFEFEFE))  shr  1) or ((y and U64($0101010101010101))  shl  7);
    x  := x xor (y and U64($FBFBFBFBFBFBFBFB));
    y := ((y and U64($FEFEFEFEFEFEFEFE))  shr  1) or ((y and U64($0101010101010101))  shl  7);
    x  := x xor (y and U64($7D7D7D7D7D7D7D7D));
    w^ := x;
end;

procedure InvShiftRows( state : Puint64);
var
  s : array[0..3] of Byte;
  s0 : PByte;
  r : integer;
begin
    s0 := PByte( state);
    for r := 0 to 3 do
    begin
        s[0] := s0[0*4 + r];
        s[1] := s0[1*4 + r];
        s[2] := s0[2*4 + r];
        s[3] := s0[3*4 + r];
        s0[0*4 + r] := s[(4-r) mod 4];
        s0[1*4 + r] := s[(5-r) mod 4];
        s0[2*4 + r] := s[(6-r) mod 4];
        s0[3*4 + r] := s[(7-r) mod 4];
    end;
end;



procedure InvCipher(const _in : PByte; _out : PByte;const w : Puint64; nr : integer);
var
  state : array[0..1] of uint64;
  i : integer;
begin
{$POINTERMATH ON}
    memcpy(@state, _in, 16);
    AddRoundKey(@state, w + nr*2);
    i := nr - 1;
    while i > 0 do
    begin
        InvShiftRows(@state);
        InvSubLong(@state[0]);
        InvSubLong(@state[1]);
        AddRoundKey(@state, w + i*2);
        InvMixColumns(@state);
        Dec(i);
    end;
    InvShiftRows(@state);
    InvSubLong(@state[0]);
    InvSubLong(@state[1]);
    AddRoundKey(@state, w);
    memcpy(_out, @state, 16);
{$POINTERMATH OFF}
end;



procedure AES_decrypt(const _in : PByte; _out : PByte;const key : Pointer);
var
  rk: PUint64;
begin
    assert( (_in<>nil)  and  (_out<>nil)  and  (key<>nil));
    rk := Puint64(@PAES_KEY(key).rd_key);
    InvCipher(_in, _out, rk, PAES_KEY(key).rounds);
end;


procedure XtimeLong( w : Puint64);
var
  a, b : uint64;
begin
    a := w^;
    b := a and U64($8080808080808080);
    a := a xor b;
    b := b - (b  shr  7);
    b := b and U64($1B1B1B1B1B1B1B1B);
    b := b xor (a  shl  1);
    w^ := b;
end;

procedure MixColumns( state : Puint64);
var
  s1, s : Tuni;
  c : integer;
begin
{$POINTERMATH ON}
    for c := 0 to 1 do
    begin
        s1.d := state[c];
        s.d := s1.d;
        s.d := s.d xor ( ((s.d and U64($FFFF0000FFFF0000))  shr  16)
                         or ((s.d and U64($0000FFFF0000FFFF))  shl  16) );
        s.d := s.d xor ( ((s.d and U64($FF00FF00FF00FF00))  shr  8)
                         or ((s.d and U64($00FF00FF00FF00FF))  shl  8) );
        s.d  := s.d xor s1.d;
        XtimeLong(@s1.d);
        s.d  := s.d xor s1.d;
        s.b[0]  := s.b[0] xor (s1.b[1]);
        s.b[1]  := s.b[1] xor (s1.b[2]);
        s.b[2]  := s.b[2] xor (s1.b[3]);
        s.b[3]  := s.b[3] xor (s1.b[0]);
        s.b[4]  := s.b[4] xor (s1.b[5]);
        s.b[5]  := s.b[5] xor (s1.b[6]);
        s.b[6]  := s.b[6] xor (s1.b[7]);
        s.b[7]  := s.b[7] xor (s1.b[4]);
        state[c] := s.d;
    end;
{$POINTERMATH OFF}
end;


procedure ShiftRows( state : Puint64);
var
  s : array[0..3] of Byte;
  s0 : PByte;
  r : integer;
begin
    s0 := PByte( state);
    for r := 0 to 3 do
    begin
        s[0] := s0[0*4 + r];
        s[1] := s0[1*4 + r];
        s[2] := s0[2*4 + r];
        s[3] := s0[3*4 + r];
        s0[0*4 + r] := s[(r+0) mod 4];
        s0[1*4 + r] := s[(r+1) mod 4];
        s0[2*4 + r] := s[(r+2) mod 4];
        s0[3*4 + r] := s[(r+3) mod 4];
    end;
end;

procedure SubLong( w : Puint64);
var
  x, y, a1, a2, a3, a4, a5, a6 : uint64;
begin
    x := w^;
    y := ((x and U64($FEFEFEFEFEFEFEFE))  shr  1) or ((x and U64($0101010101010101))  shl  7);
    x := x and U64($DDDDDDDDDDDDDDDD);
    x  := x xor (y and U64($5757575757575757));
    y := ((y and U64($FEFEFEFEFEFEFEFE))  shr  1) or ((y and U64($0101010101010101))  shl  7);
    x  := x xor (y and U64($1C1C1C1C1C1C1C1C));
    y := ((y and U64($FEFEFEFEFEFEFEFE))  shr  1) or ((y and U64($0101010101010101))  shl  7);
    x  := x xor (y and U64($4A4A4A4A4A4A4A4A));
    y := ((y and U64($FEFEFEFEFEFEFEFE))  shr  1) or ((y and U64($0101010101010101))  shl  7);
    x  := x xor (y and U64($4242424242424242));
    y := ((y and U64($FEFEFEFEFEFEFEFE))  shr  1) or ((y and U64($0101010101010101))  shl  7);
    x  := x xor (y and U64($6464646464646464));
    y := ((y and U64($FEFEFEFEFEFEFEFE))  shr  1) or ((y and U64($0101010101010101))  shl  7);
    x  := x xor (y and U64($E0E0E0E0E0E0E0E0));
    a1 := x;
    a1  := a1 xor ((x and U64($F0F0F0F0F0F0F0F0))  shr  4);
    a2 := ((x and U64($CCCCCCCCCCCCCCCC))  shr  2) or ((x and U64($3333333333333333))  shl  2);
    a3 := x and a1;
    a3  := a3 xor ((a3 and U64($AAAAAAAAAAAAAAAA))  shr  1);
    a3  := a3 xor ((((x  shl  1) and a1) xor ((a1  shl  1) and x)) and U64($AAAAAAAAAAAAAAAA));
    a4 := a2 and a1;
    a4  := a4 xor ((a4 and U64($AAAAAAAAAAAAAAAA))  shr  1);
    a4  := a4 xor ((((a2  shl  1) and a1) xor ((a1  shl  1) and a2)) and U64($AAAAAAAAAAAAAAAA));
    a5 := (a3 and U64($CCCCCCCCCCCCCCCC))  shr  2;
    a3  := a3 xor (((a4  shl  2) xor a4) and U64($CCCCCCCCCCCCCCCC));
    a4 := a5 and U64($2222222222222222);
    a4  := a4  or (a4  shr  1);
    a4  := a4 xor ((a5  shl  1) and U64($2222222222222222));
    a3  := a3 xor a4;
    a5 := a3 and U64($A0A0A0A0A0A0A0A0);
    a5  := a5  or (a5  shr  1);
    a5  := a5 xor ((a3  shl  1) and U64($A0A0A0A0A0A0A0A0));
    a4 := a5 and U64($C0C0C0C0C0C0C0C0);
    a6 := a4  shr  2;
    a4  := a4 xor ((a5  shl  2) and U64($C0C0C0C0C0C0C0C0));
    a5 := a6 and U64($2020202020202020);
    a5  := a5  or (a5  shr  1);
    a5  := a5 xor ((a6  shl  1) and U64($2020202020202020));
    a4  := a4  or a5;
    a3  := a3 xor (a4  shr  4);
    a3 := a3 and U64($0F0F0F0F0F0F0F0F);
    a2 := a3;
    a2  := a2 xor ((a3 and U64($0C0C0C0C0C0C0C0C))  shr  2);
    a4 := a3 and a2;
    a4  := a4 xor ((a4 and U64($0A0A0A0A0A0A0A0A))  shr  1);
    a4  := a4 xor ((((a3  shl  1) and a2) xor ((a2  shl  1) and a3)) and U64($0A0A0A0A0A0A0A0A));
    a5 := a4 and U64($0808080808080808);
    a5  := a5  or (a5  shr  1);
    a5  := a5 xor ((a4  shl  1) and U64($0808080808080808));
    a4  := a4 xor (a5  shr  2);
    a4 := a4 and U64($0303030303030303);
    a4  := a4 xor ((a4 and U64($0202020202020202))  shr  1);
    a4  := a4  or (a4  shl  2);
    a3 := a2 and a4;
    a3  := a3 xor ((a3 and U64($0A0A0A0A0A0A0A0A))  shr  1);
    a3  := a3 xor ((((a2  shl  1) and a4) xor ((a4  shl  1) and a2)) and U64($0A0A0A0A0A0A0A0A));
    a3  := a3  or (a3  shl  4);
    a2 := ((a1 and U64($CCCCCCCCCCCCCCCC))  shr  2) or ((a1 and U64($3333333333333333))  shl  2);
    x := a1 and a3;
    x  := x xor ((x and U64($AAAAAAAAAAAAAAAA))  shr  1);
    x  := x xor ((((a1  shl  1) and a3) xor ((a3  shl  1) and a1)) and U64($AAAAAAAAAAAAAAAA));
    a4 := a2 and a3;
    a4  := a4 xor ((a4 and U64($AAAAAAAAAAAAAAAA))  shr  1);
    a4  := a4 xor ((((a2  shl  1) and a3) xor ((a3  shl  1) and a2)) and U64($AAAAAAAAAAAAAAAA));
    a5 := (x and U64($CCCCCCCCCCCCCCCC))  shr  2;
    x  := x xor (((a4  shl  2) xor a4) and U64($CCCCCCCCCCCCCCCC));
    a4 := a5 and U64($2222222222222222);
    a4  := a4  or (a4  shr  1);
    a4  := a4 xor ((a5  shl  1) and U64($2222222222222222));
    x  := x xor a4;
    y := ((x and U64($FEFEFEFEFEFEFEFE))  shr  1) or ((x and U64($0101010101010101))  shl  7);
    x := x and U64($3939393939393939);
    x  := x xor (y and U64($3F3F3F3F3F3F3F3F));
    y := ((y and U64($FCFCFCFCFCFCFCFC))  shr  2) or ((y and U64($0303030303030303))  shl  6);
    x  := x xor (y and U64($9797979797979797));
    y := ((y and U64($FEFEFEFEFEFEFEFE))  shr  1) or ((y and U64($0101010101010101))  shl  7);
    x  := x xor (y and U64($9B9B9B9B9B9B9B9B));
    y := ((y and U64($FEFEFEFEFEFEFEFE))  shr  1) or ((y and U64($0101010101010101))  shl  7);
    x  := x xor (y and U64($3C3C3C3C3C3C3C3C));
    y := ((y and U64($FEFEFEFEFEFEFEFE))  shr  1) or ((y and U64($0101010101010101))  shl  7);
    x  := x xor (y and U64($DDDDDDDDDDDDDDDD));
    y := ((y and U64($FEFEFEFEFEFEFEFE))  shr  1) or ((y and U64($0101010101010101))  shl  7);
    x  := x xor (y and U64($7272727272727272));
    x  := x xor (U64($6363636363636363));
    w^ := x;

end;



procedure AddRoundKey(state : Puint64;const w : Puint64);
begin
{$POINTERMATH ON}
    state[0]  := state[0] xor (w[0]);
    state[1]  := state[1] xor (w[1]);
{$POINTERMATH OFF}
end;

procedure Cipher(const _in : PByte; _out : PByte;const w : Puint64; nr : integer);
var
  state : array[0..1] of uint64;
  i : integer;
begin
{$POINTERMATH ON}
    memcpy(@state, _in, 16);
    AddRoundKey(@state, w);
    for i := 1 to nr-1 do
    begin
        SubLong(@state[0]);
        SubLong(@state[1]);
        ShiftRows(@state);
        MixColumns(@state);
        AddRoundKey(@state, w + i*2);
    end;
    SubLong(@state[0]);
    SubLong(@state[1]);
    ShiftRows(@state);
    AddRoundKey(@state, w + nr*2);
    memcpy(_out, @state, 16);
{$POINTERMATH OFF}
end;

{$Q+}

procedure AES_encrypt(const _in : PByte; _out : PByte;const key : Pointer);
var
  rk : Puint64;
begin
    assert( (_in <> nil) and  (_out <> nil) and  (key<>nil));
    rk := Puint64(@PAES_KEY(key).rd_key);
    Cipher(_in, _out, rk, PAES_KEY(key).rounds);
end;

end.
