unit openssl3.crypto.rc2.rc2_skey;

interface
uses OpenSSL.Api;

const // 1d arrays
  key_table : array[0..255] of byte = (
    $d9, $78, $f9, $c4, $19, $dd, $b5, $ed, $28, $e9, $fd, $79, $4a, $a0,
    $d8, $9d, $c6, $7e, $37, $83, $2b, $76, $53, $8e, $62, $4c, $64, $88,
    $44, $8b, $fb, $a2, $17, $9a, $59, $f5, $87, $b3, $4f, $13, $61, $45,
    $6d, $8d, $09, $81, $7d, $32, $bd, $8f, $40, $eb, $86, $b7, $7b, $0b,
    $f0, $95, $21, $22, $5c, $6b, $4e, $82, $54, $d6, $65, $93, $ce, $60,
    $b2, $1c, $73, $56, $c0, $14, $a7, $8c, $f1, $dc, $12, $75, $ca, $1f,
    $3b, $be, $e4, $d1, $42, $3d, $d4, $30, $a3, $3c, $b6, $26, $6f, $bf,
    $0e, $da, $46, $69, $07, $57, $27, $f2, $1d, $9b, $bc, $94, $43, $03,
    $f8, $11, $c7, $f6, $90, $ef, $3e, $e7, $06, $c3, $d5, $2f, $c8, $66,
    $1e, $d7, $08, $e8, $ea, $de, $80, $52, $ee, $f7, $84, $aa, $72, $ac,
    $35, $4d, $6a, $2a, $96, $1a, $d2, $71, $5a, $15, $49, $74, $4b, $9f,
    $d0, $5e, $04, $18, $a4, $ec, $c2, $e0, $41, $6e, $0f, $51, $cb, $cc,
    $24, $91, $af, $50, $a1, $f4, $70, $39, $99, $7c, $3a, $85, $23, $b8,
    $b4, $7a, $fc, $02, $36, $5b, $25, $55, $97, $31, $2d, $5d, $fa, $98,
    $e3, $8a, $92, $ae, $05, $df, $29, $10, $67, $6c, $ba, $c9, $d3, $00,
    $e6, $cf, $e1, $9e, $a8, $2c, $63, $16, $01, $3f, $58, $e2, $89, $a9,
    $0d, $38, $34, $1b, $ab, $33, $ff, $b0, $bb, $48, $0c, $5f, $b9, $b1,
    $cd, $2e, $c5, $f3, $db, $47, $e5, $a5, $9c, $77, $0a, $a6, $20, $68,
    $fe, $7f, $c1, $ad );

procedure RC2_set_key(key : PRC2_KEY; len : integer;const data : PByte; bits : integer);

implementation


procedure RC2_set_key(key : PRC2_KEY; len : integer;const data : PByte; bits : integer);
var
  i, j : integer;
  k : PByte;
  ki : PRC2_INT;
  c, d : uint32;
begin
    k := PByte(@key.data[0]);
    k^ := 0;                     { for if there is a zero length key }
    if len > 128 then len := 128;
    if bits <= 0 then bits := 1024;
    if bits > 1024 then bits := 1024;
    for i := 0 to len-1 do
        k[i] := data[i];
    { expand table }
    d := k[len - 1];
    j := 0;
    for i := len to 128 -1  do
    begin
        d := key_table[(k[j] + d) and $ff];
        k[i] := d;
        Inc(j);
    end;
    { hmm.... key reduction to 'bits' bits }
    j := (bits + 7)  shr  3;
    i := 128 - j;
    c := ($ff  shr  (-bits and $07));
    d := key_table[k[i] and c];
    k[i] := d;
    while PostDec(i) > 0 do
    begin
        d := key_table[k[i + j]  xor  d];
        k[i] := d;
    end;
    { copy from bytes into RC2_INT's }
    ki := @(key.data[63]);
    i := 127;
    while i >= 0 do
    begin
        ki^ := ((k[i] shl 8) or k[i - 1]) and $ffff;
        i := i - 2;
        Dec(ki);
    end;
end;



end.
