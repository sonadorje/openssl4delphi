unit openssl3.crypto.bf.bf_skey;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;

 procedure BF_set_key(key : PBF_KEY; len : integer;const data : PByte);

implementation
uses  openssl3.crypto.bf.bf_local,   openssl3.crypto.bf.bf_enc;

procedure BF_set_key(key : PBF_KEY; len : integer;const data : PByte);
var
  i : integer;
  p : PBF_LONG;
  ri : BF_LONG;
  _in : array[0..1] of BF_LONG;
  d, _end : PByte;

begin
{$POINTERMATH ON}
    memcpy(key, @bf_init, sizeof(TBF_KEY));
    p := @key.P;
    if len > ((BF_ROUNDS + 2)  * 4) then
        len := (BF_ROUNDS + 2) * 4;
    d := data;
    _end := @(data[len]);
    for i := 0 to (BF_ROUNDS + 2)-1 do
    begin
        ri := PostInc(d)^;
        if d >= _end then
           d := data;
        ri := ri shl 8;
        ri  := ri  or (PostInc(d)^);
        if d >= _end then
           d := data;
        ri := ri shl 8;
        ri  := ri  or (PostInc(d)^);
        if d >= _end then
           d := data;
        ri := ri shl 8;
        ri  := ri  or (PostInc(d)^);
        if d >= _end then
           d := data;
        p[i]  := p[i] xor ri;
    end;
    _in[0] := 0;
    _in[1] := 0;
    i := 0;
    while i < (BF_ROUNDS + 2) do
    begin
        BF_encrypt(@_in, key);
        p[i] := _in[0];
        p[i + 1] := _in[1];
        i := i + 2;
    end;
    p := @key.S;
    i := 0;
    while i < 4 * 256 do
    begin
        BF_encrypt(@_in, key);
        p[i] := _in[0];
        p[i + 1] := _in[1];
        i := i + 2;
    end;
{$POINTERMATH OFF}
end;


end.
