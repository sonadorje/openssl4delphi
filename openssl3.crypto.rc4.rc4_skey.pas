unit openssl3.crypto.rc4.rc4_skey;

interface
uses OpenSSL.Api;

procedure RC4_set_key(key : PRC4_KEY; len : integer;const data : PByte);

implementation


procedure RC4_set_key(key : PRC4_KEY; len : integer;const data : PByte);
var
  tmp : RC4_INT;
  id1, id2 : integer;
  d : PRC4_INT;
  i : uint32;
  procedure SK_LOOP(d: PRC4_INT;n: uint32);
  begin
  {$POINTERMATH ON}
      tmp := d[n];
      id2 := (data[id1] + tmp + id2) and $ff;
      if PreInc(id1) = len  then
         id1 := 0;
      d[(n)] := d[id2];
      d[id2] := tmp;
  {$POINTERMATH OFF}
  end;
begin
{$POINTERMATH ON}
    d := @(key.data[0]);
    key.x := 0;
    key.y := 0;
    id1 := 0; id2 := 0;

    for i := 0 to 255 do
        d[i] := i;
    i := 0;
    while i < 256 do
    begin
        SK_LOOP(d, i + 0);
        SK_LOOP(d, i + 1);
        SK_LOOP(d, i + 2);
        SK_LOOP(d, i + 3);
        i := i + 4;
    end;
{$POINTERMATH OFF}
end;


end.
