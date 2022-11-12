unit openssl3.crypto.rc4.rc4_enc;

interface
uses OpenSSL.Api;

procedure RC4(key : PRC4_KEY; len : size_t;{const} indata : PByte; outdata : PByte);

implementation


procedure RC4(key : PRC4_KEY; len : size_t;{const} indata : PByte; outdata : PByte);
var
  d : PRC4_INT;
  x, y, tx, ty : RC4_INT;
  i : size_t;
  procedure LOOP(var _in, _out: Byte);
  begin
  {$POINTERMATH ON}
      x := ((x+1) and $ff);
      tx := d[x];
      y := (tx+y) and $ff;
      d[x] := d[y]; ty :=d[y];
      d[y] := tx;
      _out := d[(tx+ty) and $ff] xor  _in;
  {$POINTERMATH OFF}
  end;
begin
{$POINTERMATH ON}
    x := key.x;
    y := key.y;
    d := @key.data;

    i := len  shr  3;
    if i > 0 then
    begin
        while true do
        begin
            LOOP(indata[0], outdata[0]);
            LOOP(indata[1], outdata[1]);
            LOOP(indata[2], outdata[2]);
            LOOP(indata[3], outdata[3]);
            LOOP(indata[4], outdata[4]);
            LOOP(indata[5], outdata[5]);
            LOOP(indata[6], outdata[6]);
            LOOP(indata[7], outdata[7]);
            indata  := indata + 8;
            outdata  := outdata + 8;
            if PreDec(i) = 0  then
                break;
        end;
    end;
    i := len and $07;
    if i > 0 then
    begin
        while true do
        begin
            LOOP(indata[0], outdata[0]);
            if PreDec(i) = 0  then
                break;
            LOOP(indata[1], outdata[1]);
            if PreDec(i) = 0  then
                break;
            LOOP(indata[2], outdata[2]);
            if PreDec(i) = 0  then
                break;
            LOOP(indata[3], outdata[3]);
            if PreDec(i) = 0  then
                break;
            LOOP(indata[4], outdata[4]);
            if PreDec(i) = 0  then
                break;
            LOOP(indata[5], outdata[5]);
            if PreDec(i) = 0  then
                break;
            LOOP(indata[6], outdata[6]);
            if PreDec(i) = 0  then
                break;
        end;
    end;
    key.x := x;
    key.y := y;
{$POINTERMATH OFF}
end;


end.
