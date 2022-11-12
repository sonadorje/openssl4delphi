unit openssl3.crypto.idea.i_skey;

interface
uses OpenSSL.Api;

procedure IDEA_set_encrypt_key(const key : PByte; ks : PIDEA_KEY_SCHEDULE);
  procedure IDEA_set_decrypt_key( ek, dk : PIDEA_KEY_SCHEDULE);
  function inverse( xin : uint32):IDEA_INT;

implementation
uses openssl3.crypto.idea.idea_local;

procedure IDEA_set_encrypt_key(const key : PByte; ks : PIDEA_KEY_SCHEDULE);
var
  i : integer;
  kt, kf : PIDEA_INT;
  r0, r1, r2 : IDEA_INT;
begin
{$POINTERMATH ON}
    kt := @(ks.data[0][0]);
    n2s(key, kt[0]);
    n2s(key, kt[1]);
    n2s(key, kt[2]);
    n2s(key, kt[3]);
    n2s(key, kt[4]);
    n2s(key, kt[5]);
    n2s(key, kt[6]);
    n2s(key, kt[7]);
    kf := kt;
    kt  := kt + 8;
    for i := 0 to 5 do begin
        r2 := kf[1];
        r1 := kf[2];
        PostInc(kt)^ := ((r2 shl 9) or (r1  shr  7)) and $ffff;
        r0 := kf[3];
        PostInc(kt)^ := ((r1 shl 9) or (r0  shr  7)) and $ffff;
        r1 := kf[4];
        PostInc(kt)^ := ((r0 shl 9) or (r1  shr  7)) and $ffff;
        r0 := kf[5];
        PostInc(kt)^ := ((r1 shl 9) or (r0  shr  7)) and $ffff;
        r1 := kf[6];
        PostInc(kt)^ := ((r0 shl 9) or (r1  shr  7)) and $ffff;
        r0 := kf[7];
        PostInc(kt)^ := ((r1 shl 9) or (r0  shr  7)) and $ffff;
        r1 := kf[0];
        if i >= 5 then break;
        PostInc(kt)^ := ((r0 shl 9) or (r1  shr  7)) and $ffff;
        PostInc(kt)^ := ((r1 shl 9) or (r2  shr  7)) and $ffff;
        kf  := kf + 8;
    end;
{$POINTERMATH OFF}
end;


procedure IDEA_set_decrypt_key( ek, dk : PIDEA_KEY_SCHEDULE);
var
  r : integer;
  fp, tp : PIDEA_INT;
  t : IDEA_INT;
begin
{$POINTERMATH ON}
    tp := @(dk.data[0][0]);
    fp := @(ek.data[8][0]);
    for r := 0 to 8 do
    begin
        PostInc(tp)^ := inverse(fp[0]);
        PostInc(tp)^ := (int($10000 - fp[2]) and $ffff);
        PostInc(tp)^ := (int($10000 - fp[1]) and $ffff);
        PostInc(tp)^ := inverse(fp[3]);
        if r = 8 then break;
        fp  := fp - 6;
        PostInc(tp)^ := fp[4];
        PostInc(tp)^ := fp[5];
    end;
    tp := @(dk.data[0][0]);
    t := tp[1];
    tp[1] := tp[2];
    tp[2] := t;
    t := tp[49];
    tp[49] := tp[50];
    tp[50] := t;
{$POINTERMATH OFF}
end;


function inverse( xin : uint32):IDEA_INT;
var
  n1, n2, q, r, b1, b2, t : long;
begin
    if xin = 0 then
       b2 := 0
    else
    begin
        n1 := $10001;
        n2 := xin;
        b2 := 1;
        b1 := 0;
        repeat
            r := (n1 mod n2);
            q := (n1 - r) div n2;
            if r = 0 then
            begin
                if b2 < 0 then
                    b2 := $10001 + b2;
            end
            else
            begin
                n1 := n2;
                n2 := r;
                t := b2;
                b2 := b1 - q * b2;
                b1 := t;
            end;
        until not (r <> 0);
    end;
    Result := IDEA_INT(b2);
end;


end.
