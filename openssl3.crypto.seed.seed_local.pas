unit openssl3.crypto.seed.seed_local;

interface
uses OpenSSL.Api;

type
  seed_word = uint32;

  procedure word2char(l: seed_word; c: Pbyte);
  procedure char2word(c: Pbyte;var i: seed_word);
  procedure KEYSCHEDULE_UPDATE1(T0, T1, X1, X2, X3, X4: seed_word;const KC: int);
  procedure KEYSCHEDULE_UPDATE0(T0, T1, X1, X2, X3, X4: seed_word;const KC: int) ;

implementation

procedure KEYSCHEDULE_UPDATE0(T0, T1, X1, X2, X3, X4: seed_word;const KC: int) ;
begin
   T0 := (X3);
   X3 := (((X3) shl 8)  xor  ((X4) shr 24)) and $ffffffff;
   X4 := (((X4) shl 8)  xor  ((T0) shr 24)) and $ffffffff;
   T0 := ((X1) + (X3) - (KC))     and $ffffffff;
   T1 := ((X2) + (KC) - (X4))     and $ffffffff;
end;

procedure KEYSCHEDULE_UPDATE1(T0, T1, X1, X2, X3, X4: seed_word;const KC: int);
begin
    T0 := (X1);
    X1 := (((X1) shr 8)  xor  ((X2) shl 24)) and $ffffffff;
    X2 := (((X2) shr 8)  xor  ((T0) shl 24)) and $ffffffff;
    T0 := ((X1) + (X3) - (KC))     and $ffffffff;
    T1 := ((X2) + (KC) - (X4))     and $ffffffff
end;

procedure char2word(c: Pbyte; var i: seed_word);
begin
   i := (seed_word(c[0])  shl  24) or
        (seed_word(c[1])  shl  16) or
        (seed_word(c[2])  shl  8 ) or
        (seed_word(c[3]))
end;

procedure word2char(l: seed_word; c: Pbyte);
begin
    (c+0)^ := Byte((l) shr 24) and $ff;
    (c+1)^ := Byte((l) shr 16) and $ff;
    (c+2)^ := Byte((l) shr  8) and $ff;
    (c+3)^ := Byte((l))     and $ff
end;

end.
