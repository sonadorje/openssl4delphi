unit openssl3.crypto.rc2.rc2_local;

interface
uses OpenSSL.Api;

procedure c2l(c: PByte;var l: uint32);
procedure l2c(var l: uint32; c: PByte);
procedure c2ln(c: Pbyte;var l1,l2: uint32; n: Byte);
procedure l2cn(var l1,l2: uint32; c: PByte; n: Byte);

implementation

procedure l2cn(var l1,l2: uint32; c: PByte; n: Byte);
label fall7, fall6, fall5, fall4, fall3, fall2, fall1;
begin
  c := c + n;
  case n of
      8:
      begin
        PreDec(c)^ := Byte((l2  shr 24) and $ff);
        goto fall7;
      end;
      { fall thru }
      7:
      begin
fall7:        PreDec(c)^ := Byte((l2  shr 16) and $ff);
        goto fall6;
      end;
      { fall thru }
      6:
      begin
fall6:        PreDec(c)^ := Byte((l2  shr  8) and $ff);
        goto fall5;
      end;
      { fall thru }
      5:
      begin
fall5:        PreDec(c)^ := Byte((l2      ) and $ff);
        goto fall4;
      end;
      { fall thru }
      4:
      begin
fall4:        PreDec(c)^ := Byte((l1  shr 24) and $ff);
        goto fall3;
      end;
      { fall thru }
      3:
      begin
fall3:        PreDec(c)^ := Byte((l1  shr 16) and $ff);
        goto fall2;
      end;
      { fall thru }
      2:
      begin
fall2:        PreDec(c)^ := Byte((l1  shr  8) and $ff);
        goto fall1;
      end;
      { fall thru }
      1:
      begin
fall1:        PreDec(c)^ := Byte((l1      ) and $ff);
      end;
  end;
end;

procedure c2ln(c: Pbyte;var l1,l2: uint32; n: Byte);
label fall7, fall6, fall5, fall4, fall3, fall2, fall1;
begin
  c := c + n;
  l1 := 0; l2 :=0;
  case n of
      8:
      begin
        l2 := (ulong( PreDec(c)^)) shl 24;
        goto fall7;
      end;
      { fall thru }
      7:
      begin
fall7:        l2 := l2 or (ulong( PreDec(c)^) shl 16);
        goto fall6;
      end;
      { fall thru }
      6:
      begin
fall6:        l2 := l2 or ((ulong( PreDec(c)^)) shl 8);
        goto fall5;
      end;
      { fall thru }
      5:
      begin
fall5:        l2 := l2 or ((ulong( PreDec(c)^)));
        goto fall4;
      end;
      { fall thru }
      4:
      begin
fall4:        l1 := ulong( PreDec(c)^) shl 24;
        goto fall3;
      end;
      { fall thru }
      3:
      begin
fall3:        l1 := l1 or (ulong( PreDec(c)^) shl 16);
        goto fall2;
      end;
      { fall thru }
      2:
      begin
fall2:        l1 := l1 or (ulong( PreDec(c)^) shl 8);
        goto fall1;
      end;
      { fall thru }
      1:
fall1:
      l1 := l1 or (ulong( PreDec(c)^));
  end;
end;

procedure l2c(var l: uint32; c: PByte);
begin
  PostInc(c)^ := Byte((l     ) and $ff);
  PostInc(c)^ := Byte((l shr  8) and $ff);
  PostInc(c)^ := Byte((l shr 16) and $ff);
  PostInc(c)^ := Byte((l shr 24) and $ff);
end;

procedure c2l(c: PByte;var l: uint32);
begin
   l := ulong( PostInc(c)^)    ;
   l := l or (ulong( PostInc(c)^) shl 8);
   l := l or (ulong( PostInc(c)^) shl 16);
   l := l or (ulong( PostInc(c)^)  shl 24);
end;
end.
