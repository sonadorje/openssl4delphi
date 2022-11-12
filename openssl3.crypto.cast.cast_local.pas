unit openssl3.crypto.cast.cast_local;

interface
uses OpenSSL.Api;

procedure n2l(c: Pbyte; l: CAST_LONG);
procedure c2l(c: Pbyte; l: CAST_LONG);
procedure c2ln(c: Pbyte;var l1,l2: ulong; n: Byte);
procedure l2c( l: CAST_LONG; c: Pbyte);
procedure l2cn(l1,l2: ulong;c: PByte; n: Byte);
procedure n2ln(c: PByte; l1,l2: ulong; n: Byte);
procedure l2nn(l1,l2: ulong; c: PByte; n: Byte) ;
procedure l2n(l: ulong; c: PByte);

implementation

procedure c2l(c: Pbyte; l: CAST_LONG);
begin
   l := (ulong( (PostInc(c)^)))    ;
   l := l or (ulong( (PostInc(c)^))) shl 8;
   l := l or (ulong( (PostInc(c)^))) shl 16;
   l := l or (ulong( (PostInc(c)^))) shl 24;
end;


procedure c2ln(c: Pbyte;var l1,l2: ulong; n: Byte);
begin
    c := c + n;
    l1 := 0; l2 := 0;
    case n of
        8:  l2 :=(ulong( (PreDec(c)^))) shl 24;
        7:  l2 := l2 or ((ulong( (PreDec(c)^)))shl 16);
        6:  l2 := l2 or ((ulong( (PreDec(c)^)))shl 8);
        5:  l2 := l2 or ((ulong( (PreDec(c)^))));
        4:  l1 := (ulong( (PreDec(c)^))) shl 24;
        3:  l1 := l1 or ((ulong( (PreDec(c)^))) shl 16);
        2:  l1 := l1 or ((ulong( (PreDec(c)^))) shl 8);
        1:  l1 := l1 or ((ulong( (PreDec(c)^))));
    end;
end;


procedure l2c( l: CAST_LONG; c: Pbyte);
begin
     PostInc(c)^ := Byte((l     ) and $ff);
     PostInc(c)^ := Byte((l shr  8) and $ff);
     PostInc(c)^ := Byte((l shr 16) and $ff);
     PostInc(c)^ := Byte((l shr 24) and $ff);
end;


procedure l2cn(l1,l2: ulong;c: PByte; n: Byte);
begin
    c := c + n;
    case n of
        8:  PreDec(c)^ := Byte((l2 shr 24) and $ff);
        7:  PreDec(c)^ := Byte((l2 shr 16) and $ff);
        6:  PreDec(c)^ := Byte((l2 shr  8) and $ff);
        5:  PreDec(c)^ := Byte((l2     ) and $ff);
        4:  PreDec(c)^ := Byte((l1 shr 24) and $ff);
        3:  PreDec(c)^ := Byte((l1 shr 16) and $ff);
        2:  PreDec(c)^ := Byte((l1 shr  8) and $ff);
        1:  PreDec(c)^ := Byte((l1     ) and $ff);
    end;
end;


procedure n2ln(c: PByte; l1,l2: ulong; n: Byte);
label fall7, fall6, fall5,fall4,fall3,fall2,fall1;
begin
    c := c + n;
    l1 := 0; l2 :=0;
    case n of
        8:
        begin
        l2 :=(ulong( (PreDec(c)^)))    ;
        goto fall7;
        { fall thru }
        end;
        7:
        begin
fall7:
        l2 := l2 or ((ulong( (PreDec(c)^)))shl 8);
        goto fall6;
        end;
        { fall thru }
        6:
        begin
fall6:
        l2 := l2 or ((ulong( (PreDec(c)^))) shl 16);
        goto fall5;
        { fall thru }
        end;
        5:
        begin
fall5:
        l2 := l2 or ((ulong( (PreDec(c)^)))shl 24);
        goto fall4;
        { fall thru }
        end;
        4:
        begin
fall4:
        l1 :=(ulong( (PreDec(c)^)))    ;
        goto fall3;
        { fall thru }
        end;
        3:
        begin
fall3:
        l1 := l1 or ((ulong( (PreDec(c)^)))shl 8);
        goto fall2;
        { fall thru }
        end;
        2:
        begin
fall2:
        l1 := l1 or ((ulong( (PreDec(c)^)))shl 16);
        goto fall1;
        { fall thru }
        end;
        1:
        begin
fall1:
        l1 :=l1 or ((ulong( (PreDec(c)^)))shl 24);
        end;
    end;
end;


procedure l2nn(l1,l2: ulong; c: PByte; n: Byte) ;
label fall7, fall6, fall5,fall4,fall3,fall2,fall1;
begin
    c := c + n;
    case n of
        8:
        begin
          PreDec(c)^ :=Byte((l2    ) and $ff);
          goto fall7;
        { fall thru }
        end;
        7:
        begin
fall7:
          PreDec(c)^ :=Byte((l2 shr  8) and $ff);
          goto fall6;
        { fall thru }
        end;
        6:
        begin
fall6:
          PreDec(c)^ :=Byte((l2 shr 16) and $ff);
          goto fall5;
        { fall thru }
        end;
        5:
        begin
fall5:
          PreDec(c)^ :=Byte((l2 shr 24) and $ff);
          goto fall4;
        { fall thru }
        end;
        4:
        begin
fall4:
          PreDec(c)^ :=Byte((l1    ) and $ff);
          goto fall3;
        { fall thru }
        end;
        3:
        begin
fall3:
          PreDec(c)^ :=Byte((l1 shr  8) and $ff);
          goto fall2;
        { fall thru }
        end;
        2:
        begin
fall2:
          PreDec(c)^ :=Byte((l1 shr 16) and $ff);
          goto fall1;
        { fall thru }
        end;
        1:
        begin
fall1:
          PreDec(c)^ :=Byte((l1 shr 24) and $ff);
        end;
    end;
end;


procedure n2l(c: Pbyte; l: CAST_LONG);
begin
   l := (ulong( (PostInc(c)^))) shl 24;
   l := l or ((ulong(PostInc(c)^))shl 16);
   l := l or ((ulong(PostInc(c)^))shl 8);
   l := l or (ulong(PostInc(c)^));
end;


procedure l2n(l: ulong; c: PByte);
begin
   PostInc(c)^ :=Byte((l shr 24) and $ff);
   PostInc(c)^ :=Byte((l shr 16) and $ff);
   PostInc(c)^ :=Byte((l shr  8) and $ff);
   PostInc(c)^ :=Byte((l     ) and $ff);
end;

end.
