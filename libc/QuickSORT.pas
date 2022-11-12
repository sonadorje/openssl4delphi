UNIT QuickSORT;


INTERFACE
uses OpenSSL.Api, TypInfo, Math;



procedure qsort(aa: Pointer; n, es : size_t; cmp: OPENSSL_sk_compfunc);

IMPLEMENTATION
//https://android.googlesource.com/platform/bionic/+/a27d2baa/libc/stdlib/qsort.c
function PreDec(var n: Integer): Integer;
begin
   Dec(n);
   Result := n;
end;

procedure swapcode(&TYPE, parmi, parmj: Pointer; n: Integer);
var
  i: Integer;
  _pi, _pj, t: Pointer;
  tp: PTypeInfo;
begin
  tp := PTypeInfo(&TYPE);
	i := (n) div sizeof (&TYPE);
	_pi :=  (parmi);
	_pj :=  (parmj);
	repeat
    t := _pi;
    case tp.Kind of
      tkChar:
      begin
        PByte(_pi)^ := PByte(_pj)^;
        Inc(PByte(_pi));
        PByte(_pj)^ := PByte(t)^;
        Inc(PByte(_pj));
      end;
      tkWChar:
      begin
        PChar(_pi)^ := PChar(_pj)^;
        Inc(PChar(_pi));
        PChar(_pj)^ := PChar(t)^;
        Inc(PChar(_pj));
      end;
      tkInteger:
       begin
        PInteger(_pi)^ := PInteger(_pj)^;
        Inc(PInteger(_pi));
        PInteger(_pj)^ := PInteger(t)^;
        Inc(PInteger(_pj));
      end;
    end;


  until (PreDec(i) <= 0);
end;

procedure swapfunc( a, b : PChar; n, swaptype : integer);
begin
  if swaptype <= 1 then
    swapcode({TypeHandle}TypeInfo(longint), a, b, n)
  else
    swapcode({TypeHandle}TypeInfo(char), a, b, n);
end;



function med3(a, b, c: PChar; cmp: OPENSSL_sk_compfunc): PChar;
var
  s1, s2, s3, s4: PChar;
begin
  if cmp(a, c) < 0 then
    s1 := a
  else
    s1 := c ;
  if cmp(b, c) > 0 then
    s2 := b
  else
    s2 := s1;
  if cmp(a, c) < 0 then
    s3 := c
  else
    s3 := a ;
  if cmp(b, c) < 0 then
     s4 := b
  else
     s4 := s3;
	if cmp(a, b) < 0 then
     Result := s4
  else
     Result := s2;
end;

procedure qsort(aa: Pointer; n, es : size_t; cmp: OPENSSL_sk_compfunc);
var
  pa,
  pb,
  pc,
  pd,
  pl,
  pm,
  pn       : PChar;
  d,
  r,
  swaptype,
  swap_cnt : integer;
  a        : PChar;
  label  loop ;

  procedure SWAPINIT(a: Pointer; es: Integer) ;
  var
    t, n: Byte;
  begin
    if es = sizeof(long) then
      t := 0
    else
      t := 1;
    if es mod sizeof(longint) > 0 then
      n := 2
    else
      n := t;
    if ( (Pchar(a) - Pchar(0) ) mod sizeof(long) > 0 ) or (n > 0) then
      swaptype := 1
    else
      swaptype := 0;

  end;

  procedure swap( a, b : Pointer);
  var
    t : long;
  begin
    if swaptype = 0 then
    begin
      t := Plong (a)^;
      Plong (a)^ := Plong (b)^;
      Plong (b)^ := t;
    end
    else
      swapfunc(a, b, es, swaptype)
  end;

  procedure vecswap(a, b: PChar; n: Integer);
  begin
   	if n > 0 then
      swapfunc(a, b, n, swaptype)
  end;

begin
  a := aa;
loop:
  SWAPINIT(a, es);
  swap_cnt := 0;
  if n < 7 then
  begin
    pm := PChar (a) + es;
    while ( pm < PChar(a) + n * es) do
    begin
      pl := pm;
      while ( pl > PChar(a) )  and  ( cmp(pl - es, pl) > 0 ) do
      begin
        swap(pl, pl - es);
        pl := pl - es;
      end;
      pm := pm + es;
    end;
    exit;
  end;
  pm := PChar(a) + (n div 2) * es;

  if n > 7 then
  begin
    pl := PChar (a);
    pn := PChar (a) + (n - 1) * es;
    if n > 40 then
    begin
      d := (n div 8) * es;
      pl := med3(pl, pl + d, pl + 2 * d, cmp);
      pm := med3(pm - d, pm, pm + d, cmp);
      pn := med3(pn - 2 * d, pn - d, pn, cmp);
    end;
    pm := med3(pl, pm, pn, cmp);
  end;
  swap(a, pm);
  pb := PChar (a) + es;
  pa := pb;
  pd := PChar (a) + (n - 1) * es;
  pc := pd;
  while  true do
  begin
    r := cmp(pb, a);
    while (pb <= pc)  and  (r <= 0) do
    begin
      if r = 0 then begin
        swap_cnt := 1;
        swap(pa, pb);
        pa  := pa + es;
      end;
      pb  := pb + es;
      r := cmp(pb, a);
    end;
    r := cmp(pc, a);
    while (pb <= pc)  and  (r >= 0) do
    begin
      if r = 0 then begin
        swap_cnt := 1;
        swap(pc, pd);
        pd  := pd - es;
      end;
      pc  := pc - es;
      r := cmp(pc, a);
    end;
    if pb > pc then
       break;
    swap(pb, pc);
    swap_cnt := 1;
    pb  := pb + es;
    pc  := pc - es;
  end;
  if swap_cnt = 0 then
  begin   { Switch to insertion sort }
    pm := PChar(a) + es;
    while pm < PChar(a) + n * es do
    begin
      pl := pm;
      while ( pl > PChar(a) )  and  (cmp(pl - es, pl) > 0) do
      begin
        swap(pl, pl - es);
        pl := pl - es;
      end;
      pm := pm + es;
    end;
    exit;
  end;
  pn := PChar (a) + n * es;
  r := min(pa - PChar (a), pb - pa);
  vecswap(a, pb - r, r);
  r := min(pd - pc, pn - pd - int(es));
  vecswap(pb, pn - r, r);
  r := pb - pa  ;
  if r > int(es) then
    qsort(a, r div es, es, cmp);
  r := pd - pc;
  if r  > int(es) then
  begin
    { Iterate rather than recurse to save stack space }
    a := pn - r;
    n := r div es;
  end;
{    qsort(pn - r, r / es, es, cmp);}
end;
END.
