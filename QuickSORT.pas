UNIT QuickSORT;


INTERFACE
uses OpenSSL.Api, TypInfo, Math, Generics.Defaults;

type


  TQuickSort<T> = class
  public
    type
      PT = ^T;
      TCompareFunc = function(const a,b: T): Integer;

    class procedure qsort(var A: TArray<T>; num: int; comp: TCompareFunc); overload;static;
    class procedure Sort(var A: TArray<T>; L, R: Integer; comp: TCompareFunc); overload;static;

  end;




IMPLEMENTATION

//https://gist.github.com/Fortyseven/6b986f8a208a48b722da
class procedure TQuickSort<T>.Sort(var A: TArray<T>; L, R: Integer; comp: TCompareFunc);
var
  I, J: Integer;
  Y, X: T;
begin
  I:= L; J:= R; X:= A[(L+R) DIV 2];
  repeat
    while comp(A[I], X) < 0 do
       inc(I);

    while Comp(X, A[J]) < 0 do
       dec(J);

    if I <= J then
    begin
      Y:= A[I];
      A[I]:= A[J];
      A[J]:= Y;
      inc(I); dec(J);
    end;
  until I > J;
  if L < J then Sort(A, L,J, comp);
  if I < R then Sort(A, I,R, comp);
end;

class procedure TQuickSort<T>.qsort(var A: TArray<T>; num: int; comp: TCompareFunc);
begin
  if num <2 then
     exit;
  Sort(A, 0, num-1, comp);
end;

type
      TCompareFunc = function(const a,b: Pointer): Integer;
procedure qsort(base: Pointer; num: Cardinal; width: Cardinal; compare: TCompareFunc);
var
  m: Pointer;
  n: Integer;
  o: Pointer;
  oa,ob,oc: Integer;
  p: Integer;
begin
    if num<2 then exit;
    if compare(base,Pointer(Ptruint(base)+width))<=0 then
      Move(base^,m^,(width shl 1))
    else
    begin
      Move(Pointer(Ptruint(base)+width)^,m^,width);
      Move(base^,Pointer(Ptruint(m)+width)^,width);
    end;
    n:=2;
    while Ptruint(n)<num do
    begin
      o:=Pointer(Ptruint(base)+Ptruint(n)*width);
      if compare(m,o)>=0 then
        ob:=0
      else
      begin
        oa:=0;
        ob:=n;
        while oa+1<ob do
        begin
          oc:=((oa+ob) shr 1);
          p:=compare(Pointer(Ptruint(m)+Ptruint(oc)*width),o);
          if p<0 then
            oa:=oc
          else if p=0 then
          begin
            ob:=oc;
            break;
          end
          else
            ob:=oc;
        end;
      end;
      if ob=0 then
      begin
        Move(m^,Pointer(Ptruint(m)+width)^,Ptruint(n)*width);
        Move(o^,m^,width);
      end
      else if ob=n then
        Move(o^,Pointer(Ptruint(m)+Ptruint(n)*width)^,width)
      else
      begin
        Move(Pointer(Ptruint(m)+Ptruint(ob)*width)^,Pointer(Ptruint(m)+Ptruint(ob+1)*width)^,Ptruint(n-ob)*width);
        Move(o^,Pointer(Ptruint(m)+Ptruint(ob)*width)^,width);
      end;
      Inc(n);
    end;
    system.Move(m^,base^,num*width);
    m := nil;
    FreeMem(m);
end;

END.
