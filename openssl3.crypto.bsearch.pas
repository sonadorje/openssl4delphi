unit openssl3.crypto.bsearch;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;

type
  Tbsearch_cmp = function(const p1, p2: Pointer): int;

function ossl_bsearch(const key, base : Pointer; num, size : integer; cmp: Tbsearch_cmp; flags : integer):Pointer;  overload;
function ossl_bsearch(const key: Pointer; base : POSSL_PROPERTY_DEFINITION; num : integer; cmp: Tbsearch_cmp; flags : integer):POSSL_PROPERTY_DEFINITION; overload;

implementation

function ossl_bsearch(const key: Pointer; base : POSSL_PROPERTY_DEFINITION; num : integer; cmp: Tbsearch_cmp; flags : integer): POSSL_PROPERTY_DEFINITION;
var
  l, h, i, c : integer;
  p : POSSL_PROPERTY_DEFINITION;
begin
{$POINTERMATH ON}
    i := 0; c := 0;
    p := nil;
    if num = 0 then
       Exit(nil);
    l := 0;
    h := num;
    while l < h do
    begin
        i := (l + h) div 2;
        p := @base[i];
        c := cmp(key, p);
        if c < 0 then
          h := i
        else
        if (c > 0) then
            l := i + 1
        else
            break;
    end;
    if (c <> 0)  and ( 0>= (flags and OSSL_BSEARCH_VALUE_ON_NOMATCH) ) then
        p := nil
    else
    if (c = 0)  and  ( (flags and OSSL_BSEARCH_FIRST_VALUE_ON_MATCH)>0 ) then
    begin
        while (i > 0)  and  ( cmp(key, @base[(i - 1)]) = 0) do
            Dec(i);
        p := @base[i];
    end;
    Result := p;
{$POINTERMATH OFF}
end;

function ossl_bsearch(const key, base : Pointer; num, size : integer; cmp: Tbsearch_cmp; flags : integer):Pointer;
var
  base_ : PUTF8Char;
  l, h, i, c : integer;
  p : PUTF8Char;
begin
{$POINTERMATH ON}
    base_ := base;
    i := 0; c := 0;
    p := nil;
    if num = 0 then
       Exit(nil);
    l := 0;
    h := num;
    while l < h do
    begin
        i := (l + h) div 2;
        p := @base_[i * size];
        c := cmp(key, p);
        if c < 0 then
          h := i
        else
        if (c > 0) then
            l := i + 1
        else
            break;
    end;
    if (c <> 0)  and ( 0>= (flags and OSSL_BSEARCH_VALUE_ON_NOMATCH) ) then
        p := nil
    else
    if (c = 0)  and  ( (flags and OSSL_BSEARCH_FIRST_VALUE_ON_MATCH)>0 ) then
    begin
        while (i > 0)  and  ( cmp(key, @(base_[(i - 1) * size])) = 0) do
            Dec(i);
        p := @(base_[i * size]);
    end;
    Result := p;
{$POINTERMATH ON}
end;

end.
