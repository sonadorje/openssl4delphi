unit openssl3.crypto.asn1.a_utctm;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
 uses OpenSSL.Api;

function ossl_asn1_utctime_to_tm(tm : Ptm;const d : PASN1_UTCTIME):integer;
  function ASN1_UTCTIME_check(const d : PASN1_UTCTIME):integer;
  function ASN1_UTCTIME_set_string(s : PASN1_UTCTIME;const str : PUTF8Char):integer;
  function ASN1_UTCTIME_set( s : PASN1_UTCTIME; t : time_t):PASN1_UTCTIME;
  function ASN1_UTCTIME_adj( s : PASN1_UTCTIME; t : time_t; offset_day : integer; offset_sec : long):PASN1_UTCTIME;
  function ASN1_UTCTIME_cmp_time_t(const s : PASN1_UTCTIME; t : time_t):integer;
  function ASN1_UTCTIME_print(bp : PBIO;const tm : PASN1_UTCTIME):integer;

implementation
uses openssl3.crypto.asn1.a_time, openssl3.crypto.asn1.asn1_lib,
     openssl3.crypto.o_time;

function ossl_asn1_utctime_to_tm(tm : Ptm;const d : PASN1_UTCTIME):integer;
begin
    { wrapper around ossl_asn1_time_to_tm }
    if d.&type <> V_ASN1_UTCTIME then
       Exit(0);
    Result := ossl_asn1_time_to_tm(tm, d);
end;


function ASN1_UTCTIME_check(const d : PASN1_UTCTIME):integer;
begin
    Result := ossl_asn1_utctime_to_tm(nil, d);
end;


function ASN1_UTCTIME_set_string(s : PASN1_UTCTIME;const str : PUTF8Char):integer;
var
  t : TASN1_UTCTIME;
begin
    t.&type := V_ASN1_UTCTIME;
    t.length := Length(str);
    t.data := PByte( str);
    t.flags := 0;
    if 0>= ASN1_UTCTIME_check(@t) then
        Exit(0);
    if (s <> nil)  and  (0>= ASN1_STRING_copy(PASN1_STRING(s), @t)) then
        Exit(0);
    Result := 1;
end;


function ASN1_UTCTIME_set( s : PASN1_UTCTIME; t : time_t):PASN1_UTCTIME;
begin
    Result := ASN1_UTCTIME_adj(s, t, 0, 0);
end;


function ASN1_UTCTIME_adj( s : PASN1_UTCTIME; t : time_t; offset_day : integer; offset_sec : long):PASN1_UTCTIME;
var
  ts : Ptm;

  data : Ttm;
begin
    ts := OPENSSL_gmtime(@t, @data);
    if ts = nil then Exit(nil);
    if (offset_day>0)  or  (offset_sec>0) then
    begin
        if 0>= OPENSSL_gmtime_adj(ts, offset_day, offset_sec) then
            Exit(nil);
    end;
    Result := ossl_asn1_time_from_tm(s, ts, V_ASN1_UTCTIME);
end;


function ASN1_UTCTIME_cmp_time_t(const s : PASN1_UTCTIME; t : time_t):integer;
var
  day, sec : integer;
  stm, _ttm: Ttm;
begin

    if 0>= ossl_asn1_utctime_to_tm(@stm, s) then
        Exit(-2);
    if OPENSSL_gmtime(@t, @_ttm) = nil  then
        Exit(-2);
    if 0>= OPENSSL_gmtime_diff(@day, @sec, @_ttm, @stm) then
        Exit(-2);
    if (day > 0)  or  (sec > 0) then Exit(1);
    if (day < 0)  or  (sec < 0) then Exit(-1);
    Result := 0;
end;


function ASN1_UTCTIME_print(bp : PBIO;const tm : PASN1_UTCTIME):integer;
begin
    if tm.&type <> V_ASN1_UTCTIME then Exit(0);
    Result := ASN1_TIME_print(bp, tm);
end;


end.
