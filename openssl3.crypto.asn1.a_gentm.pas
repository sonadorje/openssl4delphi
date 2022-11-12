unit openssl3.crypto.asn1.a_gentm;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;

function asn1_generalizedtime_to_tm(tm : Ptm;const d : PASN1_GENERALIZEDTIME):integer;
  function ASN1_GENERALIZEDTIME_check(const d : PASN1_GENERALIZEDTIME):integer;
  function ASN1_GENERALIZEDTIME_set_string(s : PASN1_GENERALIZEDTIME;const str : PUTF8Char):integer;
  function ASN1_GENERALIZEDTIME_set( s : PASN1_GENERALIZEDTIME; t : time_t):PASN1_GENERALIZEDTIME;
  function ASN1_GENERALIZEDTIME_adj( s : PASN1_GENERALIZEDTIME; t : time_t; offset_day : integer; offset_sec : long):PASN1_GENERALIZEDTIME;
  function ASN1_GENERALIZEDTIME_print(bp : PBIO;const tm : PASN1_GENERALIZEDTIME):integer;

implementation
uses openssl3.crypto.asn1.a_time, openssl3.crypto.asn1.asn1_lib,
     openssl3.crypto.o_time;

function asn1_generalizedtime_to_tm(tm : Ptm;const d : PASN1_GENERALIZEDTIME):integer;
begin
    { wrapper around ossl_asn1_time_to_tm }
    if d.&type <> V_ASN1_GENERALIZEDTIME then
        Exit(0);
    Result := ossl_asn1_time_to_tm(tm, PASN1_TIME(d));
end;


function ASN1_GENERALIZEDTIME_check(const d : PASN1_GENERALIZEDTIME):integer;
begin
    Result := asn1_generalizedtime_to_tm(nil, d);
end;


function ASN1_GENERALIZEDTIME_set_string(s : PASN1_GENERALIZEDTIME;const str : PUTF8Char):integer;
var
  t : ASN1_GENERALIZEDTIME;
begin
    t.&type := V_ASN1_GENERALIZEDTIME;
    t.length := Length(str);
    t.data := PByte( str);
    t.flags := 0;
    if 0>= ASN1_GENERALIZEDTIME_check(@t) then
        Exit(0);
    if (s <> nil)  and  (0>= ASN1_STRING_copy(PASN1_STRING(s), @t)) then
        Exit(0);
    Result := 1;
end;


function ASN1_GENERALIZEDTIME_set( s : PASN1_GENERALIZEDTIME; t : time_t):PASN1_GENERALIZEDTIME;
begin
    Result := ASN1_GENERALIZEDTIME_adj(s, t, 0, 0);
end;


function ASN1_GENERALIZEDTIME_adj( s : PASN1_GENERALIZEDTIME; t : time_t; offset_day : integer; offset_sec : long):PASN1_GENERALIZEDTIME;
var
  ts : Ptm;
  data : Ttm;
begin
    ts := OPENSSL_gmtime(@t, @data);
    if ts = nil then
       Exit(nil);
    if (offset_day > 0)  or  (offset_sec > 0) then
    begin
        if 0>= OPENSSL_gmtime_adj(ts, offset_day, offset_sec) then
           Exit(nil);
    end;
    Result := ossl_asn1_time_from_tm(s, ts, V_ASN1_GENERALIZEDTIME);
end;


function ASN1_GENERALIZEDTIME_print(bp : PBIO;const tm : PASN1_GENERALIZEDTIME):integer;
begin
    if tm.&type <> V_ASN1_GENERALIZEDTIME then
       Exit(0);
    Result := ASN1_TIME_print(bp, tm);
end;

end.
