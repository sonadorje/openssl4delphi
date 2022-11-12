unit openssl3.crypto.asn1.evp_asn1;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;

type
  asn1_oct_int = record
    oct : PASN1_OCTET_STRING;
    num : integer;
  end;
  Pasn1_oct_int = ^asn1_oct_int;


  asn1_int_oct = record
    num : integer;
    oct : PASN1_OCTET_STRING;
  end;
  Pasn1_int_oct = ^asn1_int_oct;

 function ossl_asn1_type_set_octetstring_int( a : PASN1_TYPE; num : long; data : PByte; len : integer):integer;
 function ossl_asn1_type_get_octetstring_int(const a : PASN1_TYPE; num : Plong; data : PByte; max_len : integer):integer;
 function asn1_oct_int_it:PASN1_ITEM;
 procedure asn1_type_init_oct( oct : PASN1_OCTET_STRING; data : PByte; len : integer);
 function asn1_type_get_int_oct( oct : PASN1_OCTET_STRING; anum : integer; num : Plong; data : PByte; max_len : integer):integer;
 function ASN1_TYPE_set_octetstring( a : PASN1_TYPE; data : PByte; len : integer):integer;
 function ASN1_TYPE_get_octetstring(const a : PASN1_TYPE; data : PByte; max_len : integer):integer;

var
  asn1_oct_int_seq_tt, asn1_int_oct_seq_tt :array of TASN1_TEMPLATE;

function ASN1_TYPE_get_int_octetstring(const a : PASN1_TYPE; num : Plong; data : PByte; max_len : integer):integer;
function asn1_int_oct_it:PASN1_ITEM;

function ASN1_TYPE_set_int_octetstring( a : PASN1_TYPE; num : long; data : PByte; len : integer):integer;

implementation

uses  OpenSSL3.Err,                  OpenSSL3.include.openssl.asn1,
      openssl3.crypto.asn1.x_int64,  openssl3.crypto.asn1.a_octet,
      openssl3.crypto.asn1.tasn_fre, openssl3.crypto.asn1.tasn_typ,
      openssl3.crypto.asn1.a_type,   openssl3.crypto.asn1.asn1_lib;




function ASN1_TYPE_set_int_octetstring( a : PASN1_TYPE; num : long; data : PByte; len : integer):integer;
var
  atmp : asn1_int_oct;
  oct : TASN1_OCTET_STRING;
begin
    atmp.num := num;
    atmp.oct := @oct;
    asn1_type_init_oct(@oct, data, len);
    if ASN1_TYPE_pack_sequence(asn1_int_oct_it , @atmp, @a) <> nil  then
        Exit(1);
    Result := 0;
end;

function asn1_int_oct_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
    local_it := get_ASN1_ITEM($1, 16, @asn1_int_oct_seq_tt,
                    sizeof(asn1_int_oct_seq_tt) div sizeof(TASN1_TEMPLATE), Pointer(0) ,
                    sizeof(asn1_int_oct), 'asn1_int_oct');

    Result := @local_it;
end;


function ASN1_TYPE_get_int_octetstring(const a : PASN1_TYPE; num : Plong; data : PByte; max_len : integer):integer;
var
  atmp : Pasn1_int_oct;
  ret : integer;
  label _err;
begin
    atmp := nil;
    ret := -1;
    if (a._type <> V_ASN1_SEQUENCE)  or  (a.value.sequence = nil) then
    begin
        goto _err;
    end;
    atmp := ASN1_TYPE_unpack_sequence(asn1_int_oct_it, a);
    if atmp = nil then goto _err;
    ret := asn1_type_get_int_oct(atmp.oct, atmp.num, num, data, max_len);
    if ret = -1 then begin
 _err:
        ERR_raise(ERR_LIB_ASN1, ASN1_R_DATA_IS_WRONG);
    end;
    //M_ASN1_free_of(atmp, asn1_int_oct);
    if boolean(1) then
       ASN1_item_free(Pointer(atmp), asn1_int_oct_it)
    else
       ASN1_item_free(Pointer(Pasn1_int_oct(0)), asn1_int_oct_it);
    Result := ret;
end;




function ASN1_TYPE_get_octetstring(const a : PASN1_TYPE; data : PByte; max_len : integer):integer;
var
  ret, num : integer;
  p : PByte;
begin
    if (a._type <> V_ASN1_OCTET_STRING)  or  (a.value.octet_string = nil) then  begin
        ERR_raise(ERR_LIB_ASN1, ASN1_R_DATA_IS_WRONG);
        Exit(-1);
    end;
    p := ASN1_STRING_get0_data(a.value.octet_string);
    ret := ASN1_STRING_length(a.value.octet_string);
    if ret < max_len then
       num := ret
    else
        num := max_len;
    if (num > 0)  and  (data <> nil) then
       memcpy(data, p, num);
    Result := ret;
end;

function ASN1_TYPE_set_octetstring( a : PASN1_TYPE; data : PByte; len : integer):integer;
var
  os : PASN1_STRING;
begin
    os := ASN1_OCTET_STRING_new;
    if  os = nil then
        Exit(0);
    if 0>=ASN1_OCTET_STRING_set(os, data, len) then
    begin
        ASN1_OCTET_STRING_free(os);
        Exit(0);
    end;
    ASN1_TYPE_set(a, V_ASN1_OCTET_STRING, os);
    Result := 1;
end;


function asn1_type_get_int_oct( oct : PASN1_OCTET_STRING; anum : integer; num : Plong; data : PByte; max_len : integer):integer;
var
  ret, n : integer;
begin
    ret := ASN1_STRING_length(oct);
    if num <> nil then num^ := anum;
    if max_len > ret then
       n := ret
    else
       n := max_len;
    if data <> nil then
       memcpy(data, ASN1_STRING_get0_data(oct), n);
    Result := ret;
end;

function asn1_oct_int_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
  local_it := get_ASN1_ITEM($1, 16, @asn1_oct_int_seq_tt,
            sizeof(asn1_oct_int_seq_tt) div sizeof(TASN1_TEMPLATE),
      Pointer(0) , sizeof(asn1_oct_int), 'asn1_oct_int');

      Result := @local_it;
end;

procedure asn1_type_init_oct( oct : PASN1_OCTET_STRING; data : PByte; len : integer);
begin
    oct.data := data;
    oct.&type := V_ASN1_OCTET_STRING;
    oct.length := len;
    oct.flags := 0;
end;


function ossl_asn1_type_set_octetstring_int( a : PASN1_TYPE; num : long; data : PByte; len : integer):integer;
var
  atmp : asn1_oct_int;
  oct : TASN1_OCTET_STRING;
begin
    atmp.num := num;
    atmp.oct := @oct;
    asn1_type_init_oct(@oct, data, len);
    if ASN1_TYPE_pack_sequence(asn1_oct_int_it , @atmp, @a) <> nil then
        Exit(1);
    Result := 0;
end;


function ossl_asn1_type_get_octetstring_int(const a : PASN1_TYPE; num : Plong; data : PByte; max_len : integer):integer;
var
  atmp : Pasn1_oct_int;
  ret : integer;
  label _err;
  function CHECKED_PTR_OF: Pointer;
  begin
    if Boolean(1) then
       Result := Pointer(atmp)
    else
       Result := Pointer(Pasn1_oct_int(0));
  end;
begin
    atmp := nil;
    ret := -1;
    if (a._type <> V_ASN1_SEQUENCE)  or  (a.value.sequence = nil) then
        goto _err;
    atmp := ASN1_TYPE_unpack_sequence(asn1_oct_int_it, a);
    if atmp = nil then goto _err;
    ret := asn1_type_get_int_oct(atmp.oct, atmp.num, num, data, max_len);
    if ret = -1 then begin
 _err:
        ERR_raise(ERR_LIB_ASN1, ASN1_R_DATA_IS_WRONG);
    end;
    //M_ASN1_free_of(atmp, asn1_oct_int);
    ASN1_item_free(CHECKED_PTR_OF, asn1_oct_int_it);
    Result := ret;
end;

initialization
   asn1_oct_int_seq_tt := [
        get_ASN1_TEMPLATE( 0, 0, size_t(@Pasn1_oct_int(0).oct), 'oct', ASN1_OCTET_STRING_it) ,
        get_ASN1_TEMPLATE( (($1 shl 12)), 0, size_t(@Pasn1_oct_int(0).num), 'num', INT32_it)
   ] ;

   asn1_int_oct_seq_tt := [
        get_ASN1_TEMPLATE( (($1 shl 12)), 0, size_t(@Pasn1_int_oct(0).num), 'num', INT32_it ),
        get_ASN1_TEMPLATE( 0, 0, size_t(@Pasn1_int_oct(0).oct), 'oct', ASN1_OCTET_STRING_it)
  ] ;

end.
