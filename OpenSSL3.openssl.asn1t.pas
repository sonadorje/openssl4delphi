unit OpenSSL3.openssl.asn1t;

interface
uses OpenSSL.Api, TypInfo, StrUtils,
     {$IFDEF FPC} fpc_rtti, {$ELSE} rtti, {$ENDIF} SysUtils;

function ASN1_EX_TYPE(flags: Uint32; tag: Integer; const stname: Pointer; const field: PUTF8Char; _type: Pointer): TASN1_TEMPLATE;
function ASN1_EXP_OPT(const stname: Pointer; const field: PUTF8Char; _type: Pointer; tag:Integer ): TASN1_TEMPLATE;
function offsetof(const stname: Pointer; const field: PUTF8Char): UInt32;
function ASN1_OPT(const stname: Pointer; const field:PUTF8Char; _type: Pointer): TASN1_TEMPLATE;
function ASN1_SIMPLE(const stname: Pointer; const field:PUTF8Char; _type: Pointer): TASN1_TEMPLATE;
function sk_ASN1_VALUE_new_null: Pstack_st_ASN1_VALUE;
function sk_ASN1_VALUE_num(sk: Pstack_st_ASN1_VALUE): Int;
function sk_ASN1_VALUE_pop(sk: Pstack_st_ASN1_VALUE): PASN1_VALUE;
function sk_ASN1_VALUE_push(sk:Pstack_st_ASN1_VALUE ; ptr: Pointer): int;
function sk_ASN1_VALUE_value(sk:Pstack_st_ASN1_VALUE; idx: int): PASN1_VALUE;
procedure sk_ASN1_VALUE_free(sk:Pstack_st_ASN1_VALUE) ;



implementation
uses openssl3.crypto.asn1.x_algor,     openssl3.crypto.sm2.sm2_crypt,
     openssl3.crypto.stack,            OpenSSL3.fuzz.asn1;


procedure sk_ASN1_VALUE_free(sk:Pstack_st_ASN1_VALUE) ;
begin
   OPENSSL_sk_free(ossl_check_ASN1_VALUE_sk_type(sk))
end;

function sk_ASN1_VALUE_value(sk:Pstack_st_ASN1_VALUE; idx: int): PASN1_VALUE;
begin
   Result := PASN1_VALUE(OPENSSL_sk_value(ossl_check_const_ASN1_VALUE_sk_type(sk), idx))
end;

function sk_ASN1_VALUE_push(sk:Pstack_st_ASN1_VALUE ; ptr: Pointer): int;
begin
   Result := OPENSSL_sk_push(ossl_check_ASN1_VALUE_sk_type(sk), ossl_check_ASN1_VALUE_type(ptr))
end;

function sk_ASN1_VALUE_pop(sk: Pstack_st_ASN1_VALUE): PASN1_VALUE;
begin
  RESULT := PASN1_VALUE(OPENSSL_sk_pop(ossl_check_ASN1_VALUE_sk_type(sk)))
end;

function sk_ASN1_VALUE_num(sk: Pstack_st_ASN1_VALUE): Int;
begin
   Result := OPENSSL_sk_num(ossl_check_const_ASN1_VALUE_sk_type(sk))
end;

function sk_ASN1_VALUE_new_null: Pstack_st_ASN1_VALUE;
begin
  RESULT := Pstack_st_ASN1_VALUE (OPENSSL_sk_new_null)
end;

function ASN1_OPT(const stname: Pointer; const field:PUTF8Char; _type: Pointer): TASN1_TEMPLATE;
begin
   Result := ASN1_EX_TYPE(ASN1_TFLG_OPTIONAL, 0, stname, field, _type);
end;

function ASN1_SIMPLE(const stname: Pointer; const field:PUTF8Char; _type: Pointer): TASN1_TEMPLATE;
begin
   Result := ASN1_EX_TYPE(0, 0, stname, field, _type);
end;

//https://stackoverflow.com/questions/23823731/access-all-elements-of-a-record-using-rtti/23824290
//https://forum.lazarus.freepascal.org/index.php?topic=43180.0
{$IFDEF FPC}
function offsetof(const stname: Pointer; const field: PUTF8Char): UInt32;
var
  rtype: TRTTIType;
  fields: TArray<TRttiField>;
  i: Integer;
begin
    rtype := TRTTIContext.Create.GetType(stname);
    fields := rtype.GetFields;

    for i := 0 to High(fields) do
      if LowerCase(fields[i].Name) = LowerCase(field) then
      begin
         //fields[i].GetValue(@Result);
         Result := fields[i].Offset;
         Break;
      end;
end;
{$ELSE}
function offsetof(const stname: Pointer; const field: PUTF8Char): UInt32;
var
  rtype: TRTTIType;
  fields: TArray<TRttiField>;
  i: Integer;
begin
    rtype := TRTTIContext.Create.GetType(stname);
    fields := rtype.GetFields;

    for i := 0 to High(fields) do
      if LowerCase(fields[i].Name) = LowerCase(field) then
      begin
         //fields[i].GetValue(@Result);
         Result := fields[i].Offset;
         Break;
      end;

end;
{$ENDIF}

function ASN1_EX_TYPE(flags: Uint32; tag: Integer; const stname: Pointer; const field: PUTF8Char; _type: Pointer): TASN1_TEMPLATE;
begin
    Result.flags      := flags;
    Result.tag        := (tag);
    Result.offset     := offsetof(stname, field);
    Result.field_name := field;
    if PTypeInfo(_type).Name = 'TX509_ALGOR' then
       Result.item    :=  Pointer(X509_ALGOR_it)
    else
    if PTypeInfo(_type).Name = 'TSM2_Ciphertext' then
       Result.item    :=  Pointer(SM2_Ciphertext_it);
end;

function ASN1_EXP_EX(const stname: Pointer; const field: PUTF8Char; _type: Pointer; tag:Byte; ex: uint32): TASN1_TEMPLATE;
begin
  Result :=  ASN1_EX_TYPE(ASN1_TFLG_IMPLICIT or (ex), tag, stname, field, _type);
end;

function ASN1_EXP_OPT(const stname: Pointer; const field: PUTF8Char; _type: Pointer; tag:Integer ): TASN1_TEMPLATE;
begin
   Result := ASN1_EXP_EX(stname, field, _type, tag, ASN1_TFLG_OPTIONAL)
end;

end.
