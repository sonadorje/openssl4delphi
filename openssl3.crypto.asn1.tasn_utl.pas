unit openssl3.crypto.asn1.tasn_utl;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses
   OpenSSL.Api;

 function ossl_asn1_get_choice_selector_const(const pval : PPASN1_VALUE; it : PASN1_ITEM):integer;
 function ossl_asn1_get_const_field_ptr(const pval : PPASN1_VALUE; tt : PASN1_TEMPLATE):PPASN1_VALUE;
 function ossl_asn1_enc_restore(len : PInteger; &out : PPByte;const pval : PPASN1_VALUE; it : PASN1_ITEM):integer;
 function asn1_get_const_enc_ptr(const pval : PPASN1_VALUE; it : PASN1_ITEM):PASN1_ENCODING;
 function ossl_asn1_do_adb(const val : PASN1_VALUE; tt : PASN1_TEMPLATE; nullerr : integer):PASN1_TEMPLATE;
  function ossl_asn1_get_choice_selector(pval : PPASN1_VALUE;const it : PASN1_ITEM):integer;
 function ossl_asn1_get_field_ptr(pval : PPASN1_VALUE;const tt : PASN1_TEMPLATE):PPASN1_VALUE;
 function ossl_asn1_do_lock(pval : PPASN1_VALUE; op : integer;const it : PASN1_ITEM):integer;
 function offset2ptr(addr: Pointer; offset: Integer): Pointer;
  procedure ossl_asn1_enc_free(pval : PPASN1_VALUE;const it : PASN1_ITEM);
  function asn1_get_enc_ptr(pval : PPASN1_VALUE;const it : PASN1_ITEM):PASN1_ENCODING;
  function ossl_asn1_set_choice_selector(pval : PPASN1_VALUE; value : integer;const it : PASN1_ITEM):integer;
  procedure ossl_asn1_enc_init(pval : PPASN1_VALUE;const it : PASN1_ITEM);
 function ossl_asn1_enc_save(pval : PPASN1_VALUE;const _in : PByte; inlen : integer;const it : PASN1_ITEM):integer;

implementation

uses
  openssl3.crypto.stack,             openssl3.include.internal.refcount,
  OpenSSL3.Err, openssl3.crypto.mem, OpenSSL3.threads_none,
  openssl3.crypto.objects.obj_dat,   openssl3.crypto.asn1.tasn_typ,
  openssl3.crypto.asn1.a_int;

function ossl_asn1_enc_save(pval : PPASN1_VALUE;const _in : PByte; inlen : integer;const it : PASN1_ITEM):integer;
var
  enc : PASN1_ENCODING;
begin
    enc := asn1_get_enc_ptr(pval, it);
    if enc = nil then
       Exit(1);
    OPENSSL_free(enc.enc);
    if inlen <= 0 then
       Exit(0);
    enc.enc := OPENSSL_malloc(inlen );
    if enc.enc = nil then
    begin
        ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    memcpy(enc.enc, _in, inlen);
    enc.len := inlen;
    enc.modified := 0;
    Result := 1;
end;

procedure ossl_asn1_enc_init(pval : PPASN1_VALUE;const it : PASN1_ITEM);
var
  enc : PASN1_ENCODING;
begin
    enc := asn1_get_enc_ptr(pval, it);
    if enc <> nil then begin
        enc.enc := nil;
        enc.len := 0;
        enc.modified := 1;
    end;
end;

function offset2ptr(addr: Pointer; offset: Integer): Pointer;
begin
   Result := Pointer(NativeUInt(addr) + offset)
end;



function ossl_asn1_set_choice_selector(pval : PPASN1_VALUE; value : integer;const it : PASN1_ITEM):integer;
var
  sel : PInteger;
  ret : Integer;
begin
    sel := offset2ptr( pval^, it.utype);
    ret := sel^;
    sel^ := value;
    Result := ret;
end;

function asn1_get_enc_ptr(pval : PPASN1_VALUE;const it : PASN1_ITEM):PASN1_ENCODING;
var
  aux : PASN1_AUX;
begin
    if (pval = nil)  or  (pval^ = nil) then Exit(nil);
    aux := it.funcs;
    if (aux = nil)  or  ( (aux.flags and ASN1_AFLG_ENCODING) = 0) then
        Exit(nil);
    Result := offset2ptr( pval^, aux.enc_offset);
end;




procedure ossl_asn1_enc_free(pval : PPASN1_VALUE;const it : PASN1_ITEM);
var
  enc : PASN1_ENCODING;
begin
    enc := asn1_get_enc_ptr(pval, it);
    if enc <> nil then
    begin
        OPENSSL_free(Pointer(enc.enc));
        enc.enc := nil;
        enc.len := 0;
        enc.modified := 1;
    end;
end;




function ossl_asn1_do_lock(pval : PPASN1_VALUE; op : integer;const it : PASN1_ITEM):integer;
var
  aux : PASN1_AUX;
  lck : PCRYPTO_REF_COUNT;
  lock : PPCRYPTO_RWLOCK;
  ret : integer;
begin
    ret := -1;
    if (it.itype <> ASN1_ITYPE_SEQUENCE) and  (it.itype <> ASN1_ITYPE_NDEF_SEQUENCE) then
        Exit(0);
    aux := it.funcs;
    if (aux = nil)  or  ( (aux.flags and ASN1_AFLG_REFCOUNT) = 0)  then
        Exit(0);
    lck := offset2ptr( pval^, aux.ref_offset);
    lock := offset2ptr( pval^, aux.ref_lock);
    case op of
        0:
        begin
            lck^ := 1; ret := 1;
            lock^ := CRYPTO_THREAD_lock_new();
            if lock^ = nil then
            begin
                ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
                Exit(-1);
            end;
        end;
        1:
        begin
            if 0>= CRYPTO_UP_REF(lck^, ret, lock^) then
                Exit(-1);
        end;
        -1:
        begin
            if 0>= CRYPTO_DOWN_REF(lck^, ret, lock^) then Exit(-1);  { failed }
            REF_PRINT_EX(it.sname, ret, Pointer( it));
            REF_ASSERT_ISNT(ret < 0);
            if ret = 0 then
            begin
                CRYPTO_THREAD_lock_free(lock^);
                lock^ := nil;
            end;
        end;
    end;
    Result := ret;
end;

function ossl_asn1_get_field_ptr(pval : PPASN1_VALUE;const tt : PASN1_TEMPLATE):PPASN1_VALUE;
var
  pvaltmp : PPASN1_VALUE;
begin
    pvaltmp := offset2ptr( pval^, tt.offset);
    //pvaltmp := Pointer(NativeUInt(pval^) + tt.offset);

    {
     * NOTE for BOOLEAN types the field is just a plain int so we can't
     * return PInteger *, so settle for (PInteger ).
     }
    Result := pvaltmp;
end;



function ossl_asn1_get_choice_selector(pval : PPASN1_VALUE;const it : PASN1_ITEM):integer;
var
  sel : PInteger;
begin
    sel := offset2ptr( pval^, it.utype);
    Result := sel^;
end;

function ossl_asn1_do_adb(const val : PASN1_VALUE; tt : PASN1_TEMPLATE; nullerr : integer):PASN1_TEMPLATE;
var
    adb      : PASN1_ADB;
    atbl     : PASN1_ADB_TABLE;
    selector : long;
    sfld     : PPASN1_VALUE;
    i        : integer;
    it       : PASN1_ITEM;
    label _err;
begin
    if (tt.flags and ASN1_TFLG_ADB_MASK) = 0 then
        Exit(tt);
    { Else ANY DEFINED BY ... get the table }
    it := tt.item();
    adb := PASN1_ADB(it);
    { Get the selector field }
    sfld := offset2ptr(val, adb.offset);
    { Check if nil }
    if sfld^ = nil then
    begin
        if adb.null_tt = nil then
            goto _err ;
        Exit(adb.null_tt);
    end;
    {
     * Convert type to a long: NB: don't check for NID_undef here because it
     * might be a legitimate value in the table
     }
    if (tt.flags and ASN1_TFLG_ADB_OID) <> 0 then
        selector := OBJ_obj2nid(PASN1_OBJECT(sfld^))
    else
        selector := ASN1_INTEGER_get(PASN1_INTEGER(sfld^));
    { Let application callback translate value }
    if (Assigned(adb.adb_cb))  and  (adb.adb_cb(@selector) = 0)  then
    begin
        ERR_raise(ERR_LIB_ASN1, ASN1_R_UNSUPPORTED_ANY_DEFINED_BY_TYPE);
        Exit(nil);
    end;
    {
     * Try to find matching entry in table Maybe should check application
     * types first to allow application override? Might also be useful to
     * have a flag which indicates table is sorted and we can do a binary
     * search. For now stick to a linear search.
     }
     atbl := adb.tbl;
    for i := 0 to adb.tblcount-1 do
    begin
        if atbl.value = selector then
           Exit(@atbl.tt);
        Inc(atbl);
    end;
    { FIXME: need to search application table too }
    { No match, return default type }
    if nil = adb.default_tt then goto _err ;
    Exit(adb.default_tt);
 _err:
    { FIXME: should log the value or OID of unsupported type }
    if nullerr>0 then
       ERR_raise(ERR_LIB_ASN1, ASN1_R_UNSUPPORTED_ANY_DEFINED_BY_TYPE);
    Result := nil;
end;

function asn1_get_const_enc_ptr(const pval : PPASN1_VALUE; it : PASN1_ITEM):PASN1_ENCODING;
var
  aux : PASN1_AUX;
begin
    if (pval = nil)  or  (pval^ = nil) then Exit(nil);
    aux := it.funcs;
    if (aux = nil)  or  ((aux.flags and ASN1_AFLG_ENCODING) = 0)  then
        Exit(nil);
    Result := offset2ptr( pval^, aux.enc_offset);
end;



function ossl_asn1_enc_restore(len : PInteger; &out : PPByte;const pval : PPASN1_VALUE; it : PASN1_ITEM):integer;
var
  enc : PASN1_ENCODING;
begin
     enc := asn1_get_const_enc_ptr(pval, it);
    if (enc = nil)  or  (enc.modified>0) then
        Exit(0);
    if Assigned(&out) then
    begin
        memcpy( &out^, enc.enc, enc.len);
        &out^  := &out^ + enc.len;
    end;
    if len <> nil then
       len^ := enc.len;
    Result := 1;
end;



function ossl_asn1_get_const_field_ptr(const pval : PPASN1_VALUE; tt : PASN1_TEMPLATE):PPASN1_VALUE;
begin
    Result := offset2ptr(pval^, tt.offset);
end;

function ossl_asn1_get_choice_selector_const(const pval : PPASN1_VALUE; it : PASN1_ITEM):integer;
var
  sel : PInteger;
begin
    sel := offset2ptr( pval^, it.utype);
    Result := sel^;
end;





end.
