unit OpenSSL3.crypto.x509.v3_lib;

interface
 uses OpenSSL.Api;


  function X509V3_get_d2i(const x : Pstack_st_X509_EXTENSION; nid : integer; crit, idx : PInteger):Pointer;
  function X509V3_add1_i2d( x : PPstack_st_X509_EXTENSION; nid : integer; value : Pointer; crit : integer; flags : Cardinal):integer;
  function X509V3_EXT_d2i( ext : PX509_EXTENSION):Pointer;
  function X509V3_EXT_get( ext : PX509_EXTENSION):PX509V3_EXT_METHOD;
  function X509V3_EXT_get_nid( nid : integer):PX509V3_EXT_METHOD;
  function ext_cmp_BSEARCH_CMP_FN(const a_, b_ : Pointer):integer;
  function OBJ_bsearch_ext(const key, base : PPX509V3_EXT_METHOD; num : integer):PPX509V3_EXT_METHOD;
  function ext_cmp(const a, b : PPX509V3_EXT_METHOD):integer;

var
   ext_list: Pstack_st_X509V3_EXT_METHOD = nil;

implementation
uses openssl3.crypto.x509, openssl3.crypto.objects.obj_dat,
     openssl3.crypto.x509.x509_v3, OpenSSL3.Err,
     OpenSSL3.crypto.x509.x_exten,
     OpenSSL3.crypto.x509.v3_conf,  openssl3.crypto.x509.x_x509,
     openssl3.crypto.asn1.asn1_lib, openssl3.crypto.asn1.tasn_dec,
     openssl3.crypto.x509.standard_exts;





function ext_cmp(const a, b : PPX509V3_EXT_METHOD):integer;
begin
    Result := ((a^).ext_nid - (b^).ext_nid);
end;


function ext_cmp_BSEARCH_CMP_FN(const a_, b_ : Pointer):integer;
var
  a, b : PPX509V3_EXT_METHOD;
begin
   a := a_;
   b := b_;
   result := ext_cmp(a,b);
end;


function OBJ_bsearch_ext(const key, base : PPX509V3_EXT_METHOD; num : integer):PPX509V3_EXT_METHOD;
begin
   Result := PPX509V3_EXT_METHOD(OBJ_bsearch_(key, base, num,
                   sizeof(PX509V3_EXT_METHOD), ext_cmp_BSEARCH_CMP_FN));
end;



function X509V3_EXT_get_nid( nid : integer):PX509V3_EXT_METHOD;
var
  tmp : TX509V3_EXT_METHOD;
  t : PX509V3_EXT_METHOD;
  ret : PPX509V3_EXT_METHOD;
  idx : integer;
begin
    t := @tmp;
    if nid < 0 then Exit(nil);
    tmp.ext_nid := nid;
    ret := OBJ_bsearch_ext(@t, @standard_exts, Length(standard_exts));
    if ret <> nil then
       Exit(ret^);
    if nil = ext_list then
       Exit(nil);
    idx := sk_X509V3_EXT_METHOD_find(ext_list, @tmp);
    Result := sk_X509V3_EXT_METHOD_value(ext_list, idx);
end;




function X509V3_EXT_get( ext : PX509_EXTENSION):PX509V3_EXT_METHOD;
var
  nid : integer;
begin
    nid := OBJ_obj2nid(X509_EXTENSION_get_object(ext));
    if nid = NID_undef then
        Exit(nil);
    Result := X509V3_EXT_get_nid(nid);
end;

function X509V3_EXT_d2i( ext : PX509_EXTENSION):Pointer;
var
    method   : PX509V3_EXT_METHOD;
    p        : PByte;
    extvalue : PASN1_STRING;
    extlen   : integer;
begin
    method := X509V3_EXT_get(ext);
    if method =  nil then
        Exit(nil);
    extvalue := X509_EXTENSION_get_data(ext);
    p := ASN1_STRING_get0_data(extvalue);
    extlen := ASN1_STRING_length(extvalue);
    if Assigned(method.it) then
       Exit(ASN1_item_d2i(nil, @p, extlen, method.it));
    Result := method.d2i(nil, @p, extlen);
end;

function X509V3_get_d2i(const x : Pstack_st_X509_EXTENSION; nid : integer; crit, idx : PInteger):Pointer;
var
  lastpos,
  i        : integer;
  ex,
  found_ex : PX509_EXTENSION;
begin
    found_ex := nil;
    if nil = x then
    begin
        if idx <> nil then
           idx^ := -1;
        if crit <> nil then
           crit^ := -1;
        Exit(nil);
    end;
    if idx <> nil then
       lastpos := idx^ + 1
    else
        lastpos := 0;
    if lastpos < 0 then
       lastpos := 0;
    for i := lastpos to sk_X509_EXTENSION_num(x)-1 do
    begin
        ex := sk_X509_EXTENSION_value(x, i);
        if OBJ_obj2nid(X509_EXTENSION_get_object(ex)) = nid  then
        begin
            if idx <> nil then
            begin
                idx^ := i;
                found_ex := ex;
                break;
            end
            else
            if (found_ex) <> nil then
            begin
                { Found more than one }
                if crit <> nil then
                   crit^ := -2;
                Exit(nil);
            end;
            found_ex := ex;
        end;
    end;
    if found_ex <> nil then
    begin
        { Found it }
        if crit <> nil then
           crit^ := X509_EXTENSION_get_critical(found_ex);
        Exit(X509V3_EXT_d2i(found_ex));
    end;
    { Extension not found }
    if idx <> nil then
       idx^ := -1;
    if crit <> nil then
       crit^ := -1;
    Result := nil;
end;


function X509V3_add1_i2d( x : PPstack_st_X509_EXTENSION; nid : integer; value : Pointer; crit : integer; flags : Cardinal):integer;
var
  errcode, extidx : integer;
  ext, extmp : PX509_EXTENSION;
  ret : Pstack_st_X509_EXTENSION;
  ext_op : Cardinal;
  label _err, _m_fail;
begin
    extidx := -1;
    ext := nil;
    ret := nil;
    ext_op := flags and X509V3_ADD_OP_MASK;
    {
     * If appending we don't care if it exists, otherwise look for existing
     * extension.
     }
    if ext_op <> X509V3_ADD_APPEND then
       extidx := X509v3_get_ext_by_NID(x^, nid, -1);
    { See if extension exists }
    if extidx >= 0 then
    begin
        { If keep existing, nothing to do }
        if ext_op = X509V3_ADD_KEEP_EXISTING then
            Exit(1);
        { If default then its an error }
        if ext_op = X509V3_ADD_DEFAULT then begin
            errcode := X509V3_R_EXTENSION_EXISTS;
            goto _err ;
        end;
        { If delete, just delete it }
        if ext_op = X509V3_ADD_DELETE then
        begin
            if nil = sk_X509_EXTENSION_delete(x^, extidx) then
                Exit(-1);
            Exit(1);
        end;
    end
    else
    begin
        {
         * If replace existing or delete, error since extension must exist
         }
        if (ext_op = X509V3_ADD_REPLACE_EXISTING )  or
           (ext_op = X509V3_ADD_DELETE) then
        begin
            errcode := X509V3_R_EXTENSION_NOT_FOUND;
            goto _err ;
        end;
    end;
    {
     * If we get this far then we have to create an extension: could have
     * some flags for alternative encoding schemes...
     }
    ext := X509V3_EXT_i2d(nid, crit, value);
    if nil = ext then
    begin
        ERR_raise(ERR_LIB_X509V3, X509V3_R_ERROR_CREATING_EXTENSION);
        Exit(0);
    end;
    { If extension exists replace it.. }
    if extidx >= 0 then
    begin
        extmp := sk_X509_EXTENSION_value(x^, extidx);
        X509_EXTENSION_free(extmp);
        if nil = sk_X509_EXTENSION_set(x^, extidx, ext) then
            Exit(-1);
        Exit(1);
    end;
    ret := x^;
    ret := sk_X509_EXTENSION_new_null();
    if (x^ = nil) and  (ret = nil) then
        goto _m_fail ;
    if 0>= sk_X509_EXTENSION_push(ret, ext) then
        goto _m_fail ;
    x^ := ret;
    Exit(1);
 _m_fail:
    { ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE); }
    if ret <> x^ then
       sk_X509_EXTENSION_free(ret);
    X509_EXTENSION_free(ext);
    Exit(-1);
 _err:
    if 0>= (flags and X509V3_ADD_SILENT) then
        ERR_raise(ERR_LIB_X509V3, errcode);
    Result := 0;
end;


end.
