unit OpenSSL3.crypto.ct.ct_oct;

interface
uses OpenSSL.Api;

 function d2i_SCT_LIST(a : PPstack_st_SCT;const pp : PPByte; len : long):Pstack_st_SCT;
 function o2i_SCT_LIST(a : PPstack_st_SCT;const pp : PPByte; len : size_t):Pstack_st_SCT;
 function o2i_SCT(_psct : PPSCT;const _in : PPByte; len : size_t):PSCT;
 function o2i_SCT_signature(sct : PSCT;const _in : PPByte; len : size_t):integer;
 function i2d_SCT_LIST(const a : Pstack_st_SCT; _out : PPByte):integer;
 function i2o_SCT_LIST(const a : Pstack_st_SCT; pp : PPByte):integer;
  function i2o_SCT(const sct : PSCT; _out : PPByte):integer;
 function i2o_SCT_signature(const sct : PSCT; _out : PPByte):integer;

implementation

uses openssl3.crypto.asn1.tasn_typ, OpenSSL3.Err, openssl3.include.openssl.ct,
     OpenSSL3.crypto.ct.ct_sct, openssl3.crypto.mem, openssl3.crypto.o_str;

function i2o_SCT_signature(const sct : PSCT; _out : PPByte):integer;
var
  len : size_t;
  p, pstart : PByte;
  label _err;
begin
    p := nil; pstart := nil;
    if 0>= SCT_signature_is_complete(sct) then
    begin
        ERR_raise(ERR_LIB_CT, CT_R_SCT_INVALID_SIGNATURE);
        goto _err ;
    end;
    if sct.version <> SCT_VERSION_V1 then
    begin
        ERR_raise(ERR_LIB_CT, CT_R_UNSUPPORTED_VERSION);
        goto _err ;
    end;
    {
    * (1 byte) Hash algorithm
    * (1 byte) Signature algorithm
    * (2 bytes + ?) Signature
    }
    len := 4 + sct.sig_len;
    if _out <> nil then
    begin
        if _out^ <> nil then
        begin
            p := _out^;
            _out^  := _out^ + len;
        end
        else
        begin
            p := OPENSSL_malloc(len);
            pstart := p;
            if p = nil then
            begin
                ERR_raise(ERR_LIB_CT, ERR_R_MALLOC_FAILURE);
                goto _err ;
            end;
            _out^ := p;
        end;
        PostInc(p)^ :=  sct.hash_alg;
        PostInc(p)^ :=  sct.sig_alg;
        s2n(sct.sig_len, p);
        memcpy(p, sct.sig, sct.sig_len);
    end;
    Exit(len);
_err:
    OPENSSL_free(pstart);
    Result := -1;
end;

function i2o_SCT(const sct : PSCT; _out : PPByte):integer;
var
  len : size_t;
  p, pstart : PByte;
  label _err;
begin
    p := nil;
    pstart := nil;
    if 0>= SCT_is_complete(sct) then
    begin
        ERR_raise(ERR_LIB_CT, CT_R_SCT_NOT_SET);
        goto _err ;
    end;
    {
     * extensions; (1 byte) Hash algorithm (1 byte) Signature algorithm (2
     * bytes + ?) Signature
     }
    if sct.version = SCT_VERSION_V1 then
       len := 43 + sct.ext_len + 4 + sct.sig_len
    else
        len := sct.sct_len;
    if _out = nil then
       Exit(len);
    if _out^ <> nil then
    begin
        p := _out^;
        _out^  := _out^ + len;
    end
    else
    begin
        p := OPENSSL_malloc(len);
        pstart := p;
        if p = nil then
        begin
            ERR_raise(ERR_LIB_CT, ERR_R_MALLOC_FAILURE);
            goto _err ;
        end;
        _out^ := p;
    end;
    if sct.version = SCT_VERSION_V1 then
    begin
        PostInc(p)^ :=  Byte(sct.version);
        memcpy(p, sct.log_id, CT_V1_HASHLEN);
        p  := p + CT_V1_HASHLEN;
        l2n8(sct.timestamp, p);
        s2n(sct.ext_len, p);
        if sct.ext_len > 0 then
        begin
            memcpy(p, sct.ext, sct.ext_len);
            p  := p + sct.ext_len;
        end;
        if i2o_SCT_signature(sct, @p )  <= 0 then
            goto _err ;
    end
    else
    begin
        memcpy(p, sct.sct, len);
    end;
    Exit(len);
_err:
    OPENSSL_free(pstart);
    Result := -1;
end;


function i2o_SCT_LIST(const a : Pstack_st_SCT; pp : PPByte):integer;
var
  len,
  sct_len,
  i,
  is_pp_new : integer;
  len2      : size_t;
  p, p2     : PByte;
  label _err;
begin
    is_pp_new := 0;
    p := nil;
    if pp <> nil then
    begin
        if pp^ = nil then
        begin
            len := i2o_SCT_LIST(a, nil);
            if (len) = -1 then
            begin
                ERR_raise(ERR_LIB_CT, CT_R_SCT_LIST_INVALID);
                Exit(-1);
            end;
            pp^ := OPENSSL_malloc(len);
            if pp^ = nil then
            begin
                ERR_raise(ERR_LIB_CT, ERR_R_MALLOC_FAILURE);
                Exit(-1);
            end;
            is_pp_new := 1;
        end;
        p := pp^ + 2;
    end;
    len2 := 2;
    for i := 0 to sk_SCT_num(a)-1 do
    begin
        if pp <> nil then
        begin
            p2 := p;
            p  := p + 2;
            sct_len := i2o_SCT(sk_SCT_value(a, i) , @p);
            if sct_len = -1 then
                goto _err ;
            s2n(sct_len, p2);
        end
        else
        begin
          sct_len := i2o_SCT(sk_SCT_value(a, i) , nil);
          if sct_len = -1 then
              goto _err ;
        end;
        len2  := len2 + (2 + sct_len);
    end;
    if len2 > MAX_SCT_LIST_SIZE then
       goto _err ;
    if pp <> nil then
    begin
        p := pp^;
        s2n(len2 - 2, p);
        if 0>= is_pp_new then
           pp^  := pp^ + len2;
    end;
    Exit(len2);
 _err:
    if is_pp_new > 0 then
    begin
        OPENSSL_free(pp^);
        pp^ := nil;
    end;
    Result := -1;
end;




function i2d_SCT_LIST(const a : Pstack_st_SCT; _out : PPByte):integer;
var
  oct : TASN1_OCTET_STRING;
  len : integer;
begin
    oct.data := nil;
    oct.length := i2o_SCT_LIST(a, @oct.data);
    if oct.length = -1 then
        Exit(-1);
    len := i2d_ASN1_OCTET_STRING(@oct, _out);
    OPENSSL_free(oct.data);
    Result := len;
end;



function o2i_SCT_signature(sct : PSCT;const _in : PPByte; len : size_t):integer;
var
  siglen,
  len_remaining : size_t;
  p             : PByte;
begin
    len_remaining := len;
    if sct.version <> SCT_VERSION_V1 then
    begin
        ERR_raise(ERR_LIB_CT, CT_R_UNSUPPORTED_VERSION);
        Exit(-1);
    end;
    {
     * digitally-signed struct header: (1 byte) Hash algorithm (1 byte)
     * Signature algorithm (2 bytes + ?) Signature
     *
     * This explicitly rejects empty signatures: they're invalid for
     * all supported algorithms.
     }
    if len <= 4 then
    begin
        ERR_raise(ERR_LIB_CT, CT_R_SCT_INVALID_SIGNATURE);
        Exit(-1);
    end;
    p := _in^;
    { Get hash and signature algorithm }
    sct.hash_alg := PostInc(p)^;
    sct.sig_alg :=  PostInc(p)^;
    if SCT_get_signature_nid(sct) = NID_undef  then
    begin
        ERR_raise(ERR_LIB_CT, CT_R_SCT_INVALID_SIGNATURE);
        Exit(-1);
    end;
    { Retrieve signature and check it is consistent with the buffer length }
    n2s(p, siglen);
    len_remaining  := len_remaining - ((p - _in^));
    if siglen > len_remaining then
    begin
        ERR_raise(ERR_LIB_CT, CT_R_SCT_INVALID_SIGNATURE);
        Exit(-1);
    end;
    if SCT_set1_signature(sct, p, siglen) <> 1  then
        Exit(-1);
    len_remaining  := len_remaining - siglen;
    _in^ := p + siglen;
    Result := len - len_remaining;
end;

function o2i_SCT(_psct : PPSCT;const _in : PPByte; len : size_t):PSCT;
var
  sct : PSCT;
  p : PByte;
  sig_len : integer;
  len2 : size_t;
  label _err;
begin
    sct := nil;
    if (len = 0)  or  (len > MAX_SCT_SIZE) then
    begin
        ERR_raise(ERR_LIB_CT, CT_R_SCT_INVALID);
        goto _err ;
    end;
    sct := SCT_new();
    if sct = nil then
       goto _err ;
    p := _in^;
    sct.version := sct_version_t(p^);
    if sct.version = SCT_VERSION_V1 then
    begin
        {-
         * Fixed-length header:
         *   struct {
         *   }

        if len < 43 then
        begin
            ERR_raise(ERR_LIB_CT, CT_R_SCT_INVALID);
            goto _err ;
        end;
        len  := len - 43;
        Inc(p);
        sct.log_id := OPENSSL_memdup(p, CT_V1_HASHLEN);
        if sct.log_id = nil then
           goto _err ;
        sct.log_id_len := CT_V1_HASHLEN;
        p  := p + CT_V1_HASHLEN;
        n2l8(p, sct.timestamp);
        n2s(p, len2);
        if len < len2 then
        begin
            ERR_raise(ERR_LIB_CT, CT_R_SCT_INVALID);
            goto _err ;
        end;
        if len2 > 0 then
        begin
            sct.ext := OPENSSL_memdup(p, len2);
            if sct.ext = nil then
               goto _err ;
        end;
        sct.ext_len := len2;
        p  := p + len2;
        len  := len - len2;
        sig_len := o2i_SCT_signature(sct, @p, len);
        if sig_len <= 0 then
        begin
            ERR_raise(ERR_LIB_CT, CT_R_SCT_INVALID);
            goto _err ;
        end;
        len  := len - sig_len;
        _in^ := p + len;
    end
    else
    begin
        { If not V1 just cache encoding }
        sct.sct := OPENSSL_memdup(p, len);
        if sct.sct = nil then
           goto _err ;
        sct.sct_len := len;
        _in^ := p + len;
    end;
    if _psct <> nil then
    begin
        SCT_free(_psct^);
        _psct^ := sct;
    end;
    Exit(sct);
_err:
    SCT_free(sct);
    Result := nil;
end;

function o2i_SCT_LIST(a : PPstack_st_SCT;const pp : PPByte; len : size_t):Pstack_st_SCT;
var
  sk       : Pstack_st_SCT;
  list_len,
  sct_len  : size_t;
  sct      : PSCT;
  label _err;
begin
    sk := nil;
    if (len < 2)  or  (len > MAX_SCT_LIST_SIZE) then
    begin
        ERR_raise(ERR_LIB_CT, CT_R_SCT_LIST_INVALID);
        Exit(nil);
    end;
    n2s( pp^, list_len);
    if list_len <> len - 2 then
    begin
        ERR_raise(ERR_LIB_CT, CT_R_SCT_LIST_INVALID);
        Exit(nil);
    end;
    if (a = nil)  or  (a^ = nil) then
    begin
        sk := sk_SCT_new_null();
        if sk = nil then
           Exit(nil);
    end
    else
    begin
        { Use the given stack, but empty it first. }
        sk := a^;
        sct := sk_SCT_pop(sk);
        while (sct <> nil) do
        begin
            SCT_free(sct);
            sct := sk_SCT_pop(sk);
        end;
    end;

    while list_len > 0 do
    begin
        if list_len < 2 then
        begin
            ERR_raise(ERR_LIB_CT, CT_R_SCT_LIST_INVALID);
            goto _err ;
        end;
        n2s( pp^, sct_len);
        list_len  := list_len - 2;
        if (sct_len = 0)  or  (sct_len > list_len) then
        begin
            ERR_raise(ERR_LIB_CT, CT_R_SCT_LIST_INVALID);
            goto _err ;
        end;
        list_len  := list_len - sct_len;
        sct := o2i_SCT(nil, pp, sct_len);
        if sct = nil then
            goto _err ;
        if 0>= sk_SCT_push(sk, sct ) then
        begin
            SCT_free(sct);
            goto _err ;
        end;
    end;
    if (a <> nil)  and  (a^ = nil) then
       a^ := sk;
    Exit(sk);
 _err:
    if (a = nil)  or  (a^ = nil) then
       SCT_LIST_free(sk);
    Result := nil;
end;

function d2i_SCT_LIST(a : PPstack_st_SCT;const pp : PPByte; len : long):Pstack_st_SCT;
var
  oct : PASN1_OCTET_STRING;
  sk : Pstack_st_SCT;
  p : PByte;
begin
    oct := nil;
    sk := nil;
    p := pp^;
    if d2i_ASN1_OCTET_STRING(@oct, @p, len) = nil  then
        Exit(nil);
    p := oct.data;
    sk := o2i_SCT_LIST(a, @p, oct.length);
    if sk <> nil then
       pp^  := pp^ + len;
    ASN1_OCTET_STRING_free(oct);
    Result := sk;
end;

end.
