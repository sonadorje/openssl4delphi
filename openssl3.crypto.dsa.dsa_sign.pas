unit openssl3.crypto.dsa.dsa_sign;

interface
uses OpenSSL.Api;


function _DSA_verify(&type : integer;const dgst : PByte; dgst_len : integer;const sigbuf : PByte; siglen : integer; dsa : PDSA):integer;
function DSA_SIG_new:PDSA_SIG;
function d2i_DSA_SIG( psig : PPDSA_SIG;const ppin : PPByte; len : long):PDSA_SIG;
  function i2d_DSA_SIG(const sig : PDSA_SIG; ppout : PPByte):integer;
function DSA_do_sign(const dgst : PByte; dlen : integer; dsa : PDSA):PDSA_SIG;
 procedure DSA_SIG_free( sig : PDSA_SIG);
 function DSA_do_verify(const dgst : PByte; dgst_len : integer; sig : PDSA_SIG; dsa : PDSA):int;
 function DSA_sign(_type : integer;const dgst : PByte; dlen : integer; sig : PByte; siglen : Puint32; dsa : PDSA):integer;
 function ossl_dsa_sign_int(&type : integer;const dgst : PByte; dlen : integer; sig : PByte; siglen : Puint32; dsa : PDSA):integer;
 function DSA_size(const dsa : PDSA):integer;
 procedure DSA_SIG_get0(const sig : PDSA_SIG; pr, ps : PPBIGNUM);

implementation
uses openssl3.crypto.bn.bn_lib,openssl3.crypto.bn.bn_ctx, OpenSSL3.Err,
     openssl3.crypto.bn.bn_intern, openssl3.crypto.bn.bn_rand,
     openssl3.crypto.asn1_dsa,  openssl3.crypto.packet,
     openssl3.crypto.buffer.buffer,  openssl3.crypto.dsa.dsa_ossl,
     openssl3.crypto.bn.bn_mont, openssl3.crypto.bn.bn_add, openssl3.crypto.mem;






procedure DSA_SIG_get0(const sig : PDSA_SIG; pr, ps : PPBIGNUM);
begin
    if pr <> nil then pr^ := sig.r;
    if ps <> nil then ps^ := sig.s;
end;




function DSA_size(const dsa : PDSA):integer;
var
  ret : integer;
  sig : TDSA_SIG;
begin
    ret := -1;
    if dsa.params.q <> nil then
    begin
        sig.r := dsa.params.q; sig.s := dsa.params.q;
        ret := i2d_DSA_SIG(@sig, nil);
        if ret < 0 then ret := 0;
    end;
    Result := ret;
end;


function ossl_dsa_sign_int(&type : integer;const dgst : PByte; dlen : integer; sig : PByte; siglen : Puint32; dsa : PDSA):integer;
var
  s : PDSA_SIG;
begin
    { legacy case uses the method table }
    if (dsa.libctx = nil)  or  (dsa.meth <> DSA_get_default_method) then
        s := DSA_do_sign(dgst, dlen, dsa)
    else
        s := ossl_dsa_do_sign_int(dgst, dlen, dsa);
    if s = nil then
    begin
        siglen^ := 0;
        Exit(0);
    end;
    siglen^ := i2d_DSA_SIG(s, @sig);
    DSA_SIG_free(s);
    Result := 1;
end;




function DSA_sign(_type : integer;const dgst : PByte; dlen : integer; sig : PByte; siglen : Puint32; dsa : PDSA):integer;
begin
    Result := ossl_dsa_sign_int(_type, dgst, dlen, sig, siglen, dsa);
end;

function DSA_do_verify(const dgst : PByte; dgst_len : integer; sig : PDSA_SIG; dsa : PDSA):int;
begin
    Result := dsa.meth.dsa_do_verify(dgst, dgst_len, sig, dsa);
end;


procedure DSA_SIG_free( sig : PDSA_SIG);
begin
    if sig = nil then
       exit;
    BN_clear_free(sig.r);
    BN_clear_free(sig.s);
    OPENSSL_free(Pointer(sig));
end;





function DSA_do_sign(const dgst : PByte; dlen : integer; dsa : PDSA):PDSA_SIG;
begin
    Result := dsa.meth.dsa_do_sign(dgst, dlen, dsa);
end;




function d2i_DSA_SIG( psig : PPDSA_SIG;const ppin : PPByte; len : long):PDSA_SIG;
var
  sig : PDSA_SIG;
begin
    if len < 0 then Exit(nil);
    if (psig <> nil)  and  (psig^ <> nil) then
    begin
        sig := psig^;
    end
    else
    begin
        sig := DSA_SIG_new();
        if sig = nil then Exit(nil);
    end;
    if sig.r = nil then sig.r := BN_new();
    if sig.s = nil then sig.s := BN_new();
    if (sig.r = nil)  or  (sig.s = nil)
         or  (ossl_decode_der_dsa_sig(sig.r, sig.s, ppin, size_t( len )) = 0) then
    begin
        if (psig = nil)  or  (psig^ = nil) then
            DSA_SIG_free(sig);
        Exit(nil);
    end;
    if (psig <> nil)  and  (psig^ = nil) then
       psig^ := sig;
    Result := sig;
end;


function i2d_DSA_SIG(const sig : PDSA_SIG; ppout : PPByte):integer;
var
    buf         : PBUF_MEM;

    encoded_len : size_t;

    pkt         : TWPACKET;
begin
    buf := nil;
    if ppout = nil then
    begin
        if 0>= WPACKET_init_null(@pkt, 0) then
            Exit(-1);
    end
    else if ( ppout^ = nil) then
    begin
        buf := BUF_MEM_new();
        if  (buf  = nil)
                 or  (0>= WPACKET_init_len(@pkt, buf, 0)) then
        begin
            BUF_MEM_free(buf);
            Exit(-1);
        end;
    end
    else
    begin
        if 0>= WPACKET_init_static_len(@pkt, ppout^, SIZE_MAX, 0) then
            Exit(-1);
    end;
    if (0>= ossl_encode_der_dsa_sig(@pkt, sig.r, sig.s))  or
       (0>= WPACKET_get_total_written(@pkt, @encoded_len))      or
       (0>= WPACKET_finish(@pkt))  then
    begin
        BUF_MEM_free(buf);
        WPACKET_cleanup(@pkt);
        Exit(-1);
    end;
    if ppout <> nil then
    begin
        if ppout^ = nil then
        begin
            ppout^ := PByte( buf.data);
            buf.data := nil;
            BUF_MEM_free(buf);
        end
        else
        begin
            ppout^  := ppout^ + encoded_len;
        end;
    end;
    Result := int (encoded_len);
end;






function DSA_SIG_new:PDSA_SIG;
var
  sig : PDSA_SIG;
begin
    sig := OPENSSL_zalloc(sizeof( sig^));
    if sig = nil then
       ERR_raise(ERR_LIB_DSA, ERR_R_MALLOC_FAILURE);
    Result := sig;
end;


//与unit dsa_sig中的函数dsa_verify 重名
function _DSA_verify(&type : integer;const dgst : PByte; dgst_len : integer;const sigbuf : PByte; siglen : integer; dsa : PDSA):integer;
var
  s : PDSA_SIG;

  p, der : PByte;

  derlen, ret : integer;
  label _err;
begin
    p := sigbuf;
    der := nil;
    derlen := -1;
    ret := -1;
    s := DSA_SIG_new();
    if s = nil then Exit(ret);
    if d2i_DSA_SIG(@s, @p, siglen) = nil  then
        goto _err ;
    { Ensure signature uses DER and doesn't have trailing garbage }
    derlen := i2d_DSA_SIG(s, @der);
    if (derlen <> siglen)  or  (memcmp(sigbuf, der, derlen)>0) then
        goto _err ;
    ret := DSA_do_verify(dgst, dgst_len, s, dsa);
 _err:
    OPENSSL_clear_free(Pointer(der), derlen);
    DSA_SIG_free(s);
    Result := ret;
end;



end.
