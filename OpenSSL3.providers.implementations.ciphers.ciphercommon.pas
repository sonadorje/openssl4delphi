unit OpenSSL3.providers.implementations.ciphers.ciphercommon;

interface
uses OpenSSL.Api;

const
   MAX_PADDING = 256;
const
 PROV_CIPHER_FLAG_AEAD             = $0001;
 PROV_CIPHER_FLAG_CUSTOM_IV        = $0002;
 PROV_CIPHER_FLAG_CTS              = $0004;
 PROV_CIPHER_FLAG_TLS1_MULTIBLOCK  = $0008;
 PROV_CIPHER_FLAG_RAND_KEY         = $0010;

 PROV_CIPHER_FLAG_VARIABLE_LENGTH  = $0100;
 PROV_CIPHER_FLAG_INVERSE_CIPHER   = $0200;


 procedure ossl_cipher_generic_reset_ctx( ctx : PPROV_CIPHER_CTX);
 function ossl_cipher_generic_gettable_params( provctx : Pointer):POSSL_PARAM;
 function ossl_cipher_generic_get_params( params : POSSL_PARAM; md : uint32; flags : uint64; kbits, blkbits, ivbits : size_t):integer;
 procedure ossl_cipher_generic_initkey(vctx : Pointer; kbits, blkbits, ivbits : size_t; mode : uint32; flags : uint64;hw : PPROV_CIPHER_HW; provctx : Pointer);
 function ossl_cipher_generic_einit(vctx : Pointer;const key : PByte; keylen : size_t;const iv : PByte; ivlen : size_t;const params : POSSL_PARAM):integer;
 function cipher_generic_init_internal(ctx : PPROV_CIPHER_CTX;const key : PByte; keylen : size_t;const iv : PByte; ivlen : size_t;const params : POSSL_PARAM; enc : integer):integer;
 function ossl_cipher_generic_initiv(ctx : PPROV_CIPHER_CTX;const iv : PByte; ivlen : size_t):integer;
 function ossl_cipher_generic_set_ctx_params(vctx : Pointer;const params : POSSL_PARAM):integer;
 function ossl_cipher_generic_settable_ctx_params( cctx, provctx : Pointer):POSSL_PARAM;
 function ossl_cipher_generic_gettable_ctx_params( cctx, provctx : Pointer):POSSL_PARAM;
 function ossl_cipher_generic_block_update(vctx : Pointer; _out : PByte; outl : Psize_t; outsize : size_t; _in : PByte; inl : size_t):integer;
 function ossl_cipher_generic_block_final( vctx : Pointer; _out : PByte; outl : Psize_t; outsize : size_t):integer;
 function ossl_cipher_generic_get_ctx_params( vctx : Pointer; params : POSSL_PARAM):integer;
 function ossl_cipher_aead_gettable_ctx_params( cctx, provctx : Pointer):POSSL_PARAM;
 function ossl_cipher_aead_settable_ctx_params( cctx, provctx : Pointer):POSSL_PARAM;
 function ossl_cipher_generic_dinit(vctx : Pointer;const key : PByte; keylen : size_t;const iv : PByte; ivlen : size_t;const params : POSSL_PARAM):integer;
 function ossl_cipher_generic_cipher(vctx : Pointer; _out : PByte; outl : Psize_t; outsize : size_t;const _in : PByte; inl : size_t):int;
 function ossl_cipher_generic_stream_update(vctx : Pointer; _out : PByte; outl : Psize_t; outsize : size_t;const _in : PByte; inl : size_t):integer;
 function ossl_cipher_generic_stream_final( vctx : Pointer; _out : PByte; outl : Psize_t; outsize : size_t):integer;


var
  cipher_known_gettable_params: array[0..9] of TOSSL_PARAM ;
  cipher_aead_known_gettable_ctx_params,
  cipher_aead_known_settable_ctx_params : array of TOSSL_PARAM ;

implementation
uses OpenSSL3.openssl.params, openssl3.crypto.params, OpenSSL3.Err,
     openssl3.providers.common.provider_ctx, openssl3.crypto.mem,
     openssl3.providers.prov_running, OpenSSL3.common,
     OpenSSL3.providers.implementations.ciphers.ciphercommon_block;

function ossl_cipher_generic_stream_update(vctx : Pointer; _out : PByte; outl : Psize_t; outsize : size_t;const _in : PByte; inl : size_t):integer;
var
  ctx : PPROV_CIPHER_CTX;
begin
    ctx := PPROV_CIPHER_CTX ( vctx);
    if inl = 0 then
    begin
        outl^ := 0;
        Exit(1);
    end;
    if outsize < inl then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        Exit(0);
    end;
    if 0>= ctx.hw.cipher(ctx, _out, _in, inl)  then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
        Exit(0);
    end;
    outl^ := inl;
    if (0>= ctx.enc)  and  (ctx.tlsversion > 0) then
    begin
        {
        * Remove any TLS padding. Only used by cipher_aes_cbc_hmac_sha1_hw.c and
        * cipher_aes_cbc_hmac_sha256_hw.c
        }
        if ctx.removetlspad>0 then
        begin
            {
             * We should have already failed in the cipher() call above if this
             * isn't true.
             }
            if not ossl_assert( outl^ >= size_t(_out[inl - 1] + 1)) then
                Exit(0);
            { The actual padding length }
            outl^  := outl^ - (_out[inl - 1] + 1);
        end;
        { TLS MAC and explicit IV if relevant. We should have already failed
         * in the cipher() call above if *outl is too short.
         }
        if not ossl_assert( outl^ >= ctx.removetlsfixed) then
            Exit(0);
        outl^  := outl^ - ctx.removetlsfixed;
        { Extract the MAC if there is one }
        if ctx.tlsmacsize > 0 then
        begin
            if outl^ < ctx.tlsmacsize then
                Exit(0);
            ctx.tlsmac := _out + outl^ - ctx.tlsmacsize;
            outl^  := outl^ - ctx.tlsmacsize;
        end;
    end;
    Result := 1;
end;

function ossl_cipher_generic_stream_final( vctx : Pointer; _out : PByte; outl : Psize_t; outsize : size_t):integer;
begin
    if not ossl_prov_is_running then
        Exit(0);
    outl^ := 0;
    Result := 1;
end;

function ossl_cipher_generic_cipher(vctx : Pointer; _out : PByte; outl : Psize_t; outsize : size_t;const _in : PByte; inl : size_t):int;
var
  ctx : PPROV_CIPHER_CTX;
begin
    ctx := PPROV_CIPHER_CTX ( vctx);
    if not ossl_prov_is_running then
        Exit(0);
    if outsize < inl then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        Exit(0);
    end;
    if 0>= ctx.hw.cipher(ctx, _out, _in, inl) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
        Exit(0);
    end;
    outl^ := inl;
    Result := 1;
end;


function ossl_cipher_generic_dinit(vctx : Pointer;const key : PByte; keylen : size_t;const iv : PByte; ivlen : size_t;const params : POSSL_PARAM):integer;
begin
    Exit(cipher_generic_init_internal(PPROV_CIPHER_CTX (vctx), key, keylen,
                                        iv, ivlen, params, 0));
end;


function ossl_cipher_aead_settable_ctx_params( cctx, provctx : Pointer):POSSL_PARAM;
begin
    Result := @cipher_aead_known_settable_ctx_params[0];
end;



function ossl_cipher_aead_gettable_ctx_params( cctx, provctx : Pointer):POSSL_PARAM;
begin
    Result := @cipher_aead_known_gettable_ctx_params[0];
end;



function ossl_cipher_generic_get_ctx_params( vctx : Pointer; params : POSSL_PARAM):integer;
var
  ctx : PPROV_CIPHER_CTX;
  p : POSSL_PARAM;
begin
    ctx := PPROV_CIPHER_CTX (vctx);
    p := OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p <> nil)  and  (0>=OSSL_PARAM_set_size_t(p, ctx.ivlen)) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        Exit(0);
    end;
    p := OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_PADDING);
    if (p <> nil)  and  (0>=OSSL_PARAM_set_uint(p, ctx.pad)) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        Exit(0);
    end;
    p := OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
    if (p <> nil)    and
       (0>=OSSL_PARAM_set_octet_ptr(p, @ctx.oiv, ctx.ivlen))  and
       (0>=OSSL_PARAM_set_octet_string(p, @ctx.oiv, ctx.ivlen)) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        Exit(0);
    end;
    p := OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV);
    if (p <> nil) and  (0>=OSSL_PARAM_set_octet_ptr(p, @ctx.iv, ctx.ivlen)) and
      (0>=OSSL_PARAM_set_octet_string(p, @ctx.iv, ctx.ivlen)) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        Exit(0);
    end;
    p := OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_NUM);
    if (p <> nil)  and  (0>=OSSL_PARAM_set_uint(p, ctx.num)) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        Exit(0);
    end;
    p := OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p <> nil)  and  (0>=OSSL_PARAM_set_size_t(p, ctx.keylen)) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        Exit(0);
    end;
    p := OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_TLS_MAC);
    if (p <> nil)
         and  (0>=OSSL_PARAM_set_octet_ptr(p, ctx.tlsmac, ctx.tlsmacsize)) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        Exit(0);
    end;
    Result := 1;
end;

function ossl_cipher_generic_block_update(vctx : Pointer; _out : PByte; outl : Psize_t; outsize : size_t; _in : PByte; inl : size_t):integer;
var
  outlint    : size_t;
  ctx        : PPROV_CIPHER_CTX;
  blksz,
  nextblocks : size_t;
  padval     : Byte;
  padnum,
  loop       : size_t;
begin
    outlint := 0;
    ctx := PPROV_CIPHER_CTX ( vctx);
    blksz := ctx.blocksize;
    if ctx.tlsversion > 0 then
    begin
        {
         * Each update call corresponds to a TLS record and is individually
         * padded
         }
        { Sanity check inputs }
        if (_in = nil)
                 or  (_in <> _out)
                 or  (outsize < inl)
                 or  (0>= ctx.pad) then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
            Exit(0);
        end;
        if ctx.enc >0 then
        begin
            { Add padding }
            padnum := blksz - (inl mod blksz);
            if outsize < inl + padnum then
            begin
                ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
                Exit(0);
            end;
            if padnum > MAX_PADDING then
            begin
                ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
                Exit(0);
            end;
            padval := Byte(padnum - 1);
            if ctx.tlsversion = SSL3_VERSION then
            begin
                if padnum > 1 then
                    memset(_out + inl, 0, padnum - 1);
                (_out + inl + padnum - 1)^ := padval;
            end
            else
            begin
                { we need to add 'padnum' padding bytes of value padval }
                for loop := inl to inl + padnum-1 do
                    _out[loop] := padval;
            end;
            inl  := inl + padnum;
        end;
        if inl mod blksz  <> 0 then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
            Exit(0);
        end;
        { Shouldn't normally fail }
        if 0>= ctx.hw.cipher(ctx, _out, _in, inl)  then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
            Exit(0);
        end;
        if ctx.alloced >0 then
        begin
            OPENSSL_free(Pointer(ctx.tlsmac));
            ctx.alloced := 0;
            ctx.tlsmac := nil;
        end;
        { This only fails if padding is publicly invalid }
        outl^ := inl;
        if (0>= ctx.enc)
             and  (0>= ossl_cipher_tlsunpadblock(ctx.libctx, ctx.tlsversion,
                                          _out, outl,
                                          blksz, @ctx.tlsmac, @ctx.alloced,
                                          ctx.tlsmacsize, 0))  then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
            Exit(0);
        end;
        Exit(1);
    end;
    if ctx.bufsz <> 0 then
       nextblocks := ossl_cipher_fillblock(@ctx.buf, @ctx.bufsz, blksz,
                                           @_in, @inl)
    else
        nextblocks := inl and (not (blksz-1));
    {
     * If we're decrypting and we end an update on a block boundary we hold
     * the last block back in case this is the last update call and the last
     * block is padded.
     }
    if (ctx.bufsz = blksz)  and ( (ctx.enc>0)  or (inl > 0)  or  (0>= ctx.pad)) then
    begin
        if outsize < blksz then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
            Exit(0);
        end;
        if 0>= ctx.hw.cipher(ctx, _out, @ctx.buf, blksz )then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
            Exit(0);
        end;
        ctx.bufsz := 0;
        outlint := blksz;
        _out  := _out + blksz;
    end;
    if nextblocks > 0 then
    begin
        if (0>= ctx.enc)  and  (ctx.pad>0)  and  (nextblocks = inl) then
        begin
            if not ossl_assert(inl >= blksz) then
            begin
                ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
                Exit(0);
            end;
            nextblocks  := nextblocks - blksz;
        end;
        outlint  := outlint + nextblocks;
        if outsize < outlint then begin
            ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
            Exit(0);
        end;
    end;
    if nextblocks > 0 then
    begin
        if 0>= ctx.hw.cipher(ctx, _out, _in, nextblocks) then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
            Exit(0);
        end;
        _in  := _in + nextblocks;
        inl  := inl - nextblocks;
    end;
    if (inl <> 0)
         and  (0>= ossl_cipher_trailingdata(@ctx.buf, @ctx.bufsz, blksz, @_in, @inl)) then
    begin
        { ERR_raise already called }
        Exit(0);
    end;
    outl^ := outlint;
    Result := int(inl = 0);
end;


function ossl_cipher_generic_block_final( vctx : Pointer; _out : PByte; outl : Psize_t; outsize : size_t):integer;
var
  ctx : PPROV_CIPHER_CTX;
  blksz : size_t;
begin
    ctx := PPROV_CIPHER_CTX ( vctx);
    blksz := ctx.blocksize;
    if not ossl_prov_is_running then
        Exit(0);
    if ctx.tlsversion > 0 then
    begin
        { We never finalize TLS, so this is an error }
        ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
        Exit(0);
    end;
    if ctx.enc >0 then
    begin
        if ctx.pad >0 then
        begin
            ossl_cipher_padblock(@ctx.buf, @ctx.bufsz, blksz);
        end
        else
        if (ctx.bufsz = 0) then
        begin
            outl^ := 0;
            Exit(1);
        end
        else
        if (ctx.bufsz <> blksz) then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_WRONG_FINAL_BLOCK_LENGTH);
            Exit(0);
        end;
        if outsize < blksz then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
            Exit(0);
        end;
        if 0>= ctx.hw.cipher(ctx, _out, @ctx.buf, blksz)  then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
            Exit(0);
        end;
        ctx.bufsz := 0;
        outl^ := blksz;
        Exit(1);
    end;
    { Decrypting }
    if ctx.bufsz <> blksz then
    begin
        if (ctx.bufsz = 0)  and  (0>= ctx.pad) then
        begin
            outl^ := 0;
            Exit(1);
        end;
        ERR_raise(ERR_LIB_PROV, PROV_R_WRONG_FINAL_BLOCK_LENGTH);
        Exit(0);
    end;

    if 0>= ctx.hw.cipher(ctx, @ctx.buf, @ctx.buf, blksz) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
        Exit(0);
    end;
    if (ctx.pad > 0)  and  (0 >= ossl_cipher_unpadblock(@ctx.buf, @ctx.bufsz, blksz)) then
    begin
        { ERR_raise already called }
        Exit(0);
    end;
    if outsize < ctx.bufsz then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        Exit(0);
    end;
    memcpy(_out, @ctx.buf, ctx.bufsz);
    outl^ := ctx.bufsz;
    ctx.bufsz := 0;
    Result := 1;
end;


function ossl_cipher_generic_gettable_ctx_params( cctx, provctx : Pointer):POSSL_PARAM;
var
  ossl_cipher_generic_known_gettable_ctx_params: array of TOSSL_PARAM ;
begin
   ossl_cipher_generic_known_gettable_ctx_params := [
      _OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, nil),
      _OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, nil),
      _OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, nil),
      _OSSL_PARAM_uint(OSSL_CIPHER_PARAM_NUM, nil),
      _OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, nil, 0),
      _OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, nil, 0),
      OSSL_PARAM_DEFN( OSSL_CIPHER_PARAM_TLS_MAC, OSSL_PARAM_OCTET_PTR, nil, 0),
      OSSL_PARAM_END
   ];
    Result := @ossl_cipher_generic_known_gettable_ctx_params;
end;



function ossl_cipher_generic_settable_ctx_params( cctx, provctx : Pointer):POSSL_PARAM;
var
  ossl_cipher_generic_known_settable_ctx_params: array of TOSSL_PARAM ;
begin
    ossl_cipher_generic_known_settable_ctx_params := [
        _OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, nil),
        _OSSL_PARAM_uint(OSSL_CIPHER_PARAM_NUM, nil),
        _OSSL_PARAM_uint(OSSL_CIPHER_PARAM_USE_BITS, nil),
        _OSSL_PARAM_uint(OSSL_CIPHER_PARAM_TLS_VERSION, nil),
        _OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_TLS_MAC_SIZE, nil),
        OSSL_PARAM_END];
    Result := @ossl_cipher_generic_known_settable_ctx_params;
end;




function ossl_cipher_generic_set_ctx_params(vctx : Pointer;const params : POSSL_PARAM):integer;
var
  ctx : PPROV_CIPHER_CTX;
  p   : POSSL_PARAM;
  pad, bits, num : uint32;
begin
    ctx := PPROV_CIPHER_CTX ( vctx);
    if params = nil then Exit(1);
    p := OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_PADDING);
    if p <> nil then
    begin
        if 0>= OSSL_PARAM_get_uint(p, @pad) then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            Exit(0);
        end;
        ctx.pad := get_result(pad >0, 1 , 0);
    end;
    p := OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_USE_BITS);
    if p <> nil then
    begin
        if 0>= OSSL_PARAM_get_uint(p, @bits) then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            Exit(0);
        end;
        ctx.use_bits := get_result( bits >0, 1 , 0);
    end;
    p := OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_TLS_VERSION);
    if p <> nil then
    begin
        if 0>= OSSL_PARAM_get_uint(p, @ctx.tlsversion) then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            Exit(0);
        end;
    end;
    p := OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_TLS_MAC_SIZE);
    if p <> nil then
    begin
        if 0>= OSSL_PARAM_get_size_t(p, @ctx.tlsmacsize) then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            Exit(0);
        end;
    end;
    p := OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_NUM);
    if p <> nil then
    begin
        if 0>= OSSL_PARAM_get_uint(p, @num) then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            Exit(0);
        end;
        ctx.num := num;
    end;
    Result := 1;
end;




function ossl_cipher_generic_initiv(ctx : PPROV_CIPHER_CTX;const iv : PByte; ivlen : size_t):integer;
begin
    if (ivlen <> ctx.ivlen)
         or  (ivlen > sizeof(ctx.iv)) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
        Exit(0);
    end;
    ctx.iv_set := 1;
    memcpy(@ctx.iv, iv, ivlen);
    memcpy(@ctx.oiv, iv, ivlen);
    Result := 1;
end;



function cipher_generic_init_internal(ctx : PPROV_CIPHER_CTX;const key : PByte; keylen : size_t;const iv : PByte; ivlen : size_t;const params : POSSL_PARAM; enc : integer):integer;
begin
    ctx.num := 0;
    ctx.bufsz := 0;
    ctx.updated := 0;
    ctx.enc := get_result(enc >0, 1 , 0);
    if not ossl_prov_is_running then
        Exit(0);
    if (iv <> nil)  and  (ctx.mode <> EVP_CIPH_ECB_MODE) then
    begin
        if 0>= ossl_cipher_generic_initiv(ctx, iv, ivlen) then
            Exit(0);
    end;
    if (iv = nil)  and  (ctx.iv_set>0)  and
       ( (ctx.mode = EVP_CIPH_CBC_MODE)
             or  (ctx.mode = EVP_CIPH_CFB_MODE)
             or  (ctx.mode = EVP_CIPH_OFB_MODE) ) then
        { reset IV for these modes to keep compatibility with 1.1.1 }
        memcpy(@ctx.iv, @ctx.oiv, ctx.ivlen);
    if key <> nil then
    begin
        if ctx.variable_keylength = 0 then
        begin
            if keylen <> ctx.keylen then
            begin
                ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
                Exit(0);
            end;
        end
        else
        begin
            ctx.keylen := keylen;
        end;
        if 0>= ctx.hw.init(ctx, key, ctx.keylen) then
            Exit(0);
    end;
    Result := ossl_cipher_generic_set_ctx_params(ctx, params);
end;





function ossl_cipher_generic_einit(vctx : Pointer;const key : PByte; keylen : size_t;const iv : PByte; ivlen : size_t;const params : POSSL_PARAM):integer;
begin
    Exit(cipher_generic_init_internal(PPROV_CIPHER_CTX ( vctx), key, keylen,
                                        iv, ivlen, params, 1));
end;



procedure ossl_cipher_generic_reset_ctx( ctx : PPROV_CIPHER_CTX);
begin
    if (ctx <> nil)  and  (ctx.alloced >0) then
    begin
        OPENSSL_free(Pointer(ctx.tlsmac));
        ctx.alloced := 0;
        ctx.tlsmac := nil;
    end;
end;




procedure ossl_cipher_generic_initkey(vctx : Pointer; kbits, blkbits, ivbits : size_t; mode : uint32; flags : uint64;hw : PPROV_CIPHER_HW; provctx : Pointer);
var
  ctx : PPROV_CIPHER_CTX;
begin
    ctx := PPROV_CIPHER_CTX (vctx);
    if (flags and PROV_CIPHER_FLAG_INVERSE_CIPHER) <> 0 then
        ctx.inverse_cipher := 1;
    if (flags and PROV_CIPHER_FLAG_VARIABLE_LENGTH) <> 0 then
        ctx.variable_keylength := 1;
    ctx.pad := 1;
    ctx.keylen := ((kbits) div 8);
    ctx.ivlen := ((ivbits) div 8);
    ctx.hw := hw;
    ctx.mode := mode;
    ctx.blocksize := blkbits div 8;
    if provctx <> nil then
       ctx.libctx := PROV_LIBCTX_OF(provctx); { used for rand }
end;



function ossl_cipher_generic_get_params( params : POSSL_PARAM; md : uint32; flags : uint64; kbits, blkbits, ivbits : size_t):integer;
var
  p : POSSL_PARAM;
begin
    p := OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE);
    if (p <> nil)  and  (0>= OSSL_PARAM_set_uint(p, md) ) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        Exit(0);
    end;
    p := OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD);
    if (p <> nil)   and
       (0>= OSSL_PARAM_set_int(p, Int( (flags and PROV_CIPHER_FLAG_AEAD) <> 0))) then
       begin
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        Exit(0);
    end;
    p := OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_CUSTOM_IV);
    if (p <> nil)
         and  (0>= OSSL_PARAM_set_int(p, Int( (flags and PROV_CIPHER_FLAG_CUSTOM_IV) <> 0))) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        Exit(0);
    end;
    p := OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_CTS);
    if (p <> nil)
         and  (0>= OSSL_PARAM_set_int(p, Int( (flags and PROV_CIPHER_FLAG_CTS) <> 0))) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        Exit(0);
    end;
    p := OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK);
    if (p <> nil)
         and  (0>= OSSL_PARAM_set_int(p, Int((flags and PROV_CIPHER_FLAG_TLS1_MULTIBLOCK ) <> 0)))then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        Exit(0);
    end;
    p := OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_HAS_RAND_KEY);
    if (p <> nil)
         and  (0>= OSSL_PARAM_set_int(p, Int((flags and PROV_CIPHER_FLAG_RAND_KEY) <> 0))) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        Exit(0);
    end;
    p := OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p <> nil)  and  (0>= OSSL_PARAM_set_size_t(p, kbits div 8) ) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        Exit(0);
    end;
    p := OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
    if (p <> nil)  and  (0>= OSSL_PARAM_set_size_t(p, blkbits div 8)) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        Exit(0);
    end;
    p := OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p <> nil)  and  (0>= OSSL_PARAM_set_size_t(p, ivbits div 8)) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        Exit(0);
    end;
    Result := 1;
end;

function ossl_cipher_generic_gettable_params( provctx : Pointer):POSSL_PARAM;
begin
    Result := @cipher_known_gettable_params;
end;

initialization
   cipher_known_gettable_params[0] := _OSSL_PARAM_uint(OSSL_CIPHER_PARAM_MODE, nil);
  cipher_known_gettable_params[1] := _OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, nil);
  cipher_known_gettable_params[2] := _OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, nil);
  cipher_known_gettable_params[3] := _OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, nil);
  cipher_known_gettable_params[4] := _OSSL_PARAM_int(OSSL_CIPHER_PARAM_AEAD, nil);
  cipher_known_gettable_params[5] := _OSSL_PARAM_int(OSSL_CIPHER_PARAM_CUSTOM_IV, nil);
  cipher_known_gettable_params[6] := _OSSL_PARAM_int(OSSL_CIPHER_PARAM_CTS, nil);
  cipher_known_gettable_params[7] := _OSSL_PARAM_int(OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK, nil);
  cipher_known_gettable_params[8] := _OSSL_PARAM_int(OSSL_CIPHER_PARAM_HAS_RAND_KEY, nil);
  cipher_known_gettable_params[9] := OSSL_PARAM_END ;

  cipher_aead_known_gettable_ctx_params := [
    _OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, nil),
    _OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, nil),
    _OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, nil),
    _OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, nil, 0),
    _OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, nil, 0),
    _OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, nil, 0),
    _OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD, nil),
    _OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_GET_IV_GEN, nil, 0),
    OSSL_PARAM_END
  ];

  cipher_aead_known_settable_ctx_params := [
    _OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN, nil),
    _OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, nil, 0),
    _OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD, nil, 0),
    _OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED, nil, 0),
    _OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_SET_IV_INV, nil, 0),
    OSSL_PARAM_END
  ];
end.
