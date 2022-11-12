program demo_rsa_encrypt;

{$APPTYPE CONSOLE}

uses
  {$IFDEF EurekaLog}
  EMemLeaks,
  EResLeaks,
  EDebugExports,
  EDebugJCL,
  EFixSafeCallException,
  EMapWin32,
  EAppConsole,
  EDialogConsole,
  ExceptionLog7,
  {$ENDIF EurekaLog}

  {$I openssl4d.inc}

  SysUtils
  ;

const msg: PAnsiChar =
    'To be, or not to be, that is the question,'#10+
    'Whether tis nobler in the minde to suffer'#10+
    'The slings and arrowes of outragious fortune,'#10 +
    'Or to take Armes again in a sea of troubles';
const // 1d arrays
  priv_key_der : array[0..1191] of byte = (
    $30, $82, $04, $a4, $02, $01, $00, $02, $82, $01, $01, $00, $c2, $44,
    $bc, $cf, $5b, $ca, $cd, $80, $77, $ae, $f9, $7a, $34, $bb, $37, $6f,
    $5c, $76, $4c, $e4, $bb, $0c, $1d, $e7, $fe, $0f, $da, $cf, $8c, $56,
    $65, $72, $6e, $2c, $f9, $fd, $87, $43, $eb, $4c, $26, $b1, $d3, $f0,
    $87, $b1, $18, $68, $14, $7d, $3c, $2a, $fa, $c2, $5d, $70, $19, $11,
    $00, $2e, $b3, $9c, $8e, $38, $08, $be, $e3, $eb, $7d, $6e, $c7, $19,
    $c6, $7f, $59, $48, $84, $1b, $e3, $27, $30, $46, $30, $d3, $fc, $fc,
    $b3, $35, $75, $c4, $31, $1a, $c0, $c2, $4c, $0b, $c7, $01, $95, $b2,
    $dc, $17, $77, $9b, $09, $15, $04, $bc, $db, $57, $0b, $26, $da, $59,
    $54, $0d, $6e, $b7, $89, $bc, $53, $9d, $5f, $8c, $ad, $86, $97, $d2,
    $48, $4f, $5c, $94, $dd, $30, $2f, $cf, $fc, $de, $20, $31, $25, $9d,
    $29, $25, $78, $b7, $d2, $5b, $5d, $99, $5b, $08, $12, $81, $79, $89,
    $a0, $cf, $8f, $40, $b1, $77, $72, $3b, $13, $fc, $55, $43, $70, $29,
    $d5, $41, $ed, $31, $4b, $2d, $6c, $7d, $cf, $99, $5f, $d1, $72, $9f,
    $8b, $32, $96, $de, $5d, $8b, $19, $77, $75, $ff, $09, $bf, $26, $e9,
    $d7, $3d, $c7, $1a, $81, $cf, $05, $1b, $89, $bf, $45, $32, $bf, $5e,
    $c9, $e3, $5c, $33, $4a, $72, $47, $f4, $24, $ae, $9b, $38, $24, $76,
    $9a, $a2, $9a, $50, $50, $49, $f5, $26, $b9, $55, $a6, $47, $c9, $14,
    $a2, $ca, $d4, $a8, $8a, $9f, $e9, $5a, $5a, $12, $aa, $30, $d5, $78,
    $8b, $39, $02, $03, $01, $00, $01, $02, $82, $01, $00, $22, $5d, $b9,
    $8e, $ef, $1c, $91, $bd, $03, $af, $1a, $e8, $00, $f3, $0b, $8b, $f2,
    $2d, $e5, $4d, $63, $3f, $71, $fc, $eb, $c7, $4f, $3c, $7f, $05, $7b,
    $9d, $c2, $1a, $c7, $c0, $8f, $50, $b7, $0b, $ba, $1e, $a4, $30, $fd,
    $38, $19, $6a, $b4, $11, $31, $77, $22, $f4, $06, $46, $81, $d0, $ad,
    $99, $15, $62, $01, $10, $ad, $8f, $63, $4f, $71, $d9, $8a, $74, $27,
    $56, $b8, $eb, $28, $9f, $ac, $4f, $ee, $ec, $c3, $cf, $84, $86, $09,
    $87, $d0, $04, $fc, $70, $d0, $9f, $ae, $87, $38, $d5, $b1, $6f, $3a,
    $1b, $16, $a8, $00, $f3, $cc, $6a, $42, $5d, $04, $16, $83, $f2, $e0,
    $79, $1d, $d8, $6f, $0f, $b7, $34, $f4, $45, $b5, $1e, $c5, $b5, $78,
    $a7, $d3, $a3, $23, $35, $bc, $7b, $01, $59, $7d, $ee, $b9, $4f, $da,
    $28, $ad, $5d, $25, $ab, $66, $6a, $b0, $61, $f6, $12, $a7, $ee, $d1,
    $e7, $b1, $8b, $91, $29, $ba, $b5, $f8, $78, $c8, $6b, $76, $67, $32,
    $e8, $f3, $4e, $59, $ba, $c1, $44, $c0, $ec, $8d, $7c, $63, $b2, $6e,
    $0c, $b9, $33, $42, $0c, $8d, $ae, $4e, $54, $c8, $8a, $ef, $f9, $47,
    $c8, $99, $84, $c8, $46, $f6, $a6, $53, $59, $f8, $60, $e3, $d7, $1d,
    $10, $95, $f5, $6d, $f4, $a3, $18, $40, $d7, $14, $04, $ac, $8c, $69,
    $d6, $14, $dc, $d8, $cc, $bc, $1c, $ac, $d7, $21, $2b, $7e, $29, $88,
    $06, $a0, $f4, $06, $08, $14, $04, $4d, $32, $33, $84, $9c, $20, $8e,
    $cf, $02, $81, $81, $00, $f3, $f9, $bd, $d5, $43, $6f, $27, $4a, $92,
    $d6, $18, $3d, $4b, $f1, $77, $7c, $af, $ce, $01, $17, $98, $cb, $be,
    $06, $86, $3a, $13, $72, $4b, $7c, $81, $51, $24, $5d, $c3, $e9, $a2,
    $63, $1e, $4a, $eb, $66, $ae, $01, $5e, $a4, $a4, $74, $9e, $ee, $32,
    $e5, $59, $1b, $37, $ef, $7d, $b3, $42, $8c, $93, $8b, $d3, $1e, $83,
    $43, $b5, $88, $3e, $24, $eb, $dc, $92, $2d, $cc, $9a, $9d, $f1, $7d,
    $16, $71, $cb, $25, $47, $36, $b0, $c4, $6b, $c8, $53, $4a, $25, $80,
    $47, $77, $db, $97, $13, $15, $0f, $4a, $fa, $0c, $6c, $44, $13, $2f,
    $bc, $9a, $6b, $13, $57, $fc, $42, $b9, $e9, $d3, $2e, $d2, $11, $f4,
    $c5, $84, $55, $d2, $df, $1d, $a7, $02, $81, $81, $00, $cb, $d7, $d6,
    $9d, $71, $b3, $86, $be, $68, $ed, $67, $e1, $51, $92, $17, $60, $58,
    $b3, $2a, $56, $fd, $18, $fb, $39, $4b, $14, $c6, $f6, $67, $0e, $31,
    $e3, $b3, $2f, $1f, $ec, $16, $1c, $23, $2b, $60, $36, $d1, $cb, $4a,
    $03, $6a, $3a, $4c, $8c, $f2, $73, $08, $23, $29, $da, $cb, $f7, $b6,
    $18, $97, $c6, $fe, $d4, $40, $06, $87, $9d, $6e, $bb, $5d, $14, $44,
    $c8, $19, $fa, $7f, $0c, $c5, $02, $92, $00, $bb, $2e, $4f, $50, $b0,
    $71, $9f, $f3, $94, $12, $b8, $6c, $5f, $e1, $83, $7b, $bc, $8c, $0a,
    $6f, $09, $6a, $35, $4f, $f9, $a4, $92, $93, $e3, $ad, $36, $25, $28,
    $90, $85, $d2, $9f, $86, $fd, $d9, $a8, $61, $e9, $b2, $ec, $1f, $02,
    $81, $81, $00, $dd, $1c, $52, $da, $2b, $c2, $5a, $26, $b0, $cb, $0d,
    $ae, $c7, $db, $f0, $41, $75, $87, $4a, $e0, $1a, $df, $53, $b9, $cf,
    $fe, $64, $4f, $6a, $70, $4d, $36, $bf, $b1, $a6, $f3, $5f, $f3, $5a,
    $a9, $e5, $8b, $ea, $59, $5d, $6f, $f3, $87, $a9, $de, $11, $0c, $60,
    $64, $55, $9e, $5c, $1a, $91, $4e, $9c, $0d, $d5, $e9, $4a, $67, $9b,
    $e6, $fd, $03, $33, $2b, $74, $e3, $c3, $11, $c1, $e0, $f1, $4f, $dd,
    $13, $92, $16, $67, $4f, $6e, $c4, $8c, $0a, $48, $21, $92, $8f, $b2,
    $e5, $b5, $96, $5a, $b8, $c0, $67, $bb, $c8, $87, $2d, $a8, $4e, $d2,
    $d8, $05, $f0, $f0, $b3, $7c, $90, $98, $8f, $4f, $5d, $6c, $ab, $71,
    $92, $e2, $88, $c8, $f3, $02, $81, $81, $00, $99, $27, $5a, $00, $81,
    $65, $39, $5f, $e6, $c6, $38, $be, $79, $e3, $21, $dd, $29, $c7, $b3,
    $90, $18, $29, $a4, $d7, $af, $29, $b5, $33, $7c, $ca, $95, $81, $57,
    $27, $98, $fc, $70, $c0, $43, $4c, $5b, $c5, $d4, $6a, $c0, $f9, $3f,
    $de, $fd, $95, $08, $b4, $94, $f0, $96, $89, $e5, $a6, $00, $13, $0a,
    $36, $61, $50, $67, $aa, $80, $4a, $30, $e0, $65, $56, $cd, $36, $eb,
    $0d, $e2, $57, $5d, $ce, $48, $94, $74, $0e, $9f, $59, $28, $b8, $b6,
    $4c, $f4, $7b, $fc, $44, $b0, $e5, $67, $3c, $98, $b5, $3f, $41, $9d,
    $f9, $46, $85, $08, $34, $36, $4d, $17, $4b, $14, $db, $66, $56, $ef,
    $b5, $08, $57, $0c, $73, $74, $a7, $dc, $46, $aa, $51, $02, $81, $80,
    $1e, $50, $4c, $de, $9c, $60, $6d, $d7, $31, $f6, $d8, $4f, $c2, $25,
    $7d, $83, $b3, $e7, $ed, $92, $e7, $28, $1e, $b3, $9b, $cb, $f2, $86,
    $a4, $49, $45, $5e, $ba, $1d, $db, $21, $5d, $df, $eb, $3c, $5e, $01,
    $c6, $68, $25, $28, $e6, $1a, $bf, $c1, $a1, $c5, $92, $0b, $08, $43,
    $0e, $5a, $a3, $85, $8a, $65, $b4, $54, $a1, $4c, $20, $a2, $5a, $08,
    $f6, $90, $0d, $9a, $d7, $20, $f1, $10, $66, $28, $4c, $22, $56, $a6,
    $b9, $ff, $d0, $6a, $62, $8c, $9f, $f8, $7c, $f4, $ad, $d7, $e8, $f9,
    $87, $43, $bf, $73, $5b, $04, $c7, $d0, $77, $cc, $e3, $be, $da, $c2,
    $07, $ed, $8d, $2a, $15, $77, $1d, $53, $47, $e0, $a2, $11, $41, $0d,
    $e2, $e7 );

  pub_key_der : array[0..293] of byte = (
    $30, $82, $01, $22, $30, $0d, $06, $09, $2a, $86, $48, $86, $f7, $0d,
    $01, $01, $01, $05, $00, $03, $82, $01, $0f, $00, $30, $82, $01, $0a,
    $02, $82, $01, $01, $00, $c2, $44, $bc, $cf, $5b, $ca, $cd, $80, $77,
    $ae, $f9, $7a, $34, $bb, $37, $6f, $5c, $76, $4c, $e4, $bb, $0c, $1d,
    $e7, $fe, $0f, $da, $cf, $8c, $56, $65, $72, $6e, $2c, $f9, $fd, $87,
    $43, $eb, $4c, $26, $b1, $d3, $f0, $87, $b1, $18, $68, $14, $7d, $3c,
    $2a, $fa, $c2, $5d, $70, $19, $11, $00, $2e, $b3, $9c, $8e, $38, $08,
    $be, $e3, $eb, $7d, $6e, $c7, $19, $c6, $7f, $59, $48, $84, $1b, $e3,
    $27, $30, $46, $30, $d3, $fc, $fc, $b3, $35, $75, $c4, $31, $1a, $c0,
    $c2, $4c, $0b, $c7, $01, $95, $b2, $dc, $17, $77, $9b, $09, $15, $04,
    $bc, $db, $57, $0b, $26, $da, $59, $54, $0d, $6e, $b7, $89, $bc, $53,
    $9d, $5f, $8c, $ad, $86, $97, $d2, $48, $4f, $5c, $94, $dd, $30, $2f,
    $cf, $fc, $de, $20, $31, $25, $9d, $29, $25, $78, $b7, $d2, $5b, $5d,
    $99, $5b, $08, $12, $81, $79, $89, $a0, $cf, $8f, $40, $b1, $77, $72,
    $3b, $13, $fc, $55, $43, $70, $29, $d5, $41, $ed, $31, $4b, $2d, $6c,
    $7d, $cf, $99, $5f, $d1, $72, $9f, $8b, $32, $96, $de, $5d, $8b, $19,
    $77, $75, $ff, $09, $bf, $26, $e9, $d7, $3d, $c7, $1a, $81, $cf, $05,
    $1b, $89, $bf, $45, $32, $bf, $5e, $c9, $e3, $5c, $33, $4a, $72, $47,
    $f4, $24, $ae, $9b, $38, $24, $76, $9a, $a2, $9a, $50, $50, $49, $f5,
    $26, $b9, $55, $a6, $47, $c9, $14, $a2, $ca, $d4, $a8, $8a, $9f, $e9,
    $5a, $5a, $12, $aa, $30, $d5, $78, $8b, $39, $02, $03, $01, $00, $01 );

function get_key(libctx : POSSL_LIB_CTX;const propq : PUTF8Char; _public : integer):PEVP_PKEY;
var
    dctx      : POSSL_DECODER_CTX;
    pkey      : PEVP_PKEY;
    selection : integer;
    data      : PByte;
    data_len  : size_t;
begin
    dctx := nil;
    pkey := nil;
    if _public > 0 then
    begin
        selection := EVP_PKEY_PUBLIC_KEY;
        data := @pub_key_der;
        data_len := sizeof(pub_key_der);
    end
    else
    begin
        selection := EVP_PKEY_KEYPAIR;
        data := @priv_key_der;
        data_len := sizeof(priv_key_der);
    end;
    dctx := OSSL_DECODER_CTX_new_for_pkey(@pkey, 'DER', nil, 'RSA',
                                         selection, libctx, propq);
    OSSL_DECODER_from_data(dctx, @data, @data_len);
    OSSL_DECODER_CTX_free(dctx);
    Result := pkey;
end;


procedure set_optional_params(p : POSSL_PARAM;const propq : PUTF8Char);
const
  _label :PAnsichar= 'label';
begin

    { 'pkcs1' is used by default if the padding mode is not set }
    PostInc(p)^ := OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE,
                                            OSSL_PKEY_RSA_PAD_MODE_OAEP, 0);
    { No oaep_label is used if this is not set }
    PostInc(p)^ := OSSL_PARAM_construct_octet_string(OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL,
                                             _label, length(_label));
    { 'SHA1' is used if this is not set }
    PostInc(p)^ := OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST,
                                            'SHA256', 0);
    {
     * If a non default property query needs to be specified when fetching the
     * OAEP digest then it needs to be specified here.
     }
    if propq <> nil then
       PostInc(p)^ := OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST_PROPS,
                                                PUTF8Char( propq), 0);
    {
     * OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST and
     * OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST_PROPS can also be optionally added
     * here if the MGF1 digest differs from the OAEP digest.
     }
    p^ := OSSL_PARAM_construct_end;
end;


function do_encrypt(libctx : POSSL_LIB_CTX;const _in : PByte; in_len : size_t; _out : PPByte; out_len : Psize_t):integer;
var
  ret, _public : integer;
  buf_len : size_t;
  buf : PByte;
  propq : PUTF8Char;
  ctx : PEVP_PKEY_CTX;
  pub_key : PEVP_PKEY;
  params : array[0..4] of TOSSL_PARAM;
  label _cleanup;
begin
    ret := 0; _public := 1;
    buf_len := 0;
    buf := nil;
    propq := nil;
    ctx := nil;
    pub_key := nil;
    { Get public key }
    pub_key := get_key(libctx, propq, _public);
    if pub_key = nil then begin
        WriteLn('Get public key failed.');
        goto _cleanup;
    end;
    ctx := EVP_PKEY_CTX_new_from_pkey(libctx, pub_key, propq);
    if ctx = nil then begin
        WriteLn('EVP_PKEY_CTX_new_from_pkey failed.');
        goto _cleanup;
    end;
    set_optional_params(@params, propq);
    { If no optional parameters are required then nil can be passed }
    if EVP_PKEY_encrypt_init_ex(ctx, @params) <= 0  then begin
        WriteLn('EVP_PKEY_encrypt_init_ex failed.');
        goto _cleanup;
    end;
    { Calculate the size required to hold the encrypted data }
    if EVP_PKEY_encrypt(ctx, nil, @buf_len, _in, in_len) <= 0  then
    begin
        WriteLn('EVP_PKEY_encrypt failed.');
        goto _cleanup;
    end;
    buf := OPENSSL_zalloc(buf_len);
    if buf  = nil then begin
        WriteLn('Malloc failed.');
        goto _cleanup;
    end;
    if EVP_PKEY_encrypt(ctx, buf, @buf_len, _in, in_len) <= 0  then
    begin
        WriteLn('EVP_PKEY_encrypt failed.');
        goto _cleanup;
    end;
    out_len^ := buf_len;
    _out^ := buf;
    WriteLn('Encrypted:');
    BIO_dump_indent_fp(@System.output, buf, buf_len, 2);
    WriteLn('');
    ret := 1;
_cleanup:
    if 0>=ret then OPENSSL_free(buf);
    EVP_PKEY_free(pub_key);
    EVP_PKEY_CTX_free(ctx);
    Result := ret;
end;


function do_decrypt(libctx : POSSL_LIB_CTX;const _in : PByte; in_len : size_t; _out : PPByte; out_len : Psize_t):integer;
var
    ret, _public  : integer;
    buf_len  : size_t;
    buf      : PByte;
    propq    : PUTF8Char;
    ctx      : PEVP_PKEY_CTX;
    priv_key : PEVP_PKEY;
    params   : array[0..4] of TOSSL_PARAM;
    label _cleanup;
begin
    ret := 0; _public := 0;
    buf_len := 0;
    buf := nil;
    propq := nil;
    ctx := nil;
    priv_key := nil;
    { Get private key }
    priv_key := get_key(libctx, propq, _public);
    if priv_key = nil then begin
        WriteLn('Get private key failed.');
        goto _cleanup;
    end;
    ctx := EVP_PKEY_CTX_new_from_pkey(libctx, priv_key, propq);
    if ctx = nil then begin
        WriteLn('EVP_PKEY_CTX_new_from_pkey failed.');
        goto _cleanup;
    end;
    { The parameters used for encryption must also be used for decryption }
    set_optional_params(@params, propq);
    { If no optional parameters are required then nil can be passed }
    if EVP_PKEY_decrypt_init_ex(ctx, @params ) <= 0 then begin
        WriteLn('EVP_PKEY_decrypt_init_ex failed.');
        goto _cleanup;
    end;
    { Calculate the size required to hold the decrypted data }
    if EVP_PKEY_decrypt(ctx, nil, @buf_len, _in, in_len) <= 0 then begin
        WriteLn('EVP_PKEY_decrypt failed.');
        goto _cleanup;
    end;
    buf := OPENSSL_zalloc(buf_len);
    if buf = nil then begin
        WriteLn('Malloc failed.');
        goto _cleanup;
    end;
    if EVP_PKEY_decrypt(ctx, buf, @buf_len, _in, in_len) <= 0  then begin
        WriteLn('EVP_PKEY_decrypt failed.');
        goto _cleanup;
    end;
    out_len^ := buf_len;
    _out^ := buf;
    WriteLn('Decrypted:');
    BIO_dump_indent_fp(@output, buf, buf_len, 2);
    WriteLn('');
    ret := 1;
_cleanup:
    if 0>=ret then OPENSSL_free(buf);
    EVP_PKEY_free(priv_key);
    EVP_PKEY_CTX_free(ctx);
    Result := ret;
end;

const
  EXIT_FAILURE = 1;
  EXIT_SUCCESS = 0;

function main:integer;
var
  ret           : integer;
  msg_len,
  encrypted_len, decrypted_len : size_t;
  encrypted,decrypted     : PByte;
  libctx        : POSSL_LIB_CTX;
  msg_bytes: TBytes;
  label _cleanup;
begin
    ret := EXIT_FAILURE;
    msg_len := sizeof(msg) - 1;
    encrypted_len := 0; decrypted_len := 0;
    encrypted := nil; decrypted := nil;
    libctx := nil;
    msg_bytes := StrToBytes(msg);
    if 0>=do_encrypt(libctx, Pbyte(msg_bytes), msg_len, @encrypted, @encrypted_len) then
    begin
        WriteLn('encryption failed.');
        goto _cleanup;
    end;
    if 0>=do_decrypt(libctx, encrypted, encrypted_len,
                    @decrypted, @decrypted_len) then  begin
        WriteLn('decryption failed.');
        goto _cleanup;
    end;
    if CRYPTO_memcmp(msg, decrypted, decrypted_len) <> 0  then begin
        WriteLn('Decrypted data does not match expected value');
        goto _cleanup;
    end;
    ret := EXIT_SUCCESS;

_cleanup:
    OPENSSL_free(decrypted);
    OPENSSL_free(encrypted);
    OSSL_LIB_CTX_free(libctx);
    SetLength(msg_bytes, 0);
    if ret <> EXIT_SUCCESS then
       ERR_print_errors_fp(@erroutput);
    Result := ret;
end;




begin
  main;
  {try
    Main;
  except
    on e:Exception do
      WriteLn(e.Message);
  end;}
end.


