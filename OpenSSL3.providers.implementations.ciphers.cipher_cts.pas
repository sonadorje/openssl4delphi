unit OpenSSL3.providers.implementations.ciphers.cipher_cts;

interface
uses OpenSSL.Api;//OpenSSL3.providers.implementations.ciphers.ciphercommon;

const
   CTS_CS1 =0;
   CTS_CS2 =1;
   CTS_CS3 =2;
   CTS_BLOCK_SIZE =16;

type
  Taligned_16bytes = record
    case Integer of
      0: (align: size_t);
      1: (c: array[0..CTS_BLOCK_SIZE-1] of Byte);
  end ;

  cts_mode_name2id_st = record
    id: uint;
    name: PUTF8Char;
  end;
  TCTS_MODE_NAME2ID = cts_mode_name2id_st;

function ossl_cipher_cbc_cts_block_update(vctx : Pointer; _out : PByte; outl : Psize_t; outsize : size_t;const _in : PByte; inl : size_t):integer;
function cts128_cs1_encrypt(ctx : PPROV_CIPHER_CTX; _in : PByte; &out : PByte; len : size_t):size_t;
function cts128_cs2_encrypt(ctx : PPROV_CIPHER_CTX;const _in : PByte; &out : PByte; len : size_t):size_t;
 function cts128_cs3_encrypt(ctx : PPROV_CIPHER_CTX; _in : PByte; _out : PByte; len : size_t):size_t;
 function cts128_cs1_decrypt(ctx : PPROV_CIPHER_CTX; _in : PByte; _out : PByte; len : size_t):size_t;
procedure do_xor(const in1, in2 : PByte; len : size_t; &out : PByte);
function cts128_cs2_decrypt(ctx : PPROV_CIPHER_CTX;const _in : PByte; _out : PByte; len : size_t):size_t;
 function cts128_cs3_decrypt(ctx : PPROV_CIPHER_CTX; _in : PByte; _out : PByte; len : size_t):size_t;
 function ossl_cipher_cbc_cts_block_final( vctx : Pointer; &out : PByte; outl : Psize_t; outsize : size_t):integer;
 function ossl_cipher_cbc_cts_mode_name2id(const name : PUTF8Char):integer;
 function ossl_cipher_cbc_cts_mode_id2name( id : uint32):PUTF8Char;



var
  cts_modes: array[0..2] of TCTS_MODE_NAME2ID = (
    (id: CTS_CS1; name: OSSL_CIPHER_CTS_MODE_CS1 ),
    (id: CTS_CS2; name: OSSL_CIPHER_CTS_MODE_CS2 ),
    (id: CTS_CS3; name: OSSL_CIPHER_CTS_MODE_CS3 )
    );

implementation
uses openssl3.providers.fips.self_test, openssl3.crypto.mem,
     OpenSSL3.openssl.params,OpenSSL3.crypto.params, OpenSSL3.Err,
     OpenSSL3.providers.implementations.ciphers.ciphercommon,
     openssl3.crypto.aes.aes_core, openssl3.crypto.aes.aes_cbc,
     OpenSSL3.providers.implementations.ciphers.ciphercommon_hw;


function ossl_cipher_cbc_cts_mode_id2name( id : uint32):PUTF8Char;
var
    i         : size_t;

begin
    for i := 0 to Length(cts_modes)-1 do
    begin
        if cts_modes[i].id = id then
           Exit(cts_modes[i].name);
    end;
    Result := nil;
end;




function ossl_cipher_cbc_cts_mode_name2id(const name : PUTF8Char):integer;
var
  i : size_t;
begin
    for i := 0 to Length(cts_modes)-1 do
    begin
        if strcasecmp(name, cts_modes[i].name )= 0 then
            Exit(int (cts_modes[i].id));
    end;
    Result := -1;
end;


function ossl_cipher_cbc_cts_block_final( vctx : Pointer; &out : PByte; outl : Psize_t; outsize : size_t):integer;
begin
    outl^ := 0;
    Result := 1;
end;



function cts128_cs3_decrypt(ctx : PPROV_CIPHER_CTX; _in : PByte; _out : PByte; len : size_t):size_t;
var
  mid_iv, ct_mid, cn, pt_last : Taligned_16bytes;

  residue : size_t;
begin
    if len < CTS_BLOCK_SIZE then { CS3 requires at least one block }
        Exit(0);
    { If we only have one block then just process the aligned block }
    if len = CTS_BLOCK_SIZE then
        Exit(get_result(ctx.hw.cipher(ctx, _out, _in, len) >0 , len , 0));
    { Process blocks at the start - but leave the last 2 blocks }
    residue := len mod CTS_BLOCK_SIZE;
    if residue = 0 then
       residue := CTS_BLOCK_SIZE;
    len  := len - (CTS_BLOCK_SIZE + residue);
    if len > 0 then
    begin
        if 0>= ctx.hw.cipher(ctx, _out, _in, len) then
            Exit(0);
        _in  := _in + len;
        _out  := _out + len;
    end;
    { Save the iv that will be used by the second last block }
    memcpy(@mid_iv.c, @ctx.iv, CTS_BLOCK_SIZE);
    { Save the C(n) block : For CS3 it is C(1) or ... or C(n-2) or C(n) or C(n-1)* }
    memcpy(@cn.c, _in, CTS_BLOCK_SIZE);
    { Decrypt the C(n) block first using an iv of zero }
    memset(@ctx.iv, 0, CTS_BLOCK_SIZE);
    if 0>= ctx.hw.cipher(ctx, @pt_last.c, _in, CTS_BLOCK_SIZE ) then
        Exit(0);
    {
     * Rebuild the ciphertext of C(n-1) as a combination of
     * the decrypted C(n) block + replace the start with the ciphertext bytes
     * of the partial last block.
     }
    memcpy(@ct_mid.c, _in + CTS_BLOCK_SIZE, residue);
    if residue <> CTS_BLOCK_SIZE then
       memcpy(PByte(@ct_mid.c) + residue, PByte(@pt_last.c) + residue, CTS_BLOCK_SIZE - residue);
    {
     * Restore the last partial ciphertext block.
     * Now that we have the cipher text of the second last block, apply
     * that to the partial plaintext end block. We have already decrypted the
     * block using an IV of zero. For decryption the IV is just XORed after
     * doing an AES block - so just XOR in the ciphertext.
     }
    do_xor(@ct_mid.c, @pt_last.c, residue, _out + CTS_BLOCK_SIZE);
    { Restore the iv needed by the second last block }
    memcpy(@ctx.iv, @mid_iv.c, CTS_BLOCK_SIZE);
    {
     * Decrypt the second last plaintext block now that we have rebuilt the
     * ciphertext.
     }
    if 0>= ctx.hw.cipher(ctx, _out, @ct_mid.c, CTS_BLOCK_SIZE) then
        Exit(0);
    { The returned iv is the C(n) block }
    memcpy(@ctx.iv, @cn.c, CTS_BLOCK_SIZE);
    Result := len + CTS_BLOCK_SIZE + residue;
end;




function cts128_cs2_decrypt(ctx : PPROV_CIPHER_CTX;const _in : PByte; _out : PByte; len : size_t):size_t;
begin
    if len mod CTS_BLOCK_SIZE = 0 then
    begin
        { If there are no partial blocks then it is the same as CBC mode }
        if 0>= ctx.hw.cipher(ctx, _out, _in, len) then
            Exit(0);
        Exit(len);
    end;
    { For partial blocks CS2 is equivalent to CS3 }
    Result := cts128_cs3_decrypt(ctx, _in, _out, len);
end;




procedure do_xor(const in1, in2 : PByte; len : size_t; &out : PByte);
var
  i : size_t;
begin
    for i := 0 to len-1 do
        out[i] := in1[i]  xor  in2[i];
end;




function cts128_cs1_decrypt(ctx : PPROV_CIPHER_CTX; _in : PByte; _out : PByte; len : size_t):size_t;
var
  mid_iv, ct_mid, cn, pt_last : Taligned_16bytes;

  residue : size_t;
begin
    residue := len mod CTS_BLOCK_SIZE;
    if residue = 0 then
    begin
        { If there are no partial blocks then it is the same as CBC mode }
        if 0>= ctx.hw.cipher(ctx, _out, _in, len) then
            Exit(0);
        Exit(len);
    end;
    { Process blocks at the start - but leave the last 2 blocks }
    len  := len - (CTS_BLOCK_SIZE + residue);
    if len > 0 then begin
        if 0>= ctx.hw.cipher(ctx, _out, _in, len) then
            Exit(0);
        _in  := _in + len;
        _out  := _out + len;
    end;
    { Save the iv that will be used by the second last block }
    memcpy(@mid_iv.c, @ctx.iv, CTS_BLOCK_SIZE);
    { Save the C(n) block }
    memcpy(@cn.c, _in + residue, CTS_BLOCK_SIZE);
    { Decrypt the last block first using an iv of zero }
    memset(@ctx.iv, 0, CTS_BLOCK_SIZE);
    if 0>= ctx.hw.cipher(ctx, @pt_last.c, _in + residue, CTS_BLOCK_SIZE ) then
        Exit(0);
    {
     * Rebuild the ciphertext of the second last block as a combination of
     * the decrypted last block + replace the start with the ciphertext bytes
     * of the partial second last block.
     }
    memcpy(@ct_mid.c, _in, residue);
    memcpy(PByte(@ct_mid.c) + residue, PByte(@pt_last.c) + residue, CTS_BLOCK_SIZE - residue);
    {
     * Restore the last partial ciphertext block.
     * Now that we have the cipher text of the second last block, apply
     * that to the partial plaintext end block. We have already decrypted the
     * block using an IV of zero. For decryption the IV is just XORed after
     * doing an Cipher CBC block - so just XOR in the cipher text.
     }
    do_xor(@ct_mid.c, @pt_last.c, residue, _out + CTS_BLOCK_SIZE);
    { Restore the iv needed by the second last block }
    memcpy(@ctx.iv, @mid_iv.c, CTS_BLOCK_SIZE);
    {
     * Decrypt the second last plaintext block now that we have rebuilt the
     * ciphertext.
     }
    if 0>= ctx.hw.cipher(ctx, _out, @ct_mid.c, CTS_BLOCK_SIZE ) then
        Exit(0);
    { The returned iv is the C(n) block }
    memcpy(@ctx.iv, @cn.c, CTS_BLOCK_SIZE);
    Result := len + CTS_BLOCK_SIZE + residue;
end;



function cts128_cs3_encrypt(ctx : PPROV_CIPHER_CTX; _in : PByte; _out : PByte; len : size_t):size_t;
var
  tmp_in : Taligned_16bytes;

  residue : size_t;
begin
    if len < CTS_BLOCK_SIZE then { CS3 requires at least one block }
        Exit(0);
    { If we only have one block then just process the aligned block }
    if len = CTS_BLOCK_SIZE then
       Exit(get_result(ctx.hw.cipher(ctx, _out, _in, len) >0, len , 0));
    residue := len mod CTS_BLOCK_SIZE;
    if residue = 0 then
       residue := CTS_BLOCK_SIZE;
    len  := len - residue;
    if 0>= ctx.hw.cipher(ctx, _out, _in, len) then
        Exit(0);
    _in  := _in + len;
    _out  := _out + len;
    memset(@tmp_in.c, 0, sizeof(tmp_in));
    memcpy(@tmp_in.c, _in, residue);
    memcpy(_out, _out - CTS_BLOCK_SIZE, residue);
    if 0>= ctx.hw.cipher(ctx, _out - CTS_BLOCK_SIZE, @tmp_in.c, CTS_BLOCK_SIZE) then
        Exit(0);
    Result := len + residue;
end;



function cts128_cs2_encrypt(ctx : PPROV_CIPHER_CTX;const _in : PByte; &out : PByte; len : size_t):size_t;
begin
    if len mod CTS_BLOCK_SIZE = 0 then
    begin
        { If there are no partial blocks then it is the same as CBC mode }
        if 0>= ctx.hw.cipher(ctx, &out, _in, len) then
            Exit(0);
        Exit(len);
    end;
    { For partial blocks CS2 is equivalent to CS3 }
    Result := cts128_cs3_encrypt(ctx, _in, &out, len);
end;




function cts128_cs1_encrypt(ctx : PPROV_CIPHER_CTX; _in : PByte; &out : PByte; len : size_t):size_t;
var
  tmp_in : Taligned_16bytes;
  residue : size_t;
begin
    residue := len mod CTS_BLOCK_SIZE;
    len  := len - residue;
    if 0>= ctx.hw.cipher(ctx, out, _in, len )then
        Exit(0);
    if residue = 0 then Exit(len);
    _in  := _in + len;
    out  := out + len;
    memset(@tmp_in.c, 0, sizeof(tmp_in));
    memcpy(@tmp_in.c, _in, residue);
    if 0>= ctx.hw.cipher(ctx, out - CTS_BLOCK_SIZE + residue, @tmp_in.c,
                         CTS_BLOCK_SIZE ) then
        Exit(0);
    Result := len + residue;
end;




function ossl_cipher_cbc_cts_block_update(vctx : Pointer; _out : PByte; outl : Psize_t; outsize : size_t;const _in : PByte; inl : size_t):integer;
var
  ctx : PPROV_CIPHER_CTX;

  sz : size_t;
begin
    ctx := PPROV_CIPHER_CTX ( vctx);
    sz := 0;
    if inl < CTS_BLOCK_SIZE then { There must be at least one block for CTS mode }
        Exit(0);
    if outsize < inl then Exit(0);
    if _out = nil then
    begin
        outl^ := inl;
        Exit(1);
    end;
    {
     * Return an error if the update is called multiple times, only one shot
     * is supported.
     }
    if ctx.updated = 1 then Exit(0);
    if ctx.enc >0 then
    begin
        if ctx.cts_mode = CTS_CS1 then
            sz := cts128_cs1_encrypt(ctx, _in, _out, inl)
        else if (ctx.cts_mode = CTS_CS2) then
            sz := cts128_cs2_encrypt(ctx, _in, _out, inl)
        else if (ctx.cts_mode = CTS_CS3) then
            sz := cts128_cs3_encrypt(ctx, _in, _out, inl);
    end
    else
    begin
        if ctx.cts_mode = CTS_CS1 then
           sz := cts128_cs1_decrypt(ctx, _in, _out, inl)
        else if (ctx.cts_mode = CTS_CS2) then
            sz := cts128_cs2_decrypt(ctx, _in, _out, inl)
        else if (ctx.cts_mode = CTS_CS3) then
            sz := cts128_cs3_decrypt(ctx, _in, _out, inl);
    end;
    if sz = 0 then
       Exit(0);
    ctx.updated := 1; { Stop multiple updates being allowed }
    outl^ := sz;
    Result := 1;
end;

initialization








end.
