unit OpenSSL3.providers.implementations.ciphers.ciphercommon_block;

interface
uses OpenSSL.Api;

function ossl_cipher_tlsunpadblock( libctx : POSSL_LIB_CTX; tlsversion : uint32; buf : PByte; buflen : Psize_t; blocksize : size_t; mac : PPByte; alloced : PInteger; macsize : size_t; aead : integer):integer;
function ossl_cipher_fillblock(buf : PByte; buflen : Psize_t; blocksize : size_t;const &in : PPByte; inlen : Psize_t):size_t;
function ossl_cipher_trailingdata(buf : PByte; buflen : Psize_t; blocksize : size_t;const &in : PPByte; inlen : Psize_t):integer;
procedure ossl_cipher_padblock( buf : PByte; buflen : Psize_t; blocksize : size_t);
 function ossl_cipher_unpadblock( buf : PByte; buflen : Psize_t; blocksize : size_t):integer;

implementation
uses OpenSSL3.openssl.params, openssl3.crypto.params, OpenSSL3.Err,
     openssl3.providers.common.provider_ctx, openssl3.crypto.mem,
     openssl3.providers.fips.self_test, OpenSSL.ssl.record_.tls_pad;

function ossl_cipher_unpadblock( buf : PByte; buflen : Psize_t; blocksize : size_t):integer;
var
  pad, i, len : size_t;
begin
    len := buflen^;
    if len <> blocksize then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        Exit(0);
    end;
    {
     * The following assumes that the ciphertext has been authenticated.
     * Otherwise it provides a padding oracle.
     }
    pad := buf[blocksize - 1];
    if (pad = 0)  or  (pad > blocksize) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_BAD_DECRYPT);
        Exit(0);
    end;
    for i := 0 to pad-1 do
    begin
        if buf[PreDec(len)] <> pad  then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_BAD_DECRYPT);
            Exit(0);
        end;
    end;
    buflen^ := len;
    Result := 1;
end;



procedure ossl_cipher_padblock( buf : PByte; buflen : Psize_t; blocksize : size_t);
var
  i : size_t;

  pad : Byte;
begin
    pad := Byte(blocksize - buflen^);
    for i := buflen^ to blocksize-1 do
        buf[i] := pad;
end;




function ossl_cipher_trailingdata(buf : PByte; buflen : Psize_t; blocksize : size_t;const &in : PPByte; inlen : Psize_t):integer;
begin
    if inlen^ = 0 then
       Exit(1);
    if buflen^ + inlen^ > blocksize then
    begin
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        Exit(0);
    end;
    memcpy(buf + buflen^, &in^, inlen^);
    buflen^  := buflen^ + inlen^;
    inlen^ := 0;
    Result := 1;
end;

function ossl_cipher_fillblock(buf : PByte; buflen : Psize_t; blocksize : size_t;const &in : PPByte; inlen : Psize_t):size_t;
var
  blockmask,
  bufremain : size_t;
begin
    blockmask := not (blocksize - 1);
    bufremain := blocksize - buflen^;
    assert( buflen^ <= blocksize);
    assert( (blocksize > 0)  and  ( (blocksize and (blocksize - 1) = 0)));
    if inlen^ < bufremain then
       bufremain := inlen^;
    memcpy(buf + buflen^, &in^, bufremain);
    &in^  := &in^ + bufremain;
    inlen^  := inlen^ - bufremain;
    buflen^  := buflen^ + bufremain;
    Result := inlen^ and blockmask;
end;





function ossl_cipher_tlsunpadblock( libctx : POSSL_LIB_CTX; tlsversion : uint32; buf : PByte; buflen : Psize_t; blocksize : size_t; mac : PPByte; alloced : PInteger; macsize : size_t; aead : integer):integer;
var
  ret : integer;
begin
    case tlsversion of
    SSL3_VERSION:
        Exit(ssl3_cbc_remove_padding_and_mac(buflen, buflen^, buf, mac,
                                               alloced, blocksize, macsize,
                                               libctx));
    TLS1_2_VERSION,
    DTLS1_2_VERSION,
    TLS1_1_VERSION,
    DTLS1_VERSION,
    DTLS1_BAD_VER:
    begin
        { Remove the explicit IV }
        buf  := buf + blocksize;
        buflen^  := buflen^ - blocksize;
        { Fall through }
    end;
    TLS1_VERSION:
    begin
        ret := tls1_cbc_remove_padding_and_mac(buflen, buflen^, buf, mac,
                                              alloced, blocksize, macsize,
                                              aead, libctx);
        Exit(ret);
    end;
    else
        Exit(0);
    end;
end;



end.
