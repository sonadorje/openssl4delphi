unit openssl3.crypto.evp.e_rc4_hmac_md5;

interface
uses OpenSSL.Api;

type
  TEVP_RC4_HMAC_MD5 = record
    ks             : TRC4_KEY;
    head,
    tail,
    md             : TMD5_CTX;
    payload_length : size_t;
  end;
  PEVP_RC4_HMAC_MD5 = ^TEVP_RC4_HMAC_MD5;

  const NO_PAYLOAD_LENGTH  = size_t(-1);
  {$if not defined(STITCHED_CALL)}
      rc4_off = 0;
      md5_off = 0;
  {$endif}

  var
  r4_hmac_md5_cipher :TEVP_CIPHER;

function EVP_rc4_hmac_md5:PEVP_CIPHER;
function rc4_hmac_md5_init_key(ctx : PEVP_CIPHER_CTX;{const} inkey, iv : PByte; enc : integer):integer;
function data(ctx: PEVP_CIPHER_CTX): PEVP_RC4_HMAC_MD5;
function rc4_hmac_md5_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; len : size_t):integer;
function rc4_hmac_md5_ctrl( ctx : PEVP_CIPHER_CTX; _type, arg : integer; ptr : Pointer):integer;

implementation
uses openssl3.crypto.evp.evp_lib,  openssl3.crypto.rc4.rc4_skey,
     openssl3.crypto.cpuid,        openssl3.crypto.mem,
     openssl3.crypto.md5.md5_dgst, openssl3.crypto.rc4.rc4_enc;




function rc4_hmac_md5_ctrl( ctx : PEVP_CIPHER_CTX; _type, arg : integer; ptr : Pointer):integer;
var
    key      : PEVP_RC4_HMAC_MD5;
    i        : uint32;
    hmac_key : array[0..63] of Byte;
    p        : PByte;
    len      : uint32;
begin
    key := data(ctx);
    case _type of
    EVP_CTRL_AEAD_SET_MAC_KEY:
        begin
            memset(@hmac_key, 0, sizeof(hmac_key));
            if arg > int(sizeof(hmac_key)) then
            begin
                MD5_Init(@key.head);
                MD5_Update(@key.head, ptr, arg);
                MD5_Final(@hmac_key, @key.head);
            end
            else
            begin
                memcpy(@hmac_key, ptr, arg);
            end;
            for i := 0 to sizeof(hmac_key)-1 do
                hmac_key[i]  := hmac_key[i] xor $36;
            MD5_Init(@key.head);
            MD5_Update(@key.head, @hmac_key, sizeof(hmac_key));
            for i := 0 to sizeof(hmac_key)-1 do
                hmac_key[i]  := hmac_key[i] xor ($36 xor $5c);
            MD5_Init(@key.tail);
            MD5_Update(@key.tail, @hmac_key, sizeof(hmac_key));
            OPENSSL_cleanse(@hmac_key, sizeof(hmac_key));
            Exit(1);
        end;
    EVP_CTRL_AEAD_TLS1_AAD:
        begin
            p := ptr;
            if arg <> EVP_AEAD_TLS1_AAD_LEN then Exit(-1);
            len := p[arg - 2] shl 8 or p[arg - 1];
            if 0>=EVP_CIPHER_CTX_is_encrypting(ctx) then
            begin
                if len < MD5_DIGEST_LENGTH then
                    Exit(-1);
                len  := len - MD5_DIGEST_LENGTH;
                p[arg - 2] := len  shr  8;
                p[arg - 1] := len;
            end;
            key.payload_length := len;
            key.md := key.head;
            MD5_Update(@key.md, p, arg);
            Exit(MD5_DIGEST_LENGTH);
        end;
    else
        Exit(-1);
    end;
end;




function rc4_hmac_md5_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; len : size_t):integer;
var
  key : PEVP_RC4_HMAC_MD5;
  rc4_off : size_t;
  l : uint32;
  plen : size_t;
  mac : array[0..(MD5_DIGEST_LENGTH)-1] of Byte;
begin
    key := data(ctx);
{$IF defined(STITCHED_CALL)}
    size_t rc4_off = 32 - 1 - (key.ks.x and (32 - 1)), { 32 is $MOD from
                                                       * rc4_md5-x86_64.pl }
        md5_off := MD5_CBLOCK - key.md.num, blocks;
{$ENDIF}
    plen := key.payload_length;
    if (plen <> NO_PAYLOAD_LENGTH)  and  (len <> plen + MD5_DIGEST_LENGTH) then
        Exit(0);
    if EVP_CIPHER_CTX_is_encrypting(ctx) > 0 then
    begin
        if plen = NO_PAYLOAD_LENGTH then
            plen := len;
{$IF defined(STITCHED_CALL)}
        { cipher has to 'fall behind' }
        if rc4_off > md5_off then md5_off  := md5_off + MD5_CBLOCK;
        if plen > md5_off  and  (blocks = (plen - md5_off then / MD5_CBLOCK)  and
            (OPENSSL_ia32cap_P[0] and (1 shl 20)) = 0) begin
            MD5_Update(&key.md, in, md5_off);
            RC4(&key.ks, rc4_off, in, out);
            rc4_md5_enc(&key.ks, in + rc4_off, out + rc4_off,
                        &key.md, in + md5_off, blocks);
            blocks  := blocks  * MD5_CBLOCK;
            rc4_off  := rc4_off + blocks;
            md5_off  := md5_off + blocks;
            key.md.Nh  := key.md.Nh + (blocks  shr  29);
            key.md.Nl  := key.md.Nl + (blocks shl= 3);
            if key.md.Nl < uint32(blocks then key.md.PostInc(Nh);
        end;
        else
        begin
            rc4_off := 0;
            md5_off := 0;
        end;
{$ENDIF}
        MD5_Update(@key.md, _in + md5_off, plen - md5_off);
        if plen <> len then
        begin       { 'TLS' mode of operation }
            if _in <> _out then
                memcpy(_out + rc4_off, _in + rc4_off, plen - rc4_off);
            { calculate HMAC and append it to payload }
            MD5_Final(_out + plen, @key.md);
            key.md := key.tail;
            MD5_Update(@key.md, _out + plen, MD5_DIGEST_LENGTH);
            MD5_Final(_out + plen, @key.md);
            { encrypt HMAC at once }
            RC4(@key.ks, len - rc4_off, _out + rc4_off, _out + rc4_off);
        end
        else
        begin
            RC4(@key.ks, len - rc4_off, _in + rc4_off, _out + rc4_off);
        end;
    end
    else
    begin
{$IF defined(STITCHED_CALL)}
        { digest has to 'fall behind' }
        if md5_off > rc4_off then rc4_off  := rc4_off + (2 * MD5_CBLOCK);
        else
            rc4_off  := rc4_off + MD5_CBLOCK;
        if len > rc4_off  and  (blocks = (len - rc4_off then / MD5_CBLOCK)  and
            (OPENSSL_ia32cap_P[0] and (1 shl 20)) = 0) begin
            RC4(&key.ks, rc4_off, in, out);
            MD5_Update(&key.md, out, md5_off);
            rc4_md5_enc(&key.ks, in + rc4_off, out + rc4_off,
                        &key.md, out + md5_off, blocks);
            blocks  := blocks  * MD5_CBLOCK;
            rc4_off  := rc4_off + blocks;
            md5_off  := md5_off + blocks;
            l := (key.md.Nl + (blocks shl 3)) and $ffffffffU;
            if l < key.md.Nl then key.md.PostInc(Nh);
            key.md.Nl := l;
            key.md.Nh  := key.md.Nh + (blocks  shr  29);
        end
        else
        begin
            md5_off := 0;
            rc4_off := 0;
        end;
{$ENDIF}
        { decrypt HMAC at once }
        RC4(@key.ks, len - rc4_off, _in + rc4_off, _out + rc4_off);
        if plen <> NO_PAYLOAD_LENGTH then
        begin  { 'TLS' mode of operation }
            MD5_Update(@key.md, _out + md5_off, plen - md5_off);
            { calculate HMAC and verify it }
            MD5_Final(@mac, @key.md);
            key.md := key.tail;
            MD5_Update(@key.md, @mac, MD5_DIGEST_LENGTH);
            MD5_Final(@mac, @key.md);
            if CRYPTO_memcmp(_out + plen, @mac, MD5_DIGEST_LENGTH) > 0 then
                Exit(0);
        end
        else
        begin
            MD5_Update(@key.md, _out + md5_off, len - md5_off);
        end;
    end;
    key.payload_length := NO_PAYLOAD_LENGTH;
    Result := 1;
end;

function data(ctx: PEVP_CIPHER_CTX): PEVP_RC4_HMAC_MD5;
begin
  Result := PEVP_RC4_HMAC_MD5(EVP_CIPHER_CTX_get_cipher_data(ctx))
end;

function rc4_hmac_md5_init_key(ctx : PEVP_CIPHER_CTX;{const} inkey, iv : PByte; enc : integer):integer;
var
  key : PEVP_RC4_HMAC_MD5;

  keylen : integer;
begin
    key := data(ctx);
    keylen := EVP_CIPHER_CTX_get_key_length(ctx);
    if keylen <= 0 then Exit(0);
    RC4_set_key(@key.ks, keylen, inkey);
    MD5_Init(@key.head);       { handy when benchmarking }
    key.tail := key.head;
    key.md := key.head;
    key.payload_length := NO_PAYLOAD_LENGTH;
    Result := 1;
end;


function EVP_rc4_hmac_md5:PEVP_CIPHER;
begin
    Result := @r4_hmac_md5_cipher;
end;

initialization
    r4_hmac_md5_cipher := get_EVP_CIPHER (
  {$ifdef NID_rc4_hmac_md5}
    NID_rc4_hmac_md5,
  {$else}
    NID_undef,
  {$endif}
    1, EVP_RC4_KEY_SIZE, 0,
    EVP_CIPH_STREAM_CIPHER or EVP_CIPH_VARIABLE_LENGTH or
        EVP_CIPH_FLAG_AEAD_CIPHER,
    EVP_ORIG_GLOBAL,
    rc4_hmac_md5_init_key,
    rc4_hmac_md5_cipher,
    nil,
    sizeof(EVP_RC4_HMAC_MD5),
    nil,
    nil,
    rc4_hmac_md5_ctrl,
    nil);

end.
