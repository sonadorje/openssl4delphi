unit openssl3.crypto.evp.e_des;

interface
uses OpenSSL.Api;

function EVP_des_cbc:PEVP_CIPHER;
  function EVP_des_cfb64:PEVP_CIPHER;
  function EVP_des_ofb:PEVP_CIPHER;
  function EVP_des_ecb:PEVP_CIPHER;


function des_init_key(ctx : PEVP_CIPHER_CTX;{const} key, iv : PByte; enc : integer):integer;
function des_ctrl( c : PEVP_CIPHER_CTX; &type, arg : integer; ptr : Pointer):integer;
function des_cbc_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
function des_cfb64_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
function des_ofb_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
function des_ecb_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
function EVP_des_cfb1:PEVP_CIPHER;
function EVP_des_cfb8:PEVP_CIPHER;
function des_cfb1_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
function des_cfb8_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;


implementation

uses openssl3.crypto.evp.evp_lib,    openssl3.crypto.des.ecb_enc,
     openssl3.crypto.des.cfb64enc,   openssl3.crypto.des.ncbc_enc,
     openssl3.crypto.des.cfb_enc,
     openssl3.crypto.rand.rand_lib,  openssl3.crypto.des.set_key,
     openssl3.crypto.evp,            openssl3.crypto.des.ofb64enc;

const
    des_cbc   : TEVP_CIPHER = (nid:  31;block_size: 8;key_len: 8;iv_len: 8;flags: $200 or $2;origin: 1;init: des_init_key;do_cipher: des_cbc_cipher;cleanup: Pointer(0) ;ctx_size: sizeof(TEVP_DES_KEY);set_asn1_parameters: EVP_CIPHER_set_asn1_iv;get_asn1_parameters: EVP_CIPHER_get_asn1_iv;ctrl: des_ctrl;app_data: Pointer(0)  );
    des_cfb64 : TEVP_CIPHER = (nid:  30;block_size: 1;key_len: 8;iv_len: 8;flags: $200 or $3;origin: 1;init: des_init_key;do_cipher: des_cfb64_cipher;cleanup: Pointer(0) ;ctx_size: sizeof(TEVP_DES_KEY);set_asn1_parameters: EVP_CIPHER_set_asn1_iv;get_asn1_parameters: EVP_CIPHER_get_asn1_iv;ctrl: des_ctrl;app_data: Pointer(0)  );
    des_ofb   : TEVP_CIPHER = (nid:  45;block_size: 1;key_len: 8;iv_len: 8;flags: $200 or $4;origin: 1;init: des_init_key;do_cipher: des_ofb_cipher;cleanup: Pointer(0) ;ctx_size: sizeof(TEVP_DES_KEY);set_asn1_parameters: EVP_CIPHER_set_asn1_iv;get_asn1_parameters: EVP_CIPHER_get_asn1_iv;ctrl: des_ctrl;app_data: Pointer(0)  );
    des_ecb   : TEVP_CIPHER = (nid:  29;block_size: 8;key_len: 8;iv_len: 0;flags: $200 or $1;origin: 1;init: des_init_key;do_cipher: des_ecb_cipher;cleanup: Pointer(0) ;ctx_size: sizeof(TEVP_DES_KEY);set_asn1_parameters: EVP_CIPHER_set_asn1_iv;get_asn1_parameters: EVP_CIPHER_get_asn1_iv;ctrl: des_ctrl;app_data: Pointer(0)  );

    des_cfb1 : TEVP_CIPHER = (nid:  656;block_size: 1;key_len: 8;iv_len: 8;flags: $200 or $3;origin: 1;init: des_init_key;do_cipher: des_cfb1_cipher;cleanup: Pointer(0) ;ctx_size: sizeof(TEVP_DES_KEY);set_asn1_parameters: EVP_CIPHER_set_asn1_iv;get_asn1_parameters: EVP_CIPHER_get_asn1_iv;ctrl: des_ctrl;app_data: Pointer(0)  );
    des_cfb8 : TEVP_CIPHER = (nid:  657;block_size: 1;key_len: 8;iv_len: 8;flags: $200 or $3;origin: 1;init: des_init_key;do_cipher: des_cfb8_cipher;cleanup: Pointer(0) ;ctx_size: sizeof(TEVP_DES_KEY);set_asn1_parameters: EVP_CIPHER_set_asn1_iv;get_asn1_parameters: EVP_CIPHER_get_asn1_iv;ctrl: des_ctrl;app_data: Pointer(0)  );



function des_cfb8_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
begin
    while inl >= EVP_MAXCHUNK do
    begin
        DES_cfb_encrypt(_in, _out, 8, long(EVP_MAXCHUNK),
                        EVP_CIPHER_CTX_get_cipher_data(ctx),
                        PDES_cblock(@ctx.iv),
                        EVP_CIPHER_CTX_is_encrypting(ctx));
        inl  := inl - EVP_MAXCHUNK;
        _in  := _in + EVP_MAXCHUNK;
        _out  := _out + EVP_MAXCHUNK;
    end;
    if inl > 0 then DES_cfb_encrypt(_in, _out, 8, long(inl),
                        EVP_CIPHER_CTX_get_cipher_data(ctx),
                        PDES_cblock(@ctx.iv),
                        EVP_CIPHER_CTX_is_encrypting(ctx));
    Result := 1;
end;



function des_cfb1_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
var
  n, chunk : size_t;

  c,d : array[0..0] of Byte;
begin
    chunk := EVP_MAXCHUNK div 8;
    if inl < chunk then chunk := inl;
    while (inl > 0)  and  (inl >= chunk) do
    begin
        for n := 0 to chunk * 8-1 do
        begin
            c[0] := get_result(_in[n div 8] and (1 shl (7 - n mod 8)) > 0, $80 , 0);
            DES_cfb_encrypt(@c, @d, 1, 1, EVP_CIPHER_CTX_get_cipher_data(ctx),
                            PDES_cblock (@ctx.iv),
                            EVP_CIPHER_CTX_is_encrypting(ctx));
            _out[n div 8] :=
                (_out[n div 8] and not ($80  shr  uint32(n mod 8))) or
                ((d[0] and $80)  shr  uint32(n mod 8));
        end;
        inl  := inl - chunk;
        _in  := _in + chunk;
        _out  := _out + chunk;
        if inl < chunk then chunk := inl;
    end;
    Result := 1;
end;



function EVP_des_cfb1:PEVP_CIPHER;
begin
 Result := @des_cfb1;
end;


function EVP_des_cfb8:PEVP_CIPHER;
begin
 Result := @des_cfb8;
end;



function des_ecb_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
var
  i, bl: size_t ;
begin

    bl := EVP_CIPHER_CTX_get0_cipher(ctx).block_size;
    if (inl < bl) then
       Exit(1);
    inl := inl-bl;
    i :=0;
    while i <= inl do
    begin

        DES_ecb_encrypt(PDES_cblock(_in + i), PDES_cblock(_out + i),
                        EVP_CIPHER_CTX_get_cipher_data(ctx),
                        EVP_CIPHER_CTX_is_encrypting(ctx));
        i := i+bl;
    end;
    Result := 1;
end;


function des_ofb_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
var
  num : integer;
begin
    while inl >= EVP_MAXCHUNK do
    begin
        num := EVP_CIPHER_CTX_get_num(ctx);
        DES_ofb64_encrypt(_in, _out, long(EVP_MAXCHUNK),
                          EVP_CIPHER_CTX_get_cipher_data(ctx),
                          PDES_cblock (@ctx.iv), @num);
        EVP_CIPHER_CTX_set_num(ctx, num);
        inl  := inl - EVP_MAXCHUNK;
        _in  := _in + EVP_MAXCHUNK;
        _out  := _out + EVP_MAXCHUNK;
    end;
    if inl > 0 then
    begin
        num := EVP_CIPHER_CTX_get_num(ctx);
        DES_ofb64_encrypt(_in, _out, long(inl),
                          EVP_CIPHER_CTX_get_cipher_data(ctx),
                          PDES_cblock (@ctx.iv), @num);
        EVP_CIPHER_CTX_set_num(ctx, num);
    end;
    Result := 1;
end;



function des_cfb64_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
var
  num : integer;
begin
    while inl >= EVP_MAXCHUNK do
    begin
        num := EVP_CIPHER_CTX_get_num(ctx);
        DES_cfb64_encrypt(_in, _out, long(EVP_MAXCHUNK),
                          EVP_CIPHER_CTX_get_cipher_data(ctx),
                          PDES_cblock (@ctx.iv), @num,
                          EVP_CIPHER_CTX_is_encrypting(ctx));
        EVP_CIPHER_CTX_set_num(ctx, num);
        inl  := inl - EVP_MAXCHUNK;
        _in  := _in + EVP_MAXCHUNK;
        _out  := _out + EVP_MAXCHUNK;
    end;
    if inl > 0 then
    begin
        num := EVP_CIPHER_CTX_get_num(ctx);
        DES_cfb64_encrypt(_in, _out, long(inl),
                          EVP_CIPHER_CTX_get_cipher_data(ctx),
                          PDES_cblock (@ctx.iv), @num,
                          EVP_CIPHER_CTX_is_encrypting(ctx));
        EVP_CIPHER_CTX_set_num(ctx, num);
    end;
    Result := 1;
end;



function des_cbc_cipher(ctx : PEVP_CIPHER_CTX; _out : PByte;{const} _in : PByte; inl : size_t):integer;
var
  dat : PEVP_DES_KEY;
begin
    dat := PEVP_DES_KEY( EVP_CIPHER_CTX_get_cipher_data(ctx));
    if Assigned(dat.stream.cbc) then
    begin
        dat.stream.cbc(_in, _out, inl, @dat.ks.ks, @ctx.iv);
        Exit(1);
    end;
    while inl >= EVP_MAXCHUNK do
    begin
        DES_ncbc_encrypt(_in, _out, long(EVP_MAXCHUNK),
                         EVP_CIPHER_CTX_get_cipher_data(ctx),
                         PDES_cblock (@ctx.iv),
                         EVP_CIPHER_CTX_is_encrypting(ctx));
        inl  := inl - EVP_MAXCHUNK;
        _in  := _in + EVP_MAXCHUNK;
        _out  := _out + EVP_MAXCHUNK;
    end;
    if inl > 0 then
       DES_ncbc_encrypt(_in, _out, long(inl),
                         EVP_CIPHER_CTX_get_cipher_data(ctx),
                         PDES_cblock (@ctx.iv),
                         EVP_CIPHER_CTX_is_encrypting(ctx));
    Result := 1;
end;




function des_ctrl( c : PEVP_CIPHER_CTX; &type, arg : integer; ptr : Pointer):integer;
begin
    case &type of
    EVP_CTRL_RAND_KEY:
    begin
        if RAND_priv_bytes(ptr, 8) <= 0  then
            Exit(0);
        DES_set_odd_parity(PDES_cblock (ptr));
        Exit(1);
    end
    else
        Exit(-1);
    end;
end;


function des_init_key(ctx : PEVP_CIPHER_CTX;{const} key, iv : PByte; enc : integer):integer;
var
  deskey : PDES_cblock;
  dat : PEVP_DES_KEY;
  mode : integer;
begin
    deskey := PDES_cblock (key);
    dat := PEVP_DES_KEY( EVP_CIPHER_CTX_get_cipher_data(ctx));
    dat.stream.cbc := nil;
{$IF defined(SPARC_DES_CAPABLE)}
    if SPARC_DES_CAPABLE then begin
        mode := EVP_CIPHER_CTX_get_mode(ctx);
        if mode = EVP_CIPH_CBC_MODE then begin
            des_t4_key_expand(key, &dat.ks.ks);
            dat.stream.cbc := enc ? des_t4_cbc_encrypt : des_t4_cbc_decrypt;
            Exit(1);
        end;
    end;
{$ENDIF}
    DES_set_key_unchecked(deskey, EVP_CIPHER_CTX_get_cipher_data(ctx));
    Result := 1;
end;

function EVP_des_cbc:PEVP_CIPHER;
begin
 Result := @des_cbc;
end;


function EVP_des_cfb64:PEVP_CIPHER;
begin
 Result := @des_cfb64;
end;


function EVP_des_ofb:PEVP_CIPHER;
begin
 Result := @des_ofb;
end;


function EVP_des_ecb:PEVP_CIPHER;
begin
 Result := @des_ecb;
end;


end.
