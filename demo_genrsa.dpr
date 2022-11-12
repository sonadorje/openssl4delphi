program demo_genrsa;

{$APPTYPE CONSOLE}
//{$I DICompilers.inc}


uses
  {$I openssl4d.inc}
  SysUtils;

function generate_key:integer;
var
  ret        : integer;
  r          : PRSA;
  bp_public,
  bp_private : PBIO;
  bits       : integer;
  e          : Cardinal;
  bne        : PBIGNUM;
  label _free_all;
begin
    ret := 0;
    r := nil;
    bne := nil;
    bp_public := nil;
    bp_private := nil;
    bits := 2048;
    e := RSA_F4;
    // 1. generate rsa key
    bne := BN_new;
    ret := BN_set_word(bne,e);
    if ret <> 1 then begin
      goto _free_all;
    end;
    r := RSA_new;
    ret := RSA_generate_key_ex(r, bits, bne, nil);
    if ret <> 1 then begin
      goto _free_all;
    end;
    // 2. save public key
    bp_public := BIO_new_file('public.pem', 'w+');
    ret := PEM_write_bio_RSAPublicKey(bp_public, r);
    if ret <> 1 then begin
      goto _free_all;
    end;
    // 3. save private key
    bp_private := BIO_new_file('private.pem', 'w+');
    ret := PEM_write_bio_RSAPrivateKey(bp_private, r, nil, nil, 0, nil, nil);
    // 4. free
_free_all:
    BIO_free_all(bp_public);
    BIO_free_all(bp_private);
    RSA_free(r);
    BN_free(bne);
    Result := int(ret = 1);
end;

begin
  try
    generate_key;
  except
    on e:Exception do
      WriteLn(e.Message);
  end;
end.





