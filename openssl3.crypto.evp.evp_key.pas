unit openssl3.crypto.evp.evp_key;

interface
uses OpenSSL.Api;

 function EVP_get_pw_prompt:PUTF8Char;
 function EVP_read_pw_string_min(buf : PUTF8Char; min, len : integer; prompt : PUTF8Char; verify : integer):integer;
 function EVP_BytesToKey(const _type : PEVP_CIPHER; md : PEVP_MD; salt, data : PByte; datal, count : integer; key, iv : PByte):integer;

 var
   prompt_string: array[0..80-1] of UTF8Char;

implementation
uses openssl3.crypto.ui.ui_lib, openssl3.crypto.mem, openssl3.crypto.evp.evp_lib,
     openssl3.crypto.evp.digest;



function EVP_BytesToKey(const _type : PEVP_CIPHER; md : PEVP_MD; salt, data : PByte; datal, count : integer; key, iv : PByte):integer;
var
  c : PEVP_MD_CTX;
  md_buf : array[0..(EVP_MAX_MD_SIZE)-1] of Byte;
  niv, nkey, addmd : integer;
  mds, i : uint32;
  rv : integer;
  label _err;
begin
    addmd := 0;
    mds := 0;
    rv := 0;
    nkey := EVP_CIPHER_get_key_length(_type);
    niv := EVP_CIPHER_get_iv_length(_type);
    assert(nkey <= EVP_MAX_KEY_LENGTH);
    assert(niv <= EVP_MAX_IV_LENGTH);
    if data = nil then Exit(nkey);
    c := EVP_MD_CTX_new();
    if c = nil then goto _err ;
    while true do
    begin
        if 0>= EVP_DigestInit_ex(c, md, nil) then
            goto _err ;
        if PostInc(addmd) > 0 then
            if 0>= EVP_DigestUpdate(c, @(md_buf[0]), mds) then
                goto _err ;
        if 0>= EVP_DigestUpdate(c, data, datal) then
            goto _err ;
        if salt <> nil then
           if (0>= EVP_DigestUpdate(c, salt, PKCS5_SALT_LEN)) then
                goto _err ;
        if 0>= EVP_DigestFinal_ex(c, @(md_buf[0]) , @mds) then
            goto _err ;
        for i := 1 to uint32( count-1) do
        begin
            if 0>= EVP_DigestInit_ex(c, md, nil) then
                goto _err ;
            if 0>= EVP_DigestUpdate(c, @md_buf[0], mds) then
                goto _err ;
            if 0>= EVP_DigestFinal_ex(c, @md_buf[0] , @mds) then
                goto _err ;
        end;
        i := 0;
        if nkey > 0 then
        begin
            while true do
            begin
                if nkey = 0 then
                    break;
                if i = mds then break;
                if key <> nil then
                   PostInc(key)^ := md_buf[i];
                Dec(nkey);
                Inc(i);
            end;
        end;
        if (niv > 0) and  (i <> mds)  then
        begin
            while true do
            begin
                if niv = 0 then
                    break;
                if i = mds then break;
                if iv <> nil then
                   PostInc(iv)^ := md_buf[i];
                Dec(niv);
                Inc(i);
            end;
        end;
        if (nkey = 0)  and  (niv = 0) then
            break;
    end;
    rv := EVP_CIPHER_get_key_length(_type);
 _err:
    EVP_MD_CTX_free(c);
    OPENSSL_cleanse(@md_buf, sizeof(md_buf));
    Result := rv;
end;

function EVP_read_pw_string_min(buf : PUTF8Char; min, len : integer; prompt : PUTF8Char; verify : integer):integer;
var
  ret : integer;
  buff : array[0..(BUFSIZ)-1] of UTF8Char;
  ui : PUI;
  label _end;
begin
    ret := -1;
    if (prompt = nil) and  (prompt_string[0] <> #0) then
        prompt := prompt_string;
    ui := UI_new();
    if ui = nil then
       Exit(ret);
    if (UI_add_input_string(ui, prompt, 0, buf, min,
                           get_result(len >= BUFSIZ , BUFSIZ - 1 , len)) < 0 )
         or ( (verify > 0) and
              (UI_add_verify_string(ui, prompt, 0, buff, min,
                           get_result(len >= BUFSIZ , BUFSIZ - 1 , len),
                                    buf) < 0)) then
        goto _end ;
    ret := UI_process(ui);
    OPENSSL_cleanse(@buff, BUFSIZ);
 _end:
    UI_free(ui);
    Result := ret;
end;




function EVP_get_pw_prompt:PUTF8Char;
begin
    if prompt_string[0] = #0 then
       Exit(nil)
    else
        Result := prompt_string;
end;


end.
