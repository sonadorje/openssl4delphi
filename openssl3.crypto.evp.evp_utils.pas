unit openssl3.crypto.evp.evp_utils;

interface
uses OpenSSL.Api;

function evp_do_ciph_ctx_getparams(const obj : PEVP_CIPHER; algctx : Pointer; params : POSSL_PARAM):integer;
function evp_do_ciph_getparams(const obj : PEVP_CIPHER; params : POSSL_PARAM):integer;
procedure geterr;
procedure seterr;
function PARAM_CHECK(obj: PEVP_CIPHER; func, errfunc: String): Integer;
function evp_do_ciph_ctx_setparams(const obj : PEVP_CIPHER; algctx : Pointer; params : POSSL_PARAM):integer;
function evp_do_md_getparams(const obj : PEVP_MD; params : POSSL_PARAM):integer;
function evp_do_md_ctx_getparams(const obj : PEVP_MD; algctx : Pointer; params : POSSL_PARAM):integer;
function evp_do_md_ctx_setparams(const obj : PEVP_MD; algctx : Pointer; params : POSSL_PARAM):integer;


implementation
uses OpenSSL3.Err;

function evp_do_md_ctx_getparams(const obj : PEVP_MD; algctx : Pointer; params : POSSL_PARAM):integer;
begin
   if obj = Pointer(0)  then
      Exit(0);
   if obj.prov = Pointer(0)  then
      Exit(-1);
   if not Assigned(obj.get_ctx_params) then
   begin
      geterr;
      Exit(0);
   end;
   Exit(obj.get_ctx_params(algctx, params));
end;


function evp_do_md_ctx_setparams(const obj : PEVP_MD; algctx : Pointer; params : POSSL_PARAM):integer;
begin
 if obj = Pointer(0)  then Exit(0);
   if obj.prov = Pointer(0)  then Exit(-1);
   if not Assigned(obj.set_ctx_params) then
  begin
     seterr;
     Exit(0);
   end;
   Exit(obj.set_ctx_params(algctx, params));
end;

function evp_do_md_getparams(const obj : PEVP_MD; params : POSSL_PARAM):integer;
begin
   if obj = Pointer(0)  then Exit(0);
   if obj.prov = Pointer(0)  then Exit(-1);
   if not Assigned(obj.get_params) then
   begin
     geterr;
     Exit(0);
   end;
   Exit(obj.get_params(params));
end;

procedure seterr;
begin
    ERR_raise(ERR_LIB_EVP, EVP_R_CANNOT_SET_PARAMETERS);
end;


function evp_do_ciph_ctx_getparams(const obj : PEVP_CIPHER; algctx : Pointer; params : POSSL_PARAM):integer;
begin
   if obj = Pointer(0)  then Exit(0);
   if obj.prov = Pointer(0)  then Exit(-1);
   if not Assigned(obj.get_ctx_params) then
   begin
       geterr;
       Exit(0);
   end;
   Exit(obj.get_ctx_params(algctx, params));
end;


function evp_do_ciph_ctx_setparams(const obj : PEVP_CIPHER; algctx : Pointer; params : POSSL_PARAM):integer;
begin
   if obj = Pointer(0)  then Exit(0);
   if obj.prov = Pointer(0)  then Exit(-1);
   if not Assigned(obj.set_ctx_params) then
   begin
     seterr;
     Exit(0);
   end;
   Exit(obj.set_ctx_params(algctx, params));
end;


function evp_do_ciph_getparams(const obj : PEVP_CIPHER; params : POSSL_PARAM):integer;
begin
   if (obj = Pointer(0) ) then
       exit(0);
   if (obj.prov = Pointer(0) ) then
      exit(-1);
   if Assigned(obj.get_params) = false then
   begin
        geterr;
        exit(0);
   end;
   result := obj.get_params(params);

end;

procedure geterr;
begin
    ERR_raise(ERR_LIB_EVP, EVP_R_CANNOT_GET_PARAMETERS);
end;


function PARAM_CHECK(obj: PEVP_CIPHER; func, errfunc: String): Integer;
begin
    if (obj = nil) then
        Exit( 0);
    if (obj.prov = nil) then
        Exit( EVP_CTRL_RET_UNSUPPORTED);
    if func = 'get_params' then
    begin
        if not Assigned(obj.get_params) then
        begin
            if errfunc = 'geterr' then
               geterr;
            Exit( 0);
        end;
    end
    else
    if func = 'get_ctx_params' then
    begin
        if not Assigned(obj.get_ctx_params) then
        begin
            if errfunc = 'geterr' then
               geterr;
            Exit( 0);
        end;
    end;
end;

end.
