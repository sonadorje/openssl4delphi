unit openssl3.crypto.evp.evp_local;

interface
uses OpenSSL.Api;

(*
 * These methods implement different ways to pass a params array to the
 * provider.  They will return one of these values:
 *
 * -2 if the method doesn't come from a provider
 *    (evp_do_param will return this to the called)
 * -1 if the provider doesn't offer the desired function
 *    (evp_do_param will raise an error and return 0)
 * or the return value from the desired function
 *    (evp_do_param will return it to the caller)
 *)
 //该函数在evp_local.h中仅有定义，无具体实现
function evp_do_md_getparams(const md : PEVP_MD; params : POSSL_PARAM):integer;

implementation
uses OpenSSL3.Err;

function evp_do_md_getparams(const md : PEVP_MD; params : POSSL_PARAM):integer;
begin
   if (md <> nil) and (params <> nil) then
   begin
      if Assigned(md.get_params) then
         Exit(1)
      else
      begin
        ERR_raise_data(ERR_LIB_EVP, ERR_R_EVP_LIB, 'md.get_params not defined!');
        Exit(-1);
      end;
   end;
end;


end.
