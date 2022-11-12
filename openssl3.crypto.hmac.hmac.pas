unit openssl3.crypto.hmac.hmac;

interface
uses OpenSSL.Api;

const
  HMAC_MAX_MD_CBLOCK_SIZE = 144;

function _HMAC_Final( ctx : PHMAC_CTX; md : PByte; len : Puint32):integer;
function _HMAC_size(const ctx : PHMAC_CTX):size_t;
function HMAC_CTX_new:PHMAC_CTX;
function HMAC_CTX_reset( ctx : PHMAC_CTX):integer;
procedure hmac_ctx_cleanup( ctx : PHMAC_CTX);
function hmac_ctx_alloc_mds( ctx : PHMAC_CTX):integer;
procedure HMAC_CTX_free( ctx : PHMAC_CTX);
function HMAC_Init_ex(ctx : PHMAC_CTX;const key : Pointer; len : integer;{const} md : PEVP_MD; impl : PENGINE):integer;
function HMAC_Update(ctx : PHMAC_CTX;const data : PByte; len : size_t):integer;
function HMAC_Final( ctx : PHMAC_CTX; md : PByte; len : Puint32):integer;
function HMAC_CTX_copy(dctx: PHMAC_CTX; const sctx : PHMAC_CTX):integer;
procedure HMAC_CTX_set_flags( ctx : PHMAC_CTX; flags : Cardinal);

implementation

uses openssl3.crypto.evp.evp_lib, openssl3.crypto.evp.digest,
     openssl3.crypto.mem,         OpenSSL3.common;

procedure HMAC_CTX_set_flags( ctx : PHMAC_CTX; flags : Cardinal);
begin
    EVP_MD_CTX_set_flags(ctx.i_ctx, flags);
    EVP_MD_CTX_set_flags(ctx.o_ctx, flags);
    EVP_MD_CTX_set_flags(ctx.md_ctx, flags);
end;


function HMAC_CTX_copy( dctx: PHMAC_CTX;const sctx : PHMAC_CTX):integer;
label _err;
begin
    if 0>=hmac_ctx_alloc_mds(dctx ) then
        goto _err;
    if 0>=EVP_MD_CTX_copy_ex(dctx.i_ctx, sctx.i_ctx ) then
        goto _err;
    if 0>=EVP_MD_CTX_copy_ex(dctx.o_ctx, sctx.o_ctx ) then
        goto _err;
    if 0>=EVP_MD_CTX_copy_ex(dctx.md_ctx, sctx.md_ctx ) then
        goto _err;
    dctx.md := sctx.md;
    Exit(1);
 _err:
    hmac_ctx_cleanup(dctx);
    Result := 0;
end;

function HMAC_Final( ctx : PHMAC_CTX; md : PByte; len : Puint32):integer;
var
  i : uint32;
  buf : array[0..(EVP_MAX_MD_SIZE)-1] of Byte;
  label _err;
begin
    if nil =ctx.md then goto _err;
    FillChar(buf, SizeOf(BUF), 0);
    if 0>=EVP_DigestFinal_ex(ctx.md_ctx, @buf, @i) then
        goto _err;
    if 0>=EVP_MD_CTX_copy_ex(ctx.md_ctx, ctx.o_ctx ) then
        goto _err;
    if 0>=EVP_DigestUpdate(ctx.md_ctx, @buf, i) then
        goto _err;
    if 0>=EVP_DigestFinal_ex(ctx.md_ctx, md, len) then
        goto _err;
    Exit(1);
 _err:
    Result := 0;
end;



function HMAC_Update(ctx : PHMAC_CTX;const data : PByte; len : size_t):integer;
begin
    if nil =ctx.md then Exit(0);
    Result := EVP_DigestUpdate(ctx.md_ctx, data, len);
end;

function HMAC_Init_ex(ctx : PHMAC_CTX;const key : Pointer; len : integer;{const} md : PEVP_MD; impl : PENGINE):integer;
var
  rv, reset,
  i,
  j             : integer;
  pad           : array[0..(HMAC_MAX_MD_CBLOCK_SIZE)-1] of Byte;
  keytmp_length : uint32;
  keytmp        : array[0..(HMAC_MAX_MD_CBLOCK_SIZE)-1] of Byte;
  label _err;
begin
    rv := 0; reset := 0;
    FillChar(pad, SizeOf(pad), 0);
    FillChar(keytmp, SizeOf(keytmp), 0);
    { If we are changing MD then we must have a key }
    if (md <> nil)  and  (md <> ctx.md)  and ( (key = nil)  or  (len < 0) ) then
        Exit(0);
    if md <> nil then
       ctx.md := md
    else if (ctx.md <> nil) then
        md := ctx.md
    else
        Exit(0);
    {
     * The HMAC construction is not allowed to be used with the
     * extendable-output functions (XOF) shake128 and shake256.
     }
    if EVP_MD_get_flags(md) and EVP_MD_FLAG_XOF <> 0 then
        Exit(0);
    if key <> nil then begin
        reset := 1;
        j := EVP_MD_get_block_size(md);
        if not ossl_assert(j <= int(sizeof(keytmp)))  then
            Exit(0);
        if j < 0 then Exit(0);
        if j < len then
        begin
            if (0>=EVP_DigestInit_ex(ctx.md_ctx, md, impl))
                     or  (0>=EVP_DigestUpdate(ctx.md_ctx, key, len))
                     or  (0>=EVP_DigestFinal_ex(ctx.md_ctx, @keytmp,
                                           @keytmp_length))  then
                Exit(0);
        end
        else
        begin
            if (len < 0)  or  (len > int(sizeof(keytmp))) then
                Exit(0);
            memcpy(@keytmp, key, len);
            keytmp_length := len;
        end;
        if keytmp_length <> HMAC_MAX_MD_CBLOCK_SIZE then
            memset(@keytmp[keytmp_length], 0,
                   HMAC_MAX_MD_CBLOCK_SIZE - keytmp_length);
        for i := 0 to HMAC_MAX_MD_CBLOCK_SIZE-1 do
            pad[i] := $36  xor  keytmp[i];
        if (0>=EVP_DigestInit_ex(ctx.i_ctx, md, impl))  or
           (0>=EVP_DigestUpdate(ctx.i_ctx, @pad,
                                     EVP_MD_get_block_size(md))) then
            goto _err;
        for i := 0 to HMAC_MAX_MD_CBLOCK_SIZE-1 do
            pad[i] := $5c  xor  keytmp[i];
        if (0>=EVP_DigestInit_ex(ctx.o_ctx, md, impl)) or
           (0>=EVP_DigestUpdate(ctx.o_ctx, @pad,
                                     EVP_MD_get_block_size(md)))  then
            goto _err;
    end;
    if 0>=EVP_MD_CTX_copy_ex(ctx.md_ctx, ctx.i_ctx) then
        goto _err;
    rv := 1;
 _err:
    if reset > 0 then begin
        FillChar(keytmp, sizeof(keytmp), 0);
        FillChar(pad, sizeof(pad), 0);
    end;
    Result := rv;
end;



procedure HMAC_CTX_free( ctx : PHMAC_CTX);
begin
    if ctx <> nil then
    begin
        hmac_ctx_cleanup(ctx);
        EVP_MD_CTX_free(ctx.i_ctx);
        EVP_MD_CTX_free(ctx.o_ctx);
        EVP_MD_CTX_free(ctx.md_ctx);
        OPENSSL_free(Pointer(ctx));
    end;
end;




function hmac_ctx_alloc_mds( ctx : PHMAC_CTX):integer;
begin
    if ctx.i_ctx = nil then ctx.i_ctx := EVP_MD_CTX_new;
    if ctx.i_ctx = nil then Exit(0);
    if ctx.o_ctx = nil then ctx.o_ctx := EVP_MD_CTX_new;
    if ctx.o_ctx = nil then Exit(0);
    if ctx.md_ctx = nil then ctx.md_ctx := EVP_MD_CTX_new;
    if ctx.md_ctx = nil then Exit(0);
    Result := 1;
end;

procedure hmac_ctx_cleanup( ctx : PHMAC_CTX);
begin
    {EVP_MD_CTX_reset(ctx.i_ctx);
    EVP_MD_CTX_reset(ctx.o_ctx);
    EVP_MD_CTX_reset(ctx.md_ctx);}
    ctx.md := nil;
end;



function HMAC_CTX_reset( ctx : PHMAC_CTX):integer;
begin
    hmac_ctx_cleanup(ctx);
    if 0 >= hmac_ctx_alloc_mds(ctx) then
    begin
        hmac_ctx_cleanup(ctx);
        Exit(0);
    end;
    Result := 1;
end;

function HMAC_CTX_new:PHMAC_CTX;
begin
    Result := OPENSSL_zalloc(sizeof(THMAC_CTX));
    if Result <> nil then begin
        if 0>=HMAC_CTX_reset(Result) then
        begin
            HMAC_CTX_free(Result);
            Exit(nil);
        end;
    end;

end;

function _HMAC_size(const ctx : PHMAC_CTX):size_t;
var
  size : integer;
begin
    size := EVP_MD_get_size((ctx).md);
    Result := get_result(size < 0 , 0 , size);
end;



function _HMAC_Final( ctx : PHMAC_CTX; md : PByte; len : Puint32):integer;
var
  i : uint32;

  buf : array[0..(EVP_MAX_MD_SIZE)-1] of Byte;
  label _err;
begin
    if nil = ctx.md then goto _err ;
    if 0>= EVP_DigestFinal_ex(ctx.md_ctx, @buf, @i ) then
        goto _err ;
    if 0>= EVP_MD_CTX_copy_ex(ctx.md_ctx, ctx.o_ctx ) then
        goto _err ;
    if 0>= EVP_DigestUpdate(ctx.md_ctx, @buf, i ) then
        goto _err ;
    if 0>= EVP_DigestFinal_ex(ctx.md_ctx, md, len ) then
        goto _err ;
    Exit(1);
 _err:
    Result := 0;
end;


end.
