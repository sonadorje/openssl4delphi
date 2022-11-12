unit openssl3.crypto.params_dup;

interface
uses OpenSSL.Api;
const
    OSSL_PARAM_ALIGN_SIZE = sizeof(TOSSL_PARAM_ALIGNED_BLOCK);

function ossl_param_bytes_to_blocks( bytes : size_t):size_t;
 procedure ossl_param_set_secure_block( last : POSSL_PARAM; secure_buffer : Pointer; secure_buffer_sz : size_t);
 procedure OSSL_PARAM_free( params : POSSL_PARAM);

implementation
uses  openssl3.crypto.mem_sec, openssl3.crypto.mem;


procedure OSSL_PARAM_free( params : POSSL_PARAM);
var
  p : POSSL_PARAM;
begin
    if params <> nil then
    begin
        p := params;
        while ( p.key <> nil) do
            Inc(p);
        if p.data_type = OSSL_PARAM_ALLOCATED_END then
           OPENSSL_secure_clear_free(p.data, p.data_size);
        OPENSSL_free(Pointer(params));
    end;
end;



procedure ossl_param_set_secure_block( last : POSSL_PARAM; secure_buffer : Pointer; secure_buffer_sz : size_t);
begin
    last.key := nil;
    last.data_size := secure_buffer_sz;
    last.data := secure_buffer;
    last.data_type := OSSL_PARAM_ALLOCATED_END;
end;

function ossl_param_bytes_to_blocks( bytes : size_t):size_t;
begin
    Result := (bytes + OSSL_PARAM_ALIGN_SIZE - 1) div OSSL_PARAM_ALIGN_SIZE;
end;


end.
