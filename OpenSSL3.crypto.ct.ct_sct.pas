unit OpenSSL3.crypto.ct.ct_sct;

interface
uses OpenSSL.Api;

procedure SCT_LIST_free( a : Pstack_st_SCT);
procedure SCT_free( sct : PSCT);
function SCT_new:PSCT;
function SCT_get_signature_nid(const sct : PSCT):integer;
function SCT_set1_signature(sct : PSCT;const sig : PByte; sig_len : size_t):integer;
function SCT_set_source( sct : PSCT; source : sct_source_t):integer;
function SCT_set_log_entry_type( sct : PSCT; entry_type : ct_log_entry_type_t):integer;
function SCT_is_complete(const sct : PSCT):integer;
function SCT_signature_is_complete(const sct : PSCT):integer;
function SCT_get_validation_status(const sct : PSCT):sct_validation_status_t;
function SCT_set_version( sct : PSCT; version : sct_version_t):integer;
function SCT_set0_log_id( sct : PSCT; log_id : PByte; log_id_len : size_t):integer;
 procedure SCT_set0_extensions( sct : PSCT; ext : PByte; ext_len : size_t);
procedure SCT_set_timestamp( sct : PSCT; timestamp : uint64);

implementation
uses openssl3.include.openssl.ct, openssl3.crypto.mem, OpenSSL3.Err,
     openssl3.crypto.o_str;





procedure SCT_set_timestamp( sct : PSCT; timestamp : uint64);
begin
    sct.timestamp := timestamp;
    sct.validation_status := SCT_VALIDATION_STATUS_NOT_SET;
end;

procedure SCT_set0_extensions( sct : PSCT; ext : PByte; ext_len : size_t);
begin
    OPENSSL_free(sct.ext);
    sct.ext := ext;
    sct.ext_len := ext_len;
    sct.validation_status := SCT_VALIDATION_STATUS_NOT_SET;
end;


function SCT_set0_log_id( sct : PSCT; log_id : PByte; log_id_len : size_t):integer;
begin
    if (sct.version = SCT_VERSION_V1)  and  (log_id_len <> CT_V1_HASHLEN) then
    begin
        ERR_raise(ERR_LIB_CT, CT_R_INVALID_LOG_ID_LENGTH);
        Exit(0);
    end;
    OPENSSL_free(sct.log_id);
    sct.log_id := log_id;
    sct.log_id_len := log_id_len;
    sct.validation_status := SCT_VALIDATION_STATUS_NOT_SET;
    Result := 1;
end;




function SCT_set_version( sct : PSCT; version : sct_version_t):integer;
begin
    if version <> SCT_VERSION_V1 then
    begin
        ERR_raise(ERR_LIB_CT, CT_R_UNSUPPORTED_VERSION);
        Exit(0);
    end;
    sct.version := version;
    sct.validation_status := SCT_VALIDATION_STATUS_NOT_SET;
    Result := 1;
end;




function SCT_get_validation_status(const sct : PSCT):sct_validation_status_t;
begin
    Result := sct.validation_status;
end;

function SCT_signature_is_complete(const sct : PSCT):integer;
begin
    Exit(Int( (SCT_get_signature_nid(sct) <> NID_undef)  and
              (sct.sig <> nil)  and  (sct.sig_len > 0) ));
end;





function SCT_is_complete(const sct : PSCT):integer;
begin
    case sct.version of
    SCT_VERSION_NOT_SET:
        Exit(0);
    SCT_VERSION_V1:
        Exit(Int( (sct.log_id <> nil)  and  (SCT_signature_is_complete(sct)>0) ));
    else
        Result := Int(sct.sct <> nil); { Just need cached encoding }
    end;
end;

function SCT_set_log_entry_type( sct : PSCT; entry_type : ct_log_entry_type_t):integer;
begin
    sct.validation_status := SCT_VALIDATION_STATUS_NOT_SET;
    case entry_type of
        CT_LOG_ENTRY_TYPE_X509,
        CT_LOG_ENTRY_TYPE_PRECERT:
        begin
            sct.entry_type := entry_type;
            Exit(1);
        end;
        CT_LOG_ENTRY_TYPE_NOT_SET:
        begin
        //    break;
        end;
    end;
    ERR_raise(ERR_LIB_CT, CT_R_UNSUPPORTED_ENTRY_TYPE);
    Result := 0;
end;


function SCT_set_source( sct : PSCT; source : sct_source_t):integer;
begin
    sct.source := source;
    sct.validation_status := SCT_VALIDATION_STATUS_NOT_SET;
    case source of
        SCT_SOURCE_TLS_EXTENSION,
        SCT_SOURCE_OCSP_STAPLED_RESPONSE:
            Exit(SCT_set_log_entry_type(sct, CT_LOG_ENTRY_TYPE_X509));
        SCT_SOURCE_X509V3_EXTENSION:
            Exit(SCT_set_log_entry_type(sct, CT_LOG_ENTRY_TYPE_PRECERT));
        SCT_SOURCE_UNKNOWN:
            begin
               //break;
            end;
    end;
    { if we aren't sure, leave the log entry type alone }
    Result := 1;
end;

function SCT_set1_signature(sct : PSCT;const sig : PByte; sig_len : size_t):integer;
begin
    OPENSSL_free(sct.sig);
    sct.sig := nil;
    sct.sig_len := 0;
    sct.validation_status := SCT_VALIDATION_STATUS_NOT_SET;
    if (sig <> nil)  and  (sig_len > 0) then
    begin
        sct.sig := OPENSSL_memdup(sig, sig_len);
        if sct.sig = nil then
        begin
            ERR_raise(ERR_LIB_CT, ERR_R_MALLOC_FAILURE);
            Exit(0);
        end;
        sct.sig_len := sig_len;
    end;
    Result := 1;
end;




function SCT_get_signature_nid(const sct : PSCT):integer;
begin
    if sct.version = SCT_VERSION_V1 then begin
        if sct.hash_alg = TLSEXT_hash_sha256 then  begin
            case sct.sig_alg of
            TLSEXT_signature_ecdsa:
                Exit(NID_ecdsa_with_SHA256);
            TLSEXT_signature_rsa:
                Exit(NID_sha256WithRSAEncryption);
            else
                Exit(NID_undef);
            end;
        end;
    end;
    Result := NID_undef;
end;


function SCT_new:PSCT;
var
  sct : PSCT;
begin
    sct := OPENSSL_zalloc(sizeof(sct^));
    if sct = nil then
    begin
        ERR_raise(ERR_LIB_CT, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    sct.entry_type := CT_LOG_ENTRY_TYPE_NOT_SET;
    sct.version := SCT_VERSION_NOT_SET;
    Result := sct;
end;




procedure SCT_free( sct : PSCT);
begin
    if sct = nil then
       exit;
    OPENSSL_free(sct.log_id);
    OPENSSL_free(sct.ext);
    OPENSSL_free(sct.sig);
    OPENSSL_free(sct.sct);
    OPENSSL_free(sct);
end;

procedure SCT_LIST_free( a : Pstack_st_SCT);
begin
    sk_SCT_pop_free(a, SCT_free);
end;


end.
