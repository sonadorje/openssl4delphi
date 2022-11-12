unit OpenSSL3.crypto.ct.ct_prn;

interface
uses OpenSSL.Api;

procedure SCT_signature_algorithms_print(const sct : PSCT; _out : PBIO);
procedure timestamp_print( timestamp : uint64; _out : PBIO);
function SCT_validation_status_string(const sct : PSCT):PUTF8Char;
procedure SCT_print(const sct : PSCT; _out : PBIO; indent : integer;const log_store : PCTLOG_STORE);
procedure SCT_LIST_print(const sct_list : Pstack_st_SCT; _out : PBIO; indent : integer;const separator : PUTF8Char; log_store : PCTLOG_STORE);

implementation
uses OpenSSL3.crypto.ct.ct_sct, openssl3.crypto.bio.bio_print,
     OpenSSL3.crypto.ct.ct_log,  openssl3.crypto.bio.bio_dump,
     openssl3.include.openssl.ct,
     openssl3.crypto.asn1.a_gentm,  openssl3.crypto.asn1.asn1_lib,
     openssl3.crypto.objects.obj_dat, openssl3.crypto.asn1.tasn_typ;

procedure SCT_signature_algorithms_print(const sct : PSCT; _out : PBIO);
var
  nid : integer;
begin
    nid := SCT_get_signature_nid(sct);
    if nid = NID_undef then
       BIO_printf(_out, ' %02X%02X' , [sct.hash_alg, sct.sig_alg])
    else
        BIO_printf(_out, ' %s' , [OBJ_nid2ln(nid)]);
end;


procedure timestamp_print( timestamp : uint64; _out : PBIO);
var
  gen : PASN1_GENERALIZEDTIME;

  genstr : array[0..19] of UTF8Char;
begin
    gen := ASN1_GENERALIZEDTIME_new();
    if gen = nil then exit;
    ASN1_GENERALIZEDTIME_adj(gen, time_t(0),
                             int (timestamp div 86400000),
                             (timestamp mod 86400000) div 1000);
    {
     * Note GeneralizedTime from ASN1_GENERALIZETIME_adj is always 15
     * characters long with a final Z. Update it with fractional seconds.
     }
    BIO_snprintf(genstr, sizeof(genstr), ' %.14s.%03dZ' ,
                 [ASN1_STRING_get0_data(PASN1_STRING(gen)), uint32(timestamp mod 1000)]);
    if ASN1_GENERALIZEDTIME_set_string(gen, genstr) > 0 then
        ASN1_GENERALIZEDTIME_print(_out, gen);
    ASN1_GENERALIZEDTIME_free(gen);
end;


function SCT_validation_status_string(const sct : PSCT):PUTF8Char;
begin
    case (SCT_get_validation_status(sct)) of
    SCT_VALIDATION_STATUS_NOT_SET:
        Exit(' not set' );
    SCT_VALIDATION_STATUS_UNKNOWN_VERSION:
        Exit(' unknown version' );
    SCT_VALIDATION_STATUS_UNKNOWN_LOG:
        Exit(' unknown log' );
    SCT_VALIDATION_STATUS_UNVERIFIED:
        Exit(' unverified' );
    SCT_VALIDATION_STATUS_INVALID:
        Exit(' invalid' );
    SCT_VALIDATION_STATUS_VALID:
        Exit(' valid' );
    end;
    Result := ' unknown status' ;
end;


procedure SCT_print(const sct : PSCT; _out : PBIO; indent : integer;const log_store : PCTLOG_STORE);
var
  log : PCTLOG;
begin
    log := nil;
    if log_store <> nil then
    begin
        log := CTLOG_STORE_get0_log_by_id(log_store, sct.log_id,
                                         sct.log_id_len);
    end;
    BIO_printf(_out, ' %*sSigned Certificate Timestamp:' , [indent, ' '] );
    BIO_printf(_out, ' \n%*sVersion   : ' , [indent + 4, ' '] );
    if sct.version <> SCT_VERSION_V1 then
    begin
        BIO_printf(_out, ' unknown\n%*s' , [indent + 16, ' '] );
        BIO_hex_string(_out, indent + 16, 16, sct.sct, sct.sct_len);
        exit;
    end;
    BIO_printf(_out, ' v1 ($ 0)',[] );
    if log <> nil then
    begin
        BIO_printf(_out, ' \n%*sLog       : %s' , [indent + 4, ' ' ,
                   CTLOG_get0_name(log)]);
    end;
    BIO_printf(_out, ' \n%*sLog ID    : ' , [indent + 4, ' '] );
    BIO_hex_string(_out, indent + 16, 16, sct.log_id, sct.log_id_len);
    BIO_printf(_out, ' \n%*sTimestamp : ' , [indent + 4, ' '] );
    timestamp_print(sct.timestamp, _out);
    BIO_printf(_out, ' \n%*sExtensions: ' , [indent + 4, ' '] );
    if sct.ext_len = 0 then
       BIO_printf(_out, ' none',[] )
    else
        BIO_hex_string(_out, indent + 16, 16, sct.ext, sct.ext_len);
    BIO_printf(_out, ' \n%*sSignature : ' , [indent + 4, ' '] );
    SCT_signature_algorithms_print(sct, _out);
    BIO_printf(_out, ' \n%*s            ' , [indent + 4, ' '] );
    BIO_hex_string(_out, indent + 16, 16, sct.sig, sct.sig_len);
end;


procedure SCT_LIST_print(const sct_list : Pstack_st_SCT; _out : PBIO; indent : integer;const separator : PUTF8Char; log_store : PCTLOG_STORE);
var
  sct_count,
  i         : integer;
  sct       : PSCT;
begin
    sct_count := sk_SCT_num(sct_list);
    for i := 0 to sct_count-1 do
    begin
        sct := sk_SCT_value(sct_list, i);
        SCT_print(sct, _out, indent, log_store);
        if i < sk_SCT_num(sct_list) - 1  then
            BIO_printf(_out, ' %s' , [separator]);
    end;
end;


end.
