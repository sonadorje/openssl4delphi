unit openssl3.crypto.http.http_err;

interface
uses OpenSSL.Api;

 function ossl_err_load_HTTP_strings:integer;

 var
   HTTP_str_reasons: array of TERR_STRING_DATA;

implementation
uses OpenSSL3.Err;


function ossl_err_load_HTTP_strings:integer;
begin
{$IFNDEF OPENSSL_NO_ERR}
    if ERR_reason_error_string(HTTP_str_reasons[0].error) = nil  then
        ERR_load_strings_const(@HTTP_str_reasons);
{$ENDIF}
    Result := 1;
end;

initialization
  HTTP_str_reasons := [
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_HTTP, 0, HTTP_R_ASN1_LEN_EXCEEDS_MAX_RESP_LEN),
    'asn1 len exceeds max resp len'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_HTTP, 0, HTTP_R_CONNECT_FAILURE), 'connect failure'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_HTTP, 0, HTTP_R_ERROR_PARSING_ASN1_LENGTH),
    'error parsing asn1 length'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_HTTP, 0, HTTP_R_ERROR_PARSING_CONTENT_LENGTH),
    'error parsing content length'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_HTTP, 0, HTTP_R_ERROR_PARSING_URL), 'error parsing url'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_HTTP, 0, HTTP_R_ERROR_RECEIVING), 'error receiving'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_HTTP, 0, HTTP_R_ERROR_SENDING), 'error sending'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_HTTP, 0, HTTP_R_FAILED_READING_DATA),
    'failed reading data'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_HTTP, 0, HTTP_R_HEADER_PARSE_ERROR),
    'header parse error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_HTTP, 0, HTTP_R_INCONSISTENT_CONTENT_LENGTH),
    'inconsistent content length'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_HTTP, 0, HTTP_R_INVALID_PORT_NUMBER),
    'invalid port number'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_HTTP, 0, HTTP_R_INVALID_URL_PATH), 'invalid url path'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_HTTP, 0, HTTP_R_INVALID_URL_SCHEME),
    'invalid url scheme'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_HTTP, 0, HTTP_R_MAX_RESP_LEN_EXCEEDED),
    'max resp len exceeded'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_HTTP, 0, HTTP_R_MISSING_ASN1_ENCODING),
    'missing asn1 encoding'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_HTTP, 0, HTTP_R_MISSING_CONTENT_TYPE),
    'missing content type'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_HTTP, 0, HTTP_R_MISSING_REDIRECT_LOCATION),
    'missing redirect location'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_HTTP, 0, HTTP_R_RECEIVED_ERROR), 'received error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_HTTP, 0, HTTP_R_RECEIVED_WRONG_HTTP_VERSION),
    'received wrong http version'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_HTTP, 0, HTTP_R_REDIRECTION_FROM_HTTPS_TO_HTTP),
    'redirection from https to http'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_HTTP, 0, HTTP_R_REDIRECTION_NOT_ENABLED),
    'redirection not enabled'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_HTTP, 0, HTTP_R_RESPONSE_LINE_TOO_LONG),
    'response line too long'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_HTTP, 0, HTTP_R_RESPONSE_PARSE_ERROR),
    'response parse error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_HTTP, 0, HTTP_R_RETRY_TIMEOUT), 'retry timeout'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_HTTP, 0, HTTP_R_SERVER_CANCELED_CONNECTION),
    'server canceled connection'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_HTTP, 0, HTTP_R_SOCK_NOT_SUPPORTED),
    'sock not supported'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_HTTP, 0, HTTP_R_STATUS_CODE_UNSUPPORTED),
    'status code unsupported'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_HTTP, 0, HTTP_R_TLS_NOT_ENABLED), 'tls not enabled'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_HTTP, 0, HTTP_R_TOO_MANY_REDIRECTIONS),
    'too many redirections'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_HTTP, 0, HTTP_R_UNEXPECTED_CONTENT_TYPE),
    'unexpected content type'),
    get_ERR_STRING_DATA(0, nil)
];

end.
