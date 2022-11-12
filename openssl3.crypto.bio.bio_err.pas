unit openssl3.crypto.bio.bio_err;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;

 function ossl_err_load_BIO_strings:integer;

 var
   BIO_str_reasons: array of TERR_STRING_DATA;

implementation
uses OpenSSL3.Err;

function ossl_err_load_BIO_strings:integer;
begin
{$IFNDEF OPENSSL_NO_ERR}
    if ERR_reason_error_string(BIO_str_reasons[0].error) = nil then
        ERR_load_strings_const(@BIO_str_reasons);
{$ENDIF}
    Result := 1;
end;

initialization
  BIO_str_reasons := [
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_BIO, 0, BIO_R_ACCEPT_ERROR), 'accept error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_BIO, 0, BIO_R_ADDRINFO_ADDR_IS_NOT_AF_INET),
    'addrinfo addr is not af inet'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_BIO, 0, BIO_R_AMBIGUOUS_HOST_OR_SERVICE),
    'ambiguous host or service'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_BIO, 0, BIO_R_BAD_FOPEN_MODE), 'bad fopen mode'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_BIO, 0, BIO_R_BROKEN_PIPE), 'broken pipe'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_BIO, 0, BIO_R_CONNECT_ERROR), 'connect error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_BIO, 0, BIO_R_CONNECT_TIMEOUT), 'connect timeout'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_BIO, 0, BIO_R_GETHOSTBYNAME_ADDR_IS_NOT_AF_INET),
    'gethostbyname addr is not af inet'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_BIO, 0, BIO_R_GETSOCKNAME_ERROR), 'getsockname error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_BIO, 0, BIO_R_GETSOCKNAME_TRUNCATED_ADDRESS),
    'getsockname truncated address'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_BIO, 0, BIO_R_GETTING_SOCKTYPE), 'getting socktype'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_BIO, 0, BIO_R_INVALID_ARGUMENT), 'invalid argument'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_BIO, 0, BIO_R_INVALID_SOCKET), 'invalid socket'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_BIO, 0, BIO_R_IN_USE), 'in use'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_BIO, 0, BIO_R_LENGTH_TOO_LONG), 'length too long'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_BIO, 0, BIO_R_LISTEN_V6_ONLY), 'listen v6 only'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_BIO, 0, BIO_R_LOOKUP_RETURNED_NOTHING),
    'lookup returned nothing'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_BIO, 0, BIO_R_MALFORMED_HOST_OR_SERVICE),
    'malformed host or service'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_BIO, 0, BIO_R_NBIO_CONNECT_ERROR), 'nbio connect error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_BIO, 0, BIO_R_NO_ACCEPT_ADDR_OR_SERVICE_SPECIFIED),
    'no accept addr or service specified'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_BIO, 0, BIO_R_NO_HOSTNAME_OR_SERVICE_SPECIFIED),
    'no hostname or service specified'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_BIO, 0, BIO_R_NO_PORT_DEFINED), 'no port defined'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_BIO, 0, BIO_R_NO_SUCH_FILE), 'no such file'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_BIO, 0, BIO_R_TRANSFER_ERROR), 'transfer error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_BIO, 0, BIO_R_TRANSFER_TIMEOUT), 'transfer timeout'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_BIO, 0, BIO_R_UNABLE_TO_BIND_SOCKET),
    'unable to bind socket'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_BIO, 0, BIO_R_UNABLE_TO_CREATE_SOCKET),
    'unable to create socket'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_BIO, 0, BIO_R_UNABLE_TO_KEEPALIVE),
    'unable to keepalive'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_BIO, 0, BIO_R_UNABLE_TO_LISTEN_SOCKET),
    'unable to listen socket'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_BIO, 0, BIO_R_UNABLE_TO_NODELAY), 'unable to nodelay'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_BIO, 0, BIO_R_UNABLE_TO_REUSEADDR),
    'unable to reuseaddr'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_BIO, 0, BIO_R_UNAVAILABLE_IP_FAMILY),
    'unavailable ip family'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_BIO, 0, BIO_R_UNINITIALIZED), 'uninitialized'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_BIO, 0, BIO_R_UNKNOWN_INFO_TYPE), 'unknown info type'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_BIO, 0, BIO_R_UNSUPPORTED_IP_FAMILY),
    'unsupported ip family'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_BIO, 0, BIO_R_UNSUPPORTED_METHOD), 'unsupported method'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_BIO, 0, BIO_R_UNSUPPORTED_PROTOCOL_FAMILY),
    'unsupported protocol family'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_BIO, 0, BIO_R_WRITE_TO_READ_ONLY_BIO),
    'write to read only BIO'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_BIO, 0, BIO_R_WSASTARTUP), 'WSAStartup'),
    get_ERR_STRING_DATA(0, nil)
];


end.
