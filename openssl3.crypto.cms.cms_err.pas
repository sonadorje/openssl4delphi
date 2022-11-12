unit openssl3.crypto.cms.cms_err;

interface
uses OpenSSL.Api;

function ossl_err_load_CMS_strings:integer;

var
  CMS_str_reasons: array of TERR_STRING_DATA;

implementation
uses OpenSSL3.Err;



function ossl_err_load_CMS_strings:integer;
begin
{$IFNDEF OPENSSL_NO_ERR}
    if ERR_reason_error_string(CMS_str_reasons[0].error ) = nil then
        ERR_load_strings_const(@CMS_str_reasons);
{$ENDIF}
    Result := 1;
end;

initialization
   CMS_str_reasons := [
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_ADD_SIGNER_ERROR), 'add signer error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_ATTRIBUTE_ERROR), 'attribute error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_CERTIFICATE_ALREADY_PRESENT),
    'certificate already present'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_CERTIFICATE_HAS_NO_KEYID),
    'certificate has no keyid'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_CERTIFICATE_VERIFY_ERROR),
    'certificate verify error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_CIPHER_AEAD_SET_TAG_ERROR),
    'cipher aead set tag error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_CIPHER_GET_TAG), 'cipher get tag'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_CIPHER_INITIALISATION_ERROR),
    'cipher initialisation error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_CIPHER_PARAMETER_INITIALISATION_ERROR),
    'cipher parameter initialisation error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_CMS_DATAFINAL_ERROR),
    'cms datafinal error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_CMS_LIB), 'cms lib'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_CONTENTIDENTIFIER_MISMATCH),
    'contentidentifier mismatch'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_CONTENT_NOT_FOUND), 'content not found'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_CONTENT_TYPE_MISMATCH),
    'content type mismatch'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_CONTENT_TYPE_NOT_COMPRESSED_DATA),
    'content type not compressed data'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_CONTENT_TYPE_NOT_ENVELOPED_DATA),
    'content type not enveloped data'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_CONTENT_TYPE_NOT_SIGNED_DATA),
    'content type not signed data'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_CONTENT_VERIFY_ERROR),
    'content verify error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_CTRL_ERROR), 'ctrl error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_CTRL_FAILURE), 'ctrl failure'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_DECODE_ERROR), 'decode error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_DECRYPT_ERROR), 'decrypt error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_ERROR_GETTING_PUBLIC_KEY),
    'error getting public key'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_ERROR_READING_MESSAGEDIGEST_ATTRIBUTE),
    'error reading messagedigest attribute'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_ERROR_SETTING_KEY), 'error setting key'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_ERROR_SETTING_RECIPIENTINFO),
    'error setting recipientinfo'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_ESS_SIGNING_CERTID_MISMATCH_ERROR),
    'ess signing certid mismatch error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_INVALID_ENCRYPTED_KEY_LENGTH),
    'invalid encrypted key length'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_INVALID_KEY_ENCRYPTION_PARAMETER),
    'invalid key encryption parameter'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_INVALID_KEY_LENGTH), 'invalid key length'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_INVALID_LABEL), 'invalid label'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_INVALID_OAEP_PARAMETERS),
    'invalid oaep parameters'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_KDF_PARAMETER_ERROR),
    'kdf parameter error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_MD_BIO_INIT_ERROR), 'md bio init error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_MESSAGEDIGEST_ATTRIBUTE_WRONG_LENGTH),
    'messagedigest attribute wrong length'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_MESSAGEDIGEST_WRONG_LENGTH),
    'messagedigest wrong length'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_MSGSIGDIGEST_ERROR), 'msgsigdigest error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_MSGSIGDIGEST_VERIFICATION_FAILURE),
    'msgsigdigest verification failure'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_MSGSIGDIGEST_WRONG_LENGTH),
    'msgsigdigest wrong length'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_NEED_ONE_SIGNER), 'need one signer'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_NOT_A_SIGNED_RECEIPT),
    'not a signed receipt'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_NOT_ENCRYPTED_DATA), 'not encrypted data'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_NOT_KEK), 'not kek'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_NOT_KEY_AGREEMENT), 'not key agreement'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_NOT_KEY_TRANSPORT), 'not key transport'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_NOT_PWRI), 'not pwri'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_NOT_SUPPORTED_FOR_THIS_KEY_TYPE),
    'not supported for this key type'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_NO_CIPHER), 'no cipher'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_NO_CONTENT), 'no content'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_NO_CONTENT_TYPE), 'no content type'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_NO_DEFAULT_DIGEST), 'no default digest'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_NO_DIGEST_SET), 'no digest set'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_NO_KEY), 'no key'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_NO_KEY_OR_CERT), 'no key or cert'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_NO_MATCHING_DIGEST), 'no matching digest'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_NO_MATCHING_RECIPIENT),
    'no matching recipient'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_NO_MATCHING_SIGNATURE),
    'no matching signature'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_NO_MSGSIGDIGEST), 'no msgsigdigest'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_NO_PASSWORD), 'no password'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_NO_PRIVATE_KEY), 'no private key'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_NO_PUBLIC_KEY), 'no public key'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_NO_RECEIPT_REQUEST), 'no receipt request'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_NO_SIGNERS), 'no signers'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_PEER_KEY_ERROR), 'peer key error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE),
    'private key does not match certificate'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_RECEIPT_DECODE_ERROR),
    'receipt decode error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_RECIPIENT_ERROR), 'recipient error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_SHARED_INFO_ERROR), 'shared info error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_SIGNER_CERTIFICATE_NOT_FOUND),
    'signer certificate not found'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_SIGNFINAL_ERROR), 'signfinal error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_SMIME_TEXT_ERROR), 'smime text error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_STORE_INIT_ERROR), 'store init error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_TYPE_NOT_COMPRESSED_DATA),
    'type not compressed data'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_TYPE_NOT_DATA), 'type not data'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_TYPE_NOT_DIGESTED_DATA),
    'type not digested data'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_TYPE_NOT_ENCRYPTED_DATA),
    'type not encrypted data'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_TYPE_NOT_ENVELOPED_DATA),
    'type not enveloped data'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_UNABLE_TO_FINALIZE_CONTEXT),
    'unable to finalize context'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_UNKNOWN_CIPHER), 'unknown cipher'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_UNKNOWN_DIGEST_ALGORITHM),
    'unknown digest algorithm'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_UNKNOWN_ID), 'unknown id'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_UNSUPPORTED_COMPRESSION_ALGORITHM),
    'unsupported compression algorithm'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_UNSUPPORTED_CONTENT_TYPE),
    'unsupported content type'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_UNSUPPORTED_ENCRYPTION_TYPE),
    'unsupported encryption type'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_UNSUPPORTED_KEK_ALGORITHM),
    'unsupported kek algorithm'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM),
    'unsupported key encryption algorithm'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_UNSUPPORTED_LABEL_SOURCE),
    'unsupported label source'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_UNSUPPORTED_RECIPIENTINFO_TYPE),
    'unsupported recipientinfo type'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_UNSUPPORTED_RECIPIENT_TYPE),
    'unsupported recipient type'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_UNSUPPORTED_TYPE), 'unsupported type'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_UNWRAP_ERROR), 'unwrap error'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_UNWRAP_FAILURE), 'unwrap failure'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_VERIFICATION_FAILURE),
    'verification failure'),
    get_ERR_STRING_DATA(ERR_PACK(ERR_LIB_CMS, 0, CMS_R_WRAP_ERROR), 'wrap error'),
    get_ERR_STRING_DATA(0, nil)
];

end.
