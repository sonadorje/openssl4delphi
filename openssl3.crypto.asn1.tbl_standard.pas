unit openssl3.crypto.asn1.tbl_standard;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;

(*
 * Copyright 1999-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *)

(* size limits: this stuff is taken straight from RFC3280 *)
 const
ub_name                         =32768;
ub_common_name                  =64;
ub_locality_name                =128;
ub_state_name                   =128;
ub_organization_name            =64;
ub_organization_unit_name       =64;
ub_title                        =64;
ub_email_address                =128;
ub_serial_number                =64;

(* From RFC4524 *)

ub_rfc822_mailbox               =256;

(* This table must be kept in NID order *)

  tbl_standard: array[0..27] of TASN1_STRING_TABLE = (
    (nid: NID_commonName;                minsize:  1; maxsize: ub_common_name; mask: DIRSTRING_TYPE; flags: 0),
    (nid: NID_countryName;               minsize:  2; maxsize: 2; mask: B_ASN1_PRINTABLESTRING; flags: STABLE_NO_MASK),
    (nid: NID_localityName;              minsize:  1; maxsize: ub_locality_name; mask: DIRSTRING_TYPE; flags: 0),
    (nid: NID_stateOrProvinceName;       minsize: 1; maxsize: ub_state_name;  mask: DIRSTRING_TYPE; flags: 0),
    (nid: NID_organizationName;          minsize:  1; maxsize: ub_organization_name;  mask: DIRSTRING_TYPE; flags: 0),
    (nid: NID_organizationalUnitName;    minsize:  1; maxsize: ub_organization_unit_name;  mask: DIRSTRING_TYPE; flags: 0),
    (nid: NID_pkcs9_emailAddress;        minsize: 1; maxsize: ub_email_address;  mask: B_ASN1_IA5STRING; flags: STABLE_NO_MASK),
    (nid: NID_pkcs9_unstructuredName;    minsize: 1; maxsize: -1;  mask: PKCS9STRING_TYPE; flags: 0),
    (nid: NID_pkcs9_challengePassword;   minsize: 1; maxsize: -1;  mask: PKCS9STRING_TYPE; flags: 0),
    (nid: NID_pkcs9_unstructuredAddress; minsize: 1; maxsize: -1;  mask: DIRSTRING_TYPE; flags: 0),
    (nid: NID_givenName;                 minsize: 1; maxsize: ub_name;  mask: DIRSTRING_TYPE; flags: 0),
    (nid: NID_surname;                   minsize: 1; maxsize: ub_name;  mask: DIRSTRING_TYPE; flags: 0),
    (nid: NID_initials;                  minsize: 1; maxsize: ub_name;  mask: DIRSTRING_TYPE; flags: 0),
    (nid: NID_serialNumber;              minsize: 1; maxsize: ub_serial_number;  mask: B_ASN1_PRINTABLESTRING; flags: STABLE_NO_MASK),
    (nid: NID_friendlyName;              minsize: -1; maxsize: -1;  mask: B_ASN1_BMPSTRING; flags: STABLE_NO_MASK),
    (nid: NID_name;                      minsize: 1; maxsize: ub_name; mask: DIRSTRING_TYPE; flags: 0),
    (nid: NID_dnQualifier;               minsize: -1; maxsize: -1;  mask: B_ASN1_PRINTABLESTRING; flags: STABLE_NO_MASK),
    (nid: NID_domainComponent;           minsize: 1; maxsize: -1;  mask: B_ASN1_IA5STRING; flags: STABLE_NO_MASK),
    (nid: NID_ms_csp_name;               minsize: -1; maxsize: -1;  mask: B_ASN1_BMPSTRING; flags: STABLE_NO_MASK),
    (nid: NID_rfc822Mailbox;             minsize: 1; maxsize: ub_rfc822_mailbox;  mask: B_ASN1_IA5STRING;  flags: STABLE_NO_MASK),
    (nid: NID_jurisdictionCountryName;   minsize: 2; maxsize: 2;  mask: B_ASN1_PRINTABLESTRING; flags: STABLE_NO_MASK),
    (nid: NID_INN;                       minsize: 1; maxsize: 12;  mask: B_ASN1_NUMERICSTRING; flags: STABLE_NO_MASK),
    (nid: NID_OGRN;                      minsize: 1; maxsize: 13; mask: B_ASN1_NUMERICSTRING; flags: STABLE_NO_MASK),
    (nid: NID_SNILS;                     minsize: 1; maxsize: 11; mask: B_ASN1_NUMERICSTRING; flags: STABLE_NO_MASK),
    (nid: NID_countryCode3c;             minsize: 3; maxsize: 3;  mask: B_ASN1_PRINTABLESTRING; flags: STABLE_NO_MASK),
    (nid: NID_countryCode3n;             minsize: 3; maxsize: 3;  mask: B_ASN1_NUMERICSTRING; flags: STABLE_NO_MASK),
    (nid: NID_dnsName;                   minsize: 0; maxsize: -1;  mask: B_ASN1_UTF8STRING; flags: STABLE_NO_MASK),
    (nid: NID_id_on_SmtpUTF8Mailbox;     minsize: 1; maxsize: ub_email_address;  mask: B_ASN1_UTF8STRING; flags: STABLE_NO_MASK)
);


implementation

end.
