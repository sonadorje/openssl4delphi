unit openssl3.crypto.objects.obj_dat;

interface
uses OpenSSL.Api, Variants;

const
   NUM_NID = 1251;

   NUM_OBJ = 1113;
   ADDED_DATA = 0;
   ADDED_SNAME =    1;
   ADDED_LNAME =    2;
   ADDED_NID   =    3;
   NUM_LN      = 1242;
   ln_objs: array[0..NUM_LN-1] of Uint32 = (
     363,    { "AD Time Stamping" }
     405,    { "ANSI X9.62" }
     368,    { "Acceptable OCSP Responses" }
     910,    { "Any Extended Key Usage" }
     664,    { "Any language" }
     177,    { "Authority Information Access" }
    1220,    { "BGPsec Router" }
     365,    { "Basic OCSP Response" }
     285,    { "Biometric Info" }
    1221,    { "Brand Indicator for Message Identification" }
     179,    { "CA Issuers" }
     785,    { "CA Repository" }
    1219,    { "CMC Archive Server" }
    1131,    { "CMC Certificate Authority" }
    1132,    { "CMC Registration Authority" }
     954,    { "CT Certificate SCTs" }
     952,    { "CT Precertificate Poison" }
     951,    { "CT Precertificate SCTs" }
     953,    { "CT Precertificate Signer" }
    1222,    { "Certificate Management Key Generation Authority" }
    1227,    { "Class of Signing Tool" }
    1233,    { "Class of Signing Tool KA1" }
    1231,    { "Class of Signing Tool KB1" }
    1232,    { "Class of Signing Tool KB2" }
    1228,    { "Class of Signing Tool KC1" }
    1229,    { "Class of Signing Tool KC2" }
    1230,    { "Class of Signing Tool KC3" }
     131,    { "Code Signing" }
    1024,    { "Ctrl/Provision WAP Termination" }
    1023,    { "Ctrl/provision WAP Access" }
    1159,    { "DSTU 4145-2002 big endian" }
    1158,    { "DSTU 4145-2002 little endian" }
    1152,    { "DSTU Gost 28147-2009" }
    1154,    { "DSTU Gost 28147-2009 CFB mode" }
    1153,    { "DSTU Gost 28147-2009 OFB mode" }
    1155,    { "DSTU Gost 28147-2009 key wrap" }
    1157,    { "DSTU Gost 34311-95" }
    1160,    { "DSTU curve 0" }
    1161,    { "DSTU curve 1" }
    1162,    { "DSTU curve 2" }
    1163,    { "DSTU curve 3" }
    1164,    { "DSTU curve 4" }
    1165,    { "DSTU curve 5" }
    1166,    { "DSTU curve 6" }
    1167,    { "DSTU curve 7" }
    1168,    { "DSTU curve 8" }
    1169,    { "DSTU curve 9" }
     783,    { "Diffie-Hellman based MAC" }
     382,    { "Directory" }
     392,    { "Domain" }
     132,    { "E-mail Protection" }
    1087,    { "ED25519" }
    1088,    { "ED448" }
     389,    { "Enterprises" }
     384,    { "Experimental" }
     372,    { "Extended OCSP Status" }
     172,    { "Extension Request" }
     813,    { "GOST 28147-89" }
     849,    { "GOST 28147-89 Cryptocom ParamSet" }
     815,    { "GOST 28147-89 MAC" }
    1003,    { "GOST 28147-89 TC26 parameter set" }
     851,    { "GOST 34.10-2001 Cryptocom" }
     850,    { "GOST 34.10-94 Cryptocom" }
     811,    { "GOST R 34.10-2001" }
     817,    { "GOST R 34.10-2001 DH" }
    1148,    { "GOST R 34.10-2012 (256 bit) ParamSet A" }
    1184,    { "GOST R 34.10-2012 (256 bit) ParamSet B" }
    1185,    { "GOST R 34.10-2012 (256 bit) ParamSet C" }
    1186,    { "GOST R 34.10-2012 (256 bit) ParamSet D" }
     998,    { "GOST R 34.10-2012 (512 bit) ParamSet A" }
     999,    { "GOST R 34.10-2012 (512 bit) ParamSet B" }
    1149,    { "GOST R 34.10-2012 (512 bit) ParamSet C" }
     997,    { "GOST R 34.10-2012 (512 bit) testing parameter set" }
     979,    { "GOST R 34.10-2012 with 256 bit modulus" }
     980,    { "GOST R 34.10-2012 with 512 bit modulus" }
     985,    { "GOST R 34.10-2012 with GOST R 34.11-2012 (256 bit)" }
     986,    { "GOST R 34.10-2012 with GOST R 34.11-2012 (512 bit)" }
     812,    { "GOST R 34.10-94" }
     818,    { "GOST R 34.10-94 DH" }
     982,    { "GOST R 34.11-2012 with 256 bit hash" }
     983,    { "GOST R 34.11-2012 with 512 bit hash" }
     809,    { "GOST R 34.11-94" }
     816,    { "GOST R 34.11-94 PRF" }
     807,    { "GOST R 34.11-94 with GOST R 34.10-2001" }
     853,    { "GOST R 34.11-94 with GOST R 34.10-2001 Cryptocom" }
     808,    { "GOST R 34.11-94 with GOST R 34.10-94" }
     852,    { "GOST R 34.11-94 with GOST R 34.10-94 Cryptocom" }
     854,    { "GOST R 3410-2001 Parameter Set Cryptocom" }
    1156,    { "HMAC DSTU Gost 34311-95" }
     988,    { "HMAC GOST 34.11-2012 256 bit" }
     989,    { "HMAC GOST 34.11-2012 512 bit" }
     810,    { "HMAC GOST 34.11-94" }
     432,    { "Hold Instruction Call Issuer" }
     430,    { "Hold Instruction Code" }
     431,    { "Hold Instruction None" }
     433,    { "Hold Instruction Reject" }
     634,    { "ICC or token signature" }
    1171,    { "IEEE Security in Storage Working Group" }
    1004,    { "INN" }
     294,    { "IPSec End System" }
     295,    { "IPSec Tunnel" }
     296,    { "IPSec User" }
    1140,    { "ISO CN Member Body" }
     182,    { "ISO Member Body" }
     183,    { "ISO US Member Body" }
    1150,    { "ISO-UA" }
     667,    { "Independent" }
     665,    { "Inherit all" }
     647,    { "International Organizations" }
     142,    { "Invalidity Date" }
     504,    { "MIME MHS" }
     388,    { "Mail" }
     383,    { "Management" }
     417,    { "Microsoft CSP Name" }
     135,    { "Microsoft Commercial Code Signing" }
     138,    { "Microsoft Encrypted File System" }
     171,    { "Microsoft Extension Request" }
     134,    { "Microsoft Individual Code Signing" }
     856,    { "Microsoft Local Key set" }
     137,    { "Microsoft Server Gated Crypto" }
     648,    { "Microsoft Smartcard Login" }
     136,    { "Microsoft Trust List Signing" }
     649,    { "Microsoft User Principal Name" }
    1211,    { "NAIRealm" }
     393,    { "NULL" }
     404,    { "NULL" }
      72,    { "Netscape Base Url" }
      76,    { "Netscape CA Policy Url" }
      74,    { "Netscape CA Revocation Url" }
      71,    { "Netscape Cert Type" }
      58,    { "Netscape Certificate Extension" }
      79,    { "Netscape Certificate Sequence" }
      78,    { "Netscape Comment" }
      57,    { "Netscape Communications Corp." }
      59,    { "Netscape Data Type" }
      75,    { "Netscape Renewal Url" }
      73,    { "Netscape Revocation Url" }
      77,    { "Netscape SSL Server Name" }
     139,    { "Netscape Server Gated Crypto" }
     178,    { "OCSP" }
     370,    { "OCSP Archive Cutoff" }
     367,    { "OCSP CRL ID" }
     369,    { "OCSP No Check" }
     366,    { "OCSP Nonce" }
     371,    { "OCSP Service Locator" }
     180,    { "OCSP Signing" }
    1005,    { "OGRN" }
    1226,    { "OGRNIP" }
     161,    { "PBES2" }
      69,    { "PBKDF2" }
     162,    { "PBMAC1" }
    1032,    { "PKINIT Client Auth" }
     127,    { "PKIX" }
     858,    { "Permanent Identifier" }
     164,    { "Policy Qualifier CPS" }
     165,    { "Policy Qualifier User Notice" }
     385,    { "Private" }
    1093,    { "Professional Information or basis for Admission" }
     663,    { "Proxy Certificate Information" }
    1243,    { "RPKI Manifest" }
    1245,    { "RPKI Notify" }
       1,    { "RSA Data Security, Inc." }
       2,    { "RSA Data Security, Inc. PKCS" }
    1116,    { "RSA-SHA3-224" }
    1117,    { "RSA-SHA3-256" }
    1118,    { "RSA-SHA3-384" }
    1119,    { "RSA-SHA3-512" }
     188,    { "S/MIME" }
     167,    { "S/MIME Capabilities" }
    1204,    { "SM2-with-SM3" }
    1006,    { "SNILS" }
     387,    { "SNMPv2" }
    1210,    { "SRVName" }
    1025,    { "SSH Client" }
    1026,    { "SSH Server" }
     512,    { "Secure Electronic Transactions" }
     386,    { "Security" }
     394,    { "Selected Attribute Types" }
    1029,    { "Send Owner" }
    1030,    { "Send Proxied Owner" }
    1028,    { "Send Proxied Router" }
    1027,    { "Send Router" }
    1244,    { "Signed Object" }
    1033,    { "Signing KDC Response" }
    1008,    { "Signing Tool of Issuer" }
    1007,    { "Signing Tool of Subject" }
    1208,    { "Smtp UTF8 Mailbox" }
     143,    { "Strong Extranet ID" }
     398,    { "Subject Information Access" }
    1020,    { "TLS Feature" }
     130,    { "TLS Web Client Authentication" }
     129,    { "TLS Web Server Authentication" }
     133,    { "Time Stamping" }
     375,    { "Trust Root" }
    1034,    { "X25519" }
    1035,    { "X448" }
      12,    { "X509" }
     402,    { "X509v3 AC Targeting" }
     746,    { "X509v3 Any Policy" }
      90,    { "X509v3 Authority Key Identifier" }
      87,    { "X509v3 Basic Constraints" }
     103,    { "X509v3 CRL Distribution Points" }
      88,    { "X509v3 CRL Number" }
     141,    { "X509v3 CRL Reason Code" }
     771,    { "X509v3 Certificate Issuer" }
      89,    { "X509v3 Certificate Policies" }
     140,    { "X509v3 Delta CRL Indicator" }
     126,    { "X509v3 Extended Key Usage" }
     857,    { "X509v3 Freshest CRL" }
     748,    { "X509v3 Inhibit Any Policy" }
      86,    { "X509v3 Issuer Alternative Name" }
     770,    { "X509v3 Issuing Distribution Point" }
      83,    { "X509v3 Key Usage" }
     666,    { "X509v3 Name Constraints" }
     403,    { "X509v3 No Revocation Available" }
     401,    { "X509v3 Policy Constraints" }
     747,    { "X509v3 Policy Mappings" }
      84,    { "X509v3 Private Key Usage Period" }
      85,    { "X509v3 Subject Alternative Name" }
     769,    { "X509v3 Subject Directory Attributes" }
      82,    { "X509v3 Subject Key Identifier" }
     920,    { "X9.42 DH" }
     184,    { "X9.57" }
     185,    { "X9.57 CM ?" }
    1209,    { "XmppAddr" }
     478,    { "aRecord" }
     289,    { "aaControls" }
     287,    { "ac-auditEntity" }
     397,    { "ac-proxying" }
     288,    { "ac-targeting" }
     446,    { "account" }
     364,    { "ad dvcs" }
     606,    { "additional verification" }
     419,    { "aes-128-cbc" }
     916,    { "aes-128-cbc-hmac-sha1" }
     948,    { "aes-128-cbc-hmac-sha256" }
     896,    { "aes-128-ccm" }
     421,    { "aes-128-cfb" }
     650,    { "aes-128-cfb1" }
     653,    { "aes-128-cfb8" }
     904,    { "aes-128-ctr" }
     418,    { "aes-128-ecb" }
     895,    { "aes-128-gcm" }
     958,    { "aes-128-ocb" }
     420,    { "aes-128-ofb" }
    1198,    { "aes-128-siv" }
     913,    { "aes-128-xts" }
     423,    { "aes-192-cbc" }
     917,    { "aes-192-cbc-hmac-sha1" }
     949,    { "aes-192-cbc-hmac-sha256" }
     899,    { "aes-192-ccm" }
     425,    { "aes-192-cfb" }
     651,    { "aes-192-cfb1" }
     654,    { "aes-192-cfb8" }
     905,    { "aes-192-ctr" }
     422,    { "aes-192-ecb" }
     898,    { "aes-192-gcm" }
     959,    { "aes-192-ocb" }
     424,    { "aes-192-ofb" }
    1199,    { "aes-192-siv" }
     427,    { "aes-256-cbc" }
     918,    { "aes-256-cbc-hmac-sha1" }
     950,    { "aes-256-cbc-hmac-sha256" }
     902,    { "aes-256-ccm" }
     429,    { "aes-256-cfb" }
     652,    { "aes-256-cfb1" }
     655,    { "aes-256-cfb8" }
     906,    { "aes-256-ctr" }
     426,    { "aes-256-ecb" }
     901,    { "aes-256-gcm" }
     960,    { "aes-256-ocb" }
     428,    { "aes-256-ofb" }
    1200,    { "aes-256-siv" }
     914,    { "aes-256-xts" }
     376,    { "algorithm" }
    1066,    { "aria-128-cbc" }
    1120,    { "aria-128-ccm" }
    1067,    { "aria-128-cfb" }
    1080,    { "aria-128-cfb1" }
    1083,    { "aria-128-cfb8" }
    1069,    { "aria-128-ctr" }
    1065,    { "aria-128-ecb" }
    1123,    { "aria-128-gcm" }
    1068,    { "aria-128-ofb" }
    1071,    { "aria-192-cbc" }
    1121,    { "aria-192-ccm" }
    1072,    { "aria-192-cfb" }
    1081,    { "aria-192-cfb1" }
    1084,    { "aria-192-cfb8" }
    1074,    { "aria-192-ctr" }
    1070,    { "aria-192-ecb" }
    1124,    { "aria-192-gcm" }
    1073,    { "aria-192-ofb" }
    1076,    { "aria-256-cbc" }
    1122,    { "aria-256-ccm" }
    1077,    { "aria-256-cfb" }
    1082,    { "aria-256-cfb1" }
    1085,    { "aria-256-cfb8" }
    1079,    { "aria-256-ctr" }
    1075,    { "aria-256-ecb" }
    1125,    { "aria-256-gcm" }
    1078,    { "aria-256-ofb" }
     484,    { "associatedDomain" }
     485,    { "associatedName" }
     501,    { "audio" }
    1064,    { "auth-any" }
    1049,    { "auth-dss" }
    1047,    { "auth-ecdsa" }
    1050,    { "auth-gost01" }
    1051,    { "auth-gost12" }
    1053,    { "auth-null" }
    1048,    { "auth-psk" }
    1046,    { "auth-rsa" }
    1052,    { "auth-srp" }
     882,    { "authorityRevocationList" }
      91,    { "bf-cbc" }
      93,    { "bf-cfb" }
      92,    { "bf-ecb" }
      94,    { "bf-ofb" }
    1056,    { "blake2b512" }
    1201,    { "blake2bmac" }
    1057,    { "blake2s256" }
    1202,    { "blake2smac" }
     921,    { "brainpoolP160r1" }
     922,    { "brainpoolP160t1" }
     923,    { "brainpoolP192r1" }
     924,    { "brainpoolP192t1" }
     925,    { "brainpoolP224r1" }
     926,    { "brainpoolP224t1" }
     927,    { "brainpoolP256r1" }
     928,    { "brainpoolP256t1" }
     929,    { "brainpoolP320r1" }
     930,    { "brainpoolP320t1" }
     931,    { "brainpoolP384r1" }
     932,    { "brainpoolP384t1" }
     933,    { "brainpoolP512r1" }
     934,    { "brainpoolP512t1" }
     494,    { "buildingName" }
     860,    { "businessCategory" }
     691,    { "c2onb191v4" }
     692,    { "c2onb191v5" }
     697,    { "c2onb239v4" }
     698,    { "c2onb239v5" }
     684,    { "c2pnb163v1" }
     685,    { "c2pnb163v2" }
     686,    { "c2pnb163v3" }
     687,    { "c2pnb176v1" }
     693,    { "c2pnb208w1" }
     699,    { "c2pnb272w1" }
     700,    { "c2pnb304w1" }
     702,    { "c2pnb368w1" }
     688,    { "c2tnb191v1" }
     689,    { "c2tnb191v2" }
     690,    { "c2tnb191v3" }
     694,    { "c2tnb239v1" }
     695,    { "c2tnb239v2" }
     696,    { "c2tnb239v3" }
     701,    { "c2tnb359v1" }
     703,    { "c2tnb431r1" }
     881,    { "cACertificate" }
     483,    { "cNAMERecord" }
     751,    { "camellia-128-cbc" }
     962,    { "camellia-128-ccm" }
     757,    { "camellia-128-cfb" }
     760,    { "camellia-128-cfb1" }
     763,    { "camellia-128-cfb8" }
     964,    { "camellia-128-cmac" }
     963,    { "camellia-128-ctr" }
     754,    { "camellia-128-ecb" }
     961,    { "camellia-128-gcm" }
     766,    { "camellia-128-ofb" }
     752,    { "camellia-192-cbc" }
     966,    { "camellia-192-ccm" }
     758,    { "camellia-192-cfb" }
     761,    { "camellia-192-cfb1" }
     764,    { "camellia-192-cfb8" }
     968,    { "camellia-192-cmac" }
     967,    { "camellia-192-ctr" }
     755,    { "camellia-192-ecb" }
     965,    { "camellia-192-gcm" }
     767,    { "camellia-192-ofb" }
     753,    { "camellia-256-cbc" }
     970,    { "camellia-256-ccm" }
     759,    { "camellia-256-cfb" }
     762,    { "camellia-256-cfb1" }
     765,    { "camellia-256-cfb8" }
     972,    { "camellia-256-cmac" }
     971,    { "camellia-256-ctr" }
     756,    { "camellia-256-ecb" }
     969,    { "camellia-256-gcm" }
     768,    { "camellia-256-ofb" }
     443,    { "caseIgnoreIA5StringSyntax" }
     108,    { "cast5-cbc" }
     110,    { "cast5-cfb" }
     109,    { "cast5-ecb" }
     111,    { "cast5-ofb" }
     152,    { "certBag" }
     677,    { "certicom-arc" }
     517,    { "certificate extensions" }
     883,    { "certificateRevocationList" }
    1019,    { "chacha20" }
    1018,    { "chacha20-poly1305" }
      54,    { "challengePassword" }
     407,    { "characteristic-two-field" }
     395,    { "clearance" }
     633,    { "cleartext track 2" }
     894,    { "cmac" }
      13,    { "commonName" }
     513,    { "content types" }
      50,    { "contentType" }
      53,    { "countersignature" }
    1090,    { "countryCode3c" }
    1091,    { "countryCode3n" }
      14,    { "countryName" }
     153,    { "crlBag" }
     884,    { "crossCertificatePair" }
     806,    { "cryptocom" }
     805,    { "cryptopro" }
     500,    { "dITRedirect" }
     451,    { "dNSDomain" }
     495,    { "dSAQuality" }
     434,    { "data" }
     390,    { "dcObject" }
     891,    { "deltaRevocationList" }
      31,    { "des-cbc" }
     643,    { "des-cdmf" }
      30,    { "des-cfb" }
     656,    { "des-cfb1" }
     657,    { "des-cfb8" }
      29,    { "des-ecb" }
      32,    { "des-ede" }
      43,    { "des-ede-cbc" }
      60,    { "des-ede-cfb" }
      62,    { "des-ede-ofb" }
      33,    { "des-ede3" }
      44,    { "des-ede3-cbc" }
      61,    { "des-ede3-cfb" }
     658,    { "des-ede3-cfb1" }
     659,    { "des-ede3-cfb8" }
      63,    { "des-ede3-ofb" }
      45,    { "des-ofb" }
     107,    { "description" }
     871,    { "destinationIndicator" }
      80,    { "desx-cbc" }
     947,    { "dh-cofactor-kdf" }
     946,    { "dh-std-kdf" }
      28,    { "dhKeyAgreement" }
     941,    { "dhSinglePass-cofactorDH-sha1kdf-scheme" }
     942,    { "dhSinglePass-cofactorDH-sha224kdf-scheme" }
     943,    { "dhSinglePass-cofactorDH-sha256kdf-scheme" }
     944,    { "dhSinglePass-cofactorDH-sha384kdf-scheme" }
     945,    { "dhSinglePass-cofactorDH-sha512kdf-scheme" }
     936,    { "dhSinglePass-stdDH-sha1kdf-scheme" }
     937,    { "dhSinglePass-stdDH-sha224kdf-scheme" }
     938,    { "dhSinglePass-stdDH-sha256kdf-scheme" }
     939,    { "dhSinglePass-stdDH-sha384kdf-scheme" }
     940,    { "dhSinglePass-stdDH-sha512kdf-scheme" }
      11,    { "directory services (X.500)" }
     378,    { "directory services - algorithms" }
     887,    { "distinguishedName" }
     892,    { "dmdName" }
     174,    { "dnQualifier" }
    1092,    { "dnsName" }
     447,    { "document" }
     471,    { "documentAuthor" }
     468,    { "documentIdentifier" }
     472,    { "documentLocation" }
     502,    { "documentPublisher" }
     449,    { "documentSeries" }
     469,    { "documentTitle" }
     470,    { "documentVersion" }
     380,    { "dod" }
     391,    { "domainComponent" }
     452,    { "domainRelatedObject" }
     116,    { "dsaEncryption" }
      67,    { "dsaEncryption-old" }
      66,    { "dsaWithSHA" }
     113,    { "dsaWithSHA1" }
      70,    { "dsaWithSHA1-old" }
     802,    { "dsa_with_SHA224" }
     803,    { "dsa_with_SHA256" }
    1108,    { "dsa_with_SHA3-224" }
    1109,    { "dsa_with_SHA3-256" }
    1110,    { "dsa_with_SHA3-384" }
    1111,    { "dsa_with_SHA3-512" }
    1106,    { "dsa_with_SHA384" }
    1107,    { "dsa_with_SHA512" }
     297,    { "dvcs" }
     791,    { "ecdsa-with-Recommended" }
     416,    { "ecdsa-with-SHA1" }
     793,    { "ecdsa-with-SHA224" }
     794,    { "ecdsa-with-SHA256" }
     795,    { "ecdsa-with-SHA384" }
     796,    { "ecdsa-with-SHA512" }
     792,    { "ecdsa-with-Specified" }
    1112,    { "ecdsa_with_SHA3-224" }
    1113,    { "ecdsa_with_SHA3-256" }
    1114,    { "ecdsa_with_SHA3-384" }
    1115,    { "ecdsa_with_SHA3-512" }
      48,    { "emailAddress" }
     632,    { "encrypted track 2" }
     885,    { "enhancedSearchGuide" }
      56,    { "extendedCertificateAttributes" }
     867,    { "facsimileTelephoneNumber" }
     462,    { "favouriteDrink" }
    1126,    { "ffdhe2048" }
    1127,    { "ffdhe3072" }
    1128,    { "ffdhe4096" }
    1129,    { "ffdhe6144" }
    1130,    { "ffdhe8192" }
     453,    { "friendlyCountry" }
     490,    { "friendlyCountryName" }
     156,    { "friendlyName" }
     631,    { "generate cryptogram" }
     509,    { "generationQualifier" }
     601,    { "generic cryptogram" }
      99,    { "givenName" }
    1195,    { "gmac" }
     976,    { "gost-mac-12" }
    1009,    { "gost89-cbc" }
     814,    { "gost89-cnt" }
     975,    { "gost89-cnt-12" }
    1011,    { "gost89-ctr" }
    1010,    { "gost89-ecb" }
    1036,    { "hkdf" }
     855,    { "hmac" }
     780,    { "hmac-md5" }
     781,    { "hmac-sha1" }
    1102,    { "hmac-sha3-224" }
    1103,    { "hmac-sha3-256" }
    1104,    { "hmac-sha3-384" }
    1105,    { "hmac-sha3-512" }
     797,    { "hmacWithMD5" }
     163,    { "hmacWithSHA1" }
     798,    { "hmacWithSHA224" }
     799,    { "hmacWithSHA256" }
     800,    { "hmacWithSHA384" }
     801,    { "hmacWithSHA512" }
    1193,    { "hmacWithSHA512-224" }
    1194,    { "hmacWithSHA512-256" }
     486,    { "homePostalAddress" }
     473,    { "homeTelephoneNumber" }
     466,    { "host" }
     889,    { "houseIdentifier" }
     442,    { "iA5StringSyntax" }
     381,    { "iana" }
     824,    { "id-Gost28147-89-CryptoPro-A-ParamSet" }
     825,    { "id-Gost28147-89-CryptoPro-B-ParamSet" }
     826,    { "id-Gost28147-89-CryptoPro-C-ParamSet" }
     827,    { "id-Gost28147-89-CryptoPro-D-ParamSet" }
     819,    { "id-Gost28147-89-CryptoPro-KeyMeshing" }
     829,    { "id-Gost28147-89-CryptoPro-Oscar-1-0-ParamSet" }
     828,    { "id-Gost28147-89-CryptoPro-Oscar-1-1-ParamSet" }
     830,    { "id-Gost28147-89-CryptoPro-RIC-1-ParamSet" }
     820,    { "id-Gost28147-89-None-KeyMeshing" }
     823,    { "id-Gost28147-89-TestParamSet" }
     840,    { "id-GostR3410-2001-CryptoPro-A-ParamSet" }
     841,    { "id-GostR3410-2001-CryptoPro-B-ParamSet" }
     842,    { "id-GostR3410-2001-CryptoPro-C-ParamSet" }
     843,    { "id-GostR3410-2001-CryptoPro-XchA-ParamSet" }
     844,    { "id-GostR3410-2001-CryptoPro-XchB-ParamSet" }
     839,    { "id-GostR3410-2001-TestParamSet" }
     832,    { "id-GostR3410-94-CryptoPro-A-ParamSet" }
     833,    { "id-GostR3410-94-CryptoPro-B-ParamSet" }
     834,    { "id-GostR3410-94-CryptoPro-C-ParamSet" }
     835,    { "id-GostR3410-94-CryptoPro-D-ParamSet" }
     836,    { "id-GostR3410-94-CryptoPro-XchA-ParamSet" }
     837,    { "id-GostR3410-94-CryptoPro-XchB-ParamSet" }
     838,    { "id-GostR3410-94-CryptoPro-XchC-ParamSet" }
     831,    { "id-GostR3410-94-TestParamSet" }
     845,    { "id-GostR3410-94-a" }
     846,    { "id-GostR3410-94-aBis" }
     847,    { "id-GostR3410-94-b" }
     848,    { "id-GostR3410-94-bBis" }
     822,    { "id-GostR3411-94-CryptoProParamSet" }
     821,    { "id-GostR3411-94-TestParamSet" }
     266,    { "id-aca" }
     355,    { "id-aca-accessIdentity" }
     354,    { "id-aca-authenticationInfo" }
     356,    { "id-aca-chargingIdentity" }
     399,    { "id-aca-encAttrs" }
     357,    { "id-aca-group" }
     358,    { "id-aca-role" }
     176,    { "id-ad" }
     788,    { "id-aes128-wrap" }
     897,    { "id-aes128-wrap-pad" }
     789,    { "id-aes192-wrap" }
     900,    { "id-aes192-wrap-pad" }
     790,    { "id-aes256-wrap" }
     903,    { "id-aes256-wrap-pad" }
     262,    { "id-alg" }
     893,    { "id-alg-PWRI-KEK" }
     323,    { "id-alg-des40" }
     326,    { "id-alg-dh-pop" }
     325,    { "id-alg-dh-sig-hmac-sha1" }
     324,    { "id-alg-noSignature" }
     907,    { "id-camellia128-wrap" }
     908,    { "id-camellia192-wrap" }
     909,    { "id-camellia256-wrap" }
     268,    { "id-cct" }
     361,    { "id-cct-PKIData" }
     362,    { "id-cct-PKIResponse" }
     360,    { "id-cct-crs" }
      81,    { "id-ce" }
     680,    { "id-characteristic-two-basis" }
     263,    { "id-cmc" }
     334,    { "id-cmc-addExtensions" }
     346,    { "id-cmc-confirmCertAcceptance" }
     330,    { "id-cmc-dataReturn" }
     336,    { "id-cmc-decryptedPOP" }
     335,    { "id-cmc-encryptedPOP" }
     339,    { "id-cmc-getCRL" }
     338,    { "id-cmc-getCert" }
     328,    { "id-cmc-identification" }
     329,    { "id-cmc-identityProof" }
     337,    { "id-cmc-lraPOPWitness" }
     344,    { "id-cmc-popLinkRandom" }
     345,    { "id-cmc-popLinkWitness" }
     343,    { "id-cmc-queryPending" }
     333,    { "id-cmc-recipientNonce" }
     341,    { "id-cmc-regInfo" }
     342,    { "id-cmc-responseInfo" }
     340,    { "id-cmc-revokeRequest" }
     332,    { "id-cmc-senderNonce" }
     327,    { "id-cmc-statusInfo" }
     331,    { "id-cmc-transactionId" }
    1238,    { "id-cp" }
    1250,    { "id-ct-ASPA" }
     787,    { "id-ct-asciiTextWithCRLF" }
    1246,    { "id-ct-geofeedCSVwithCRLF" }
    1237,    { "id-ct-resourceTaggedAttest" }
    1234,    { "id-ct-routeOriginAuthz" }
    1236,    { "id-ct-rpkiGhostbusters" }
    1235,    { "id-ct-rpkiManifest" }
    1247,    { "id-ct-signedChecklist" }
    1060,    { "id-ct-xml" }
     408,    { "id-ecPublicKey" }
     508,    { "id-hex-multipart-message" }
     507,    { "id-hex-partial-message" }
     260,    { "id-it" }
    1223,    { "id-it-caCerts" }
     302,    { "id-it-caKeyUpdateInfo" }
     298,    { "id-it-caProtEncCert" }
    1225,    { "id-it-certReqTemplate" }
     311,    { "id-it-confirmWaitTime" }
     303,    { "id-it-currentCRL" }
     300,    { "id-it-encKeyPairTypes" }
     310,    { "id-it-implicitConfirm" }
     308,    { "id-it-keyPairParamRep" }
     307,    { "id-it-keyPairParamReq" }
     312,    { "id-it-origPKIMessage" }
     301,    { "id-it-preferredSymmAlg" }
     309,    { "id-it-revPassphrase" }
    1224,    { "id-it-rootCaKeyUpdate" }
     299,    { "id-it-signKeyPairTypes" }
     305,    { "id-it-subscriptionRequest" }
     306,    { "id-it-subscriptionResponse" }
     784,    { "id-it-suppLangTags" }
     304,    { "id-it-unsupportedOIDs" }
     128,    { "id-kp" }
     280,    { "id-mod-attribute-cert" }
     274,    { "id-mod-cmc" }
     277,    { "id-mod-cmp" }
     284,    { "id-mod-cmp2000" }
     273,    { "id-mod-crmf" }
     283,    { "id-mod-dvcs" }
     275,    { "id-mod-kea-profile-88" }
     276,    { "id-mod-kea-profile-93" }
     282,    { "id-mod-ocsp" }
     278,    { "id-mod-qualified-cert-88" }
     279,    { "id-mod-qualified-cert-93" }
     281,    { "id-mod-timestamp-protocol" }
     264,    { "id-on" }
     347,    { "id-on-personalData" }
     265,    { "id-pda" }
     352,    { "id-pda-countryOfCitizenship" }
     353,    { "id-pda-countryOfResidence" }
     348,    { "id-pda-dateOfBirth" }
     351,    { "id-pda-gender" }
     349,    { "id-pda-placeOfBirth" }
     175,    { "id-pe" }
    1031,    { "id-pkinit" }
     261,    { "id-pkip" }
     258,    { "id-pkix-mod" }
     269,    { "id-pkix1-explicit-88" }
     271,    { "id-pkix1-explicit-93" }
     270,    { "id-pkix1-implicit-88" }
     272,    { "id-pkix1-implicit-93" }
     662,    { "id-ppl" }
     267,    { "id-qcs" }
     359,    { "id-qcs-pkixQCSyntax-v1" }
     259,    { "id-qt" }
     313,    { "id-regCtrl" }
     316,    { "id-regCtrl-authenticator" }
     319,    { "id-regCtrl-oldCertID" }
     318,    { "id-regCtrl-pkiArchiveOptions" }
     317,    { "id-regCtrl-pkiPublicationInfo" }
     320,    { "id-regCtrl-protocolEncrKey" }
     315,    { "id-regCtrl-regToken" }
     314,    { "id-regInfo" }
     322,    { "id-regInfo-certReq" }
     321,    { "id-regInfo-utf8Pairs" }
     191,    { "id-smime-aa" }
     215,    { "id-smime-aa-contentHint" }
     218,    { "id-smime-aa-contentIdentifier" }
     221,    { "id-smime-aa-contentReference" }
     240,    { "id-smime-aa-dvcs-dvc" }
     217,    { "id-smime-aa-encapContentType" }
     222,    { "id-smime-aa-encrypKeyPref" }
     220,    { "id-smime-aa-equivalentLabels" }
     232,    { "id-smime-aa-ets-CertificateRefs" }
     233,    { "id-smime-aa-ets-RevocationRefs" }
     238,    { "id-smime-aa-ets-archiveTimeStamp" }
     237,    { "id-smime-aa-ets-certCRLTimestamp" }
     234,    { "id-smime-aa-ets-certValues" }
     227,    { "id-smime-aa-ets-commitmentType" }
     231,    { "id-smime-aa-ets-contentTimestamp" }
     236,    { "id-smime-aa-ets-escTimeStamp" }
     230,    { "id-smime-aa-ets-otherSigCert" }
     235,    { "id-smime-aa-ets-revocationValues" }
     226,    { "id-smime-aa-ets-sigPolicyId" }
     229,    { "id-smime-aa-ets-signerAttr" }
     228,    { "id-smime-aa-ets-signerLocation" }
     219,    { "id-smime-aa-macValue" }
     214,    { "id-smime-aa-mlExpandHistory" }
     216,    { "id-smime-aa-msgSigDigest" }
     212,    { "id-smime-aa-receiptRequest" }
     213,    { "id-smime-aa-securityLabel" }
     239,    { "id-smime-aa-signatureType" }
     223,    { "id-smime-aa-signingCertificate" }
    1086,    { "id-smime-aa-signingCertificateV2" }
     224,    { "id-smime-aa-smimeEncryptCerts" }
     225,    { "id-smime-aa-timeStampToken" }
     192,    { "id-smime-alg" }
     243,    { "id-smime-alg-3DESwrap" }
     246,    { "id-smime-alg-CMS3DESwrap" }
     247,    { "id-smime-alg-CMSRC2wrap" }
     245,    { "id-smime-alg-ESDH" }
     241,    { "id-smime-alg-ESDHwith3DES" }
     242,    { "id-smime-alg-ESDHwithRC2" }
     244,    { "id-smime-alg-RC2wrap" }
     193,    { "id-smime-cd" }
     248,    { "id-smime-cd-ldap" }
     190,    { "id-smime-ct" }
     210,    { "id-smime-ct-DVCSRequestData" }
     211,    { "id-smime-ct-DVCSResponseData" }
     208,    { "id-smime-ct-TDTInfo" }
     207,    { "id-smime-ct-TSTInfo" }
     205,    { "id-smime-ct-authData" }
    1059,    { "id-smime-ct-authEnvelopedData" }
     786,    { "id-smime-ct-compressedData" }
    1058,    { "id-smime-ct-contentCollection" }
     209,    { "id-smime-ct-contentInfo" }
     206,    { "id-smime-ct-publishCert" }
     204,    { "id-smime-ct-receipt" }
     195,    { "id-smime-cti" }
     255,    { "id-smime-cti-ets-proofOfApproval" }
     256,    { "id-smime-cti-ets-proofOfCreation" }
     253,    { "id-smime-cti-ets-proofOfDelivery" }
     251,    { "id-smime-cti-ets-proofOfOrigin" }
     252,    { "id-smime-cti-ets-proofOfReceipt" }
     254,    { "id-smime-cti-ets-proofOfSender" }
     189,    { "id-smime-mod" }
     196,    { "id-smime-mod-cms" }
     197,    { "id-smime-mod-ess" }
     202,    { "id-smime-mod-ets-eSigPolicy-88" }
     203,    { "id-smime-mod-ets-eSigPolicy-97" }
     200,    { "id-smime-mod-ets-eSignature-88" }
     201,    { "id-smime-mod-ets-eSignature-97" }
     199,    { "id-smime-mod-msg-v3" }
     198,    { "id-smime-mod-oid" }
     194,    { "id-smime-spq" }
     250,    { "id-smime-spq-ets-sqt-unotice" }
     249,    { "id-smime-spq-ets-sqt-uri" }
     974,    { "id-tc26" }
     991,    { "id-tc26-agreement" }
     992,    { "id-tc26-agreement-gost-3410-2012-256" }
     993,    { "id-tc26-agreement-gost-3410-2012-512" }
     977,    { "id-tc26-algorithms" }
     990,    { "id-tc26-cipher" }
    1001,    { "id-tc26-cipher-constants" }
    1176,    { "id-tc26-cipher-gostr3412-2015-kuznyechik" }
    1173,    { "id-tc26-cipher-gostr3412-2015-magma" }
     994,    { "id-tc26-constants" }
     981,    { "id-tc26-digest" }
    1000,    { "id-tc26-digest-constants" }
    1002,    { "id-tc26-gost-28147-constants" }
    1147,    { "id-tc26-gost-3410-2012-256-constants" }
     996,    { "id-tc26-gost-3410-2012-512-constants" }
     987,    { "id-tc26-mac" }
     978,    { "id-tc26-sign" }
     995,    { "id-tc26-sign-constants" }
     984,    { "id-tc26-signwithdigest" }
    1179,    { "id-tc26-wrap" }
    1182,    { "id-tc26-wrap-gostr3412-2015-kuznyechik" }
    1180,    { "id-tc26-wrap-gostr3412-2015-magma" }
      34,    { "idea-cbc" }
      35,    { "idea-cfb" }
      36,    { "idea-ecb" }
      46,    { "idea-ofb" }
     676,    { "identified-organization" }
    1170,    { "ieee" }
     461,    { "info" }
     101,    { "initials" }
     869,    { "internationaliSDNNumber" }
    1241,    { "ipAddr-asNumber" }
    1242,    { "ipAddr-asNumberv2" }
    1022,    { "ipsec Internet Key Exchange" }
     749,    { "ipsec3" }
     750,    { "ipsec4" }
     181,    { "iso" }
     623,    { "issuer capabilities" }
     645,    { "itu-t" }
     492,    { "janetMailbox" }
     646,    { "joint-iso-itu-t" }
     957,    { "jurisdictionCountryName" }
     955,    { "jurisdictionLocalityName" }
     956,    { "jurisdictionStateOrProvinceName" }
     150,    { "keyBag" }
     773,    { "kisa" }
    1196,    { "kmac128" }
    1197,    { "kmac256" }
    1015,    { "kuznyechik-cbc" }
    1016,    { "kuznyechik-cfb" }
    1013,    { "kuznyechik-ctr" }
    1177,    { "kuznyechik-ctr-acpkm" }
    1178,    { "kuznyechik-ctr-acpkm-omac" }
    1012,    { "kuznyechik-ecb" }
    1183,    { "kuznyechik-kexp15" }
    1017,    { "kuznyechik-mac" }
    1014,    { "kuznyechik-ofb" }
    1063,    { "kx-any" }
    1039,    { "kx-dhe" }
    1041,    { "kx-dhe-psk" }
    1038,    { "kx-ecdhe" }
    1040,    { "kx-ecdhe-psk" }
    1045,    { "kx-gost" }
    1218,    { "kx-gost18" }
    1043,    { "kx-psk" }
    1037,    { "kx-rsa" }
    1042,    { "kx-rsa-psk" }
    1044,    { "kx-srp" }
     477,    { "lastModifiedBy" }
     476,    { "lastModifiedTime" }
     157,    { "localKeyID" }
      15,    { "localityName" }
     480,    { "mXRecord" }
    1190,    { "magma-cbc" }
    1191,    { "magma-cfb" }
    1188,    { "magma-ctr" }
    1174,    { "magma-ctr-acpkm" }
    1175,    { "magma-ctr-acpkm-omac" }
    1187,    { "magma-ecb" }
    1181,    { "magma-kexp15" }
    1192,    { "magma-mac" }
    1189,    { "magma-ofb" }
     493,    { "mailPreferenceOption" }
     467,    { "manager" }
       3,    { "md2" }
       7,    { "md2WithRSAEncryption" }
     257,    { "md4" }
     396,    { "md4WithRSAEncryption" }
       4,    { "md5" }
     114,    { "md5-sha1" }
     104,    { "md5WithRSA" }
       8,    { "md5WithRSAEncryption" }
      95,    { "mdc2" }
      96,    { "mdc2WithRSA" }
     875,    { "member" }
     602,    { "merchant initiated auth" }
     514,    { "message extensions" }
      51,    { "messageDigest" }
     911,    { "mgf1" }
     506,    { "mime-mhs-bodies" }
     505,    { "mime-mhs-headings" }
     488,    { "mobileTelephoneNumber" }
    1212,    { "modp_1536" }
    1213,    { "modp_2048" }
    1214,    { "modp_3072" }
    1215,    { "modp_4096" }
    1216,    { "modp_6144" }
    1217,    { "modp_8192" }
     481,    { "nSRecord" }
     173,    { "name" }
     681,    { "onBasis" }
     379,    { "org" }
    1089,    { "organizationIdentifier" }
      17,    { "organizationName" }
     491,    { "organizationalStatus" }
      18,    { "organizationalUnitName" }
    1141,    { "oscca" }
     475,    { "otherMailbox" }
     876,    { "owner" }
     935,    { "pSpecified" }
     489,    { "pagerTelephoneNumber" }
     782,    { "password based MAC" }
     374,    { "path" }
     621,    { "payment gateway capabilities" }
       9,    { "pbeWithMD2AndDES-CBC" }
     168,    { "pbeWithMD2AndRC2-CBC" }
     112,    { "pbeWithMD5AndCast5CBC" }
      10,    { "pbeWithMD5AndDES-CBC" }
     169,    { "pbeWithMD5AndRC2-CBC" }
     148,    { "pbeWithSHA1And128BitRC2-CBC" }
     144,    { "pbeWithSHA1And128BitRC4" }
     147,    { "pbeWithSHA1And2-KeyTripleDES-CBC" }
     146,    { "pbeWithSHA1And3-KeyTripleDES-CBC" }
     149,    { "pbeWithSHA1And40BitRC2-CBC" }
     145,    { "pbeWithSHA1And40BitRC4" }
     170,    { "pbeWithSHA1AndDES-CBC" }
      68,    { "pbeWithSHA1AndRC2-CBC" }
     499,    { "personalSignature" }
     487,    { "personalTitle" }
     464,    { "photo" }
     863,    { "physicalDeliveryOfficeName" }
     437,    { "pilot" }
     439,    { "pilotAttributeSyntax" }
     438,    { "pilotAttributeType" }
     479,    { "pilotAttributeType27" }
     456,    { "pilotDSA" }
     441,    { "pilotGroups" }
     444,    { "pilotObject" }
     440,    { "pilotObjectClass" }
     455,    { "pilotOrganization" }
     445,    { "pilotPerson" }
     186,    { "pkcs1" }
      27,    { "pkcs3" }
     187,    { "pkcs5" }
      20,    { "pkcs7" }
      21,    { "pkcs7-data" }
      25,    { "pkcs7-digestData" }
      26,    { "pkcs7-encryptedData" }
      23,    { "pkcs7-envelopedData" }
      24,    { "pkcs7-signedAndEnvelopedData" }
      22,    { "pkcs7-signedData" }
     151,    { "pkcs8ShroudedKeyBag" }
      47,    { "pkcs9" }
    1061,    { "poly1305" }
     862,    { "postOfficeBox" }
     861,    { "postalAddress" }
     661,    { "postalCode" }
     683,    { "ppBasis" }
     872,    { "preferredDeliveryMethod" }
     873,    { "presentationAddress" }
     406,    { "prime-field" }
     409,    { "prime192v1" }
     410,    { "prime192v2" }
     411,    { "prime192v3" }
     412,    { "prime239v1" }
     413,    { "prime239v2" }
     414,    { "prime239v3" }
     415,    { "prime256v1" }
     886,    { "protocolInformation" }
     510,    { "pseudonym" }
     435,    { "pss" }
     286,    { "qcStatements" }
     457,    { "qualityLabelledData" }
     450,    { "rFC822localPart" }
      98,    { "rc2-40-cbc" }
     166,    { "rc2-64-cbc" }
      37,    { "rc2-cbc" }
      39,    { "rc2-cfb" }
      38,    { "rc2-ecb" }
      40,    { "rc2-ofb" }
       5,    { "rc4" }
      97,    { "rc4-40" }
     915,    { "rc4-hmac-md5" }
     120,    { "rc5-cbc" }
     122,    { "rc5-cfb" }
     121,    { "rc5-ecb" }
     123,    { "rc5-ofb" }
     870,    { "registeredAddress" }
     460,    { "rfc822Mailbox" }
     117,    { "ripemd160" }
     119,    { "ripemd160WithRSA" }
     400,    { "role" }
     877,    { "roleOccupant" }
     448,    { "room" }
     463,    { "roomNumber" }
      19,    { "rsa" }
       6,    { "rsaEncryption" }
     644,    { "rsaOAEPEncryptionSET" }
     377,    { "rsaSignature" }
     919,    { "rsaesOaep" }
     912,    { "rsassaPss" }
     482,    { "sOARecord" }
     155,    { "safeContentsBag" }
     291,    { "sbgp-autonomousSysNum" }
    1240,    { "sbgp-autonomousSysNumv2" }
     290,    { "sbgp-ipAddrBlock" }
    1239,    { "sbgp-ipAddrBlockv2" }
     292,    { "sbgp-routerIdentifier" }
     973,    { "scrypt" }
     159,    { "sdsiCertificate" }
     859,    { "searchGuide" }
     704,    { "secp112r1" }
     705,    { "secp112r2" }
     706,    { "secp128r1" }
     707,    { "secp128r2" }
     708,    { "secp160k1" }
     709,    { "secp160r1" }
     710,    { "secp160r2" }
     711,    { "secp192k1" }
     712,    { "secp224k1" }
     713,    { "secp224r1" }
     714,    { "secp256k1" }
     715,    { "secp384r1" }
     716,    { "secp521r1" }
     154,    { "secretBag" }
     474,    { "secretary" }
     717,    { "sect113r1" }
     718,    { "sect113r2" }
     719,    { "sect131r1" }
     720,    { "sect131r2" }
     721,    { "sect163k1" }
     722,    { "sect163r1" }
     723,    { "sect163r2" }
     724,    { "sect193r1" }
     725,    { "sect193r2" }
     726,    { "sect233k1" }
     727,    { "sect233r1" }
     728,    { "sect239k1" }
     729,    { "sect283k1" }
     730,    { "sect283r1" }
     731,    { "sect409k1" }
     732,    { "sect409r1" }
     733,    { "sect571k1" }
     734,    { "sect571r1" }
     635,    { "secure device signature" }
     878,    { "seeAlso" }
     777,    { "seed-cbc" }
     779,    { "seed-cfb" }
     776,    { "seed-ecb" }
     778,    { "seed-ofb" }
     105,    { "serialNumber" }
     625,    { "set-addPolicy" }
     515,    { "set-attr" }
     518,    { "set-brand" }
     638,    { "set-brand-AmericanExpress" }
     637,    { "set-brand-Diners" }
     636,    { "set-brand-IATA-ATA" }
     639,    { "set-brand-JCB" }
     641,    { "set-brand-MasterCard" }
     642,    { "set-brand-Novus" }
     640,    { "set-brand-Visa" }
     516,    { "set-policy" }
     607,    { "set-policy-root" }
     624,    { "set-rootKeyThumb" }
     620,    { "setAttr-Cert" }
     628,    { "setAttr-IssCap-CVM" }
     630,    { "setAttr-IssCap-Sig" }
     629,    { "setAttr-IssCap-T2" }
     627,    { "setAttr-Token-B0Prime" }
     626,    { "setAttr-Token-EMV" }
     622,    { "setAttr-TokenType" }
     619,    { "setCext-IssuerCapabilities" }
     615,    { "setCext-PGWYcapabilities" }
     616,    { "setCext-TokenIdentifier" }
     618,    { "setCext-TokenType" }
     617,    { "setCext-Track2Data" }
     611,    { "setCext-cCertRequired" }
     609,    { "setCext-certType" }
     608,    { "setCext-hashedRoot" }
     610,    { "setCext-merchData" }
     613,    { "setCext-setExt" }
     614,    { "setCext-setQualf" }
     612,    { "setCext-tunneling" }
     540,    { "setct-AcqCardCodeMsg" }
     576,    { "setct-AcqCardCodeMsgTBE" }
     570,    { "setct-AuthReqTBE" }
     534,    { "setct-AuthReqTBS" }
     527,    { "setct-AuthResBaggage" }
     571,    { "setct-AuthResTBE" }
     572,    { "setct-AuthResTBEX" }
     535,    { "setct-AuthResTBS" }
     536,    { "setct-AuthResTBSX" }
     528,    { "setct-AuthRevReqBaggage" }
     577,    { "setct-AuthRevReqTBE" }
     541,    { "setct-AuthRevReqTBS" }
     529,    { "setct-AuthRevResBaggage" }
     542,    { "setct-AuthRevResData" }
     578,    { "setct-AuthRevResTBE" }
     579,    { "setct-AuthRevResTBEB" }
     543,    { "setct-AuthRevResTBS" }
     573,    { "setct-AuthTokenTBE" }
     537,    { "setct-AuthTokenTBS" }
     600,    { "setct-BCIDistributionTBS" }
     558,    { "setct-BatchAdminReqData" }
     592,    { "setct-BatchAdminReqTBE" }
     559,    { "setct-BatchAdminResData" }
     593,    { "setct-BatchAdminResTBE" }
     599,    { "setct-CRLNotificationResTBS" }
     598,    { "setct-CRLNotificationTBS" }
     580,    { "setct-CapReqTBE" }
     581,    { "setct-CapReqTBEX" }
     544,    { "setct-CapReqTBS" }
     545,    { "setct-CapReqTBSX" }
     546,    { "setct-CapResData" }
     582,    { "setct-CapResTBE" }
     583,    { "setct-CapRevReqTBE" }
     584,    { "setct-CapRevReqTBEX" }
     547,    { "setct-CapRevReqTBS" }
     548,    { "setct-CapRevReqTBSX" }
     549,    { "setct-CapRevResData" }
     585,    { "setct-CapRevResTBE" }
     538,    { "setct-CapTokenData" }
     530,    { "setct-CapTokenSeq" }
     574,    { "setct-CapTokenTBE" }
     575,    { "setct-CapTokenTBEX" }
     539,    { "setct-CapTokenTBS" }
     560,    { "setct-CardCInitResTBS" }
     566,    { "setct-CertInqReqTBS" }
     563,    { "setct-CertReqData" }
     595,    { "setct-CertReqTBE" }
     596,    { "setct-CertReqTBEX" }
     564,    { "setct-CertReqTBS" }
     565,    { "setct-CertResData" }
     597,    { "setct-CertResTBE" }
     586,    { "setct-CredReqTBE" }
     587,    { "setct-CredReqTBEX" }
     550,    { "setct-CredReqTBS" }
     551,    { "setct-CredReqTBSX" }
     552,    { "setct-CredResData" }
     588,    { "setct-CredResTBE" }
     589,    { "setct-CredRevReqTBE" }
     590,    { "setct-CredRevReqTBEX" }
     553,    { "setct-CredRevReqTBS" }
     554,    { "setct-CredRevReqTBSX" }
     555,    { "setct-CredRevResData" }
     591,    { "setct-CredRevResTBE" }
     567,    { "setct-ErrorTBS" }
     526,    { "setct-HODInput" }
     561,    { "setct-MeAqCInitResTBS" }
     522,    { "setct-OIData" }
     519,    { "setct-PANData" }
     521,    { "setct-PANOnly" }
     520,    { "setct-PANToken" }
     556,    { "setct-PCertReqData" }
     557,    { "setct-PCertResTBS" }
     523,    { "setct-PI" }
     532,    { "setct-PI-TBS" }
     524,    { "setct-PIData" }
     525,    { "setct-PIDataUnsigned" }
     568,    { "setct-PIDualSignedTBE" }
     569,    { "setct-PIUnsignedTBE" }
     531,    { "setct-PInitResData" }
     533,    { "setct-PResData" }
     594,    { "setct-RegFormReqTBE" }
     562,    { "setct-RegFormResTBS" }
     604,    { "setext-pinAny" }
     603,    { "setext-pinSecure" }
     605,    { "setext-track2" }
      41,    { "sha" }
      64,    { "sha1" }
     115,    { "sha1WithRSA" }
      65,    { "sha1WithRSAEncryption" }
     675,    { "sha224" }
     671,    { "sha224WithRSAEncryption" }
     672,    { "sha256" }
     668,    { "sha256WithRSAEncryption" }
    1096,    { "sha3-224" }
    1097,    { "sha3-256" }
    1098,    { "sha3-384" }
    1099,    { "sha3-512" }
     673,    { "sha384" }
     669,    { "sha384WithRSAEncryption" }
     674,    { "sha512" }
    1094,    { "sha512-224" }
    1145,    { "sha512-224WithRSAEncryption" }
    1095,    { "sha512-256" }
    1146,    { "sha512-256WithRSAEncryption" }
     670,    { "sha512WithRSAEncryption" }
      42,    { "shaWithRSAEncryption" }
    1100,    { "shake128" }
    1101,    { "shake256" }
      52,    { "signingTime" }
     454,    { "simpleSecurityObject" }
     496,    { "singleLevelQuality" }
    1062,    { "siphash" }
    1142,    { "sm-scheme" }
    1172,    { "sm2" }
    1143,    { "sm3" }
    1144,    { "sm3WithRSAEncryption" }
    1134,    { "sm4-cbc" }
    1249,    { "sm4-ccm" }
    1137,    { "sm4-cfb" }
    1136,    { "sm4-cfb1" }
    1138,    { "sm4-cfb8" }
    1139,    { "sm4-ctr" }
    1133,    { "sm4-ecb" }
    1248,    { "sm4-gcm" }
    1135,    { "sm4-ofb" }
    1203,    { "sshkdf" }
    1205,    { "sskdf" }
      16,    { "stateOrProvinceName" }
     660,    { "streetAddress" }
     498,    { "subtreeMaximumQuality" }
     497,    { "subtreeMinimumQuality" }
     890,    { "supportedAlgorithms" }
     874,    { "supportedApplicationContext" }
     100,    { "surname" }
     864,    { "telephoneNumber" }
     866,    { "teletexTerminalIdentifier" }
     865,    { "telexNumber" }
     459,    { "textEncodedORAddress" }
     293,    { "textNotice" }
     106,    { "title" }
    1021,    { "tls1-prf" }
     682,    { "tpBasis" }
    1151,    { "ua-pki" }
     436,    { "ucl" }
       0,    { "undefined" }
     102,    { "uniqueIdentifier" }
     888,    { "uniqueMember" }
      55,    { "unstructuredAddress" }
      49,    { "unstructuredName" }
     880,    { "userCertificate" }
     465,    { "userClass" }
     458,    { "userId" }
     879,    { "userPassword" }
     373,    { "valid" }
     678,    { "wap" }
     679,    { "wap-wsg" }
     735,    { "wap-wsg-idm-ecid-wtls1" }
     743,    { "wap-wsg-idm-ecid-wtls10" }
     744,    { "wap-wsg-idm-ecid-wtls11" }
     745,    { "wap-wsg-idm-ecid-wtls12" }
     736,    { "wap-wsg-idm-ecid-wtls3" }
     737,    { "wap-wsg-idm-ecid-wtls4" }
     738,    { "wap-wsg-idm-ecid-wtls5" }
     739,    { "wap-wsg-idm-ecid-wtls6" }
     740,    { "wap-wsg-idm-ecid-wtls7" }
     741,    { "wap-wsg-idm-ecid-wtls8" }
     742,    { "wap-wsg-idm-ecid-wtls9" }
     804,    { "whirlpool" }
     868,    { "x121Address" }
     503,    { "x500UniqueIdentifier" }
     158,    { "x509Certificate" }
     160,    { "x509Crl" }
    1207,    { "x942kdf" }
    1206,    { "x963kdf" }
     125    { "zlib compression" }
);


   obj_objs: array[0..NUM_OBJ-1] of uint32 = (
       0,    (* OBJ_undef                        0 *)
     181,    (* OBJ_iso                          1 *)
     393,    (* OBJ_joint_iso_ccitt              OBJ_joint_iso_itu_t *)
     404,    (* OBJ_ccitt                        OBJ_itu_t *)
     645,    (* OBJ_itu_t                        0 *)
     646,    (* OBJ_joint_iso_itu_t              2 *)
     434,    (* OBJ_data                         0 9 *)
     182,    (* OBJ_member_body                  1 2 *)
     379,    (* OBJ_org                          1 3 *)
     676,    (* OBJ_identified_organization      1 3 *)
      11,    (* OBJ_X500                         2 5 *)
     647,    (* OBJ_international_organizations  2 23 *)
     380,    (* OBJ_dod                          1 3 6 *)
    1170,    (* OBJ_ieee                         1 3 111 *)
      12,    (* OBJ_X509                         2 5 4 *)
     378,    (* OBJ_X500algorithms               2 5 8 *)
      81,    (* OBJ_id_ce                        2 5 29 *)
     512,    (* OBJ_id_set                       2 23 42 *)
     678,    (* OBJ_wap                          2 23 43 *)
     435,    (* OBJ_pss                          0 9 2342 *)
    1140,    (* OBJ_ISO_CN                       1 2 156 *)
    1150,    (* OBJ_ISO_UA                       1 2 804 *)
     183,    (* OBJ_ISO_US                       1 2 840 *)
     381,    (* OBJ_iana                         1 3 6 1 *)
    1034,    (* OBJ_X25519                       1 3 101 110 *)
    1035,    (* OBJ_X448                         1 3 101 111 *)
    1087,    (* OBJ_ED25519                      1 3 101 112 *)
    1088,    (* OBJ_ED448                        1 3 101 113 *)
     677,    (* OBJ_certicom_arc                 1 3 132 *)
     394,    (* OBJ_selected_attribute_types     2 5 1 5 *)
      13,    (* OBJ_commonName                   2 5 4 3 *)
     100,    (* OBJ_surname                      2 5 4 4 *)
     105,    (* OBJ_serialNumber                 2 5 4 5 *)
      14,    (* OBJ_countryName                  2 5 4 6 *)
      15,    (* OBJ_localityName                 2 5 4 7 *)
      16,    (* OBJ_stateOrProvinceName          2 5 4 8 *)
     660,    (* OBJ_streetAddress                2 5 4 9 *)
      17,    (* OBJ_organizationName             2 5 4 10 *)
      18,    (* OBJ_organizationalUnitName       2 5 4 11 *)
     106,    (* OBJ_title                        2 5 4 12 *)
     107,    (* OBJ_description                  2 5 4 13 *)
     859,    (* OBJ_searchGuide                  2 5 4 14 *)
     860,    (* OBJ_businessCategory             2 5 4 15 *)
     861,    (* OBJ_postalAddress                2 5 4 16 *)
     661,    (* OBJ_postalCode                   2 5 4 17 *)
     862,    (* OBJ_postOfficeBox                2 5 4 18 *)
     863,    (* OBJ_physicalDeliveryOfficeName   2 5 4 19 *)
     864,    (* OBJ_telephoneNumber              2 5 4 20 *)
     865,    (* OBJ_telexNumber                  2 5 4 21 *)
     866,    (* OBJ_teletexTerminalIdentifier    2 5 4 22 *)
     867,    (* OBJ_facsimileTelephoneNumber     2 5 4 23 *)
     868,    (* OBJ_x121Address                  2 5 4 24 *)
     869,    (* OBJ_internationaliSDNNumber      2 5 4 25 *)
     870,    (* OBJ_registeredAddress            2 5 4 26 *)
     871,    (* OBJ_destinationIndicator         2 5 4 27 *)
     872,    (* OBJ_preferredDeliveryMethod      2 5 4 28 *)
     873,    (* OBJ_presentationAddress          2 5 4 29 *)
     874,    (* OBJ_supportedApplicationContext  2 5 4 30 *)
     875,    (* OBJ_member                       2 5 4 31 *)
     876,    (* OBJ_owner                        2 5 4 32 *)
     877,    (* OBJ_roleOccupant                 2 5 4 33 *)
     878,    (* OBJ_seeAlso                      2 5 4 34 *)
     879,    (* OBJ_userPassword                 2 5 4 35 *)
     880,    (* OBJ_userCertificate              2 5 4 36 *)
     881,    (* OBJ_cACertificate                2 5 4 37 *)
     882,    (* OBJ_authorityRevocationList      2 5 4 38 *)
     883,    (* OBJ_certificateRevocationList    2 5 4 39 *)
     884,    (* OBJ_crossCertificatePair         2 5 4 40 *)
     173,    (* OBJ_name                         2 5 4 41 *)
      99,    (* OBJ_givenName                    2 5 4 42 *)
     101,    (* OBJ_initials                     2 5 4 43 *)
     509,    (* OBJ_generationQualifier          2 5 4 44 *)
     503,    (* OBJ_x500UniqueIdentifier         2 5 4 45 *)
     174,    (* OBJ_dnQualifier                  2 5 4 46 *)
     885,    (* OBJ_enhancedSearchGuide          2 5 4 47 *)
     886,    (* OBJ_protocolInformation          2 5 4 48 *)
     887,    (* OBJ_distinguishedName            2 5 4 49 *)
     888,    (* OBJ_uniqueMember                 2 5 4 50 *)
     889,    (* OBJ_houseIdentifier              2 5 4 51 *)
     890,    (* OBJ_supportedAlgorithms          2 5 4 52 *)
     891,    (* OBJ_deltaRevocationList          2 5 4 53 *)
     892,    (* OBJ_dmdName                      2 5 4 54 *)
     510,    (* OBJ_pseudonym                    2 5 4 65 *)
     400,    (* OBJ_role                         2 5 4 72 *)
    1089,    (* OBJ_organizationIdentifier       2 5 4 97 *)
    1090,    (* OBJ_countryCode3c                2 5 4 98 *)
    1091,    (* OBJ_countryCode3n                2 5 4 99 *)
    1092,    (* OBJ_dnsName                      2 5 4 100 *)
     769,    (* OBJ_subject_directory_attributes 2 5 29 9 *)
      82,    (* OBJ_subject_key_identifier       2 5 29 14 *)
      83,    (* OBJ_key_usage                    2 5 29 15 *)
      84,    (* OBJ_private_key_usage_period     2 5 29 16 *)
      85,    (* OBJ_subject_alt_name             2 5 29 17 *)
      86,    (* OBJ_issuer_alt_name              2 5 29 18 *)
      87,    (* OBJ_basic_constraints            2 5 29 19 *)
      88,    (* OBJ_crl_number                   2 5 29 20 *)
     141,    (* OBJ_crl_reason                   2 5 29 21 *)
     430,    (* OBJ_hold_instruction_code        2 5 29 23 *)
     142,    (* OBJ_invalidity_date              2 5 29 24 *)
     140,    (* OBJ_delta_crl                    2 5 29 27 *)
     770,    (* OBJ_issuing_distribution_point   2 5 29 28 *)
     771,    (* OBJ_certificate_issuer           2 5 29 29 *)
     666,    (* OBJ_name_constraints             2 5 29 30 *)
     103,    (* OBJ_crl_distribution_points      2 5 29 31 *)
      89,    (* OBJ_certificate_policies         2 5 29 32 *)
     747,    (* OBJ_policy_mappings              2 5 29 33 *)
      90,    (* OBJ_authority_key_identifier     2 5 29 35 *)
     401,    (* OBJ_policy_constraints           2 5 29 36 *)
     126,    (* OBJ_ext_key_usage                2 5 29 37 *)
     857,    (* OBJ_freshest_crl                 2 5 29 46 *)
     748,    (* OBJ_inhibit_any_policy           2 5 29 54 *)
     402,    (* OBJ_target_information           2 5 29 55 *)
     403,    (* OBJ_no_rev_avail                 2 5 29 56 *)
     513,    (* OBJ_set_ctype                    2 23 42 0 *)
     514,    (* OBJ_set_msgExt                   2 23 42 1 *)
     515,    (* OBJ_set_attr                     2 23 42 3 *)
     516,    (* OBJ_set_policy                   2 23 42 5 *)
     517,    (* OBJ_set_certExt                  2 23 42 7 *)
     518,    (* OBJ_set_brand                    2 23 42 8 *)
     679,    (* OBJ_wap_wsg                      2 23 43 1 *)
     382,    (* OBJ_Directory                    1 3 6 1 1 *)
     383,    (* OBJ_Management                   1 3 6 1 2 *)
     384,    (* OBJ_Experimental                 1 3 6 1 3 *)
     385,    (* OBJ_Private                      1 3 6 1 4 *)
     386,    (* OBJ_Security                     1 3 6 1 5 *)
     387,    (* OBJ_SNMPv2                       1 3 6 1 6 *)
     388,    (* OBJ_Mail                         1 3 6 1 7 *)
     376,    (* OBJ_algorithm                    1 3 14 3 2 *)
     395,    (* OBJ_clearance                    2 5 1 5 55 *)
      19,    (* OBJ_rsa                          2 5 8 1 1 *)
      96,    (* OBJ_mdc2WithRSA                  2 5 8 3 100 *)
      95,    (* OBJ_mdc2                         2 5 8 3 101 *)
     746,    (* OBJ_any_policy                   2 5 29 32 0 *)
     910,    (* OBJ_anyExtendedKeyUsage          2 5 29 37 0 *)
     519,    (* OBJ_setct_PANData                2 23 42 0 0 *)
     520,    (* OBJ_setct_PANToken               2 23 42 0 1 *)
     521,    (* OBJ_setct_PANOnly                2 23 42 0 2 *)
     522,    (* OBJ_setct_OIData                 2 23 42 0 3 *)
     523,    (* OBJ_setct_PI                     2 23 42 0 4 *)
     524,    (* OBJ_setct_PIData                 2 23 42 0 5 *)
     525,    (* OBJ_setct_PIDataUnsigned         2 23 42 0 6 *)
     526,    (* OBJ_setct_HODInput               2 23 42 0 7 *)
     527,    (* OBJ_setct_AuthResBaggage         2 23 42 0 8 *)
     528,    (* OBJ_setct_AuthRevReqBaggage      2 23 42 0 9 *)
     529,    (* OBJ_setct_AuthRevResBaggage      2 23 42 0 10 *)
     530,    (* OBJ_setct_CapTokenSeq            2 23 42 0 11 *)
     531,    (* OBJ_setct_PInitResData           2 23 42 0 12 *)
     532,    (* OBJ_setct_PI_TBS                 2 23 42 0 13 *)
     533,    (* OBJ_setct_PResData               2 23 42 0 14 *)
     534,    (* OBJ_setct_AuthReqTBS             2 23 42 0 16 *)
     535,    (* OBJ_setct_AuthResTBS             2 23 42 0 17 *)
     536,    (* OBJ_setct_AuthResTBSX            2 23 42 0 18 *)
     537,    (* OBJ_setct_AuthTokenTBS           2 23 42 0 19 *)
     538,    (* OBJ_setct_CapTokenData           2 23 42 0 20 *)
     539,    (* OBJ_setct_CapTokenTBS            2 23 42 0 21 *)
     540,    (* OBJ_setct_AcqCardCodeMsg         2 23 42 0 22 *)
     541,    (* OBJ_setct_AuthRevReqTBS          2 23 42 0 23 *)
     542,    (* OBJ_setct_AuthRevResData         2 23 42 0 24 *)
     543,    (* OBJ_setct_AuthRevResTBS          2 23 42 0 25 *)
     544,    (* OBJ_setct_CapReqTBS              2 23 42 0 26 *)
     545,    (* OBJ_setct_CapReqTBSX             2 23 42 0 27 *)
     546,    (* OBJ_setct_CapResData             2 23 42 0 28 *)
     547,    (* OBJ_setct_CapRevReqTBS           2 23 42 0 29 *)
     548,    (* OBJ_setct_CapRevReqTBSX          2 23 42 0 30 *)
     549,    (* OBJ_setct_CapRevResData          2 23 42 0 31 *)
     550,    (* OBJ_setct_CredReqTBS             2 23 42 0 32 *)
     551,    (* OBJ_setct_CredReqTBSX            2 23 42 0 33 *)
     552,    (* OBJ_setct_CredResData            2 23 42 0 34 *)
     553,    (* OBJ_setct_CredRevReqTBS          2 23 42 0 35 *)
     554,    (* OBJ_setct_CredRevReqTBSX         2 23 42 0 36 *)
     555,    (* OBJ_setct_CredRevResData         2 23 42 0 37 *)
     556,    (* OBJ_setct_PCertReqData           2 23 42 0 38 *)
     557,    (* OBJ_setct_PCertResTBS            2 23 42 0 39 *)
     558,    (* OBJ_setct_BatchAdminReqData      2 23 42 0 40 *)
     559,    (* OBJ_setct_BatchAdminResData      2 23 42 0 41 *)
     560,    (* OBJ_setct_CardCInitResTBS        2 23 42 0 42 *)
     561,    (* OBJ_setct_MeAqCInitResTBS        2 23 42 0 43 *)
     562,    (* OBJ_setct_RegFormResTBS          2 23 42 0 44 *)
     563,    (* OBJ_setct_CertReqData            2 23 42 0 45 *)
     564,    (* OBJ_setct_CertReqTBS             2 23 42 0 46 *)
     565,    (* OBJ_setct_CertResData            2 23 42 0 47 *)
     566,    (* OBJ_setct_CertInqReqTBS          2 23 42 0 48 *)
     567,    (* OBJ_setct_ErrorTBS               2 23 42 0 49 *)
     568,    (* OBJ_setct_PIDualSignedTBE        2 23 42 0 50 *)
     569,    (* OBJ_setct_PIUnsignedTBE          2 23 42 0 51 *)
     570,    (* OBJ_setct_AuthReqTBE             2 23 42 0 52 *)
     571,    (* OBJ_setct_AuthResTBE             2 23 42 0 53 *)
     572,    (* OBJ_setct_AuthResTBEX            2 23 42 0 54 *)
     573,    (* OBJ_setct_AuthTokenTBE           2 23 42 0 55 *)
     574,    (* OBJ_setct_CapTokenTBE            2 23 42 0 56 *)
     575,    (* OBJ_setct_CapTokenTBEX           2 23 42 0 57 *)
     576,    (* OBJ_setct_AcqCardCodeMsgTBE      2 23 42 0 58 *)
     577,    (* OBJ_setct_AuthRevReqTBE          2 23 42 0 59 *)
     578,    (* OBJ_setct_AuthRevResTBE          2 23 42 0 60 *)
     579,    (* OBJ_setct_AuthRevResTBEB         2 23 42 0 61 *)
     580,    (* OBJ_setct_CapReqTBE              2 23 42 0 62 *)
     581,    (* OBJ_setct_CapReqTBEX             2 23 42 0 63 *)
     582,    (* OBJ_setct_CapResTBE              2 23 42 0 64 *)
     583,    (* OBJ_setct_CapRevReqTBE           2 23 42 0 65 *)
     584,    (* OBJ_setct_CapRevReqTBEX          2 23 42 0 66 *)
     585,    (* OBJ_setct_CapRevResTBE           2 23 42 0 67 *)
     586,    (* OBJ_setct_CredReqTBE             2 23 42 0 68 *)
     587,    (* OBJ_setct_CredReqTBEX            2 23 42 0 69 *)
     588,    (* OBJ_setct_CredResTBE             2 23 42 0 70 *)
     589,    (* OBJ_setct_CredRevReqTBE          2 23 42 0 71 *)
     590,    (* OBJ_setct_CredRevReqTBEX         2 23 42 0 72 *)
     591,    (* OBJ_setct_CredRevResTBE          2 23 42 0 73 *)
     592,    (* OBJ_setct_BatchAdminReqTBE       2 23 42 0 74 *)
     593,    (* OBJ_setct_BatchAdminResTBE       2 23 42 0 75 *)
     594,    (* OBJ_setct_RegFormReqTBE          2 23 42 0 76 *)
     595,    (* OBJ_setct_CertReqTBE             2 23 42 0 77 *)
     596,    (* OBJ_setct_CertReqTBEX            2 23 42 0 78 *)
     597,    (* OBJ_setct_CertResTBE             2 23 42 0 79 *)
     598,    (* OBJ_setct_CRLNotificationTBS     2 23 42 0 80 *)
     599,    (* OBJ_setct_CRLNotificationResTBS  2 23 42 0 81 *)
     600,    (* OBJ_setct_BCIDistributionTBS     2 23 42 0 82 *)
     601,    (* OBJ_setext_genCrypt              2 23 42 1 1 *)
     602,    (* OBJ_setext_miAuth                2 23 42 1 3 *)
     603,    (* OBJ_setext_pinSecure             2 23 42 1 4 *)
     604,    (* OBJ_setext_pinAny                2 23 42 1 5 *)
     605,    (* OBJ_setext_track2                2 23 42 1 7 *)
     606,    (* OBJ_setext_cv                    2 23 42 1 8 *)
     620,    (* OBJ_setAttr_Cert                 2 23 42 3 0 *)
     621,    (* OBJ_setAttr_PGWYcap              2 23 42 3 1 *)
     622,    (* OBJ_setAttr_TokenType            2 23 42 3 2 *)
     623,    (* OBJ_setAttr_IssCap               2 23 42 3 3 *)
     607,    (* OBJ_set_policy_root              2 23 42 5 0 *)
     608,    (* OBJ_setCext_hashedRoot           2 23 42 7 0 *)
     609,    (* OBJ_setCext_certType             2 23 42 7 1 *)
     610,    (* OBJ_setCext_merchData            2 23 42 7 2 *)
     611,    (* OBJ_setCext_cCertRequired        2 23 42 7 3 *)
     612,    (* OBJ_setCext_tunneling            2 23 42 7 4 *)
     613,    (* OBJ_setCext_setExt               2 23 42 7 5 *)
     614,    (* OBJ_setCext_setQualf             2 23 42 7 6 *)
     615,    (* OBJ_setCext_PGWYcapabilities     2 23 42 7 7 *)
     616,    (* OBJ_setCext_TokenIdentifier      2 23 42 7 8 *)
     617,    (* OBJ_setCext_Track2Data           2 23 42 7 9 *)
     618,    (* OBJ_setCext_TokenType            2 23 42 7 10 *)
     619,    (* OBJ_setCext_IssuerCapabilities   2 23 42 7 11 *)
     636,    (* OBJ_set_brand_IATA_ATA           2 23 42 8 1 *)
     640,    (* OBJ_set_brand_Visa               2 23 42 8 4 *)
     641,    (* OBJ_set_brand_MasterCard         2 23 42 8 5 *)
     637,    (* OBJ_set_brand_Diners             2 23 42 8 30 *)
     638,    (* OBJ_set_brand_AmericanExpress    2 23 42 8 34 *)
     639,    (* OBJ_set_brand_JCB                2 23 42 8 35 *)
    1195,    (* OBJ_gmac                         1 0 9797 3 4 *)
    1141,    (* OBJ_oscca                        1 2 156 10197 *)
     805,    (* OBJ_cryptopro                    1 2 643 2 2 *)
     806,    (* OBJ_cryptocom                    1 2 643 2 9 *)
     974,    (* OBJ_id_tc26                      1 2 643 7 1 *)
    1005,    (* OBJ_OGRN                         1 2 643 100 1 *)
    1006,    (* OBJ_SNILS                        1 2 643 100 3 *)
    1226,    (* OBJ_OGRNIP                       1 2 643 100 5 *)
    1007,    (* OBJ_subjectSignTool              1 2 643 100 111 *)
    1008,    (* OBJ_issuerSignTool               1 2 643 100 112 *)
    1227,    (* OBJ_classSignTool                1 2 643 100 113 *)
     184,    (* OBJ_X9_57                        1 2 840 10040 *)
     405,    (* OBJ_ansi_X9_62                   1 2 840 10045 *)
     389,    (* OBJ_Enterprises                  1 3 6 1 4 1 *)
     504,    (* OBJ_mime_mhs                     1 3 6 1 7 1 *)
     104,    (* OBJ_md5WithRSA                   1 3 14 3 2 3 *)
      29,    (* OBJ_des_ecb                      1 3 14 3 2 6 *)
      31,    (* OBJ_des_cbc                      1 3 14 3 2 7 *)
      45,    (* OBJ_des_ofb64                    1 3 14 3 2 8 *)
      30,    (* OBJ_des_cfb64                    1 3 14 3 2 9 *)
     377,    (* OBJ_rsaSignature                 1 3 14 3 2 11 *)
      67,    (* OBJ_dsa_2                        1 3 14 3 2 12 *)
      66,    (* OBJ_dsaWithSHA                   1 3 14 3 2 13 *)
      42,    (* OBJ_shaWithRSAEncryption         1 3 14 3 2 15 *)
      32,    (* OBJ_des_ede_ecb                  1 3 14 3 2 17 *)
      41,    (* OBJ_sha                          1 3 14 3 2 18 *)
      64,    (* OBJ_sha1                         1 3 14 3 2 26 *)
      70,    (* OBJ_dsaWithSHA1_2                1 3 14 3 2 27 *)
     115,    (* OBJ_sha1WithRSA                  1 3 14 3 2 29 *)
     117,    (* OBJ_ripemd160                    1 3 36 3 2 1 *)
    1093,    (* OBJ_x509ExtAdmission             1 3 36 8 3 3 *)
     143,    (* OBJ_sxnet                        1 3 101 1 4 1 *)
    1171,    (* OBJ_ieee_siswg                   1 3 111 2 1619 *)
     721,    (* OBJ_sect163k1                    1 3 132 0 1 *)
     722,    (* OBJ_sect163r1                    1 3 132 0 2 *)
     728,    (* OBJ_sect239k1                    1 3 132 0 3 *)
     717,    (* OBJ_sect113r1                    1 3 132 0 4 *)
     718,    (* OBJ_sect113r2                    1 3 132 0 5 *)
     704,    (* OBJ_secp112r1                    1 3 132 0 6 *)
     705,    (* OBJ_secp112r2                    1 3 132 0 7 *)
     709,    (* OBJ_secp160r1                    1 3 132 0 8 *)
     708,    (* OBJ_secp160k1                    1 3 132 0 9 *)
     714,    (* OBJ_secp256k1                    1 3 132 0 10 *)
     723,    (* OBJ_sect163r2                    1 3 132 0 15 *)
     729,    (* OBJ_sect283k1                    1 3 132 0 16 *)
     730,    (* OBJ_sect283r1                    1 3 132 0 17 *)
     719,    (* OBJ_sect131r1                    1 3 132 0 22 *)
     720,    (* OBJ_sect131r2                    1 3 132 0 23 *)
     724,    (* OBJ_sect193r1                    1 3 132 0 24 *)
     725,    (* OBJ_sect193r2                    1 3 132 0 25 *)
     726,    (* OBJ_sect233k1                    1 3 132 0 26 *)
     727,    (* OBJ_sect233r1                    1 3 132 0 27 *)
     706,    (* OBJ_secp128r1                    1 3 132 0 28 *)
     707,    (* OBJ_secp128r2                    1 3 132 0 29 *)
     710,    (* OBJ_secp160r2                    1 3 132 0 30 *)
     711,    (* OBJ_secp192k1                    1 3 132 0 31 *)
     712,    (* OBJ_secp224k1                    1 3 132 0 32 *)
     713,    (* OBJ_secp224r1                    1 3 132 0 33 *)
     715,    (* OBJ_secp384r1                    1 3 132 0 34 *)
     716,    (* OBJ_secp521r1                    1 3 132 0 35 *)
     731,    (* OBJ_sect409k1                    1 3 132 0 36 *)
     732,    (* OBJ_sect409r1                    1 3 132 0 37 *)
     733,    (* OBJ_sect571k1                    1 3 132 0 38 *)
     734,    (* OBJ_sect571r1                    1 3 132 0 39 *)
     624,    (* OBJ_set_rootKeyThumb             2 23 42 3 0 0 *)
     625,    (* OBJ_set_addPolicy                2 23 42 3 0 1 *)
     626,    (* OBJ_setAttr_Token_EMV            2 23 42 3 2 1 *)
     627,    (* OBJ_setAttr_Token_B0Prime        2 23 42 3 2 2 *)
     628,    (* OBJ_setAttr_IssCap_CVM           2 23 42 3 3 3 *)
     629,    (* OBJ_setAttr_IssCap_T2            2 23 42 3 3 4 *)
     630,    (* OBJ_setAttr_IssCap_Sig           2 23 42 3 3 5 *)
     642,    (* OBJ_set_brand_Novus              2 23 42 8 6011 *)
     735,    (* OBJ_wap_wsg_idm_ecid_wtls1       2 23 43 1 4 1 *)
     736,    (* OBJ_wap_wsg_idm_ecid_wtls3       2 23 43 1 4 3 *)
     737,    (* OBJ_wap_wsg_idm_ecid_wtls4       2 23 43 1 4 4 *)
     738,    (* OBJ_wap_wsg_idm_ecid_wtls5       2 23 43 1 4 5 *)
     739,    (* OBJ_wap_wsg_idm_ecid_wtls6       2 23 43 1 4 6 *)
     740,    (* OBJ_wap_wsg_idm_ecid_wtls7       2 23 43 1 4 7 *)
     741,    (* OBJ_wap_wsg_idm_ecid_wtls8       2 23 43 1 4 8 *)
     742,    (* OBJ_wap_wsg_idm_ecid_wtls9       2 23 43 1 4 9 *)
     743,    (* OBJ_wap_wsg_idm_ecid_wtls10      2 23 43 1 4 10 *)
     744,    (* OBJ_wap_wsg_idm_ecid_wtls11      2 23 43 1 4 11 *)
     745,    (* OBJ_wap_wsg_idm_ecid_wtls12      2 23 43 1 4 12 *)
     804,    (* OBJ_whirlpool                    1 0 10118 3 0 55 *)
    1142,    (* OBJ_sm_scheme                    1 2 156 10197 1 *)
     773,    (* OBJ_kisa                         1 2 410 200004 *)
     807,    (* OBJ_id_GostR3411_94_with_GostR3410_2001 1 2 643 2 2 3 *)
     808,    (* OBJ_id_GostR3411_94_with_GostR3410_94 1 2 643 2 2 4 *)
     809,    (* OBJ_id_GostR3411_94              1 2 643 2 2 9 *)
     810,    (* OBJ_id_HMACGostR3411_94          1 2 643 2 2 10 *)
     811,    (* OBJ_id_GostR3410_2001            1 2 643 2 2 19 *)
     812,    (* OBJ_id_GostR3410_94              1 2 643 2 2 20 *)
     813,    (* OBJ_id_Gost28147_89              1 2 643 2 2 21 *)
     815,    (* OBJ_id_Gost28147_89_MAC          1 2 643 2 2 22 *)
     816,    (* OBJ_id_GostR3411_94_prf          1 2 643 2 2 23 *)
     817,    (* OBJ_id_GostR3410_2001DH          1 2 643 2 2 98 *)
     818,    (* OBJ_id_GostR3410_94DH            1 2 643 2 2 99 *)
     977,    (* OBJ_id_tc26_algorithms           1 2 643 7 1 1 *)
     994,    (* OBJ_id_tc26_constants            1 2 643 7 1 2 *)
    1228,    (* OBJ_classSignToolKC1             1 2 643 100 113 1 *)
    1229,    (* OBJ_classSignToolKC2             1 2 643 100 113 2 *)
    1230,    (* OBJ_classSignToolKC3             1 2 643 100 113 3 *)
    1231,    (* OBJ_classSignToolKB1             1 2 643 100 113 4 *)
    1232,    (* OBJ_classSignToolKB2             1 2 643 100 113 5 *)
    1233,    (* OBJ_classSignToolKA1             1 2 643 100 113 6 *)
       1,    (* OBJ_rsadsi                       1 2 840 113549 *)
     185,    (* OBJ_X9cm                         1 2 840 10040 4 *)
    1031,    (* OBJ_id_pkinit                    1 3 6 1 5 2 3 *)
     127,    (* OBJ_id_pkix                      1 3 6 1 5 5 7 *)
     505,    (* OBJ_mime_mhs_headings            1 3 6 1 7 1 1 *)
     506,    (* OBJ_mime_mhs_bodies              1 3 6 1 7 1 2 *)
     119,    (* OBJ_ripemd160WithRSA             1 3 36 3 3 1 2 *)
     937,    (* OBJ_dhSinglePass_stdDH_sha224kdf_scheme 1 3 132 1 11 0 *)
     938,    (* OBJ_dhSinglePass_stdDH_sha256kdf_scheme 1 3 132 1 11 1 *)
     939,    (* OBJ_dhSinglePass_stdDH_sha384kdf_scheme 1 3 132 1 11 2 *)
     940,    (* OBJ_dhSinglePass_stdDH_sha512kdf_scheme 1 3 132 1 11 3 *)
     942,    (* OBJ_dhSinglePass_cofactorDH_sha224kdf_scheme 1 3 132 1 14 0 *)
     943,    (* OBJ_dhSinglePass_cofactorDH_sha256kdf_scheme 1 3 132 1 14 1 *)
     944,    (* OBJ_dhSinglePass_cofactorDH_sha384kdf_scheme 1 3 132 1 14 2 *)
     945,    (* OBJ_dhSinglePass_cofactorDH_sha512kdf_scheme 1 3 132 1 14 3 *)
     631,    (* OBJ_setAttr_GenCryptgrm          2 23 42 3 3 3 1 *)
     632,    (* OBJ_setAttr_T2Enc                2 23 42 3 3 4 1 *)
     633,    (* OBJ_setAttr_T2cleartxt           2 23 42 3 3 4 2 *)
     634,    (* OBJ_setAttr_TokICCsig            2 23 42 3 3 5 1 *)
     635,    (* OBJ_setAttr_SecDevSig            2 23 42 3 3 5 2 *)
     436,    (* OBJ_ucl                          0 9 2342 19200300 *)
     820,    (* OBJ_id_Gost28147_89_None_KeyMeshing 1 2 643 2 2 14 0 *)
     819,    (* OBJ_id_Gost28147_89_CryptoPro_KeyMeshing 1 2 643 2 2 14 1 *)
     845,    (* OBJ_id_GostR3410_94_a            1 2 643 2 2 20 1 *)
     846,    (* OBJ_id_GostR3410_94_aBis         1 2 643 2 2 20 2 *)
     847,    (* OBJ_id_GostR3410_94_b            1 2 643 2 2 20 3 *)
     848,    (* OBJ_id_GostR3410_94_bBis         1 2 643 2 2 20 4 *)
     821,    (* OBJ_id_GostR3411_94_TestParamSet 1 2 643 2 2 30 0 *)
     822,    (* OBJ_id_GostR3411_94_CryptoProParamSet 1 2 643 2 2 30 1 *)
     823,    (* OBJ_id_Gost28147_89_TestParamSet 1 2 643 2 2 31 0 *)
     824,    (* OBJ_id_Gost28147_89_CryptoPro_A_ParamSet 1 2 643 2 2 31 1 *)
     825,    (* OBJ_id_Gost28147_89_CryptoPro_B_ParamSet 1 2 643 2 2 31 2 *)
     826,    (* OBJ_id_Gost28147_89_CryptoPro_C_ParamSet 1 2 643 2 2 31 3 *)
     827,    (* OBJ_id_Gost28147_89_CryptoPro_D_ParamSet 1 2 643 2 2 31 4 *)
     828,    (* OBJ_id_Gost28147_89_CryptoPro_Oscar_1_1_ParamSet 1 2 643 2 2 31 5 *)
     829,    (* OBJ_id_Gost28147_89_CryptoPro_Oscar_1_0_ParamSet 1 2 643 2 2 31 6 *)
     830,    (* OBJ_id_Gost28147_89_CryptoPro_RIC_1_ParamSet 1 2 643 2 2 31 7 *)
     831,    (* OBJ_id_GostR3410_94_TestParamSet 1 2 643 2 2 32 0 *)
     832,    (* OBJ_id_GostR3410_94_CryptoPro_A_ParamSet 1 2 643 2 2 32 2 *)
     833,    (* OBJ_id_GostR3410_94_CryptoPro_B_ParamSet 1 2 643 2 2 32 3 *)
     834,    (* OBJ_id_GostR3410_94_CryptoPro_C_ParamSet 1 2 643 2 2 32 4 *)
     835,    (* OBJ_id_GostR3410_94_CryptoPro_D_ParamSet 1 2 643 2 2 32 5 *)
     836,    (* OBJ_id_GostR3410_94_CryptoPro_XchA_ParamSet 1 2 643 2 2 33 1 *)
     837,    (* OBJ_id_GostR3410_94_CryptoPro_XchB_ParamSet 1 2 643 2 2 33 2 *)
     838,    (* OBJ_id_GostR3410_94_CryptoPro_XchC_ParamSet 1 2 643 2 2 33 3 *)
     839,    (* OBJ_id_GostR3410_2001_TestParamSet 1 2 643 2 2 35 0 *)
     840,    (* OBJ_id_GostR3410_2001_CryptoPro_A_ParamSet 1 2 643 2 2 35 1 *)
     841,    (* OBJ_id_GostR3410_2001_CryptoPro_B_ParamSet 1 2 643 2 2 35 2 *)
     842,    (* OBJ_id_GostR3410_2001_CryptoPro_C_ParamSet 1 2 643 2 2 35 3 *)
     843,    (* OBJ_id_GostR3410_2001_CryptoPro_XchA_ParamSet 1 2 643 2 2 36 0 *)
     844,    (* OBJ_id_GostR3410_2001_CryptoPro_XchB_ParamSet 1 2 643 2 2 36 1 *)
     978,    (* OBJ_id_tc26_sign                 1 2 643 7 1 1 1 *)
     981,    (* OBJ_id_tc26_digest               1 2 643 7 1 1 2 *)
     984,    (* OBJ_id_tc26_signwithdigest       1 2 643 7 1 1 3 *)
     987,    (* OBJ_id_tc26_mac                  1 2 643 7 1 1 4 *)
     990,    (* OBJ_id_tc26_cipher               1 2 643 7 1 1 5 *)
     991,    (* OBJ_id_tc26_agreement            1 2 643 7 1 1 6 *)
    1179,    (* OBJ_id_tc26_wrap                 1 2 643 7 1 1 7 *)
     995,    (* OBJ_id_tc26_sign_constants       1 2 643 7 1 2 1 *)
    1000,    (* OBJ_id_tc26_digest_constants     1 2 643 7 1 2 2 *)
    1001,    (* OBJ_id_tc26_cipher_constants     1 2 643 7 1 2 5 *)
    1151,    (* OBJ_ua_pki                       1 2 804 2 1 1 1 *)
       2,    (* OBJ_pkcs                         1 2 840 113549 1 *)
     431,    (* OBJ_hold_instruction_none        1 2 840 10040 2 1 *)
     432,    (* OBJ_hold_instruction_call_issuer 1 2 840 10040 2 2 *)
     433,    (* OBJ_hold_instruction_reject      1 2 840 10040 2 3 *)
     116,    (* OBJ_dsa                          1 2 840 10040 4 1 *)
     113,    (* OBJ_dsaWithSHA1                  1 2 840 10040 4 3 *)
     406,    (* OBJ_X9_62_prime_field            1 2 840 10045 1 1 *)
     407,    (* OBJ_X9_62_characteristic_two_field 1 2 840 10045 1 2 *)
     408,    (* OBJ_X9_62_id_ecPublicKey         1 2 840 10045 2 1 *)
     416,    (* OBJ_ecdsa_with_SHA1              1 2 840 10045 4 1 *)
     791,    (* OBJ_ecdsa_with_Recommended       1 2 840 10045 4 2 *)
     792,    (* OBJ_ecdsa_with_Specified         1 2 840 10045 4 3 *)
     920,    (* OBJ_dhpublicnumber               1 2 840 10046 2 1 *)
    1032,    (* OBJ_pkInitClientAuth             1 3 6 1 5 2 3 4 *)
    1033,    (* OBJ_pkInitKDC                    1 3 6 1 5 2 3 5 *)
     258,    (* OBJ_id_pkix_mod                  1 3 6 1 5 5 7 0 *)
     175,    (* OBJ_id_pe                        1 3 6 1 5 5 7 1 *)
     259,    (* OBJ_id_qt                        1 3 6 1 5 5 7 2 *)
     128,    (* OBJ_id_kp                        1 3 6 1 5 5 7 3 *)
     260,    (* OBJ_id_it                        1 3 6 1 5 5 7 4 *)
     261,    (* OBJ_id_pkip                      1 3 6 1 5 5 7 5 *)
     262,    (* OBJ_id_alg                       1 3 6 1 5 5 7 6 *)
     263,    (* OBJ_id_cmc                       1 3 6 1 5 5 7 7 *)
     264,    (* OBJ_id_on                        1 3 6 1 5 5 7 8 *)
     265,    (* OBJ_id_pda                       1 3 6 1 5 5 7 9 *)
     266,    (* OBJ_id_aca                       1 3 6 1 5 5 7 10 *)
     267,    (* OBJ_id_qcs                       1 3 6 1 5 5 7 11 *)
     268,    (* OBJ_id_cct                       1 3 6 1 5 5 7 12 *)
    1238,    (* OBJ_id_cp                        1 3 6 1 5 5 7 14 *)
     662,    (* OBJ_id_ppl                       1 3 6 1 5 5 7 21 *)
     176,    (* OBJ_id_ad                        1 3 6 1 5 5 7 48 *)
     507,    (* OBJ_id_hex_partial_message       1 3 6 1 7 1 1 1 *)
     508,    (* OBJ_id_hex_multipart_message     1 3 6 1 7 1 1 2 *)
      57,    (* OBJ_netscape                     2 16 840 1 113730 *)
     754,    (* OBJ_camellia_128_ecb             0 3 4401 5 3 1 9 1 *)
     766,    (* OBJ_camellia_128_ofb128          0 3 4401 5 3 1 9 3 *)
     757,    (* OBJ_camellia_128_cfb128          0 3 4401 5 3 1 9 4 *)
     961,    (* OBJ_camellia_128_gcm             0 3 4401 5 3 1 9 6 *)
     962,    (* OBJ_camellia_128_ccm             0 3 4401 5 3 1 9 7 *)
     963,    (* OBJ_camellia_128_ctr             0 3 4401 5 3 1 9 9 *)
     964,    (* OBJ_camellia_128_cmac            0 3 4401 5 3 1 9 10 *)
     755,    (* OBJ_camellia_192_ecb             0 3 4401 5 3 1 9 21 *)
     767,    (* OBJ_camellia_192_ofb128          0 3 4401 5 3 1 9 23 *)
     758,    (* OBJ_camellia_192_cfb128          0 3 4401 5 3 1 9 24 *)
     965,    (* OBJ_camellia_192_gcm             0 3 4401 5 3 1 9 26 *)
     966,    (* OBJ_camellia_192_ccm             0 3 4401 5 3 1 9 27 *)
     967,    (* OBJ_camellia_192_ctr             0 3 4401 5 3 1 9 29 *)
     968,    (* OBJ_camellia_192_cmac            0 3 4401 5 3 1 9 30 *)
     756,    (* OBJ_camellia_256_ecb             0 3 4401 5 3 1 9 41 *)
     768,    (* OBJ_camellia_256_ofb128          0 3 4401 5 3 1 9 43 *)
     759,    (* OBJ_camellia_256_cfb128          0 3 4401 5 3 1 9 44 *)
     969,    (* OBJ_camellia_256_gcm             0 3 4401 5 3 1 9 46 *)
     970,    (* OBJ_camellia_256_ccm             0 3 4401 5 3 1 9 47 *)
     971,    (* OBJ_camellia_256_ctr             0 3 4401 5 3 1 9 49 *)
     972,    (* OBJ_camellia_256_cmac            0 3 4401 5 3 1 9 50 *)
     437,    (* OBJ_pilot                        0 9 2342 19200300 100 *)
    1133,    (* OBJ_sm4_ecb                      1 2 156 10197 1 104 1 *)
    1134,    (* OBJ_sm4_cbc                      1 2 156 10197 1 104 2 *)
    1135,    (* OBJ_sm4_ofb128                   1 2 156 10197 1 104 3 *)
    1137,    (* OBJ_sm4_cfb128                   1 2 156 10197 1 104 4 *)
    1136,    (* OBJ_sm4_cfb1                     1 2 156 10197 1 104 5 *)
    1138,    (* OBJ_sm4_cfb8                     1 2 156 10197 1 104 6 *)
    1139,    (* OBJ_sm4_ctr                      1 2 156 10197 1 104 7 *)
    1248,    (* OBJ_sm4_gcm                      1 2 156 10197 1 104 8 *)
    1249,    (* OBJ_sm4_ccm                      1 2 156 10197 1 104 9 *)
    1172,    (* OBJ_sm2                          1 2 156 10197 1 301 *)
    1143,    (* OBJ_sm3                          1 2 156 10197 1 401 *)
    1204,    (* OBJ_SM2_with_SM3                 1 2 156 10197 1 501 *)
    1144,    (* OBJ_sm3WithRSAEncryption         1 2 156 10197 1 504 *)
     776,    (* OBJ_seed_ecb                     1 2 410 200004 1 3 *)
     777,    (* OBJ_seed_cbc                     1 2 410 200004 1 4 *)
     779,    (* OBJ_seed_cfb128                  1 2 410 200004 1 5 *)
     778,    (* OBJ_seed_ofb128                  1 2 410 200004 1 6 *)
     852,    (* OBJ_id_GostR3411_94_with_GostR3410_94_cc 1 2 643 2 9 1 3 3 *)
     853,    (* OBJ_id_GostR3411_94_with_GostR3410_2001_cc 1 2 643 2 9 1 3 4 *)
     850,    (* OBJ_id_GostR3410_94_cc           1 2 643 2 9 1 5 3 *)
     851,    (* OBJ_id_GostR3410_2001_cc         1 2 643 2 9 1 5 4 *)
     849,    (* OBJ_id_Gost28147_89_cc           1 2 643 2 9 1 6 1 *)
     854,    (* OBJ_id_GostR3410_2001_ParamSet_cc 1 2 643 2 9 1 8 1 *)
    1004,    (* OBJ_INN                          1 2 643 3 131 1 1 *)
     979,    (* OBJ_id_GostR3410_2012_256        1 2 643 7 1 1 1 1 *)
     980,    (* OBJ_id_GostR3410_2012_512        1 2 643 7 1 1 1 2 *)
     982,    (* OBJ_id_GostR3411_2012_256        1 2 643 7 1 1 2 2 *)
     983,    (* OBJ_id_GostR3411_2012_512        1 2 643 7 1 1 2 3 *)
     985,    (* OBJ_id_tc26_signwithdigest_gost3410_2012_256 1 2 643 7 1 1 3 2 *)
     986,    (* OBJ_id_tc26_signwithdigest_gost3410_2012_512 1 2 643 7 1 1 3 3 *)
     988,    (* OBJ_id_tc26_hmac_gost_3411_2012_256 1 2 643 7 1 1 4 1 *)
     989,    (* OBJ_id_tc26_hmac_gost_3411_2012_512 1 2 643 7 1 1 4 2 *)
    1173,    (* OBJ_id_tc26_cipher_gostr3412_2015_magma 1 2 643 7 1 1 5 1 *)
    1176,    (* OBJ_id_tc26_cipher_gostr3412_2015_kuznyechik 1 2 643 7 1 1 5 2 *)
     992,    (* OBJ_id_tc26_agreement_gost_3410_2012_256 1 2 643 7 1 1 6 1 *)
     993,    (* OBJ_id_tc26_agreement_gost_3410_2012_512 1 2 643 7 1 1 6 2 *)
    1180,    (* OBJ_id_tc26_wrap_gostr3412_2015_magma 1 2 643 7 1 1 7 1 *)
    1182,    (* OBJ_id_tc26_wrap_gostr3412_2015_kuznyechik 1 2 643 7 1 1 7 2 *)
    1147,    (* OBJ_id_tc26_gost_3410_2012_256_constants 1 2 643 7 1 2 1 1 *)
     996,    (* OBJ_id_tc26_gost_3410_2012_512_constants 1 2 643 7 1 2 1 2 *)
    1002,    (* OBJ_id_tc26_gost_28147_constants 1 2 643 7 1 2 5 1 *)
     186,    (* OBJ_pkcs1                        1 2 840 113549 1 1 *)
      27,    (* OBJ_pkcs3                        1 2 840 113549 1 3 *)
     187,    (* OBJ_pkcs5                        1 2 840 113549 1 5 *)
      20,    (* OBJ_pkcs7                        1 2 840 113549 1 7 *)
      47,    (* OBJ_pkcs9                        1 2 840 113549 1 9 *)
       3,    (* OBJ_md2                          1 2 840 113549 2 2 *)
     257,    (* OBJ_md4                          1 2 840 113549 2 4 *)
       4,    (* OBJ_md5                          1 2 840 113549 2 5 *)
     797,    (* OBJ_hmacWithMD5                  1 2 840 113549 2 6 *)
     163,    (* OBJ_hmacWithSHA1                 1 2 840 113549 2 7 *)
     798,    (* OBJ_hmacWithSHA224               1 2 840 113549 2 8 *)
     799,    (* OBJ_hmacWithSHA256               1 2 840 113549 2 9 *)
     800,    (* OBJ_hmacWithSHA384               1 2 840 113549 2 10 *)
     801,    (* OBJ_hmacWithSHA512               1 2 840 113549 2 11 *)
    1193,    (* OBJ_hmacWithSHA512_224           1 2 840 113549 2 12 *)
    1194,    (* OBJ_hmacWithSHA512_256           1 2 840 113549 2 13 *)
      37,    (* OBJ_rc2_cbc                      1 2 840 113549 3 2 *)
       5,    (* OBJ_rc4                          1 2 840 113549 3 4 *)
      44,    (* OBJ_des_ede3_cbc                 1 2 840 113549 3 7 *)
     120,    (* OBJ_rc5_cbc                      1 2 840 113549 3 8 *)
     643,    (* OBJ_des_cdmf                     1 2 840 113549 3 10 *)
     680,    (* OBJ_X9_62_id_characteristic_two_basis 1 2 840 10045 1 2 3 *)
     684,    (* OBJ_X9_62_c2pnb163v1             1 2 840 10045 3 0 1 *)
     685,    (* OBJ_X9_62_c2pnb163v2             1 2 840 10045 3 0 2 *)
     686,    (* OBJ_X9_62_c2pnb163v3             1 2 840 10045 3 0 3 *)
     687,    (* OBJ_X9_62_c2pnb176v1             1 2 840 10045 3 0 4 *)
     688,    (* OBJ_X9_62_c2tnb191v1             1 2 840 10045 3 0 5 *)
     689,    (* OBJ_X9_62_c2tnb191v2             1 2 840 10045 3 0 6 *)
     690,    (* OBJ_X9_62_c2tnb191v3             1 2 840 10045 3 0 7 *)
     691,    (* OBJ_X9_62_c2onb191v4             1 2 840 10045 3 0 8 *)
     692,    (* OBJ_X9_62_c2onb191v5             1 2 840 10045 3 0 9 *)
     693,    (* OBJ_X9_62_c2pnb208w1             1 2 840 10045 3 0 10 *)
     694,    (* OBJ_X9_62_c2tnb239v1             1 2 840 10045 3 0 11 *)
     695,    (* OBJ_X9_62_c2tnb239v2             1 2 840 10045 3 0 12 *)
     696,    (* OBJ_X9_62_c2tnb239v3             1 2 840 10045 3 0 13 *)
     697,    (* OBJ_X9_62_c2onb239v4             1 2 840 10045 3 0 14 *)
     698,    (* OBJ_X9_62_c2onb239v5             1 2 840 10045 3 0 15 *)
     699,    (* OBJ_X9_62_c2pnb272w1             1 2 840 10045 3 0 16 *)
     700,    (* OBJ_X9_62_c2pnb304w1             1 2 840 10045 3 0 17 *)
     701,    (* OBJ_X9_62_c2tnb359v1             1 2 840 10045 3 0 18 *)
     702,    (* OBJ_X9_62_c2pnb368w1             1 2 840 10045 3 0 19 *)
     703,    (* OBJ_X9_62_c2tnb431r1             1 2 840 10045 3 0 20 *)
     409,    (* OBJ_X9_62_prime192v1             1 2 840 10045 3 1 1 *)
     410,    (* OBJ_X9_62_prime192v2             1 2 840 10045 3 1 2 *)
     411,    (* OBJ_X9_62_prime192v3             1 2 840 10045 3 1 3 *)
     412,    (* OBJ_X9_62_prime239v1             1 2 840 10045 3 1 4 *)
     413,    (* OBJ_X9_62_prime239v2             1 2 840 10045 3 1 5 *)
     414,    (* OBJ_X9_62_prime239v3             1 2 840 10045 3 1 6 *)
     415,    (* OBJ_X9_62_prime256v1             1 2 840 10045 3 1 7 *)
     793,    (* OBJ_ecdsa_with_SHA224            1 2 840 10045 4 3 1 *)
     794,    (* OBJ_ecdsa_with_SHA256            1 2 840 10045 4 3 2 *)
     795,    (* OBJ_ecdsa_with_SHA384            1 2 840 10045 4 3 3 *)
     796,    (* OBJ_ecdsa_with_SHA512            1 2 840 10045 4 3 4 *)
     269,    (* OBJ_id_pkix1_explicit_88         1 3 6 1 5 5 7 0 1 *)
     270,    (* OBJ_id_pkix1_implicit_88         1 3 6 1 5 5 7 0 2 *)
     271,    (* OBJ_id_pkix1_explicit_93         1 3 6 1 5 5 7 0 3 *)
     272,    (* OBJ_id_pkix1_implicit_93         1 3 6 1 5 5 7 0 4 *)
     273,    (* OBJ_id_mod_crmf                  1 3 6 1 5 5 7 0 5 *)
     274,    (* OBJ_id_mod_cmc                   1 3 6 1 5 5 7 0 6 *)
     275,    (* OBJ_id_mod_kea_profile_88        1 3 6 1 5 5 7 0 7 *)
     276,    (* OBJ_id_mod_kea_profile_93        1 3 6 1 5 5 7 0 8 *)
     277,    (* OBJ_id_mod_cmp                   1 3 6 1 5 5 7 0 9 *)
     278,    (* OBJ_id_mod_qualified_cert_88     1 3 6 1 5 5 7 0 10 *)
     279,    (* OBJ_id_mod_qualified_cert_93     1 3 6 1 5 5 7 0 11 *)
     280,    (* OBJ_id_mod_attribute_cert        1 3 6 1 5 5 7 0 12 *)
     281,    (* OBJ_id_mod_timestamp_protocol    1 3 6 1 5 5 7 0 13 *)
     282,    (* OBJ_id_mod_ocsp                  1 3 6 1 5 5 7 0 14 *)
     283,    (* OBJ_id_mod_dvcs                  1 3 6 1 5 5 7 0 15 *)
     284,    (* OBJ_id_mod_cmp2000               1 3 6 1 5 5 7 0 16 *)
     177,    (* OBJ_info_access                  1 3 6 1 5 5 7 1 1 *)
     285,    (* OBJ_biometricInfo                1 3 6 1 5 5 7 1 2 *)
     286,    (* OBJ_qcStatements                 1 3 6 1 5 5 7 1 3 *)
     287,    (* OBJ_ac_auditEntity               1 3 6 1 5 5 7 1 4 *)
     288,    (* OBJ_ac_targeting                 1 3 6 1 5 5 7 1 5 *)
     289,    (* OBJ_aaControls                   1 3 6 1 5 5 7 1 6 *)
     290,    (* OBJ_sbgp_ipAddrBlock             1 3 6 1 5 5 7 1 7 *)
     291,    (* OBJ_sbgp_autonomousSysNum        1 3 6 1 5 5 7 1 8 *)
     292,    (* OBJ_sbgp_routerIdentifier        1 3 6 1 5 5 7 1 9 *)
     397,    (* OBJ_ac_proxying                  1 3 6 1 5 5 7 1 10 *)
     398,    (* OBJ_sinfo_access                 1 3 6 1 5 5 7 1 11 *)
     663,    (* OBJ_proxyCertInfo                1 3 6 1 5 5 7 1 14 *)
    1020,    (* OBJ_tlsfeature                   1 3 6 1 5 5 7 1 24 *)
    1239,    (* OBJ_sbgp_ipAddrBlockv2           1 3 6 1 5 5 7 1 28 *)
    1240,    (* OBJ_sbgp_autonomousSysNumv2      1 3 6 1 5 5 7 1 29 *)
     164,    (* OBJ_id_qt_cps                    1 3 6 1 5 5 7 2 1 *)
     165,    (* OBJ_id_qt_unotice                1 3 6 1 5 5 7 2 2 *)
     293,    (* OBJ_textNotice                   1 3 6 1 5 5 7 2 3 *)
     129,    (* OBJ_server_auth                  1 3 6 1 5 5 7 3 1 *)
     130,    (* OBJ_client_auth                  1 3 6 1 5 5 7 3 2 *)
     131,    (* OBJ_code_sign                    1 3 6 1 5 5 7 3 3 *)
     132,    (* OBJ_email_protect                1 3 6 1 5 5 7 3 4 *)
     294,    (* OBJ_ipsecEndSystem               1 3 6 1 5 5 7 3 5 *)
     295,    (* OBJ_ipsecTunnel                  1 3 6 1 5 5 7 3 6 *)
     296,    (* OBJ_ipsecUser                    1 3 6 1 5 5 7 3 7 *)
     133,    (* OBJ_time_stamp                   1 3 6 1 5 5 7 3 8 *)
     180,    (* OBJ_OCSP_sign                    1 3 6 1 5 5 7 3 9 *)
     297,    (* OBJ_dvcs                         1 3 6 1 5 5 7 3 10 *)
    1022,    (* OBJ_ipsec_IKE                    1 3 6 1 5 5 7 3 17 *)
    1023,    (* OBJ_capwapAC                     1 3 6 1 5 5 7 3 18 *)
    1024,    (* OBJ_capwapWTP                    1 3 6 1 5 5 7 3 19 *)
    1025,    (* OBJ_sshClient                    1 3 6 1 5 5 7 3 21 *)
    1026,    (* OBJ_sshServer                    1 3 6 1 5 5 7 3 22 *)
    1027,    (* OBJ_sendRouter                   1 3 6 1 5 5 7 3 23 *)
    1028,    (* OBJ_sendProxiedRouter            1 3 6 1 5 5 7 3 24 *)
    1029,    (* OBJ_sendOwner                    1 3 6 1 5 5 7 3 25 *)
    1030,    (* OBJ_sendProxiedOwner             1 3 6 1 5 5 7 3 26 *)
    1131,    (* OBJ_cmcCA                        1 3 6 1 5 5 7 3 27 *)
    1132,    (* OBJ_cmcRA                        1 3 6 1 5 5 7 3 28 *)
    1219,    (* OBJ_cmcArchive                   1 3 6 1 5 5 7 3 29 *)
    1220,    (* OBJ_id_kp_bgpsec_router          1 3 6 1 5 5 7 3 30 *)
    1221,    (* OBJ_id_kp_BrandIndicatorforMessageIdentification 1 3 6 1 5 5 7 3 31 *)
    1222,    (* OBJ_cmKGA                        1 3 6 1 5 5 7 3 32 *)
     298,    (* OBJ_id_it_caProtEncCert          1 3 6 1 5 5 7 4 1 *)
     299,    (* OBJ_id_it_signKeyPairTypes       1 3 6 1 5 5 7 4 2 *)
     300,    (* OBJ_id_it_encKeyPairTypes        1 3 6 1 5 5 7 4 3 *)
     301,    (* OBJ_id_it_preferredSymmAlg       1 3 6 1 5 5 7 4 4 *)
     302,    (* OBJ_id_it_caKeyUpdateInfo        1 3 6 1 5 5 7 4 5 *)
     303,    (* OBJ_id_it_currentCRL             1 3 6 1 5 5 7 4 6 *)
     304,    (* OBJ_id_it_unsupportedOIDs        1 3 6 1 5 5 7 4 7 *)
     305,    (* OBJ_id_it_subscriptionRequest    1 3 6 1 5 5 7 4 8 *)
     306,    (* OBJ_id_it_subscriptionResponse   1 3 6 1 5 5 7 4 9 *)
     307,    (* OBJ_id_it_keyPairParamReq        1 3 6 1 5 5 7 4 10 *)
     308,    (* OBJ_id_it_keyPairParamRep        1 3 6 1 5 5 7 4 11 *)
     309,    (* OBJ_id_it_revPassphrase          1 3 6 1 5 5 7 4 12 *)
     310,    (* OBJ_id_it_implicitConfirm        1 3 6 1 5 5 7 4 13 *)
     311,    (* OBJ_id_it_confirmWaitTime        1 3 6 1 5 5 7 4 14 *)
     312,    (* OBJ_id_it_origPKIMessage         1 3 6 1 5 5 7 4 15 *)
     784,    (* OBJ_id_it_suppLangTags           1 3 6 1 5 5 7 4 16 *)
    1223,    (* OBJ_id_it_caCerts                1 3 6 1 5 5 7 4 17 *)
    1224,    (* OBJ_id_it_rootCaKeyUpdate        1 3 6 1 5 5 7 4 18 *)
    1225,    (* OBJ_id_it_certReqTemplate        1 3 6 1 5 5 7 4 19 *)
     313,    (* OBJ_id_regCtrl                   1 3 6 1 5 5 7 5 1 *)
     314,    (* OBJ_id_regInfo                   1 3 6 1 5 5 7 5 2 *)
     323,    (* OBJ_id_alg_des40                 1 3 6 1 5 5 7 6 1 *)
     324,    (* OBJ_id_alg_noSignature           1 3 6 1 5 5 7 6 2 *)
     325,    (* OBJ_id_alg_dh_sig_hmac_sha1      1 3 6 1 5 5 7 6 3 *)
     326,    (* OBJ_id_alg_dh_pop                1 3 6 1 5 5 7 6 4 *)
     327,    (* OBJ_id_cmc_statusInfo            1 3 6 1 5 5 7 7 1 *)
     328,    (* OBJ_id_cmc_identification        1 3 6 1 5 5 7 7 2 *)
     329,    (* OBJ_id_cmc_identityProof         1 3 6 1 5 5 7 7 3 *)
     330,    (* OBJ_id_cmc_dataReturn            1 3 6 1 5 5 7 7 4 *)
     331,    (* OBJ_id_cmc_transactionId         1 3 6 1 5 5 7 7 5 *)
     332,    (* OBJ_id_cmc_senderNonce           1 3 6 1 5 5 7 7 6 *)
     333,    (* OBJ_id_cmc_recipientNonce        1 3 6 1 5 5 7 7 7 *)
     334,    (* OBJ_id_cmc_addExtensions         1 3 6 1 5 5 7 7 8 *)
     335,    (* OBJ_id_cmc_encryptedPOP          1 3 6 1 5 5 7 7 9 *)
     336,    (* OBJ_id_cmc_decryptedPOP          1 3 6 1 5 5 7 7 10 *)
     337,    (* OBJ_id_cmc_lraPOPWitness         1 3 6 1 5 5 7 7 11 *)
     338,    (* OBJ_id_cmc_getCert               1 3 6 1 5 5 7 7 15 *)
     339,    (* OBJ_id_cmc_getCRL                1 3 6 1 5 5 7 7 16 *)
     340,    (* OBJ_id_cmc_revokeRequest         1 3 6 1 5 5 7 7 17 *)
     341,    (* OBJ_id_cmc_regInfo               1 3 6 1 5 5 7 7 18 *)
     342,    (* OBJ_id_cmc_responseInfo          1 3 6 1 5 5 7 7 19 *)
     343,    (* OBJ_id_cmc_queryPending          1 3 6 1 5 5 7 7 21 *)
     344,    (* OBJ_id_cmc_popLinkRandom         1 3 6 1 5 5 7 7 22 *)
     345,    (* OBJ_id_cmc_popLinkWitness        1 3 6 1 5 5 7 7 23 *)
     346,    (* OBJ_id_cmc_confirmCertAcceptance 1 3 6 1 5 5 7 7 24 *)
     347,    (* OBJ_id_on_personalData           1 3 6 1 5 5 7 8 1 *)
     858,    (* OBJ_id_on_permanentIdentifier    1 3 6 1 5 5 7 8 3 *)
    1209,    (* OBJ_XmppAddr                     1 3 6 1 5 5 7 8 5 *)
    1210,    (* OBJ_SRVName                      1 3 6 1 5 5 7 8 7 *)
    1211,    (* OBJ_NAIRealm                     1 3 6 1 5 5 7 8 8 *)
    1208,    (* OBJ_id_on_SmtpUTF8Mailbox        1 3 6 1 5 5 7 8 9 *)
     348,    (* OBJ_id_pda_dateOfBirth           1 3 6 1 5 5 7 9 1 *)
     349,    (* OBJ_id_pda_placeOfBirth          1 3 6 1 5 5 7 9 2 *)
     351,    (* OBJ_id_pda_gender                1 3 6 1 5 5 7 9 3 *)
     352,    (* OBJ_id_pda_countryOfCitizenship  1 3 6 1 5 5 7 9 4 *)
     353,    (* OBJ_id_pda_countryOfResidence    1 3 6 1 5 5 7 9 5 *)
     354,    (* OBJ_id_aca_authenticationInfo    1 3 6 1 5 5 7 10 1 *)
     355,    (* OBJ_id_aca_accessIdentity        1 3 6 1 5 5 7 10 2 *)
     356,    (* OBJ_id_aca_chargingIdentity      1 3 6 1 5 5 7 10 3 *)
     357,    (* OBJ_id_aca_group                 1 3 6 1 5 5 7 10 4 *)
     358,    (* OBJ_id_aca_role                  1 3 6 1 5 5 7 10 5 *)
     399,    (* OBJ_id_aca_encAttrs              1 3 6 1 5 5 7 10 6 *)
     359,    (* OBJ_id_qcs_pkixQCSyntax_v1       1 3 6 1 5 5 7 11 1 *)
     360,    (* OBJ_id_cct_crs                   1 3 6 1 5 5 7 12 1 *)
     361,    (* OBJ_id_cct_PKIData               1 3 6 1 5 5 7 12 2 *)
     362,    (* OBJ_id_cct_PKIResponse           1 3 6 1 5 5 7 12 3 *)
    1241,    (* OBJ_ipAddr_asNumber              1 3 6 1 5 5 7 14 2 *)
    1242,    (* OBJ_ipAddr_asNumberv2            1 3 6 1 5 5 7 14 3 *)
     664,    (* OBJ_id_ppl_anyLanguage           1 3 6 1 5 5 7 21 0 *)
     665,    (* OBJ_id_ppl_inheritAll            1 3 6 1 5 5 7 21 1 *)
     667,    (* OBJ_Independent                  1 3 6 1 5 5 7 21 2 *)
     178,    (* OBJ_ad_OCSP                      1 3 6 1 5 5 7 48 1 *)
     179,    (* OBJ_ad_ca_issuers                1 3 6 1 5 5 7 48 2 *)
     363,    (* OBJ_ad_timeStamping              1 3 6 1 5 5 7 48 3 *)
     364,    (* OBJ_ad_dvcs                      1 3 6 1 5 5 7 48 4 *)
     785,    (* OBJ_caRepository                 1 3 6 1 5 5 7 48 5 *)
    1243,    (* OBJ_rpkiManifest                 1 3 6 1 5 5 7 48 10 *)
    1244,    (* OBJ_signedObject                 1 3 6 1 5 5 7 48 11 *)
    1245,    (* OBJ_rpkiNotify                   1 3 6 1 5 5 7 48 13 *)
     780,    (* OBJ_hmac_md5                     1 3 6 1 5 5 8 1 1 *)
     781,    (* OBJ_hmac_sha1                    1 3 6 1 5 5 8 1 2 *)
     913,    (* OBJ_aes_128_xts                  1 3 111 2 1619 0 1 1 *)
     914,    (* OBJ_aes_256_xts                  1 3 111 2 1619 0 1 2 *)
      58,    (* OBJ_netscape_cert_extension      2 16 840 1 113730 1 *)
      59,    (* OBJ_netscape_data_type           2 16 840 1 113730 2 *)
     438,    (* OBJ_pilotAttributeType           0 9 2342 19200300 100 1 *)
     439,    (* OBJ_pilotAttributeSyntax         0 9 2342 19200300 100 3 *)
     440,    (* OBJ_pilotObjectClass             0 9 2342 19200300 100 4 *)
     441,    (* OBJ_pilotGroups                  0 9 2342 19200300 100 10 *)
    1065,    (* OBJ_aria_128_ecb                 1 2 410 200046 1 1 1 *)
    1066,    (* OBJ_aria_128_cbc                 1 2 410 200046 1 1 2 *)
    1067,    (* OBJ_aria_128_cfb128              1 2 410 200046 1 1 3 *)
    1068,    (* OBJ_aria_128_ofb128              1 2 410 200046 1 1 4 *)
    1069,    (* OBJ_aria_128_ctr                 1 2 410 200046 1 1 5 *)
    1070,    (* OBJ_aria_192_ecb                 1 2 410 200046 1 1 6 *)
    1071,    (* OBJ_aria_192_cbc                 1 2 410 200046 1 1 7 *)
    1072,    (* OBJ_aria_192_cfb128              1 2 410 200046 1 1 8 *)
    1073,    (* OBJ_aria_192_ofb128              1 2 410 200046 1 1 9 *)
    1074,    (* OBJ_aria_192_ctr                 1 2 410 200046 1 1 10 *)
    1075,    (* OBJ_aria_256_ecb                 1 2 410 200046 1 1 11 *)
    1076,    (* OBJ_aria_256_cbc                 1 2 410 200046 1 1 12 *)
    1077,    (* OBJ_aria_256_cfb128              1 2 410 200046 1 1 13 *)
    1078,    (* OBJ_aria_256_ofb128              1 2 410 200046 1 1 14 *)
    1079,    (* OBJ_aria_256_ctr                 1 2 410 200046 1 1 15 *)
    1123,    (* OBJ_aria_128_gcm                 1 2 410 200046 1 1 34 *)
    1124,    (* OBJ_aria_192_gcm                 1 2 410 200046 1 1 35 *)
    1125,    (* OBJ_aria_256_gcm                 1 2 410 200046 1 1 36 *)
    1120,    (* OBJ_aria_128_ccm                 1 2 410 200046 1 1 37 *)
    1121,    (* OBJ_aria_192_ccm                 1 2 410 200046 1 1 38 *)
    1122,    (* OBJ_aria_256_ccm                 1 2 410 200046 1 1 39 *)
    1174,    (* OBJ_magma_ctr_acpkm              1 2 643 7 1 1 5 1 1 *)
    1175,    (* OBJ_magma_ctr_acpkm_omac         1 2 643 7 1 1 5 1 2 *)
    1177,    (* OBJ_kuznyechik_ctr_acpkm         1 2 643 7 1 1 5 2 1 *)
    1178,    (* OBJ_kuznyechik_ctr_acpkm_omac    1 2 643 7 1 1 5 2 2 *)
    1181,    (* OBJ_magma_kexp15                 1 2 643 7 1 1 7 1 1 *)
    1183,    (* OBJ_kuznyechik_kexp15            1 2 643 7 1 1 7 2 1 *)
    1148,    (* OBJ_id_tc26_gost_3410_2012_256_paramSetA 1 2 643 7 1 2 1 1 1 *)
    1184,    (* OBJ_id_tc26_gost_3410_2012_256_paramSetB 1 2 643 7 1 2 1 1 2 *)
    1185,    (* OBJ_id_tc26_gost_3410_2012_256_paramSetC 1 2 643 7 1 2 1 1 3 *)
    1186,    (* OBJ_id_tc26_gost_3410_2012_256_paramSetD 1 2 643 7 1 2 1 1 4 *)
     997,    (* OBJ_id_tc26_gost_3410_2012_512_paramSetTest 1 2 643 7 1 2 1 2 0 *)
     998,    (* OBJ_id_tc26_gost_3410_2012_512_paramSetA 1 2 643 7 1 2 1 2 1 *)
     999,    (* OBJ_id_tc26_gost_3410_2012_512_paramSetB 1 2 643 7 1 2 1 2 2 *)
    1149,    (* OBJ_id_tc26_gost_3410_2012_512_paramSetC 1 2 643 7 1 2 1 2 3 *)
    1003,    (* OBJ_id_tc26_gost_28147_param_Z   1 2 643 7 1 2 5 1 1 *)
     108,    (* OBJ_cast5_cbc                    1 2 840 113533 7 66 10 *)
     112,    (* OBJ_pbeWithMD5AndCast5_CBC       1 2 840 113533 7 66 12 *)
     782,    (* OBJ_id_PasswordBasedMAC          1 2 840 113533 7 66 13 *)
     783,    (* OBJ_id_DHBasedMac                1 2 840 113533 7 66 30 *)
       6,    (* OBJ_rsaEncryption                1 2 840 113549 1 1 1 *)
       7,    (* OBJ_md2WithRSAEncryption         1 2 840 113549 1 1 2 *)
     396,    (* OBJ_md4WithRSAEncryption         1 2 840 113549 1 1 3 *)
       8,    (* OBJ_md5WithRSAEncryption         1 2 840 113549 1 1 4 *)
      65,    (* OBJ_sha1WithRSAEncryption        1 2 840 113549 1 1 5 *)
     644,    (* OBJ_rsaOAEPEncryptionSET         1 2 840 113549 1 1 6 *)
     919,    (* OBJ_rsaesOaep                    1 2 840 113549 1 1 7 *)
     911,    (* OBJ_mgf1                         1 2 840 113549 1 1 8 *)
     935,    (* OBJ_pSpecified                   1 2 840 113549 1 1 9 *)
     912,    (* OBJ_rsassaPss                    1 2 840 113549 1 1 10 *)
     668,    (* OBJ_sha256WithRSAEncryption      1 2 840 113549 1 1 11 *)
     669,    (* OBJ_sha384WithRSAEncryption      1 2 840 113549 1 1 12 *)
     670,    (* OBJ_sha512WithRSAEncryption      1 2 840 113549 1 1 13 *)
     671,    (* OBJ_sha224WithRSAEncryption      1 2 840 113549 1 1 14 *)
    1145,    (* OBJ_sha512_224WithRSAEncryption  1 2 840 113549 1 1 15 *)
    1146,    (* OBJ_sha512_256WithRSAEncryption  1 2 840 113549 1 1 16 *)
      28,    (* OBJ_dhKeyAgreement               1 2 840 113549 1 3 1 *)
       9,    (* OBJ_pbeWithMD2AndDES_CBC         1 2 840 113549 1 5 1 *)
      10,    (* OBJ_pbeWithMD5AndDES_CBC         1 2 840 113549 1 5 3 *)
     168,    (* OBJ_pbeWithMD2AndRC2_CBC         1 2 840 113549 1 5 4 *)
     169,    (* OBJ_pbeWithMD5AndRC2_CBC         1 2 840 113549 1 5 6 *)
     170,    (* OBJ_pbeWithSHA1AndDES_CBC        1 2 840 113549 1 5 10 *)
      68,    (* OBJ_pbeWithSHA1AndRC2_CBC        1 2 840 113549 1 5 11 *)
      69,    (* OBJ_id_pbkdf2                    1 2 840 113549 1 5 12 *)
     161,    (* OBJ_pbes2                        1 2 840 113549 1 5 13 *)
     162,    (* OBJ_pbmac1                       1 2 840 113549 1 5 14 *)
      21,    (* OBJ_pkcs7_data                   1 2 840 113549 1 7 1 *)
      22,    (* OBJ_pkcs7_signed                 1 2 840 113549 1 7 2 *)
      23,    (* OBJ_pkcs7_enveloped              1 2 840 113549 1 7 3 *)
      24,    (* OBJ_pkcs7_signedAndEnveloped     1 2 840 113549 1 7 4 *)
      25,    (* OBJ_pkcs7_digest                 1 2 840 113549 1 7 5 *)
      26,    (* OBJ_pkcs7_encrypted              1 2 840 113549 1 7 6 *)
      48,    (* OBJ_pkcs9_emailAddress           1 2 840 113549 1 9 1 *)
      49,    (* OBJ_pkcs9_unstructuredName       1 2 840 113549 1 9 2 *)
      50,    (* OBJ_pkcs9_contentType            1 2 840 113549 1 9 3 *)
      51,    (* OBJ_pkcs9_messageDigest          1 2 840 113549 1 9 4 *)
      52,    (* OBJ_pkcs9_signingTime            1 2 840 113549 1 9 5 *)
      53,    (* OBJ_pkcs9_countersignature       1 2 840 113549 1 9 6 *)
      54,    (* OBJ_pkcs9_challengePassword      1 2 840 113549 1 9 7 *)
      55,    (* OBJ_pkcs9_unstructuredAddress    1 2 840 113549 1 9 8 *)
      56,    (* OBJ_pkcs9_extCertAttributes      1 2 840 113549 1 9 9 *)
     172,    (* OBJ_ext_req                      1 2 840 113549 1 9 14 *)
     167,    (* OBJ_SMIMECapabilities            1 2 840 113549 1 9 15 *)
     188,    (* OBJ_SMIME                        1 2 840 113549 1 9 16 *)
     156,    (* OBJ_friendlyName                 1 2 840 113549 1 9 20 *)
     157,    (* OBJ_localKeyID                   1 2 840 113549 1 9 21 *)
     681,    (* OBJ_X9_62_onBasis                1 2 840 10045 1 2 3 1 *)
     682,    (* OBJ_X9_62_tpBasis                1 2 840 10045 1 2 3 2 *)
     683,    (* OBJ_X9_62_ppBasis                1 2 840 10045 1 2 3 3 *)
     417,    (* OBJ_ms_csp_name                  1 3 6 1 4 1 311 17 1 *)
     856,    (* OBJ_LocalKeySet                  1 3 6 1 4 1 311 17 2 *)
     390,    (* OBJ_dcObject                     1 3 6 1 4 1 1466 344 *)
      91,    (* OBJ_bf_cbc                       1 3 6 1 4 1 3029 1 2 *)
     973,    (* OBJ_id_scrypt                    1 3 6 1 4 1 11591 4 11 *)
     315,    (* OBJ_id_regCtrl_regToken          1 3 6 1 5 5 7 5 1 1 *)
     316,    (* OBJ_id_regCtrl_authenticator     1 3 6 1 5 5 7 5 1 2 *)
     317,    (* OBJ_id_regCtrl_pkiPublicationInfo 1 3 6 1 5 5 7 5 1 3 *)
     318,    (* OBJ_id_regCtrl_pkiArchiveOptions 1 3 6 1 5 5 7 5 1 4 *)
     319,    (* OBJ_id_regCtrl_oldCertID         1 3 6 1 5 5 7 5 1 5 *)
     320,    (* OBJ_id_regCtrl_protocolEncrKey   1 3 6 1 5 5 7 5 1 6 *)
     321,    (* OBJ_id_regInfo_utf8Pairs         1 3 6 1 5 5 7 5 2 1 *)
     322,    (* OBJ_id_regInfo_certReq           1 3 6 1 5 5 7 5 2 2 *)
     365,    (* OBJ_id_pkix_OCSP_basic           1 3 6 1 5 5 7 48 1 1 *)
     366,    (* OBJ_id_pkix_OCSP_Nonce           1 3 6 1 5 5 7 48 1 2 *)
     367,    (* OBJ_id_pkix_OCSP_CrlID           1 3 6 1 5 5 7 48 1 3 *)
     368,    (* OBJ_id_pkix_OCSP_acceptableResponses 1 3 6 1 5 5 7 48 1 4 *)
     369,    (* OBJ_id_pkix_OCSP_noCheck         1 3 6 1 5 5 7 48 1 5 *)
     370,    (* OBJ_id_pkix_OCSP_archiveCutoff   1 3 6 1 5 5 7 48 1 6 *)
     371,    (* OBJ_id_pkix_OCSP_serviceLocator  1 3 6 1 5 5 7 48 1 7 *)
     372,    (* OBJ_id_pkix_OCSP_extendedStatus  1 3 6 1 5 5 7 48 1 8 *)
     373,    (* OBJ_id_pkix_OCSP_valid           1 3 6 1 5 5 7 48 1 9 *)
     374,    (* OBJ_id_pkix_OCSP_path            1 3 6 1 5 5 7 48 1 10 *)
     375,    (* OBJ_id_pkix_OCSP_trustRoot       1 3 6 1 5 5 7 48 1 11 *)
     921,    (* OBJ_brainpoolP160r1              1 3 36 3 3 2 8 1 1 1 *)
     922,    (* OBJ_brainpoolP160t1              1 3 36 3 3 2 8 1 1 2 *)
     923,    (* OBJ_brainpoolP192r1              1 3 36 3 3 2 8 1 1 3 *)
     924,    (* OBJ_brainpoolP192t1              1 3 36 3 3 2 8 1 1 4 *)
     925,    (* OBJ_brainpoolP224r1              1 3 36 3 3 2 8 1 1 5 *)
     926,    (* OBJ_brainpoolP224t1              1 3 36 3 3 2 8 1 1 6 *)
     927,    (* OBJ_brainpoolP256r1              1 3 36 3 3 2 8 1 1 7 *)
     928,    (* OBJ_brainpoolP256t1              1 3 36 3 3 2 8 1 1 8 *)
     929,    (* OBJ_brainpoolP320r1              1 3 36 3 3 2 8 1 1 9 *)
     930,    (* OBJ_brainpoolP320t1              1 3 36 3 3 2 8 1 1 10 *)
     931,    (* OBJ_brainpoolP384r1              1 3 36 3 3 2 8 1 1 11 *)
     932,    (* OBJ_brainpoolP384t1              1 3 36 3 3 2 8 1 1 12 *)
     933,    (* OBJ_brainpoolP512r1              1 3 36 3 3 2 8 1 1 13 *)
     934,    (* OBJ_brainpoolP512t1              1 3 36 3 3 2 8 1 1 14 *)
     936,    (* OBJ_dhSinglePass_stdDH_sha1kdf_scheme 1 3 133 16 840 63 0 2 *)
     941,    (* OBJ_dhSinglePass_cofactorDH_sha1kdf_scheme 1 3 133 16 840 63 0 3 *)
     418,    (* OBJ_aes_128_ecb                  2 16 840 1 101 3 4 1 1 *)
     419,    (* OBJ_aes_128_cbc                  2 16 840 1 101 3 4 1 2 *)
     420,    (* OBJ_aes_128_ofb128               2 16 840 1 101 3 4 1 3 *)
     421,    (* OBJ_aes_128_cfb128               2 16 840 1 101 3 4 1 4 *)
     788,    (* OBJ_id_aes128_wrap               2 16 840 1 101 3 4 1 5 *)
     895,    (* OBJ_aes_128_gcm                  2 16 840 1 101 3 4 1 6 *)
     896,    (* OBJ_aes_128_ccm                  2 16 840 1 101 3 4 1 7 *)
     897,    (* OBJ_id_aes128_wrap_pad           2 16 840 1 101 3 4 1 8 *)
     422,    (* OBJ_aes_192_ecb                  2 16 840 1 101 3 4 1 21 *)
     423,    (* OBJ_aes_192_cbc                  2 16 840 1 101 3 4 1 22 *)
     424,    (* OBJ_aes_192_ofb128               2 16 840 1 101 3 4 1 23 *)
     425,    (* OBJ_aes_192_cfb128               2 16 840 1 101 3 4 1 24 *)
     789,    (* OBJ_id_aes192_wrap               2 16 840 1 101 3 4 1 25 *)
     898,    (* OBJ_aes_192_gcm                  2 16 840 1 101 3 4 1 26 *)
     899,    (* OBJ_aes_192_ccm                  2 16 840 1 101 3 4 1 27 *)
     900,    (* OBJ_id_aes192_wrap_pad           2 16 840 1 101 3 4 1 28 *)
     426,    (* OBJ_aes_256_ecb                  2 16 840 1 101 3 4 1 41 *)
     427,    (* OBJ_aes_256_cbc                  2 16 840 1 101 3 4 1 42 *)
     428,    (* OBJ_aes_256_ofb128               2 16 840 1 101 3 4 1 43 *)
     429,    (* OBJ_aes_256_cfb128               2 16 840 1 101 3 4 1 44 *)
     790,    (* OBJ_id_aes256_wrap               2 16 840 1 101 3 4 1 45 *)
     901,    (* OBJ_aes_256_gcm                  2 16 840 1 101 3 4 1 46 *)
     902,    (* OBJ_aes_256_ccm                  2 16 840 1 101 3 4 1 47 *)
     903,    (* OBJ_id_aes256_wrap_pad           2 16 840 1 101 3 4 1 48 *)
     672,    (* OBJ_sha256                       2 16 840 1 101 3 4 2 1 *)
     673,    (* OBJ_sha384                       2 16 840 1 101 3 4 2 2 *)
     674,    (* OBJ_sha512                       2 16 840 1 101 3 4 2 3 *)
     675,    (* OBJ_sha224                       2 16 840 1 101 3 4 2 4 *)
    1094,    (* OBJ_sha512_224                   2 16 840 1 101 3 4 2 5 *)
    1095,    (* OBJ_sha512_256                   2 16 840 1 101 3 4 2 6 *)
    1096,    (* OBJ_sha3_224                     2 16 840 1 101 3 4 2 7 *)
    1097,    (* OBJ_sha3_256                     2 16 840 1 101 3 4 2 8 *)
    1098,    (* OBJ_sha3_384                     2 16 840 1 101 3 4 2 9 *)
    1099,    (* OBJ_sha3_512                     2 16 840 1 101 3 4 2 10 *)
    1100,    (* OBJ_shake128                     2 16 840 1 101 3 4 2 11 *)
    1101,    (* OBJ_shake256                     2 16 840 1 101 3 4 2 12 *)
    1102,    (* OBJ_hmac_sha3_224                2 16 840 1 101 3 4 2 13 *)
    1103,    (* OBJ_hmac_sha3_256                2 16 840 1 101 3 4 2 14 *)
    1104,    (* OBJ_hmac_sha3_384                2 16 840 1 101 3 4 2 15 *)
    1105,    (* OBJ_hmac_sha3_512                2 16 840 1 101 3 4 2 16 *)
    1196,    (* OBJ_kmac128                      2 16 840 1 101 3 4 2 19 *)
    1197,    (* OBJ_kmac256                      2 16 840 1 101 3 4 2 20 *)
     802,    (* OBJ_dsa_with_SHA224              2 16 840 1 101 3 4 3 1 *)
     803,    (* OBJ_dsa_with_SHA256              2 16 840 1 101 3 4 3 2 *)
    1106,    (* OBJ_dsa_with_SHA384              2 16 840 1 101 3 4 3 3 *)
    1107,    (* OBJ_dsa_with_SHA512              2 16 840 1 101 3 4 3 4 *)
    1108,    (* OBJ_dsa_with_SHA3_224            2 16 840 1 101 3 4 3 5 *)
    1109,    (* OBJ_dsa_with_SHA3_256            2 16 840 1 101 3 4 3 6 *)
    1110,    (* OBJ_dsa_with_SHA3_384            2 16 840 1 101 3 4 3 7 *)
    1111,    (* OBJ_dsa_with_SHA3_512            2 16 840 1 101 3 4 3 8 *)
    1112,    (* OBJ_ecdsa_with_SHA3_224          2 16 840 1 101 3 4 3 9 *)
    1113,    (* OBJ_ecdsa_with_SHA3_256          2 16 840 1 101 3 4 3 10 *)
    1114,    (* OBJ_ecdsa_with_SHA3_384          2 16 840 1 101 3 4 3 11 *)
    1115,    (* OBJ_ecdsa_with_SHA3_512          2 16 840 1 101 3 4 3 12 *)
    1116,    (* OBJ_RSA_SHA3_224                 2 16 840 1 101 3 4 3 13 *)
    1117,    (* OBJ_RSA_SHA3_256                 2 16 840 1 101 3 4 3 14 *)
    1118,    (* OBJ_RSA_SHA3_384                 2 16 840 1 101 3 4 3 15 *)
    1119,    (* OBJ_RSA_SHA3_512                 2 16 840 1 101 3 4 3 16 *)
      71,    (* OBJ_netscape_cert_type           2 16 840 1 113730 1 1 *)
      72,    (* OBJ_netscape_base_url            2 16 840 1 113730 1 2 *)
      73,    (* OBJ_netscape_revocation_url      2 16 840 1 113730 1 3 *)
      74,    (* OBJ_netscape_ca_revocation_url   2 16 840 1 113730 1 4 *)
      75,    (* OBJ_netscape_renewal_url         2 16 840 1 113730 1 7 *)
      76,    (* OBJ_netscape_ca_policy_url       2 16 840 1 113730 1 8 *)
      77,    (* OBJ_netscape_ssl_server_name     2 16 840 1 113730 1 12 *)
      78,    (* OBJ_netscape_comment             2 16 840 1 113730 1 13 *)
      79,    (* OBJ_netscape_cert_sequence       2 16 840 1 113730 2 5 *)
     139,    (* OBJ_ns_sgc                       2 16 840 1 113730 4 1 *)
     458,    (* OBJ_userId                       0 9 2342 19200300 100 1 1 *)
     459,    (* OBJ_textEncodedORAddress         0 9 2342 19200300 100 1 2 *)
     460,    (* OBJ_rfc822Mailbox                0 9 2342 19200300 100 1 3 *)
     461,    (* OBJ_info                         0 9 2342 19200300 100 1 4 *)
     462,    (* OBJ_favouriteDrink               0 9 2342 19200300 100 1 5 *)
     463,    (* OBJ_roomNumber                   0 9 2342 19200300 100 1 6 *)
     464,    (* OBJ_photo                        0 9 2342 19200300 100 1 7 *)
     465,    (* OBJ_userClass                    0 9 2342 19200300 100 1 8 *)
     466,    (* OBJ_host                         0 9 2342 19200300 100 1 9 *)
     467,    (* OBJ_manager                      0 9 2342 19200300 100 1 10 *)
     468,    (* OBJ_documentIdentifier           0 9 2342 19200300 100 1 11 *)
     469,    (* OBJ_documentTitle                0 9 2342 19200300 100 1 12 *)
     470,    (* OBJ_documentVersion              0 9 2342 19200300 100 1 13 *)
     471,    (* OBJ_documentAuthor               0 9 2342 19200300 100 1 14 *)
     472,    (* OBJ_documentLocation             0 9 2342 19200300 100 1 15 *)
     473,    (* OBJ_homeTelephoneNumber          0 9 2342 19200300 100 1 20 *)
     474,    (* OBJ_secretary                    0 9 2342 19200300 100 1 21 *)
     475,    (* OBJ_otherMailbox                 0 9 2342 19200300 100 1 22 *)
     476,    (* OBJ_lastModifiedTime             0 9 2342 19200300 100 1 23 *)
     477,    (* OBJ_lastModifiedBy               0 9 2342 19200300 100 1 24 *)
     391,    (* OBJ_domainComponent              0 9 2342 19200300 100 1 25 *)
     478,    (* OBJ_aRecord                      0 9 2342 19200300 100 1 26 *)
     479,    (* OBJ_pilotAttributeType27         0 9 2342 19200300 100 1 27 *)
     480,    (* OBJ_mXRecord                     0 9 2342 19200300 100 1 28 *)
     481,    (* OBJ_nSRecord                     0 9 2342 19200300 100 1 29 *)
     482,    (* OBJ_sOARecord                    0 9 2342 19200300 100 1 30 *)
     483,    (* OBJ_cNAMERecord                  0 9 2342 19200300 100 1 31 *)
     484,    (* OBJ_associatedDomain             0 9 2342 19200300 100 1 37 *)
     485,    (* OBJ_associatedName               0 9 2342 19200300 100 1 38 *)
     486,    (* OBJ_homePostalAddress            0 9 2342 19200300 100 1 39 *)
     487,    (* OBJ_personalTitle                0 9 2342 19200300 100 1 40 *)
     488,    (* OBJ_mobileTelephoneNumber        0 9 2342 19200300 100 1 41 *)
     489,    (* OBJ_pagerTelephoneNumber         0 9 2342 19200300 100 1 42 *)
     490,    (* OBJ_friendlyCountryName          0 9 2342 19200300 100 1 43 *)
     102,    (* OBJ_uniqueIdentifier             0 9 2342 19200300 100 1 44 *)
     491,    (* OBJ_organizationalStatus         0 9 2342 19200300 100 1 45 *)
     492,    (* OBJ_janetMailbox                 0 9 2342 19200300 100 1 46 *)
     493,    (* OBJ_mailPreferenceOption         0 9 2342 19200300 100 1 47 *)
     494,    (* OBJ_buildingName                 0 9 2342 19200300 100 1 48 *)
     495,    (* OBJ_dSAQuality                   0 9 2342 19200300 100 1 49 *)
     496,    (* OBJ_singleLevelQuality           0 9 2342 19200300 100 1 50 *)
     497,    (* OBJ_subtreeMinimumQuality        0 9 2342 19200300 100 1 51 *)
     498,    (* OBJ_subtreeMaximumQuality        0 9 2342 19200300 100 1 52 *)
     499,    (* OBJ_personalSignature            0 9 2342 19200300 100 1 53 *)
     500,    (* OBJ_dITRedirect                  0 9 2342 19200300 100 1 54 *)
     501,    (* OBJ_audio                        0 9 2342 19200300 100 1 55 *)
     502,    (* OBJ_documentPublisher            0 9 2342 19200300 100 1 56 *)
     442,    (* OBJ_iA5StringSyntax              0 9 2342 19200300 100 3 4 *)
     443,    (* OBJ_caseIgnoreIA5StringSyntax    0 9 2342 19200300 100 3 5 *)
     444,    (* OBJ_pilotObject                  0 9 2342 19200300 100 4 3 *)
     445,    (* OBJ_pilotPerson                  0 9 2342 19200300 100 4 4 *)
     446,    (* OBJ_account                      0 9 2342 19200300 100 4 5 *)
     447,    (* OBJ_document                     0 9 2342 19200300 100 4 6 *)
     448,    (* OBJ_room                         0 9 2342 19200300 100 4 7 *)
     449,    (* OBJ_documentSeries               0 9 2342 19200300 100 4 9 *)
     392,    (* OBJ_Domain                       0 9 2342 19200300 100 4 13 *)
     450,    (* OBJ_rFC822localPart              0 9 2342 19200300 100 4 14 *)
     451,    (* OBJ_dNSDomain                    0 9 2342 19200300 100 4 15 *)
     452,    (* OBJ_domainRelatedObject          0 9 2342 19200300 100 4 17 *)
     453,    (* OBJ_friendlyCountry              0 9 2342 19200300 100 4 18 *)
     454,    (* OBJ_simpleSecurityObject         0 9 2342 19200300 100 4 19 *)
     455,    (* OBJ_pilotOrganization            0 9 2342 19200300 100 4 20 *)
     456,    (* OBJ_pilotDSA                     0 9 2342 19200300 100 4 21 *)
     457,    (* OBJ_qualityLabelledData          0 9 2342 19200300 100 4 22 *)
    1152,    (* OBJ_dstu28147                    1 2 804 2 1 1 1 1 1 1 *)
    1156,    (* OBJ_hmacWithDstu34311            1 2 804 2 1 1 1 1 1 2 *)
    1157,    (* OBJ_dstu34311                    1 2 804 2 1 1 1 1 2 1 *)
     189,    (* OBJ_id_smime_mod                 1 2 840 113549 1 9 16 0 *)
     190,    (* OBJ_id_smime_ct                  1 2 840 113549 1 9 16 1 *)
     191,    (* OBJ_id_smime_aa                  1 2 840 113549 1 9 16 2 *)
     192,    (* OBJ_id_smime_alg                 1 2 840 113549 1 9 16 3 *)
     193,    (* OBJ_id_smime_cd                  1 2 840 113549 1 9 16 4 *)
     194,    (* OBJ_id_smime_spq                 1 2 840 113549 1 9 16 5 *)
     195,    (* OBJ_id_smime_cti                 1 2 840 113549 1 9 16 6 *)
     158,    (* OBJ_x509Certificate              1 2 840 113549 1 9 22 1 *)
     159,    (* OBJ_sdsiCertificate              1 2 840 113549 1 9 22 2 *)
     160,    (* OBJ_x509Crl                      1 2 840 113549 1 9 23 1 *)
     144,    (* OBJ_pbe_WithSHA1And128BitRC4     1 2 840 113549 1 12 1 1 *)
     145,    (* OBJ_pbe_WithSHA1And40BitRC4      1 2 840 113549 1 12 1 2 *)
     146,    (* OBJ_pbe_WithSHA1And3_Key_TripleDES_CBC 1 2 840 113549 1 12 1 3 *)
     147,    (* OBJ_pbe_WithSHA1And2_Key_TripleDES_CBC 1 2 840 113549 1 12 1 4 *)
     148,    (* OBJ_pbe_WithSHA1And128BitRC2_CBC 1 2 840 113549 1 12 1 5 *)
     149,    (* OBJ_pbe_WithSHA1And40BitRC2_CBC  1 2 840 113549 1 12 1 6 *)
     171,    (* OBJ_ms_ext_req                   1 3 6 1 4 1 311 2 1 14 *)
     134,    (* OBJ_ms_code_ind                  1 3 6 1 4 1 311 2 1 21 *)
     135,    (* OBJ_ms_code_com                  1 3 6 1 4 1 311 2 1 22 *)
     136,    (* OBJ_ms_ctl_sign                  1 3 6 1 4 1 311 10 3 1 *)
     137,    (* OBJ_ms_sgc                       1 3 6 1 4 1 311 10 3 3 *)
     138,    (* OBJ_ms_efs                       1 3 6 1 4 1 311 10 3 4 *)
     648,    (* OBJ_ms_smartcard_login           1 3 6 1 4 1 311 20 2 2 *)
     649,    (* OBJ_ms_upn                       1 3 6 1 4 1 311 20 2 3 *)
    1201,    (* OBJ_blake2bmac                   1 3 6 1 4 1 1722 12 2 1 *)
    1202,    (* OBJ_blake2smac                   1 3 6 1 4 1 1722 12 2 2 *)
     951,    (* OBJ_ct_precert_scts              1 3 6 1 4 1 11129 2 4 2 *)
     952,    (* OBJ_ct_precert_poison            1 3 6 1 4 1 11129 2 4 3 *)
     953,    (* OBJ_ct_precert_signer            1 3 6 1 4 1 11129 2 4 4 *)
     954,    (* OBJ_ct_cert_scts                 1 3 6 1 4 1 11129 2 4 5 *)
     751,    (* OBJ_camellia_128_cbc             1 2 392 200011 61 1 1 1 2 *)
     752,    (* OBJ_camellia_192_cbc             1 2 392 200011 61 1 1 1 3 *)
     753,    (* OBJ_camellia_256_cbc             1 2 392 200011 61 1 1 1 4 *)
     907,    (* OBJ_id_camellia128_wrap          1 2 392 200011 61 1 1 3 2 *)
     908,    (* OBJ_id_camellia192_wrap          1 2 392 200011 61 1 1 3 3 *)
     909,    (* OBJ_id_camellia256_wrap          1 2 392 200011 61 1 1 3 4 *)
    1153,    (* OBJ_dstu28147_ofb                1 2 804 2 1 1 1 1 1 1 2 *)
    1154,    (* OBJ_dstu28147_cfb                1 2 804 2 1 1 1 1 1 1 3 *)
    1155,    (* OBJ_dstu28147_wrap               1 2 804 2 1 1 1 1 1 1 5 *)
    1158,    (* OBJ_dstu4145le                   1 2 804 2 1 1 1 1 3 1 1 *)
     196,    (* OBJ_id_smime_mod_cms             1 2 840 113549 1 9 16 0 1 *)
     197,    (* OBJ_id_smime_mod_ess             1 2 840 113549 1 9 16 0 2 *)
     198,    (* OBJ_id_smime_mod_oid             1 2 840 113549 1 9 16 0 3 *)
     199,    (* OBJ_id_smime_mod_msg_v3          1 2 840 113549 1 9 16 0 4 *)
     200,    (* OBJ_id_smime_mod_ets_eSignature_88 1 2 840 113549 1 9 16 0 5 *)
     201,    (* OBJ_id_smime_mod_ets_eSignature_97 1 2 840 113549 1 9 16 0 6 *)
     202,    (* OBJ_id_smime_mod_ets_eSigPolicy_88 1 2 840 113549 1 9 16 0 7 *)
     203,    (* OBJ_id_smime_mod_ets_eSigPolicy_97 1 2 840 113549 1 9 16 0 8 *)
     204,    (* OBJ_id_smime_ct_receipt          1 2 840 113549 1 9 16 1 1 *)
     205,    (* OBJ_id_smime_ct_authData         1 2 840 113549 1 9 16 1 2 *)
     206,    (* OBJ_id_smime_ct_publishCert      1 2 840 113549 1 9 16 1 3 *)
     207,    (* OBJ_id_smime_ct_TSTInfo          1 2 840 113549 1 9 16 1 4 *)
     208,    (* OBJ_id_smime_ct_TDTInfo          1 2 840 113549 1 9 16 1 5 *)
     209,    (* OBJ_id_smime_ct_contentInfo      1 2 840 113549 1 9 16 1 6 *)
     210,    (* OBJ_id_smime_ct_DVCSRequestData  1 2 840 113549 1 9 16 1 7 *)
     211,    (* OBJ_id_smime_ct_DVCSResponseData 1 2 840 113549 1 9 16 1 8 *)
     786,    (* OBJ_id_smime_ct_compressedData   1 2 840 113549 1 9 16 1 9 *)
    1058,    (* OBJ_id_smime_ct_contentCollection 1 2 840 113549 1 9 16 1 19 *)
    1059,    (* OBJ_id_smime_ct_authEnvelopedData 1 2 840 113549 1 9 16 1 23 *)
    1234,    (* OBJ_id_ct_routeOriginAuthz       1 2 840 113549 1 9 16 1 24 *)
    1235,    (* OBJ_id_ct_rpkiManifest           1 2 840 113549 1 9 16 1 26 *)
     787,    (* OBJ_id_ct_asciiTextWithCRLF      1 2 840 113549 1 9 16 1 27 *)
    1060,    (* OBJ_id_ct_xml                    1 2 840 113549 1 9 16 1 28 *)
    1236,    (* OBJ_id_ct_rpkiGhostbusters       1 2 840 113549 1 9 16 1 35 *)
    1237,    (* OBJ_id_ct_resourceTaggedAttest   1 2 840 113549 1 9 16 1 36 *)
    1246,    (* OBJ_id_ct_geofeedCSVwithCRLF     1 2 840 113549 1 9 16 1 47 *)
    1247,    (* OBJ_id_ct_signedChecklist        1 2 840 113549 1 9 16 1 48 *)
    1250,    (* OBJ_id_ct_ASPA                   1 2 840 113549 1 9 16 1 49 *)
     212,    (* OBJ_id_smime_aa_receiptRequest   1 2 840 113549 1 9 16 2 1 *)
     213,    (* OBJ_id_smime_aa_securityLabel    1 2 840 113549 1 9 16 2 2 *)
     214,    (* OBJ_id_smime_aa_mlExpandHistory  1 2 840 113549 1 9 16 2 3 *)
     215,    (* OBJ_id_smime_aa_contentHint      1 2 840 113549 1 9 16 2 4 *)
     216,    (* OBJ_id_smime_aa_msgSigDigest     1 2 840 113549 1 9 16 2 5 *)
     217,    (* OBJ_id_smime_aa_encapContentType 1 2 840 113549 1 9 16 2 6 *)
     218,    (* OBJ_id_smime_aa_contentIdentifier 1 2 840 113549 1 9 16 2 7 *)
     219,    (* OBJ_id_smime_aa_macValue         1 2 840 113549 1 9 16 2 8 *)
     220,    (* OBJ_id_smime_aa_equivalentLabels 1 2 840 113549 1 9 16 2 9 *)
     221,    (* OBJ_id_smime_aa_contentReference 1 2 840 113549 1 9 16 2 10 *)
     222,    (* OBJ_id_smime_aa_encrypKeyPref    1 2 840 113549 1 9 16 2 11 *)
     223,    (* OBJ_id_smime_aa_signingCertificate 1 2 840 113549 1 9 16 2 12 *)
     224,    (* OBJ_id_smime_aa_smimeEncryptCerts 1 2 840 113549 1 9 16 2 13 *)
     225,    (* OBJ_id_smime_aa_timeStampToken   1 2 840 113549 1 9 16 2 14 *)
     226,    (* OBJ_id_smime_aa_ets_sigPolicyId  1 2 840 113549 1 9 16 2 15 *)
     227,    (* OBJ_id_smime_aa_ets_commitmentType 1 2 840 113549 1 9 16 2 16 *)
     228,    (* OBJ_id_smime_aa_ets_signerLocation 1 2 840 113549 1 9 16 2 17 *)
     229,    (* OBJ_id_smime_aa_ets_signerAttr   1 2 840 113549 1 9 16 2 18 *)
     230,    (* OBJ_id_smime_aa_ets_otherSigCert 1 2 840 113549 1 9 16 2 19 *)
     231,    (* OBJ_id_smime_aa_ets_contentTimestamp 1 2 840 113549 1 9 16 2 20 *)
     232,    (* OBJ_id_smime_aa_ets_CertificateRefs 1 2 840 113549 1 9 16 2 21 *)
     233,    (* OBJ_id_smime_aa_ets_RevocationRefs 1 2 840 113549 1 9 16 2 22 *)
     234,    (* OBJ_id_smime_aa_ets_certValues   1 2 840 113549 1 9 16 2 23 *)
     235,    (* OBJ_id_smime_aa_ets_revocationValues 1 2 840 113549 1 9 16 2 24 *)
     236,    (* OBJ_id_smime_aa_ets_escTimeStamp 1 2 840 113549 1 9 16 2 25 *)
     237,    (* OBJ_id_smime_aa_ets_certCRLTimestamp 1 2 840 113549 1 9 16 2 26 *)
     238,    (* OBJ_id_smime_aa_ets_archiveTimeStamp 1 2 840 113549 1 9 16 2 27 *)
     239,    (* OBJ_id_smime_aa_signatureType    1 2 840 113549 1 9 16 2 28 *)
     240,    (* OBJ_id_smime_aa_dvcs_dvc         1 2 840 113549 1 9 16 2 29 *)
    1086,    (* OBJ_id_smime_aa_signingCertificateV2 1 2 840 113549 1 9 16 2 47 *)
     241,    (* OBJ_id_smime_alg_ESDHwith3DES    1 2 840 113549 1 9 16 3 1 *)
     242,    (* OBJ_id_smime_alg_ESDHwithRC2     1 2 840 113549 1 9 16 3 2 *)
     243,    (* OBJ_id_smime_alg_3DESwrap        1 2 840 113549 1 9 16 3 3 *)
     244,    (* OBJ_id_smime_alg_RC2wrap         1 2 840 113549 1 9 16 3 4 *)
     245,    (* OBJ_id_smime_alg_ESDH            1 2 840 113549 1 9 16 3 5 *)
     246,    (* OBJ_id_smime_alg_CMS3DESwrap     1 2 840 113549 1 9 16 3 6 *)
     247,    (* OBJ_id_smime_alg_CMSRC2wrap      1 2 840 113549 1 9 16 3 7 *)
     125,    (* OBJ_zlib_compression             1 2 840 113549 1 9 16 3 8 *)
     893,    (* OBJ_id_alg_PWRI_KEK              1 2 840 113549 1 9 16 3 9 *)
     248,    (* OBJ_id_smime_cd_ldap             1 2 840 113549 1 9 16 4 1 *)
     249,    (* OBJ_id_smime_spq_ets_sqt_uri     1 2 840 113549 1 9 16 5 1 *)
     250,    (* OBJ_id_smime_spq_ets_sqt_unotice 1 2 840 113549 1 9 16 5 2 *)
     251,    (* OBJ_id_smime_cti_ets_proofOfOrigin 1 2 840 113549 1 9 16 6 1 *)
     252,    (* OBJ_id_smime_cti_ets_proofOfReceipt 1 2 840 113549 1 9 16 6 2 *)
     253,    (* OBJ_id_smime_cti_ets_proofOfDelivery 1 2 840 113549 1 9 16 6 3 *)
     254,    (* OBJ_id_smime_cti_ets_proofOfSender 1 2 840 113549 1 9 16 6 4 *)
     255,    (* OBJ_id_smime_cti_ets_proofOfApproval 1 2 840 113549 1 9 16 6 5 *)
     256,    (* OBJ_id_smime_cti_ets_proofOfCreation 1 2 840 113549 1 9 16 6 6 *)
     150,    (* OBJ_keyBag                       1 2 840 113549 1 12 10 1 1 *)
     151,    (* OBJ_pkcs8ShroudedKeyBag          1 2 840 113549 1 12 10 1 2 *)
     152,    (* OBJ_certBag                      1 2 840 113549 1 12 10 1 3 *)
     153,    (* OBJ_crlBag                       1 2 840 113549 1 12 10 1 4 *)
     154,    (* OBJ_secretBag                    1 2 840 113549 1 12 10 1 5 *)
     155,    (* OBJ_safeContentsBag              1 2 840 113549 1 12 10 1 6 *)
      34,    (* OBJ_idea_cbc                     1 3 6 1 4 1 188 7 1 1 2 *)
     955,    (* OBJ_jurisdictionLocalityName     1 3 6 1 4 1 311 60 2 1 1 *)
     956,    (* OBJ_jurisdictionStateOrProvinceName 1 3 6 1 4 1 311 60 2 1 2 *)
     957,    (* OBJ_jurisdictionCountryName      1 3 6 1 4 1 311 60 2 1 3 *)
    1056,    (* OBJ_blake2b512                   1 3 6 1 4 1 1722 12 2 1 16 *)
    1057,    (* OBJ_blake2s256                   1 3 6 1 4 1 1722 12 2 2 8 *)
    1159,    (* OBJ_dstu4145be                   1 2 804 2 1 1 1 1 3 1 1 1 1 *)
    1160,    (* OBJ_uacurve0                     1 2 804 2 1 1 1 1 3 1 1 2 0 *)
    1161,    (* OBJ_uacurve1                     1 2 804 2 1 1 1 1 3 1 1 2 1 *)
    1162,    (* OBJ_uacurve2                     1 2 804 2 1 1 1 1 3 1 1 2 2 *)
    1163,    (* OBJ_uacurve3                     1 2 804 2 1 1 1 1 3 1 1 2 3 *)
    1164,    (* OBJ_uacurve4                     1 2 804 2 1 1 1 1 3 1 1 2 4 *)
    1165,    (* OBJ_uacurve5                     1 2 804 2 1 1 1 1 3 1 1 2 5 *)
    1166,    (* OBJ_uacurve6                     1 2 804 2 1 1 1 1 3 1 1 2 6 *)
    1167,    (* OBJ_uacurve7                     1 2 804 2 1 1 1 1 3 1 1 2 7 *)
    1168,    (* OBJ_uacurve8                     1 2 804 2 1 1 1 1 3 1 1 2 8 *)
    1169    (* OBJ_uacurve9                     1 2 804 2 1 1 1 1 3 1 1 2 9 *)
);

function OBJ_bsearch_(const key, base : Pointer; num, size : integer; cmp: Tcmp_func):Pointer;
function OBJ_get0_data(const obj : PASN1_OBJECT):PByte;
function OBJ_length(const obj : PASN1_OBJECT):size_t;
function OBJ_nid2sn( n : integer):PUTF8Char;
function OBJ_nid2obj( n : integer):PASN1_OBJECT;
function OBJ_bsearch_ex_(const key, base : Pointer; num, size : integer; cmp : Tcmp_func; flags : integer):Pointer;
function ossl_obj_read_lock( lock : integer):integer;
function ossl_init_added_lock:integer;
 procedure obj_lock_initialise_ossl_;
  function obj_lock_initialise:integer;
function lh_ADDED_OBJ_retrieve(lh : Plhash_st_ADDED_OBJ;const d : PADDED_OBJ):PADDED_OBJ;
procedure ossl_obj_unlock( lock : integer);



const so: array[0..8101] of Byte = (
    $2A,$86,$48,$86,$F7,$0D,                 (* [    0] OBJ_rsadsi *)
    $2A,$86,$48,$86,$F7,$0D,$01,            (* [    6] OBJ_pkcs *)
    $2A,$86,$48,$86,$F7,$0D,$02,$02,       (* [   13] OBJ_md2 *)
    $2A,$86,$48,$86,$F7,$0D,$02,$05,       (* [   21] OBJ_md5 *)
    $2A,$86,$48,$86,$F7,$0D,$03,$04,       (* [   29] OBJ_rc4 *)
    $2A,$86,$48,$86,$F7,$0D,$01,$01,$01,  (* [   37] OBJ_rsaEncryption *)
    $2A,$86,$48,$86,$F7,$0D,$01,$01,$02,  (* [   46] OBJ_md2WithRSAEncryption *)
    $2A,$86,$48,$86,$F7,$0D,$01,$01,$04,  (* [   55] OBJ_md5WithRSAEncryption *)
    $2A,$86,$48,$86,$F7,$0D,$01,$05,$01,  (* [   64] OBJ_pbeWithMD2AndDES_CBC *)
    $2A,$86,$48,$86,$F7,$0D,$01,$05,$03,  (* [   73] OBJ_pbeWithMD5AndDES_CBC *)
    $55,                                          (* [   82] OBJ_X500 *)
    $55,$04,                                     (* [   83] OBJ_X509 *)
    $55,$04,$03,                                (* [   85] OBJ_commonName *)
    $55,$04,$06,                                (* [   88] OBJ_countryName *)
    $55,$04,$07,                                (* [   91] OBJ_localityName *)
    $55,$04,$08,                                (* [   94] OBJ_stateOrProvinceName *)
    $55,$04,$0A,                                (* [   97] OBJ_organizationName *)
    $55,$04,$0B,                                (* [  100] OBJ_organizationalUnitName *)
    $55,$08,$01,$01,                           (* [  103] OBJ_rsa *)
    $2A,$86,$48,$86,$F7,$0D,$01,$07,       (* [  107] OBJ_pkcs7 *)
    $2A,$86,$48,$86,$F7,$0D,$01,$07,$01,  (* [  115] OBJ_pkcs7_data *)
    $2A,$86,$48,$86,$F7,$0D,$01,$07,$02,  (* [  124] OBJ_pkcs7_signed *)
    $2A,$86,$48,$86,$F7,$0D,$01,$07,$03,  (* [  133] OBJ_pkcs7_enveloped *)
    $2A,$86,$48,$86,$F7,$0D,$01,$07,$04,  (* [  142] OBJ_pkcs7_signedAndEnveloped *)
    $2A,$86,$48,$86,$F7,$0D,$01,$07,$05,  (* [  151] OBJ_pkcs7_digest *)
    $2A,$86,$48,$86,$F7,$0D,$01,$07,$06,  (* [  160] OBJ_pkcs7_encrypted *)
    $2A,$86,$48,$86,$F7,$0D,$01,$03,       (* [  169] OBJ_pkcs3 *)
    $2A,$86,$48,$86,$F7,$0D,$01,$03,$01,  (* [  177] OBJ_dhKeyAgreement *)
    $2B,$0E,$03,$02,$06,                      (* [  186] OBJ_des_ecb *)
    $2B,$0E,$03,$02,$09,                      (* [  191] OBJ_des_cfb64 *)
    $2B,$0E,$03,$02,$07,                      (* [  196] OBJ_des_cbc *)
    $2B,$0E,$03,$02,$11,                      (* [  201] OBJ_des_ede_ecb *)
    $2B,$06,$01,$04,$01,$81,$3C,$07,$01,$01,$02,  (* [  206] OBJ_idea_cbc *)
    $2A,$86,$48,$86,$F7,$0D,$03,$02,       (* [  217] OBJ_rc2_cbc *)
    $2B,$0E,$03,$02,$12,                      (* [  225] OBJ_sha *)
    $2B,$0E,$03,$02,$0F,                      (* [  230] OBJ_shaWithRSAEncryption *)
    $2A,$86,$48,$86,$F7,$0D,$03,$07,       (* [  235] OBJ_des_ede3_cbc *)
    $2B,$0E,$03,$02,$08,                      (* [  243] OBJ_des_ofb64 *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,       (* [  248] OBJ_pkcs9 *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$01,  (* [  256] OBJ_pkcs9_emailAddress *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$02,  (* [  265] OBJ_pkcs9_unstructuredName *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$03,  (* [  274] OBJ_pkcs9_contentType *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$04,  (* [  283] OBJ_pkcs9_messageDigest *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$05,  (* [  292] OBJ_pkcs9_signingTime *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$06,  (* [  301] OBJ_pkcs9_countersignature *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$07,  (* [  310] OBJ_pkcs9_challengePassword *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$08,  (* [  319] OBJ_pkcs9_unstructuredAddress *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$09,  (* [  328] OBJ_pkcs9_extCertAttributes *)
    $60,$86,$48,$01,$86,$F8,$42,            (* [  337] OBJ_netscape *)
    $60,$86,$48,$01,$86,$F8,$42,$01,       (* [  344] OBJ_netscape_cert_extension *)
    $60,$86,$48,$01,$86,$F8,$42,$02,       (* [  352] OBJ_netscape_data_type *)
    $2B,$0E,$03,$02,$1A,                      (* [  360] OBJ_sha1 *)
    $2A,$86,$48,$86,$F7,$0D,$01,$01,$05,  (* [  365] OBJ_sha1WithRSAEncryption *)
    $2B,$0E,$03,$02,$0D,                      (* [  374] OBJ_dsaWithSHA *)
    $2B,$0E,$03,$02,$0C,                      (* [  379] OBJ_dsa_2 *)
    $2A,$86,$48,$86,$F7,$0D,$01,$05,$0B,  (* [  384] OBJ_pbeWithSHA1AndRC2_CBC *)
    $2A,$86,$48,$86,$F7,$0D,$01,$05,$0C,  (* [  393] OBJ_id_pbkdf2 *)
    $2B,$0E,$03,$02,$1B,                      (* [  402] OBJ_dsaWithSHA1_2 *)
    $60,$86,$48,$01,$86,$F8,$42,$01,$01,  (* [  407] OBJ_netscape_cert_type *)
    $60,$86,$48,$01,$86,$F8,$42,$01,$02,  (* [  416] OBJ_netscape_base_url *)
    $60,$86,$48,$01,$86,$F8,$42,$01,$03,  (* [  425] OBJ_netscape_revocation_url *)
    $60,$86,$48,$01,$86,$F8,$42,$01,$04,  (* [  434] OBJ_netscape_ca_revocation_url *)
    $60,$86,$48,$01,$86,$F8,$42,$01,$07,  (* [  443] OBJ_netscape_renewal_url *)
    $60,$86,$48,$01,$86,$F8,$42,$01,$08,  (* [  452] OBJ_netscape_ca_policy_url *)
    $60,$86,$48,$01,$86,$F8,$42,$01,$0C,  (* [  461] OBJ_netscape_ssl_server_name *)
    $60,$86,$48,$01,$86,$F8,$42,$01,$0D,  (* [  470] OBJ_netscape_comment *)
    $60,$86,$48,$01,$86,$F8,$42,$02,$05,  (* [  479] OBJ_netscape_cert_sequence *)
    $55,$1D,                                     (* [  488] OBJ_id_ce *)
    $55,$1D,$0E,                                (* [  490] OBJ_subject_key_identifier *)
    $55,$1D,$0F,                                (* [  493] OBJ_key_usage *)
    $55,$1D,$10,                                (* [  496] OBJ_private_key_usage_period *)
    $55,$1D,$11,                                (* [  499] OBJ_subject_alt_name *)
    $55,$1D,$12,                                (* [  502] OBJ_issuer_alt_name *)
    $55,$1D,$13,                                (* [  505] OBJ_basic_constraints *)
    $55,$1D,$14,                                (* [  508] OBJ_crl_number *)
    $55,$1D,$20,                                (* [  511] OBJ_certificate_policies *)
    $55,$1D,$23,                                (* [  514] OBJ_authority_key_identifier *)
    $2B,$06,$01,$04,$01,$97,$55,$01,$02,  (* [  517] OBJ_bf_cbc *)
    $55,$08,$03,$65,                           (* [  526] OBJ_mdc2 *)
    $55,$08,$03,$64,                           (* [  530] OBJ_mdc2WithRSA *)
    $55,$04,$2A,                                (* [  534] OBJ_givenName *)
    $55,$04,$04,                                (* [  537] OBJ_surname *)
    $55,$04,$2B,                                (* [  540] OBJ_initials *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$01,$2C,  (* [  543] OBJ_uniqueIdentifier *)
    $55,$1D,$1F,                                (* [  553] OBJ_crl_distribution_points *)
    $2B,$0E,$03,$02,$03,                      (* [  556] OBJ_md5WithRSA *)
    $55,$04,$05,                                (* [  561] OBJ_serialNumber *)
    $55,$04,$0C,                                (* [  564] OBJ_title *)
    $55,$04,$0D,                                (* [  567] OBJ_description *)
    $2A,$86,$48,$86,$F6,$7D,$07,$42,$0A,  (* [  570] OBJ_cast5_cbc *)
    $2A,$86,$48,$86,$F6,$7D,$07,$42,$0C,  (* [  579] OBJ_pbeWithMD5AndCast5_CBC *)
    $2A,$86,$48,$CE,$38,$04,$03,            (* [  588] OBJ_dsaWithSHA1 *)
    $2B,$0E,$03,$02,$1D,                      (* [  595] OBJ_sha1WithRSA *)
    $2A,$86,$48,$CE,$38,$04,$01,            (* [  600] OBJ_dsa *)
    $2B,$24,$03,$02,$01,                      (* [  607] OBJ_ripemd160 *)
    $2B,$24,$03,$03,$01,$02,                 (* [  612] OBJ_ripemd160WithRSA *)
    $2A,$86,$48,$86,$F7,$0D,$03,$08,       (* [  618] OBJ_rc5_cbc *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$03,$08,  (* [  626] OBJ_zlib_compression *)
    $55,$1D,$25,                                (* [  637] OBJ_ext_key_usage *)
    $2B,$06,$01,$05,$05,$07,                 (* [  640] OBJ_id_pkix *)
    $2B,$06,$01,$05,$05,$07,$03,            (* [  646] OBJ_id_kp *)
    $2B,$06,$01,$05,$05,$07,$03,$01,       (* [  653] OBJ_server_auth *)
    $2B,$06,$01,$05,$05,$07,$03,$02,       (* [  661] OBJ_client_auth *)
    $2B,$06,$01,$05,$05,$07,$03,$03,       (* [  669] OBJ_code_sign *)
    $2B,$06,$01,$05,$05,$07,$03,$04,       (* [  677] OBJ_email_protect *)
    $2B,$06,$01,$05,$05,$07,$03,$08,       (* [  685] OBJ_time_stamp *)
    $2B,$06,$01,$04,$01,$82,$37,$02,$01,$15,  (* [  693] OBJ_ms_code_ind *)
    $2B,$06,$01,$04,$01,$82,$37,$02,$01,$16,  (* [  703] OBJ_ms_code_com *)
    $2B,$06,$01,$04,$01,$82,$37,$0A,$03,$01,  (* [  713] OBJ_ms_ctl_sign *)
    $2B,$06,$01,$04,$01,$82,$37,$0A,$03,$03,  (* [  723] OBJ_ms_sgc *)
    $2B,$06,$01,$04,$01,$82,$37,$0A,$03,$04,  (* [  733] OBJ_ms_efs *)
    $60,$86,$48,$01,$86,$F8,$42,$04,$01,  (* [  743] OBJ_ns_sgc *)
    $55,$1D,$1B,                                (* [  752] OBJ_delta_crl *)
    $55,$1D,$15,                                (* [  755] OBJ_crl_reason *)
    $55,$1D,$18,                                (* [  758] OBJ_invalidity_date *)
    $2B,$65,$01,$04,$01,                      (* [  761] OBJ_sxnet *)
    $2A,$86,$48,$86,$F7,$0D,$01,$0C,$01,$01,  (* [  766] OBJ_pbe_WithSHA1And128BitRC4 *)
    $2A,$86,$48,$86,$F7,$0D,$01,$0C,$01,$02,  (* [  776] OBJ_pbe_WithSHA1And40BitRC4 *)
    $2A,$86,$48,$86,$F7,$0D,$01,$0C,$01,$03,  (* [  786] OBJ_pbe_WithSHA1And3_Key_TripleDES_CBC *)
    $2A,$86,$48,$86,$F7,$0D,$01,$0C,$01,$04,  (* [  796] OBJ_pbe_WithSHA1And2_Key_TripleDES_CBC *)
    $2A,$86,$48,$86,$F7,$0D,$01,$0C,$01,$05,  (* [  806] OBJ_pbe_WithSHA1And128BitRC2_CBC *)
    $2A,$86,$48,$86,$F7,$0D,$01,$0C,$01,$06,  (* [  816] OBJ_pbe_WithSHA1And40BitRC2_CBC *)
    $2A,$86,$48,$86,$F7,$0D,$01,$0C,$0A,$01,$01,  (* [  826] OBJ_keyBag *)
    $2A,$86,$48,$86,$F7,$0D,$01,$0C,$0A,$01,$02,  (* [  837] OBJ_pkcs8ShroudedKeyBag *)
    $2A,$86,$48,$86,$F7,$0D,$01,$0C,$0A,$01,$03,  (* [  848] OBJ_certBag *)
    $2A,$86,$48,$86,$F7,$0D,$01,$0C,$0A,$01,$04,  (* [  859] OBJ_crlBag *)
    $2A,$86,$48,$86,$F7,$0D,$01,$0C,$0A,$01,$05,  (* [  870] OBJ_secretBag *)
    $2A,$86,$48,$86,$F7,$0D,$01,$0C,$0A,$01,$06,  (* [  881] OBJ_safeContentsBag *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$14,  (* [  892] OBJ_friendlyName *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$15,  (* [  901] OBJ_localKeyID *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$16,$01,  (* [  910] OBJ_x509Certificate *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$16,$02,  (* [  920] OBJ_sdsiCertificate *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$17,$01,  (* [  930] OBJ_x509Crl *)
    $2A,$86,$48,$86,$F7,$0D,$01,$05,$0D,  (* [  940] OBJ_pbes2 *)
    $2A,$86,$48,$86,$F7,$0D,$01,$05,$0E,  (* [  949] OBJ_pbmac1 *)
    $2A,$86,$48,$86,$F7,$0D,$02,$07,       (* [  958] OBJ_hmacWithSHA1 *)
    $2B,$06,$01,$05,$05,$07,$02,$01,       (* [  966] OBJ_id_qt_cps *)
    $2B,$06,$01,$05,$05,$07,$02,$02,       (* [  974] OBJ_id_qt_unotice *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$0F,  (* [  982] OBJ_SMIMECapabilities *)
    $2A,$86,$48,$86,$F7,$0D,$01,$05,$04,  (* [  991] OBJ_pbeWithMD2AndRC2_CBC *)
    $2A,$86,$48,$86,$F7,$0D,$01,$05,$06,  (* [ 1000] OBJ_pbeWithMD5AndRC2_CBC *)
    $2A,$86,$48,$86,$F7,$0D,$01,$05,$0A,  (* [ 1009] OBJ_pbeWithSHA1AndDES_CBC *)
    $2B,$06,$01,$04,$01,$82,$37,$02,$01,$0E,  (* [ 1018] OBJ_ms_ext_req *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$0E,  (* [ 1028] OBJ_ext_req *)
    $55,$04,$29,                                (* [ 1037] OBJ_name *)
    $55,$04,$2E,                                (* [ 1040] OBJ_dnQualifier *)
    $2B,$06,$01,$05,$05,$07,$01,            (* [ 1043] OBJ_id_pe *)
    $2B,$06,$01,$05,$05,$07,$30,            (* [ 1050] OBJ_id_ad *)
    $2B,$06,$01,$05,$05,$07,$01,$01,       (* [ 1057] OBJ_info_access *)
    $2B,$06,$01,$05,$05,$07,$30,$01,       (* [ 1065] OBJ_ad_OCSP *)
    $2B,$06,$01,$05,$05,$07,$30,$02,       (* [ 1073] OBJ_ad_ca_issuers *)
    $2B,$06,$01,$05,$05,$07,$03,$09,       (* [ 1081] OBJ_OCSP_sign *)
    $2A,                                          (* [ 1089] OBJ_member_body *)
    $2A,$86,$48,                                (* [ 1090] OBJ_ISO_US *)
    $2A,$86,$48,$CE,$38,                      (* [ 1093] OBJ_X9_57 *)
    $2A,$86,$48,$CE,$38,$04,                 (* [ 1098] OBJ_X9cm *)
    $2A,$86,$48,$86,$F7,$0D,$01,$01,       (* [ 1104] OBJ_pkcs1 *)
    $2A,$86,$48,$86,$F7,$0D,$01,$05,       (* [ 1112] OBJ_pkcs5 *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,  (* [ 1120] OBJ_SMIME *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$00,  (* [ 1129] OBJ_id_smime_mod *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$01,  (* [ 1139] OBJ_id_smime_ct *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$02,  (* [ 1149] OBJ_id_smime_aa *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$03,  (* [ 1159] OBJ_id_smime_alg *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$04,  (* [ 1169] OBJ_id_smime_cd *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$05,  (* [ 1179] OBJ_id_smime_spq *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$06,  (* [ 1189] OBJ_id_smime_cti *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$00,$01,  (* [ 1199] OBJ_id_smime_mod_cms *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$00,$02,  (* [ 1210] OBJ_id_smime_mod_ess *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$00,$03,  (* [ 1221] OBJ_id_smime_mod_oid *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$00,$04,  (* [ 1232] OBJ_id_smime_mod_msg_v3 *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$00,$05,  (* [ 1243] OBJ_id_smime_mod_ets_eSignature_88 *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$00,$06,  (* [ 1254] OBJ_id_smime_mod_ets_eSignature_97 *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$00,$07,  (* [ 1265] OBJ_id_smime_mod_ets_eSigPolicy_88 *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$00,$08,  (* [ 1276] OBJ_id_smime_mod_ets_eSigPolicy_97 *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$01,$01,  (* [ 1287] OBJ_id_smime_ct_receipt *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$01,$02,  (* [ 1298] OBJ_id_smime_ct_authData *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$01,$03,  (* [ 1309] OBJ_id_smime_ct_publishCert *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$01,$04,  (* [ 1320] OBJ_id_smime_ct_TSTInfo *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$01,$05,  (* [ 1331] OBJ_id_smime_ct_TDTInfo *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$01,$06,  (* [ 1342] OBJ_id_smime_ct_contentInfo *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$01,$07,  (* [ 1353] OBJ_id_smime_ct_DVCSRequestData *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$01,$08,  (* [ 1364] OBJ_id_smime_ct_DVCSResponseData *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$02,$01,  (* [ 1375] OBJ_id_smime_aa_receiptRequest *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$02,$02,  (* [ 1386] OBJ_id_smime_aa_securityLabel *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$02,$03,  (* [ 1397] OBJ_id_smime_aa_mlExpandHistory *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$02,$04,  (* [ 1408] OBJ_id_smime_aa_contentHint *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$02,$05,  (* [ 1419] OBJ_id_smime_aa_msgSigDigest *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$02,$06,  (* [ 1430] OBJ_id_smime_aa_encapContentType *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$02,$07,  (* [ 1441] OBJ_id_smime_aa_contentIdentifier *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$02,$08,  (* [ 1452] OBJ_id_smime_aa_macValue *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$02,$09,  (* [ 1463] OBJ_id_smime_aa_equivalentLabels *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$02,$0A,  (* [ 1474] OBJ_id_smime_aa_contentReference *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$02,$0B,  (* [ 1485] OBJ_id_smime_aa_encrypKeyPref *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$02,$0C,  (* [ 1496] OBJ_id_smime_aa_signingCertificate *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$02,$0D,  (* [ 1507] OBJ_id_smime_aa_smimeEncryptCerts *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$02,$0E,  (* [ 1518] OBJ_id_smime_aa_timeStampToken *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$02,$0F,  (* [ 1529] OBJ_id_smime_aa_ets_sigPolicyId *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$02,$10,  (* [ 1540] OBJ_id_smime_aa_ets_commitmentType *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$02,$11,  (* [ 1551] OBJ_id_smime_aa_ets_signerLocation *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$02,$12,  (* [ 1562] OBJ_id_smime_aa_ets_signerAttr *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$02,$13,  (* [ 1573] OBJ_id_smime_aa_ets_otherSigCert *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$02,$14,  (* [ 1584] OBJ_id_smime_aa_ets_contentTimestamp *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$02,$15,  (* [ 1595] OBJ_id_smime_aa_ets_CertificateRefs *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$02,$16,  (* [ 1606] OBJ_id_smime_aa_ets_RevocationRefs *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$02,$17,  (* [ 1617] OBJ_id_smime_aa_ets_certValues *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$02,$18,  (* [ 1628] OBJ_id_smime_aa_ets_revocationValues *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$02,$19,  (* [ 1639] OBJ_id_smime_aa_ets_escTimeStamp *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$02,$1A,  (* [ 1650] OBJ_id_smime_aa_ets_certCRLTimestamp *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$02,$1B,  (* [ 1661] OBJ_id_smime_aa_ets_archiveTimeStamp *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$02,$1C,  (* [ 1672] OBJ_id_smime_aa_signatureType *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$02,$1D,  (* [ 1683] OBJ_id_smime_aa_dvcs_dvc *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$03,$01,  (* [ 1694] OBJ_id_smime_alg_ESDHwith3DES *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$03,$02,  (* [ 1705] OBJ_id_smime_alg_ESDHwithRC2 *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$03,$03,  (* [ 1716] OBJ_id_smime_alg_3DESwrap *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$03,$04,  (* [ 1727] OBJ_id_smime_alg_RC2wrap *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$03,$05,  (* [ 1738] OBJ_id_smime_alg_ESDH *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$03,$06,  (* [ 1749] OBJ_id_smime_alg_CMS3DESwrap *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$03,$07,  (* [ 1760] OBJ_id_smime_alg_CMSRC2wrap *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$04,$01,  (* [ 1771] OBJ_id_smime_cd_ldap *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$05,$01,  (* [ 1782] OBJ_id_smime_spq_ets_sqt_uri *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$05,$02,  (* [ 1793] OBJ_id_smime_spq_ets_sqt_unotice *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$06,$01,  (* [ 1804] OBJ_id_smime_cti_ets_proofOfOrigin *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$06,$02,  (* [ 1815] OBJ_id_smime_cti_ets_proofOfReceipt *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$06,$03,  (* [ 1826] OBJ_id_smime_cti_ets_proofOfDelivery *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$06,$04,  (* [ 1837] OBJ_id_smime_cti_ets_proofOfSender *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$06,$05,  (* [ 1848] OBJ_id_smime_cti_ets_proofOfApproval *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$06,$06,  (* [ 1859] OBJ_id_smime_cti_ets_proofOfCreation *)
    $2A,$86,$48,$86,$F7,$0D,$02,$04,       (* [ 1870] OBJ_md4 *)
    $2B,$06,$01,$05,$05,$07,$00,            (* [ 1878] OBJ_id_pkix_mod *)
    $2B,$06,$01,$05,$05,$07,$02,            (* [ 1885] OBJ_id_qt *)
    $2B,$06,$01,$05,$05,$07,$04,            (* [ 1892] OBJ_id_it *)
    $2B,$06,$01,$05,$05,$07,$05,            (* [ 1899] OBJ_id_pkip *)
    $2B,$06,$01,$05,$05,$07,$06,            (* [ 1906] OBJ_id_alg *)
    $2B,$06,$01,$05,$05,$07,$07,            (* [ 1913] OBJ_id_cmc *)
    $2B,$06,$01,$05,$05,$07,$08,            (* [ 1920] OBJ_id_on *)
    $2B,$06,$01,$05,$05,$07,$09,            (* [ 1927] OBJ_id_pda *)
    $2B,$06,$01,$05,$05,$07,$0A,            (* [ 1934] OBJ_id_aca *)
    $2B,$06,$01,$05,$05,$07,$0B,            (* [ 1941] OBJ_id_qcs *)
    $2B,$06,$01,$05,$05,$07,$0C,            (* [ 1948] OBJ_id_cct *)
    $2B,$06,$01,$05,$05,$07,$00,$01,       (* [ 1955] OBJ_id_pkix1_explicit_88 *)
    $2B,$06,$01,$05,$05,$07,$00,$02,       (* [ 1963] OBJ_id_pkix1_implicit_88 *)
    $2B,$06,$01,$05,$05,$07,$00,$03,       (* [ 1971] OBJ_id_pkix1_explicit_93 *)
    $2B,$06,$01,$05,$05,$07,$00,$04,       (* [ 1979] OBJ_id_pkix1_implicit_93 *)
    $2B,$06,$01,$05,$05,$07,$00,$05,       (* [ 1987] OBJ_id_mod_crmf *)
    $2B,$06,$01,$05,$05,$07,$00,$06,       (* [ 1995] OBJ_id_mod_cmc *)
    $2B,$06,$01,$05,$05,$07,$00,$07,       (* [ 2003] OBJ_id_mod_kea_profile_88 *)
    $2B,$06,$01,$05,$05,$07,$00,$08,       (* [ 2011] OBJ_id_mod_kea_profile_93 *)
    $2B,$06,$01,$05,$05,$07,$00,$09,       (* [ 2019] OBJ_id_mod_cmp *)
    $2B,$06,$01,$05,$05,$07,$00,$0A,       (* [ 2027] OBJ_id_mod_qualified_cert_88 *)
    $2B,$06,$01,$05,$05,$07,$00,$0B,       (* [ 2035] OBJ_id_mod_qualified_cert_93 *)
    $2B,$06,$01,$05,$05,$07,$00,$0C,       (* [ 2043] OBJ_id_mod_attribute_cert *)
    $2B,$06,$01,$05,$05,$07,$00,$0D,       (* [ 2051] OBJ_id_mod_timestamp_protocol *)
    $2B,$06,$01,$05,$05,$07,$00,$0E,       (* [ 2059] OBJ_id_mod_ocsp *)
    $2B,$06,$01,$05,$05,$07,$00,$0F,       (* [ 2067] OBJ_id_mod_dvcs *)
    $2B,$06,$01,$05,$05,$07,$00,$10,       (* [ 2075] OBJ_id_mod_cmp2000 *)
    $2B,$06,$01,$05,$05,$07,$01,$02,       (* [ 2083] OBJ_biometricInfo *)
    $2B,$06,$01,$05,$05,$07,$01,$03,       (* [ 2091] OBJ_qcStatements *)
    $2B,$06,$01,$05,$05,$07,$01,$04,       (* [ 2099] OBJ_ac_auditEntity *)
    $2B,$06,$01,$05,$05,$07,$01,$05,       (* [ 2107] OBJ_ac_targeting *)
    $2B,$06,$01,$05,$05,$07,$01,$06,       (* [ 2115] OBJ_aaControls *)
    $2B,$06,$01,$05,$05,$07,$01,$07,       (* [ 2123] OBJ_sbgp_ipAddrBlock *)
    $2B,$06,$01,$05,$05,$07,$01,$08,       (* [ 2131] OBJ_sbgp_autonomousSysNum *)
    $2B,$06,$01,$05,$05,$07,$01,$09,       (* [ 2139] OBJ_sbgp_routerIdentifier *)
    $2B,$06,$01,$05,$05,$07,$02,$03,       (* [ 2147] OBJ_textNotice *)
    $2B,$06,$01,$05,$05,$07,$03,$05,       (* [ 2155] OBJ_ipsecEndSystem *)
    $2B,$06,$01,$05,$05,$07,$03,$06,       (* [ 2163] OBJ_ipsecTunnel *)
    $2B,$06,$01,$05,$05,$07,$03,$07,       (* [ 2171] OBJ_ipsecUser *)
    $2B,$06,$01,$05,$05,$07,$03,$0A,       (* [ 2179] OBJ_dvcs *)
    $2B,$06,$01,$05,$05,$07,$04,$01,       (* [ 2187] OBJ_id_it_caProtEncCert *)
    $2B,$06,$01,$05,$05,$07,$04,$02,       (* [ 2195] OBJ_id_it_signKeyPairTypes *)
    $2B,$06,$01,$05,$05,$07,$04,$03,       (* [ 2203] OBJ_id_it_encKeyPairTypes *)
    $2B,$06,$01,$05,$05,$07,$04,$04,       (* [ 2211] OBJ_id_it_preferredSymmAlg *)
    $2B,$06,$01,$05,$05,$07,$04,$05,       (* [ 2219] OBJ_id_it_caKeyUpdateInfo *)
    $2B,$06,$01,$05,$05,$07,$04,$06,       (* [ 2227] OBJ_id_it_currentCRL *)
    $2B,$06,$01,$05,$05,$07,$04,$07,       (* [ 2235] OBJ_id_it_unsupportedOIDs *)
    $2B,$06,$01,$05,$05,$07,$04,$08,       (* [ 2243] OBJ_id_it_subscriptionRequest *)
    $2B,$06,$01,$05,$05,$07,$04,$09,       (* [ 2251] OBJ_id_it_subscriptionResponse *)
    $2B,$06,$01,$05,$05,$07,$04,$0A,       (* [ 2259] OBJ_id_it_keyPairParamReq *)
    $2B,$06,$01,$05,$05,$07,$04,$0B,       (* [ 2267] OBJ_id_it_keyPairParamRep *)
    $2B,$06,$01,$05,$05,$07,$04,$0C,       (* [ 2275] OBJ_id_it_revPassphrase *)
    $2B,$06,$01,$05,$05,$07,$04,$0D,       (* [ 2283] OBJ_id_it_implicitConfirm *)
    $2B,$06,$01,$05,$05,$07,$04,$0E,       (* [ 2291] OBJ_id_it_confirmWaitTime *)
    $2B,$06,$01,$05,$05,$07,$04,$0F,       (* [ 2299] OBJ_id_it_origPKIMessage *)
    $2B,$06,$01,$05,$05,$07,$05,$01,       (* [ 2307] OBJ_id_regCtrl *)
    $2B,$06,$01,$05,$05,$07,$05,$02,       (* [ 2315] OBJ_id_regInfo *)
    $2B,$06,$01,$05,$05,$07,$05,$01,$01,  (* [ 2323] OBJ_id_regCtrl_regToken *)
    $2B,$06,$01,$05,$05,$07,$05,$01,$02,  (* [ 2332] OBJ_id_regCtrl_authenticator *)
    $2B,$06,$01,$05,$05,$07,$05,$01,$03,  (* [ 2341] OBJ_id_regCtrl_pkiPublicationInfo *)
    $2B,$06,$01,$05,$05,$07,$05,$01,$04,  (* [ 2350] OBJ_id_regCtrl_pkiArchiveOptions *)
    $2B,$06,$01,$05,$05,$07,$05,$01,$05,  (* [ 2359] OBJ_id_regCtrl_oldCertID *)
    $2B,$06,$01,$05,$05,$07,$05,$01,$06,  (* [ 2368] OBJ_id_regCtrl_protocolEncrKey *)
    $2B,$06,$01,$05,$05,$07,$05,$02,$01,  (* [ 2377] OBJ_id_regInfo_utf8Pairs *)
    $2B,$06,$01,$05,$05,$07,$05,$02,$02,  (* [ 2386] OBJ_id_regInfo_certReq *)
    $2B,$06,$01,$05,$05,$07,$06,$01,       (* [ 2395] OBJ_id_alg_des40 *)
    $2B,$06,$01,$05,$05,$07,$06,$02,       (* [ 2403] OBJ_id_alg_noSignature *)
    $2B,$06,$01,$05,$05,$07,$06,$03,       (* [ 2411] OBJ_id_alg_dh_sig_hmac_sha1 *)
    $2B,$06,$01,$05,$05,$07,$06,$04,       (* [ 2419] OBJ_id_alg_dh_pop *)
    $2B,$06,$01,$05,$05,$07,$07,$01,       (* [ 2427] OBJ_id_cmc_statusInfo *)
    $2B,$06,$01,$05,$05,$07,$07,$02,       (* [ 2435] OBJ_id_cmc_identification *)
    $2B,$06,$01,$05,$05,$07,$07,$03,       (* [ 2443] OBJ_id_cmc_identityProof *)
    $2B,$06,$01,$05,$05,$07,$07,$04,       (* [ 2451] OBJ_id_cmc_dataReturn *)
    $2B,$06,$01,$05,$05,$07,$07,$05,       (* [ 2459] OBJ_id_cmc_transactionId *)
    $2B,$06,$01,$05,$05,$07,$07,$06,       (* [ 2467] OBJ_id_cmc_senderNonce *)
    $2B,$06,$01,$05,$05,$07,$07,$07,       (* [ 2475] OBJ_id_cmc_recipientNonce *)
    $2B,$06,$01,$05,$05,$07,$07,$08,       (* [ 2483] OBJ_id_cmc_addExtensions *)
    $2B,$06,$01,$05,$05,$07,$07,$09,       (* [ 2491] OBJ_id_cmc_encryptedPOP *)
    $2B,$06,$01,$05,$05,$07,$07,$0A,       (* [ 2499] OBJ_id_cmc_decryptedPOP *)
    $2B,$06,$01,$05,$05,$07,$07,$0B,       (* [ 2507] OBJ_id_cmc_lraPOPWitness *)
    $2B,$06,$01,$05,$05,$07,$07,$0F,       (* [ 2515] OBJ_id_cmc_getCert *)
    $2B,$06,$01,$05,$05,$07,$07,$10,       (* [ 2523] OBJ_id_cmc_getCRL *)
    $2B,$06,$01,$05,$05,$07,$07,$11,       (* [ 2531] OBJ_id_cmc_revokeRequest *)
    $2B,$06,$01,$05,$05,$07,$07,$12,       (* [ 2539] OBJ_id_cmc_regInfo *)
    $2B,$06,$01,$05,$05,$07,$07,$13,       (* [ 2547] OBJ_id_cmc_responseInfo *)
    $2B,$06,$01,$05,$05,$07,$07,$15,       (* [ 2555] OBJ_id_cmc_queryPending *)
    $2B,$06,$01,$05,$05,$07,$07,$16,       (* [ 2563] OBJ_id_cmc_popLinkRandom *)
    $2B,$06,$01,$05,$05,$07,$07,$17,       (* [ 2571] OBJ_id_cmc_popLinkWitness *)
    $2B,$06,$01,$05,$05,$07,$07,$18,       (* [ 2579] OBJ_id_cmc_confirmCertAcceptance *)
    $2B,$06,$01,$05,$05,$07,$08,$01,       (* [ 2587] OBJ_id_on_personalData *)
    $2B,$06,$01,$05,$05,$07,$09,$01,       (* [ 2595] OBJ_id_pda_dateOfBirth *)
    $2B,$06,$01,$05,$05,$07,$09,$02,       (* [ 2603] OBJ_id_pda_placeOfBirth *)
    $2B,$06,$01,$05,$05,$07,$09,$03,       (* [ 2611] OBJ_id_pda_gender *)
    $2B,$06,$01,$05,$05,$07,$09,$04,       (* [ 2619] OBJ_id_pda_countryOfCitizenship *)
    $2B,$06,$01,$05,$05,$07,$09,$05,       (* [ 2627] OBJ_id_pda_countryOfResidence *)
    $2B,$06,$01,$05,$05,$07,$0A,$01,       (* [ 2635] OBJ_id_aca_authenticationInfo *)
    $2B,$06,$01,$05,$05,$07,$0A,$02,       (* [ 2643] OBJ_id_aca_accessIdentity *)
    $2B,$06,$01,$05,$05,$07,$0A,$03,       (* [ 2651] OBJ_id_aca_chargingIdentity *)
    $2B,$06,$01,$05,$05,$07,$0A,$04,       (* [ 2659] OBJ_id_aca_group *)
    $2B,$06,$01,$05,$05,$07,$0A,$05,       (* [ 2667] OBJ_id_aca_role *)
    $2B,$06,$01,$05,$05,$07,$0B,$01,       (* [ 2675] OBJ_id_qcs_pkixQCSyntax_v1 *)
    $2B,$06,$01,$05,$05,$07,$0C,$01,       (* [ 2683] OBJ_id_cct_crs *)
    $2B,$06,$01,$05,$05,$07,$0C,$02,       (* [ 2691] OBJ_id_cct_PKIData *)
    $2B,$06,$01,$05,$05,$07,$0C,$03,       (* [ 2699] OBJ_id_cct_PKIResponse *)
    $2B,$06,$01,$05,$05,$07,$30,$03,       (* [ 2707] OBJ_ad_timeStamping *)
    $2B,$06,$01,$05,$05,$07,$30,$04,       (* [ 2715] OBJ_ad_dvcs *)
    $2B,$06,$01,$05,$05,$07,$30,$01,$01,  (* [ 2723] OBJ_id_pkix_OCSP_basic *)
    $2B,$06,$01,$05,$05,$07,$30,$01,$02,  (* [ 2732] OBJ_id_pkix_OCSP_Nonce *)
    $2B,$06,$01,$05,$05,$07,$30,$01,$03,  (* [ 2741] OBJ_id_pkix_OCSP_CrlID *)
    $2B,$06,$01,$05,$05,$07,$30,$01,$04,  (* [ 2750] OBJ_id_pkix_OCSP_acceptableResponses *)
    $2B,$06,$01,$05,$05,$07,$30,$01,$05,  (* [ 2759] OBJ_id_pkix_OCSP_noCheck *)
    $2B,$06,$01,$05,$05,$07,$30,$01,$06,  (* [ 2768] OBJ_id_pkix_OCSP_archiveCutoff *)
    $2B,$06,$01,$05,$05,$07,$30,$01,$07,  (* [ 2777] OBJ_id_pkix_OCSP_serviceLocator *)
    $2B,$06,$01,$05,$05,$07,$30,$01,$08,  (* [ 2786] OBJ_id_pkix_OCSP_extendedStatus *)
    $2B,$06,$01,$05,$05,$07,$30,$01,$09,  (* [ 2795] OBJ_id_pkix_OCSP_valid *)
    $2B,$06,$01,$05,$05,$07,$30,$01,$0A,  (* [ 2804] OBJ_id_pkix_OCSP_path *)
    $2B,$06,$01,$05,$05,$07,$30,$01,$0B,  (* [ 2813] OBJ_id_pkix_OCSP_trustRoot *)
    $2B,$0E,$03,$02,                           (* [ 2822] OBJ_algorithm *)
    $2B,$0E,$03,$02,$0B,                      (* [ 2826] OBJ_rsaSignature *)
    $55,$08,                                     (* [ 2831] OBJ_X500algorithms *)
    $2B,                                          (* [ 2833] OBJ_org *)
    $2B,$06,                                     (* [ 2834] OBJ_dod *)
    $2B,$06,$01,                                (* [ 2836] OBJ_iana *)
    $2B,$06,$01,$01,                           (* [ 2839] OBJ_Directory *)
    $2B,$06,$01,$02,                           (* [ 2843] OBJ_Management *)
    $2B,$06,$01,$03,                           (* [ 2847] OBJ_Experimental *)
    $2B,$06,$01,$04,                           (* [ 2851] OBJ_Private *)
    $2B,$06,$01,$05,                           (* [ 2855] OBJ_Security *)
    $2B,$06,$01,$06,                           (* [ 2859] OBJ_SNMPv2 *)
    $2B,$06,$01,$07,                           (* [ 2863] OBJ_Mail *)
    $2B,$06,$01,$04,$01,                      (* [ 2867] OBJ_Enterprises *)
    $2B,$06,$01,$04,$01,$8B,$3A,$82,$58,  (* [ 2872] OBJ_dcObject *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$01,$19,  (* [ 2881] OBJ_domainComponent *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$04,$0D,  (* [ 2891] OBJ_Domain *)
    $55,$01,$05,                                (* [ 2901] OBJ_selected_attribute_types *)
    $55,$01,$05,$37,                           (* [ 2904] OBJ_clearance *)
    $2A,$86,$48,$86,$F7,$0D,$01,$01,$03,  (* [ 2908] OBJ_md4WithRSAEncryption *)
    $2B,$06,$01,$05,$05,$07,$01,$0A,       (* [ 2917] OBJ_ac_proxying *)
    $2B,$06,$01,$05,$05,$07,$01,$0B,       (* [ 2925] OBJ_sinfo_access *)
    $2B,$06,$01,$05,$05,$07,$0A,$06,       (* [ 2933] OBJ_id_aca_encAttrs *)
    $55,$04,$48,                                (* [ 2941] OBJ_role *)
    $55,$1D,$24,                                (* [ 2944] OBJ_policy_constraints *)
    $55,$1D,$37,                                (* [ 2947] OBJ_target_information *)
    $55,$1D,$38,                                (* [ 2950] OBJ_no_rev_avail *)
    $2A,$86,$48,$CE,$3D,                      (* [ 2953] OBJ_ansi_X9_62 *)
    $2A,$86,$48,$CE,$3D,$01,$01,            (* [ 2958] OBJ_X9_62_prime_field *)
    $2A,$86,$48,$CE,$3D,$01,$02,            (* [ 2965] OBJ_X9_62_characteristic_two_field *)
    $2A,$86,$48,$CE,$3D,$02,$01,            (* [ 2972] OBJ_X9_62_id_ecPublicKey *)
    $2A,$86,$48,$CE,$3D,$03,$01,$01,       (* [ 2979] OBJ_X9_62_prime192v1 *)
    $2A,$86,$48,$CE,$3D,$03,$01,$02,       (* [ 2987] OBJ_X9_62_prime192v2 *)
    $2A,$86,$48,$CE,$3D,$03,$01,$03,       (* [ 2995] OBJ_X9_62_prime192v3 *)
    $2A,$86,$48,$CE,$3D,$03,$01,$04,       (* [ 3003] OBJ_X9_62_prime239v1 *)
    $2A,$86,$48,$CE,$3D,$03,$01,$05,       (* [ 3011] OBJ_X9_62_prime239v2 *)
    $2A,$86,$48,$CE,$3D,$03,$01,$06,       (* [ 3019] OBJ_X9_62_prime239v3 *)
    $2A,$86,$48,$CE,$3D,$03,$01,$07,       (* [ 3027] OBJ_X9_62_prime256v1 *)
    $2A,$86,$48,$CE,$3D,$04,$01,            (* [ 3035] OBJ_ecdsa_with_SHA1 *)
    $2B,$06,$01,$04,$01,$82,$37,$11,$01,  (* [ 3042] OBJ_ms_csp_name *)
    $60,$86,$48,$01,$65,$03,$04,$01,$01,  (* [ 3051] OBJ_aes_128_ecb *)
    $60,$86,$48,$01,$65,$03,$04,$01,$02,  (* [ 3060] OBJ_aes_128_cbc *)
    $60,$86,$48,$01,$65,$03,$04,$01,$03,  (* [ 3069] OBJ_aes_128_ofb128 *)
    $60,$86,$48,$01,$65,$03,$04,$01,$04,  (* [ 3078] OBJ_aes_128_cfb128 *)
    $60,$86,$48,$01,$65,$03,$04,$01,$15,  (* [ 3087] OBJ_aes_192_ecb *)
    $60,$86,$48,$01,$65,$03,$04,$01,$16,  (* [ 3096] OBJ_aes_192_cbc *)
    $60,$86,$48,$01,$65,$03,$04,$01,$17,  (* [ 3105] OBJ_aes_192_ofb128 *)
    $60,$86,$48,$01,$65,$03,$04,$01,$18,  (* [ 3114] OBJ_aes_192_cfb128 *)
    $60,$86,$48,$01,$65,$03,$04,$01,$29,  (* [ 3123] OBJ_aes_256_ecb *)
    $60,$86,$48,$01,$65,$03,$04,$01,$2A,  (* [ 3132] OBJ_aes_256_cbc *)
    $60,$86,$48,$01,$65,$03,$04,$01,$2B,  (* [ 3141] OBJ_aes_256_ofb128 *)
    $60,$86,$48,$01,$65,$03,$04,$01,$2C,  (* [ 3150] OBJ_aes_256_cfb128 *)
    $55,$1D,$17,                                (* [ 3159] OBJ_hold_instruction_code *)
    $2A,$86,$48,$CE,$38,$02,$01,            (* [ 3162] OBJ_hold_instruction_none *)
    $2A,$86,$48,$CE,$38,$02,$02,            (* [ 3169] OBJ_hold_instruction_call_issuer *)
    $2A,$86,$48,$CE,$38,$02,$03,            (* [ 3176] OBJ_hold_instruction_reject *)
    $09,                                          (* [ 3183] OBJ_data *)
    $09,$92,$26,                                (* [ 3184] OBJ_pss *)
    $09,$92,$26,$89,$93,$F2,$2C,            (* [ 3187] OBJ_ucl *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,       (* [ 3194] OBJ_pilot *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$01,  (* [ 3202] OBJ_pilotAttributeType *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$03,  (* [ 3211] OBJ_pilotAttributeSyntax *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$04,  (* [ 3220] OBJ_pilotObjectClass *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$0A,  (* [ 3229] OBJ_pilotGroups *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$03,$04,  (* [ 3238] OBJ_iA5StringSyntax *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$03,$05,  (* [ 3248] OBJ_caseIgnoreIA5StringSyntax *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$04,$03,  (* [ 3258] OBJ_pilotObject *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$04,$04,  (* [ 3268] OBJ_pilotPerson *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$04,$05,  (* [ 3278] OBJ_account *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$04,$06,  (* [ 3288] OBJ_document *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$04,$07,  (* [ 3298] OBJ_room *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$04,$09,  (* [ 3308] OBJ_documentSeries *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$04,$0E,  (* [ 3318] OBJ_rFC822localPart *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$04,$0F,  (* [ 3328] OBJ_dNSDomain *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$04,$11,  (* [ 3338] OBJ_domainRelatedObject *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$04,$12,  (* [ 3348] OBJ_friendlyCountry *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$04,$13,  (* [ 3358] OBJ_simpleSecurityObject *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$04,$14,  (* [ 3368] OBJ_pilotOrganization *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$04,$15,  (* [ 3378] OBJ_pilotDSA *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$04,$16,  (* [ 3388] OBJ_qualityLabelledData *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$01,$01,  (* [ 3398] OBJ_userId *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$01,$02,  (* [ 3408] OBJ_textEncodedORAddress *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$01,$03,  (* [ 3418] OBJ_rfc822Mailbox *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$01,$04,  (* [ 3428] OBJ_info *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$01,$05,  (* [ 3438] OBJ_favouriteDrink *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$01,$06,  (* [ 3448] OBJ_roomNumber *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$01,$07,  (* [ 3458] OBJ_photo *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$01,$08,  (* [ 3468] OBJ_userClass *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$01,$09,  (* [ 3478] OBJ_host *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$01,$0A,  (* [ 3488] OBJ_manager *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$01,$0B,  (* [ 3498] OBJ_documentIdentifier *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$01,$0C,  (* [ 3508] OBJ_documentTitle *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$01,$0D,  (* [ 3518] OBJ_documentVersion *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$01,$0E,  (* [ 3528] OBJ_documentAuthor *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$01,$0F,  (* [ 3538] OBJ_documentLocation *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$01,$14,  (* [ 3548] OBJ_homeTelephoneNumber *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$01,$15,  (* [ 3558] OBJ_secretary *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$01,$16,  (* [ 3568] OBJ_otherMailbox *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$01,$17,  (* [ 3578] OBJ_lastModifiedTime *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$01,$18,  (* [ 3588] OBJ_lastModifiedBy *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$01,$1A,  (* [ 3598] OBJ_aRecord *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$01,$1B,  (* [ 3608] OBJ_pilotAttributeType27 *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$01,$1C,  (* [ 3618] OBJ_mXRecord *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$01,$1D,  (* [ 3628] OBJ_nSRecord *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$01,$1E,  (* [ 3638] OBJ_sOARecord *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$01,$1F,  (* [ 3648] OBJ_cNAMERecord *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$01,$25,  (* [ 3658] OBJ_associatedDomain *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$01,$26,  (* [ 3668] OBJ_associatedName *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$01,$27,  (* [ 3678] OBJ_homePostalAddress *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$01,$28,  (* [ 3688] OBJ_personalTitle *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$01,$29,  (* [ 3698] OBJ_mobileTelephoneNumber *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$01,$2A,  (* [ 3708] OBJ_pagerTelephoneNumber *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$01,$2B,  (* [ 3718] OBJ_friendlyCountryName *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$01,$2D,  (* [ 3728] OBJ_organizationalStatus *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$01,$2E,  (* [ 3738] OBJ_janetMailbox *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$01,$2F,  (* [ 3748] OBJ_mailPreferenceOption *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$01,$30,  (* [ 3758] OBJ_buildingName *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$01,$31,  (* [ 3768] OBJ_dSAQuality *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$01,$32,  (* [ 3778] OBJ_singleLevelQuality *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$01,$33,  (* [ 3788] OBJ_subtreeMinimumQuality *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$01,$34,  (* [ 3798] OBJ_subtreeMaximumQuality *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$01,$35,  (* [ 3808] OBJ_personalSignature *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$01,$36,  (* [ 3818] OBJ_dITRedirect *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$01,$37,  (* [ 3828] OBJ_audio *)
    $09,$92,$26,$89,$93,$F2,$2C,$64,$01,$38,  (* [ 3838] OBJ_documentPublisher *)
    $55,$04,$2D,                                (* [ 3848] OBJ_x500UniqueIdentifier *)
    $2B,$06,$01,$07,$01,                      (* [ 3851] OBJ_mime_mhs *)
    $2B,$06,$01,$07,$01,$01,                 (* [ 3856] OBJ_mime_mhs_headings *)
    $2B,$06,$01,$07,$01,$02,                 (* [ 3862] OBJ_mime_mhs_bodies *)
    $2B,$06,$01,$07,$01,$01,$01,            (* [ 3868] OBJ_id_hex_partial_message *)
    $2B,$06,$01,$07,$01,$01,$02,            (* [ 3875] OBJ_id_hex_multipart_message *)
    $55,$04,$2C,                                (* [ 3882] OBJ_generationQualifier *)
    $55,$04,$41,                                (* [ 3885] OBJ_pseudonym *)
    $67,$2A,                                     (* [ 3888] OBJ_id_set *)
    $67,$2A,$00,                                (* [ 3890] OBJ_set_ctype *)
    $67,$2A,$01,                                (* [ 3893] OBJ_set_msgExt *)
    $67,$2A,$03,                                (* [ 3896] OBJ_set_attr *)
    $67,$2A,$05,                                (* [ 3899] OBJ_set_policy *)
    $67,$2A,$07,                                (* [ 3902] OBJ_set_certExt *)
    $67,$2A,$08,                                (* [ 3905] OBJ_set_brand *)
    $67,$2A,$00,$00,                           (* [ 3908] OBJ_setct_PANData *)
    $67,$2A,$00,$01,                           (* [ 3912] OBJ_setct_PANToken *)
    $67,$2A,$00,$02,                           (* [ 3916] OBJ_setct_PANOnly *)
    $67,$2A,$00,$03,                           (* [ 3920] OBJ_setct_OIData *)
    $67,$2A,$00,$04,                           (* [ 3924] OBJ_setct_PI *)
    $67,$2A,$00,$05,                           (* [ 3928] OBJ_setct_PIData *)
    $67,$2A,$00,$06,                           (* [ 3932] OBJ_setct_PIDataUnsigned *)
    $67,$2A,$00,$07,                           (* [ 3936] OBJ_setct_HODInput *)
    $67,$2A,$00,$08,                           (* [ 3940] OBJ_setct_AuthResBaggage *)
    $67,$2A,$00,$09,                           (* [ 3944] OBJ_setct_AuthRevReqBaggage *)
    $67,$2A,$00,$0A,                           (* [ 3948] OBJ_setct_AuthRevResBaggage *)
    $67,$2A,$00,$0B,                           (* [ 3952] OBJ_setct_CapTokenSeq *)
    $67,$2A,$00,$0C,                           (* [ 3956] OBJ_setct_PInitResData *)
    $67,$2A,$00,$0D,                           (* [ 3960] OBJ_setct_PI_TBS *)
    $67,$2A,$00,$0E,                           (* [ 3964] OBJ_setct_PResData *)
    $67,$2A,$00,$10,                           (* [ 3968] OBJ_setct_AuthReqTBS *)
    $67,$2A,$00,$11,                           (* [ 3972] OBJ_setct_AuthResTBS *)
    $67,$2A,$00,$12,                           (* [ 3976] OBJ_setct_AuthResTBSX *)
    $67,$2A,$00,$13,                           (* [ 3980] OBJ_setct_AuthTokenTBS *)
    $67,$2A,$00,$14,                           (* [ 3984] OBJ_setct_CapTokenData *)
    $67,$2A,$00,$15,                           (* [ 3988] OBJ_setct_CapTokenTBS *)
    $67,$2A,$00,$16,                           (* [ 3992] OBJ_setct_AcqCardCodeMsg *)
    $67,$2A,$00,$17,                           (* [ 3996] OBJ_setct_AuthRevReqTBS *)
    $67,$2A,$00,$18,                           (* [ 4000] OBJ_setct_AuthRevResData *)
    $67,$2A,$00,$19,                           (* [ 4004] OBJ_setct_AuthRevResTBS *)
    $67,$2A,$00,$1A,                           (* [ 4008] OBJ_setct_CapReqTBS *)
    $67,$2A,$00,$1B,                           (* [ 4012] OBJ_setct_CapReqTBSX *)
    $67,$2A,$00,$1C,                           (* [ 4016] OBJ_setct_CapResData *)
    $67,$2A,$00,$1D,                           (* [ 4020] OBJ_setct_CapRevReqTBS *)
    $67,$2A,$00,$1E,                           (* [ 4024] OBJ_setct_CapRevReqTBSX *)
    $67,$2A,$00,$1F,                           (* [ 4028] OBJ_setct_CapRevResData *)
    $67,$2A,$00,$20,                           (* [ 4032] OBJ_setct_CredReqTBS *)
    $67,$2A,$00,$21,                           (* [ 4036] OBJ_setct_CredReqTBSX *)
    $67,$2A,$00,$22,                           (* [ 4040] OBJ_setct_CredResData *)
    $67,$2A,$00,$23,                           (* [ 4044] OBJ_setct_CredRevReqTBS *)
    $67,$2A,$00,$24,                           (* [ 4048] OBJ_setct_CredRevReqTBSX *)
    $67,$2A,$00,$25,                           (* [ 4052] OBJ_setct_CredRevResData *)
    $67,$2A,$00,$26,                           (* [ 4056] OBJ_setct_PCertReqData *)
    $67,$2A,$00,$27,                           (* [ 4060] OBJ_setct_PCertResTBS *)
    $67,$2A,$00,$28,                           (* [ 4064] OBJ_setct_BatchAdminReqData *)
    $67,$2A,$00,$29,                           (* [ 4068] OBJ_setct_BatchAdminResData *)
    $67,$2A,$00,$2A,                           (* [ 4072] OBJ_setct_CardCInitResTBS *)
    $67,$2A,$00,$2B,                           (* [ 4076] OBJ_setct_MeAqCInitResTBS *)
    $67,$2A,$00,$2C,                           (* [ 4080] OBJ_setct_RegFormResTBS *)
    $67,$2A,$00,$2D,                           (* [ 4084] OBJ_setct_CertReqData *)
    $67,$2A,$00,$2E,                           (* [ 4088] OBJ_setct_CertReqTBS *)
    $67,$2A,$00,$2F,                           (* [ 4092] OBJ_setct_CertResData *)
    $67,$2A,$00,$30,                           (* [ 4096] OBJ_setct_CertInqReqTBS *)
    $67,$2A,$00,$31,                           (* [ 4100] OBJ_setct_ErrorTBS *)
    $67,$2A,$00,$32,                           (* [ 4104] OBJ_setct_PIDualSignedTBE *)
    $67,$2A,$00,$33,                           (* [ 4108] OBJ_setct_PIUnsignedTBE *)
    $67,$2A,$00,$34,                           (* [ 4112] OBJ_setct_AuthReqTBE *)
    $67,$2A,$00,$35,                           (* [ 4116] OBJ_setct_AuthResTBE *)
    $67,$2A,$00,$36,                           (* [ 4120] OBJ_setct_AuthResTBEX *)
    $67,$2A,$00,$37,                           (* [ 4124] OBJ_setct_AuthTokenTBE *)
    $67,$2A,$00,$38,                           (* [ 4128] OBJ_setct_CapTokenTBE *)
    $67,$2A,$00,$39,                           (* [ 4132] OBJ_setct_CapTokenTBEX *)
    $67,$2A,$00,$3A,                           (* [ 4136] OBJ_setct_AcqCardCodeMsgTBE *)
    $67,$2A,$00,$3B,                           (* [ 4140] OBJ_setct_AuthRevReqTBE *)
    $67,$2A,$00,$3C,                           (* [ 4144] OBJ_setct_AuthRevResTBE *)
    $67,$2A,$00,$3D,                           (* [ 4148] OBJ_setct_AuthRevResTBEB *)
    $67,$2A,$00,$3E,                           (* [ 4152] OBJ_setct_CapReqTBE *)
    $67,$2A,$00,$3F,                           (* [ 4156] OBJ_setct_CapReqTBEX *)
    $67,$2A,$00,$40,                           (* [ 4160] OBJ_setct_CapResTBE *)
    $67,$2A,$00,$41,                           (* [ 4164] OBJ_setct_CapRevReqTBE *)
    $67,$2A,$00,$42,                           (* [ 4168] OBJ_setct_CapRevReqTBEX *)
    $67,$2A,$00,$43,                           (* [ 4172] OBJ_setct_CapRevResTBE *)
    $67,$2A,$00,$44,                           (* [ 4176] OBJ_setct_CredReqTBE *)
    $67,$2A,$00,$45,                           (* [ 4180] OBJ_setct_CredReqTBEX *)
    $67,$2A,$00,$46,                           (* [ 4184] OBJ_setct_CredResTBE *)
    $67,$2A,$00,$47,                           (* [ 4188] OBJ_setct_CredRevReqTBE *)
    $67,$2A,$00,$48,                           (* [ 4192] OBJ_setct_CredRevReqTBEX *)
    $67,$2A,$00,$49,                           (* [ 4196] OBJ_setct_CredRevResTBE *)
    $67,$2A,$00,$4A,                           (* [ 4200] OBJ_setct_BatchAdminReqTBE *)
    $67,$2A,$00,$4B,                           (* [ 4204] OBJ_setct_BatchAdminResTBE *)
    $67,$2A,$00,$4C,                           (* [ 4208] OBJ_setct_RegFormReqTBE *)
    $67,$2A,$00,$4D,                           (* [ 4212] OBJ_setct_CertReqTBE *)
    $67,$2A,$00,$4E,                           (* [ 4216] OBJ_setct_CertReqTBEX *)
    $67,$2A,$00,$4F,                           (* [ 4220] OBJ_setct_CertResTBE *)
    $67,$2A,$00,$50,                           (* [ 4224] OBJ_setct_CRLNotificationTBS *)
    $67,$2A,$00,$51,                           (* [ 4228] OBJ_setct_CRLNotificationResTBS *)
    $67,$2A,$00,$52,                           (* [ 4232] OBJ_setct_BCIDistributionTBS *)
    $67,$2A,$01,$01,                           (* [ 4236] OBJ_setext_genCrypt *)
    $67,$2A,$01,$03,                           (* [ 4240] OBJ_setext_miAuth *)
    $67,$2A,$01,$04,                           (* [ 4244] OBJ_setext_pinSecure *)
    $67,$2A,$01,$05,                           (* [ 4248] OBJ_setext_pinAny *)
    $67,$2A,$01,$07,                           (* [ 4252] OBJ_setext_track2 *)
    $67,$2A,$01,$08,                           (* [ 4256] OBJ_setext_cv *)
    $67,$2A,$05,$00,                           (* [ 4260] OBJ_set_policy_root *)
    $67,$2A,$07,$00,                           (* [ 4264] OBJ_setCext_hashedRoot *)
    $67,$2A,$07,$01,                           (* [ 4268] OBJ_setCext_certType *)
    $67,$2A,$07,$02,                           (* [ 4272] OBJ_setCext_merchData *)
    $67,$2A,$07,$03,                           (* [ 4276] OBJ_setCext_cCertRequired *)
    $67,$2A,$07,$04,                           (* [ 4280] OBJ_setCext_tunneling *)
    $67,$2A,$07,$05,                           (* [ 4284] OBJ_setCext_setExt *)
    $67,$2A,$07,$06,                           (* [ 4288] OBJ_setCext_setQualf *)
    $67,$2A,$07,$07,                           (* [ 4292] OBJ_setCext_PGWYcapabilities *)
    $67,$2A,$07,$08,                           (* [ 4296] OBJ_setCext_TokenIdentifier *)
    $67,$2A,$07,$09,                           (* [ 4300] OBJ_setCext_Track2Data *)
    $67,$2A,$07,$0A,                           (* [ 4304] OBJ_setCext_TokenType *)
    $67,$2A,$07,$0B,                           (* [ 4308] OBJ_setCext_IssuerCapabilities *)
    $67,$2A,$03,$00,                           (* [ 4312] OBJ_setAttr_Cert *)
    $67,$2A,$03,$01,                           (* [ 4316] OBJ_setAttr_PGWYcap *)
    $67,$2A,$03,$02,                           (* [ 4320] OBJ_setAttr_TokenType *)
    $67,$2A,$03,$03,                           (* [ 4324] OBJ_setAttr_IssCap *)
    $67,$2A,$03,$00,$00,                      (* [ 4328] OBJ_set_rootKeyThumb *)
    $67,$2A,$03,$00,$01,                      (* [ 4333] OBJ_set_addPolicy *)
    $67,$2A,$03,$02,$01,                      (* [ 4338] OBJ_setAttr_Token_EMV *)
    $67,$2A,$03,$02,$02,                      (* [ 4343] OBJ_setAttr_Token_B0Prime *)
    $67,$2A,$03,$03,$03,                      (* [ 4348] OBJ_setAttr_IssCap_CVM *)
    $67,$2A,$03,$03,$04,                      (* [ 4353] OBJ_setAttr_IssCap_T2 *)
    $67,$2A,$03,$03,$05,                      (* [ 4358] OBJ_setAttr_IssCap_Sig *)
    $67,$2A,$03,$03,$03,$01,                 (* [ 4363] OBJ_setAttr_GenCryptgrm *)
    $67,$2A,$03,$03,$04,$01,                 (* [ 4369] OBJ_setAttr_T2Enc *)
    $67,$2A,$03,$03,$04,$02,                 (* [ 4375] OBJ_setAttr_T2cleartxt *)
    $67,$2A,$03,$03,$05,$01,                 (* [ 4381] OBJ_setAttr_TokICCsig *)
    $67,$2A,$03,$03,$05,$02,                 (* [ 4387] OBJ_setAttr_SecDevSig *)
    $67,$2A,$08,$01,                           (* [ 4393] OBJ_set_brand_IATA_ATA *)
    $67,$2A,$08,$1E,                           (* [ 4397] OBJ_set_brand_Diners *)
    $67,$2A,$08,$22,                           (* [ 4401] OBJ_set_brand_AmericanExpress *)
    $67,$2A,$08,$23,                           (* [ 4405] OBJ_set_brand_JCB *)
    $67,$2A,$08,$04,                           (* [ 4409] OBJ_set_brand_Visa *)
    $67,$2A,$08,$05,                           (* [ 4413] OBJ_set_brand_MasterCard *)
    $67,$2A,$08,$AE,$7B,                      (* [ 4417] OBJ_set_brand_Novus *)
    $2A,$86,$48,$86,$F7,$0D,$03,$0A,       (* [ 4422] OBJ_des_cdmf *)
    $2A,$86,$48,$86,$F7,$0D,$01,$01,$06,  (* [ 4430] OBJ_rsaOAEPEncryptionSET *)
    $67,                                          (* [ 4439] OBJ_international_organizations *)
    $2B,$06,$01,$04,$01,$82,$37,$14,$02,$02,  (* [ 4440] OBJ_ms_smartcard_login *)
    $2B,$06,$01,$04,$01,$82,$37,$14,$02,$03,  (* [ 4450] OBJ_ms_upn *)
    $55,$04,$09,                                (* [ 4460] OBJ_streetAddress *)
    $55,$04,$11,                                (* [ 4463] OBJ_postalCode *)
    $2B,$06,$01,$05,$05,$07,$15,            (* [ 4466] OBJ_id_ppl *)
    $2B,$06,$01,$05,$05,$07,$01,$0E,       (* [ 4473] OBJ_proxyCertInfo *)
    $2B,$06,$01,$05,$05,$07,$15,$00,       (* [ 4481] OBJ_id_ppl_anyLanguage *)
    $2B,$06,$01,$05,$05,$07,$15,$01,       (* [ 4489] OBJ_id_ppl_inheritAll *)
    $55,$1D,$1E,                                (* [ 4497] OBJ_name_constraints *)
    $2B,$06,$01,$05,$05,$07,$15,$02,       (* [ 4500] OBJ_Independent *)
    $2A,$86,$48,$86,$F7,$0D,$01,$01,$0B,  (* [ 4508] OBJ_sha256WithRSAEncryption *)
    $2A,$86,$48,$86,$F7,$0D,$01,$01,$0C,  (* [ 4517] OBJ_sha384WithRSAEncryption *)
    $2A,$86,$48,$86,$F7,$0D,$01,$01,$0D,  (* [ 4526] OBJ_sha512WithRSAEncryption *)
    $2A,$86,$48,$86,$F7,$0D,$01,$01,$0E,  (* [ 4535] OBJ_sha224WithRSAEncryption *)
    $60,$86,$48,$01,$65,$03,$04,$02,$01,  (* [ 4544] OBJ_sha256 *)
    $60,$86,$48,$01,$65,$03,$04,$02,$02,  (* [ 4553] OBJ_sha384 *)
    $60,$86,$48,$01,$65,$03,$04,$02,$03,  (* [ 4562] OBJ_sha512 *)
    $60,$86,$48,$01,$65,$03,$04,$02,$04,  (* [ 4571] OBJ_sha224 *)
    $2B,                                          (* [ 4580] OBJ_identified_organization *)
    $2B,$81,$04,                                (* [ 4581] OBJ_certicom_arc *)
    $67,$2B,                                     (* [ 4584] OBJ_wap *)
    $67,$2B,$01,                                (* [ 4586] OBJ_wap_wsg *)
    $2A,$86,$48,$CE,$3D,$01,$02,$03,       (* [ 4589] OBJ_X9_62_id_characteristic_two_basis *)
    $2A,$86,$48,$CE,$3D,$01,$02,$03,$01,  (* [ 4597] OBJ_X9_62_onBasis *)
    $2A,$86,$48,$CE,$3D,$01,$02,$03,$02,  (* [ 4606] OBJ_X9_62_tpBasis *)
    $2A,$86,$48,$CE,$3D,$01,$02,$03,$03,  (* [ 4615] OBJ_X9_62_ppBasis *)
    $2A,$86,$48,$CE,$3D,$03,$00,$01,       (* [ 4624] OBJ_X9_62_c2pnb163v1 *)
    $2A,$86,$48,$CE,$3D,$03,$00,$02,       (* [ 4632] OBJ_X9_62_c2pnb163v2 *)
    $2A,$86,$48,$CE,$3D,$03,$00,$03,       (* [ 4640] OBJ_X9_62_c2pnb163v3 *)
    $2A,$86,$48,$CE,$3D,$03,$00,$04,       (* [ 4648] OBJ_X9_62_c2pnb176v1 *)
    $2A,$86,$48,$CE,$3D,$03,$00,$05,       (* [ 4656] OBJ_X9_62_c2tnb191v1 *)
    $2A,$86,$48,$CE,$3D,$03,$00,$06,       (* [ 4664] OBJ_X9_62_c2tnb191v2 *)
    $2A,$86,$48,$CE,$3D,$03,$00,$07,       (* [ 4672] OBJ_X9_62_c2tnb191v3 *)
    $2A,$86,$48,$CE,$3D,$03,$00,$08,       (* [ 4680] OBJ_X9_62_c2onb191v4 *)
    $2A,$86,$48,$CE,$3D,$03,$00,$09,       (* [ 4688] OBJ_X9_62_c2onb191v5 *)
    $2A,$86,$48,$CE,$3D,$03,$00,$0A,       (* [ 4696] OBJ_X9_62_c2pnb208w1 *)
    $2A,$86,$48,$CE,$3D,$03,$00,$0B,       (* [ 4704] OBJ_X9_62_c2tnb239v1 *)
    $2A,$86,$48,$CE,$3D,$03,$00,$0C,       (* [ 4712] OBJ_X9_62_c2tnb239v2 *)
    $2A,$86,$48,$CE,$3D,$03,$00,$0D,       (* [ 4720] OBJ_X9_62_c2tnb239v3 *)
    $2A,$86,$48,$CE,$3D,$03,$00,$0E,       (* [ 4728] OBJ_X9_62_c2onb239v4 *)
    $2A,$86,$48,$CE,$3D,$03,$00,$0F,       (* [ 4736] OBJ_X9_62_c2onb239v5 *)
    $2A,$86,$48,$CE,$3D,$03,$00,$10,       (* [ 4744] OBJ_X9_62_c2pnb272w1 *)
    $2A,$86,$48,$CE,$3D,$03,$00,$11,       (* [ 4752] OBJ_X9_62_c2pnb304w1 *)
    $2A,$86,$48,$CE,$3D,$03,$00,$12,       (* [ 4760] OBJ_X9_62_c2tnb359v1 *)
    $2A,$86,$48,$CE,$3D,$03,$00,$13,       (* [ 4768] OBJ_X9_62_c2pnb368w1 *)
    $2A,$86,$48,$CE,$3D,$03,$00,$14,       (* [ 4776] OBJ_X9_62_c2tnb431r1 *)
    $2B,$81,$04,$00,$06,                      (* [ 4784] OBJ_secp112r1 *)
    $2B,$81,$04,$00,$07,                      (* [ 4789] OBJ_secp112r2 *)
    $2B,$81,$04,$00,$1C,                      (* [ 4794] OBJ_secp128r1 *)
    $2B,$81,$04,$00,$1D,                      (* [ 4799] OBJ_secp128r2 *)
    $2B,$81,$04,$00,$09,                      (* [ 4804] OBJ_secp160k1 *)
    $2B,$81,$04,$00,$08,                      (* [ 4809] OBJ_secp160r1 *)
    $2B,$81,$04,$00,$1E,                      (* [ 4814] OBJ_secp160r2 *)
    $2B,$81,$04,$00,$1F,                      (* [ 4819] OBJ_secp192k1 *)
    $2B,$81,$04,$00,$20,                      (* [ 4824] OBJ_secp224k1 *)
    $2B,$81,$04,$00,$21,                      (* [ 4829] OBJ_secp224r1 *)
    $2B,$81,$04,$00,$0A,                      (* [ 4834] OBJ_secp256k1 *)
    $2B,$81,$04,$00,$22,                      (* [ 4839] OBJ_secp384r1 *)
    $2B,$81,$04,$00,$23,                      (* [ 4844] OBJ_secp521r1 *)
    $2B,$81,$04,$00,$04,                      (* [ 4849] OBJ_sect113r1 *)
    $2B,$81,$04,$00,$05,                      (* [ 4854] OBJ_sect113r2 *)
    $2B,$81,$04,$00,$16,                      (* [ 4859] OBJ_sect131r1 *)
    $2B,$81,$04,$00,$17,                      (* [ 4864] OBJ_sect131r2 *)
    $2B,$81,$04,$00,$01,                      (* [ 4869] OBJ_sect163k1 *)
    $2B,$81,$04,$00,$02,                      (* [ 4874] OBJ_sect163r1 *)
    $2B,$81,$04,$00,$0F,                      (* [ 4879] OBJ_sect163r2 *)
    $2B,$81,$04,$00,$18,                      (* [ 4884] OBJ_sect193r1 *)
    $2B,$81,$04,$00,$19,                      (* [ 4889] OBJ_sect193r2 *)
    $2B,$81,$04,$00,$1A,                      (* [ 4894] OBJ_sect233k1 *)
    $2B,$81,$04,$00,$1B,                      (* [ 4899] OBJ_sect233r1 *)
    $2B,$81,$04,$00,$03,                      (* [ 4904] OBJ_sect239k1 *)
    $2B,$81,$04,$00,$10,                      (* [ 4909] OBJ_sect283k1 *)
    $2B,$81,$04,$00,$11,                      (* [ 4914] OBJ_sect283r1 *)
    $2B,$81,$04,$00,$24,                      (* [ 4919] OBJ_sect409k1 *)
    $2B,$81,$04,$00,$25,                      (* [ 4924] OBJ_sect409r1 *)
    $2B,$81,$04,$00,$26,                      (* [ 4929] OBJ_sect571k1 *)
    $2B,$81,$04,$00,$27,                      (* [ 4934] OBJ_sect571r1 *)
    $67,$2B,$01,$04,$01,                      (* [ 4939] OBJ_wap_wsg_idm_ecid_wtls1 *)
    $67,$2B,$01,$04,$03,                      (* [ 4944] OBJ_wap_wsg_idm_ecid_wtls3 *)
    $67,$2B,$01,$04,$04,                      (* [ 4949] OBJ_wap_wsg_idm_ecid_wtls4 *)
    $67,$2B,$01,$04,$05,                      (* [ 4954] OBJ_wap_wsg_idm_ecid_wtls5 *)
    $67,$2B,$01,$04,$06,                      (* [ 4959] OBJ_wap_wsg_idm_ecid_wtls6 *)
    $67,$2B,$01,$04,$07,                      (* [ 4964] OBJ_wap_wsg_idm_ecid_wtls7 *)
    $67,$2B,$01,$04,$08,                      (* [ 4969] OBJ_wap_wsg_idm_ecid_wtls8 *)
    $67,$2B,$01,$04,$09,                      (* [ 4974] OBJ_wap_wsg_idm_ecid_wtls9 *)
    $67,$2B,$01,$04,$0A,                      (* [ 4979] OBJ_wap_wsg_idm_ecid_wtls10 *)
    $67,$2B,$01,$04,$0B,                      (* [ 4984] OBJ_wap_wsg_idm_ecid_wtls11 *)
    $67,$2B,$01,$04,$0C,                      (* [ 4989] OBJ_wap_wsg_idm_ecid_wtls12 *)
    $55,$1D,$20,$00,                           (* [ 4994] OBJ_any_policy *)
    $55,$1D,$21,                                (* [ 4998] OBJ_policy_mappings *)
    $55,$1D,$36,                                (* [ 5001] OBJ_inhibit_any_policy *)
    $2A,$83,$08,$8C,$9A,$4B,$3D,$01,$01,$01,$02,  (* [ 5004] OBJ_camellia_128_cbc *)
    $2A,$83,$08,$8C,$9A,$4B,$3D,$01,$01,$01,$03,  (* [ 5015] OBJ_camellia_192_cbc *)
    $2A,$83,$08,$8C,$9A,$4B,$3D,$01,$01,$01,$04,  (* [ 5026] OBJ_camellia_256_cbc *)
    $03,$A2,$31,$05,$03,$01,$09,$01,       (* [ 5037] OBJ_camellia_128_ecb *)
    $03,$A2,$31,$05,$03,$01,$09,$15,       (* [ 5045] OBJ_camellia_192_ecb *)
    $03,$A2,$31,$05,$03,$01,$09,$29,       (* [ 5053] OBJ_camellia_256_ecb *)
    $03,$A2,$31,$05,$03,$01,$09,$04,       (* [ 5061] OBJ_camellia_128_cfb128 *)
    $03,$A2,$31,$05,$03,$01,$09,$18,       (* [ 5069] OBJ_camellia_192_cfb128 *)
    $03,$A2,$31,$05,$03,$01,$09,$2C,       (* [ 5077] OBJ_camellia_256_cfb128 *)
    $03,$A2,$31,$05,$03,$01,$09,$03,       (* [ 5085] OBJ_camellia_128_ofb128 *)
    $03,$A2,$31,$05,$03,$01,$09,$17,       (* [ 5093] OBJ_camellia_192_ofb128 *)
    $03,$A2,$31,$05,$03,$01,$09,$2B,       (* [ 5101] OBJ_camellia_256_ofb128 *)
    $55,$1D,$09,                                (* [ 5109] OBJ_subject_directory_attributes *)
    $55,$1D,$1C,                                (* [ 5112] OBJ_issuing_distribution_point *)
    $55,$1D,$1D,                                (* [ 5115] OBJ_certificate_issuer *)
    $2A,$83,$1A,$8C,$9A,$44,                 (* [ 5118] OBJ_kisa *)
    $2A,$83,$1A,$8C,$9A,$44,$01,$03,       (* [ 5124] OBJ_seed_ecb *)
    $2A,$83,$1A,$8C,$9A,$44,$01,$04,       (* [ 5132] OBJ_seed_cbc *)
    $2A,$83,$1A,$8C,$9A,$44,$01,$06,       (* [ 5140] OBJ_seed_ofb128 *)
    $2A,$83,$1A,$8C,$9A,$44,$01,$05,       (* [ 5148] OBJ_seed_cfb128 *)
    $2B,$06,$01,$05,$05,$08,$01,$01,       (* [ 5156] OBJ_hmac_md5 *)
    $2B,$06,$01,$05,$05,$08,$01,$02,       (* [ 5164] OBJ_hmac_sha1 *)
    $2A,$86,$48,$86,$F6,$7D,$07,$42,$0D,  (* [ 5172] OBJ_id_PasswordBasedMAC *)
    $2A,$86,$48,$86,$F6,$7D,$07,$42,$1E,  (* [ 5181] OBJ_id_DHBasedMac *)
    $2B,$06,$01,$05,$05,$07,$04,$10,       (* [ 5190] OBJ_id_it_suppLangTags *)
    $2B,$06,$01,$05,$05,$07,$30,$05,       (* [ 5198] OBJ_caRepository *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$01,$09,  (* [ 5206] OBJ_id_smime_ct_compressedData *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$01,$1B,  (* [ 5217] OBJ_id_ct_asciiTextWithCRLF *)
    $60,$86,$48,$01,$65,$03,$04,$01,$05,  (* [ 5228] OBJ_id_aes128_wrap *)
    $60,$86,$48,$01,$65,$03,$04,$01,$19,  (* [ 5237] OBJ_id_aes192_wrap *)
    $60,$86,$48,$01,$65,$03,$04,$01,$2D,  (* [ 5246] OBJ_id_aes256_wrap *)
    $2A,$86,$48,$CE,$3D,$04,$02,            (* [ 5255] OBJ_ecdsa_with_Recommended *)
    $2A,$86,$48,$CE,$3D,$04,$03,            (* [ 5262] OBJ_ecdsa_with_Specified *)
    $2A,$86,$48,$CE,$3D,$04,$03,$01,       (* [ 5269] OBJ_ecdsa_with_SHA224 *)
    $2A,$86,$48,$CE,$3D,$04,$03,$02,       (* [ 5277] OBJ_ecdsa_with_SHA256 *)
    $2A,$86,$48,$CE,$3D,$04,$03,$03,       (* [ 5285] OBJ_ecdsa_with_SHA384 *)
    $2A,$86,$48,$CE,$3D,$04,$03,$04,       (* [ 5293] OBJ_ecdsa_with_SHA512 *)
    $2A,$86,$48,$86,$F7,$0D,$02,$06,       (* [ 5301] OBJ_hmacWithMD5 *)
    $2A,$86,$48,$86,$F7,$0D,$02,$08,       (* [ 5309] OBJ_hmacWithSHA224 *)
    $2A,$86,$48,$86,$F7,$0D,$02,$09,       (* [ 5317] OBJ_hmacWithSHA256 *)
    $2A,$86,$48,$86,$F7,$0D,$02,$0A,       (* [ 5325] OBJ_hmacWithSHA384 *)
    $2A,$86,$48,$86,$F7,$0D,$02,$0B,       (* [ 5333] OBJ_hmacWithSHA512 *)
    $60,$86,$48,$01,$65,$03,$04,$03,$01,  (* [ 5341] OBJ_dsa_with_SHA224 *)
    $60,$86,$48,$01,$65,$03,$04,$03,$02,  (* [ 5350] OBJ_dsa_with_SHA256 *)
    $28,$CF,$06,$03,$00,$37,                 (* [ 5359] OBJ_whirlpool *)
    $2A,$85,$03,$02,$02,                      (* [ 5365] OBJ_cryptopro *)
    $2A,$85,$03,$02,$09,                      (* [ 5370] OBJ_cryptocom *)
    $2A,$85,$03,$02,$02,$03,                 (* [ 5375] OBJ_id_GostR3411_94_with_GostR3410_2001 *)
    $2A,$85,$03,$02,$02,$04,                 (* [ 5381] OBJ_id_GostR3411_94_with_GostR3410_94 *)
    $2A,$85,$03,$02,$02,$09,                 (* [ 5387] OBJ_id_GostR3411_94 *)
    $2A,$85,$03,$02,$02,$0A,                 (* [ 5393] OBJ_id_HMACGostR3411_94 *)
    $2A,$85,$03,$02,$02,$13,                 (* [ 5399] OBJ_id_GostR3410_2001 *)
    $2A,$85,$03,$02,$02,$14,                 (* [ 5405] OBJ_id_GostR3410_94 *)
    $2A,$85,$03,$02,$02,$15,                 (* [ 5411] OBJ_id_Gost28147_89 *)
    $2A,$85,$03,$02,$02,$16,                 (* [ 5417] OBJ_id_Gost28147_89_MAC *)
    $2A,$85,$03,$02,$02,$17,                 (* [ 5423] OBJ_id_GostR3411_94_prf *)
    $2A,$85,$03,$02,$02,$62,                 (* [ 5429] OBJ_id_GostR3410_2001DH *)
    $2A,$85,$03,$02,$02,$63,                 (* [ 5435] OBJ_id_GostR3410_94DH *)
    $2A,$85,$03,$02,$02,$0E,$01,            (* [ 5441] OBJ_id_Gost28147_89_CryptoPro_KeyMeshing *)
    $2A,$85,$03,$02,$02,$0E,$00,            (* [ 5448] OBJ_id_Gost28147_89_None_KeyMeshing *)
    $2A,$85,$03,$02,$02,$1E,$00,            (* [ 5455] OBJ_id_GostR3411_94_TestParamSet *)
    $2A,$85,$03,$02,$02,$1E,$01,            (* [ 5462] OBJ_id_GostR3411_94_CryptoProParamSet *)
    $2A,$85,$03,$02,$02,$1F,$00,            (* [ 5469] OBJ_id_Gost28147_89_TestParamSet *)
    $2A,$85,$03,$02,$02,$1F,$01,            (* [ 5476] OBJ_id_Gost28147_89_CryptoPro_A_ParamSet *)
    $2A,$85,$03,$02,$02,$1F,$02,            (* [ 5483] OBJ_id_Gost28147_89_CryptoPro_B_ParamSet *)
    $2A,$85,$03,$02,$02,$1F,$03,            (* [ 5490] OBJ_id_Gost28147_89_CryptoPro_C_ParamSet *)
    $2A,$85,$03,$02,$02,$1F,$04,            (* [ 5497] OBJ_id_Gost28147_89_CryptoPro_D_ParamSet *)
    $2A,$85,$03,$02,$02,$1F,$05,            (* [ 5504] OBJ_id_Gost28147_89_CryptoPro_Oscar_1_1_ParamSet *)
    $2A,$85,$03,$02,$02,$1F,$06,            (* [ 5511] OBJ_id_Gost28147_89_CryptoPro_Oscar_1_0_ParamSet *)
    $2A,$85,$03,$02,$02,$1F,$07,            (* [ 5518] OBJ_id_Gost28147_89_CryptoPro_RIC_1_ParamSet *)
    $2A,$85,$03,$02,$02,$20,$00,            (* [ 5525] OBJ_id_GostR3410_94_TestParamSet *)
    $2A,$85,$03,$02,$02,$20,$02,            (* [ 5532] OBJ_id_GostR3410_94_CryptoPro_A_ParamSet *)
    $2A,$85,$03,$02,$02,$20,$03,            (* [ 5539] OBJ_id_GostR3410_94_CryptoPro_B_ParamSet *)
    $2A,$85,$03,$02,$02,$20,$04,            (* [ 5546] OBJ_id_GostR3410_94_CryptoPro_C_ParamSet *)
    $2A,$85,$03,$02,$02,$20,$05,            (* [ 5553] OBJ_id_GostR3410_94_CryptoPro_D_ParamSet *)
    $2A,$85,$03,$02,$02,$21,$01,            (* [ 5560] OBJ_id_GostR3410_94_CryptoPro_XchA_ParamSet *)
    $2A,$85,$03,$02,$02,$21,$02,            (* [ 5567] OBJ_id_GostR3410_94_CryptoPro_XchB_ParamSet *)
    $2A,$85,$03,$02,$02,$21,$03,            (* [ 5574] OBJ_id_GostR3410_94_CryptoPro_XchC_ParamSet *)
    $2A,$85,$03,$02,$02,$23,$00,            (* [ 5581] OBJ_id_GostR3410_2001_TestParamSet *)
    $2A,$85,$03,$02,$02,$23,$01,            (* [ 5588] OBJ_id_GostR3410_2001_CryptoPro_A_ParamSet *)
    $2A,$85,$03,$02,$02,$23,$02,            (* [ 5595] OBJ_id_GostR3410_2001_CryptoPro_B_ParamSet *)
    $2A,$85,$03,$02,$02,$23,$03,            (* [ 5602] OBJ_id_GostR3410_2001_CryptoPro_C_ParamSet *)
    $2A,$85,$03,$02,$02,$24,$00,            (* [ 5609] OBJ_id_GostR3410_2001_CryptoPro_XchA_ParamSet *)
    $2A,$85,$03,$02,$02,$24,$01,            (* [ 5616] OBJ_id_GostR3410_2001_CryptoPro_XchB_ParamSet *)
    $2A,$85,$03,$02,$02,$14,$01,            (* [ 5623] OBJ_id_GostR3410_94_a *)
    $2A,$85,$03,$02,$02,$14,$02,            (* [ 5630] OBJ_id_GostR3410_94_aBis *)
    $2A,$85,$03,$02,$02,$14,$03,            (* [ 5637] OBJ_id_GostR3410_94_b *)
    $2A,$85,$03,$02,$02,$14,$04,            (* [ 5644] OBJ_id_GostR3410_94_bBis *)
    $2A,$85,$03,$02,$09,$01,$06,$01,       (* [ 5651] OBJ_id_Gost28147_89_cc *)
    $2A,$85,$03,$02,$09,$01,$05,$03,       (* [ 5659] OBJ_id_GostR3410_94_cc *)
    $2A,$85,$03,$02,$09,$01,$05,$04,       (* [ 5667] OBJ_id_GostR3410_2001_cc *)
    $2A,$85,$03,$02,$09,$01,$03,$03,       (* [ 5675] OBJ_id_GostR3411_94_with_GostR3410_94_cc *)
    $2A,$85,$03,$02,$09,$01,$03,$04,       (* [ 5683] OBJ_id_GostR3411_94_with_GostR3410_2001_cc *)
    $2A,$85,$03,$02,$09,$01,$08,$01,       (* [ 5691] OBJ_id_GostR3410_2001_ParamSet_cc *)
    $2B,$06,$01,$04,$01,$82,$37,$11,$02,  (* [ 5699] OBJ_LocalKeySet *)
    $55,$1D,$2E,                                (* [ 5708] OBJ_freshest_crl *)
    $2B,$06,$01,$05,$05,$07,$08,$03,       (* [ 5711] OBJ_id_on_permanentIdentifier *)
    $55,$04,$0E,                                (* [ 5719] OBJ_searchGuide *)
    $55,$04,$0F,                                (* [ 5722] OBJ_businessCategory *)
    $55,$04,$10,                                (* [ 5725] OBJ_postalAddress *)
    $55,$04,$12,                                (* [ 5728] OBJ_postOfficeBox *)
    $55,$04,$13,                                (* [ 5731] OBJ_physicalDeliveryOfficeName *)
    $55,$04,$14,                                (* [ 5734] OBJ_telephoneNumber *)
    $55,$04,$15,                                (* [ 5737] OBJ_telexNumber *)
    $55,$04,$16,                                (* [ 5740] OBJ_teletexTerminalIdentifier *)
    $55,$04,$17,                                (* [ 5743] OBJ_facsimileTelephoneNumber *)
    $55,$04,$18,                                (* [ 5746] OBJ_x121Address *)
    $55,$04,$19,                                (* [ 5749] OBJ_internationaliSDNNumber *)
    $55,$04,$1A,                                (* [ 5752] OBJ_registeredAddress *)
    $55,$04,$1B,                                (* [ 5755] OBJ_destinationIndicator *)
    $55,$04,$1C,                                (* [ 5758] OBJ_preferredDeliveryMethod *)
    $55,$04,$1D,                                (* [ 5761] OBJ_presentationAddress *)
    $55,$04,$1E,                                (* [ 5764] OBJ_supportedApplicationContext *)
    $55,$04,$1F,                                (* [ 5767] OBJ_member *)
    $55,$04,$20,                                (* [ 5770] OBJ_owner *)
    $55,$04,$21,                                (* [ 5773] OBJ_roleOccupant *)
    $55,$04,$22,                                (* [ 5776] OBJ_seeAlso *)
    $55,$04,$23,                                (* [ 5779] OBJ_userPassword *)
    $55,$04,$24,                                (* [ 5782] OBJ_userCertificate *)
    $55,$04,$25,                                (* [ 5785] OBJ_cACertificate *)
    $55,$04,$26,                                (* [ 5788] OBJ_authorityRevocationList *)
    $55,$04,$27,                                (* [ 5791] OBJ_certificateRevocationList *)
    $55,$04,$28,                                (* [ 5794] OBJ_crossCertificatePair *)
    $55,$04,$2F,                                (* [ 5797] OBJ_enhancedSearchGuide *)
    $55,$04,$30,                                (* [ 5800] OBJ_protocolInformation *)
    $55,$04,$31,                                (* [ 5803] OBJ_distinguishedName *)
    $55,$04,$32,                                (* [ 5806] OBJ_uniqueMember *)
    $55,$04,$33,                                (* [ 5809] OBJ_houseIdentifier *)
    $55,$04,$34,                                (* [ 5812] OBJ_supportedAlgorithms *)
    $55,$04,$35,                                (* [ 5815] OBJ_deltaRevocationList *)
    $55,$04,$36,                                (* [ 5818] OBJ_dmdName *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$03,$09,  (* [ 5821] OBJ_id_alg_PWRI_KEK *)
    $60,$86,$48,$01,$65,$03,$04,$01,$06,  (* [ 5832] OBJ_aes_128_gcm *)
    $60,$86,$48,$01,$65,$03,$04,$01,$07,  (* [ 5841] OBJ_aes_128_ccm *)
    $60,$86,$48,$01,$65,$03,$04,$01,$08,  (* [ 5850] OBJ_id_aes128_wrap_pad *)
    $60,$86,$48,$01,$65,$03,$04,$01,$1A,  (* [ 5859] OBJ_aes_192_gcm *)
    $60,$86,$48,$01,$65,$03,$04,$01,$1B,  (* [ 5868] OBJ_aes_192_ccm *)
    $60,$86,$48,$01,$65,$03,$04,$01,$1C,  (* [ 5877] OBJ_id_aes192_wrap_pad *)
    $60,$86,$48,$01,$65,$03,$04,$01,$2E,  (* [ 5886] OBJ_aes_256_gcm *)
    $60,$86,$48,$01,$65,$03,$04,$01,$2F,  (* [ 5895] OBJ_aes_256_ccm *)
    $60,$86,$48,$01,$65,$03,$04,$01,$30,  (* [ 5904] OBJ_id_aes256_wrap_pad *)
    $2A,$83,$08,$8C,$9A,$4B,$3D,$01,$01,$03,$02,  (* [ 5913] OBJ_id_camellia128_wrap *)
    $2A,$83,$08,$8C,$9A,$4B,$3D,$01,$01,$03,$03,  (* [ 5924] OBJ_id_camellia192_wrap *)
    $2A,$83,$08,$8C,$9A,$4B,$3D,$01,$01,$03,$04,  (* [ 5935] OBJ_id_camellia256_wrap *)
    $55,$1D,$25,$00,                           (* [ 5946] OBJ_anyExtendedKeyUsage *)
    $2A,$86,$48,$86,$F7,$0D,$01,$01,$08,  (* [ 5950] OBJ_mgf1 *)
    $2A,$86,$48,$86,$F7,$0D,$01,$01,$0A,  (* [ 5959] OBJ_rsassaPss *)
    $2B,$6F,$02,$8C,$53,$00,$01,$01,       (* [ 5968] OBJ_aes_128_xts *)
    $2B,$6F,$02,$8C,$53,$00,$01,$02,       (* [ 5976] OBJ_aes_256_xts *)
    $2A,$86,$48,$86,$F7,$0D,$01,$01,$07,  (* [ 5984] OBJ_rsaesOaep *)
    $2A,$86,$48,$CE,$3E,$02,$01,            (* [ 5993] OBJ_dhpublicnumber *)
    $2B,$24,$03,$03,$02,$08,$01,$01,$01,  (* [ 6000] OBJ_brainpoolP160r1 *)
    $2B,$24,$03,$03,$02,$08,$01,$01,$02,  (* [ 6009] OBJ_brainpoolP160t1 *)
    $2B,$24,$03,$03,$02,$08,$01,$01,$03,  (* [ 6018] OBJ_brainpoolP192r1 *)
    $2B,$24,$03,$03,$02,$08,$01,$01,$04,  (* [ 6027] OBJ_brainpoolP192t1 *)
    $2B,$24,$03,$03,$02,$08,$01,$01,$05,  (* [ 6036] OBJ_brainpoolP224r1 *)
    $2B,$24,$03,$03,$02,$08,$01,$01,$06,  (* [ 6045] OBJ_brainpoolP224t1 *)
    $2B,$24,$03,$03,$02,$08,$01,$01,$07,  (* [ 6054] OBJ_brainpoolP256r1 *)
    $2B,$24,$03,$03,$02,$08,$01,$01,$08,  (* [ 6063] OBJ_brainpoolP256t1 *)
    $2B,$24,$03,$03,$02,$08,$01,$01,$09,  (* [ 6072] OBJ_brainpoolP320r1 *)
    $2B,$24,$03,$03,$02,$08,$01,$01,$0A,  (* [ 6081] OBJ_brainpoolP320t1 *)
    $2B,$24,$03,$03,$02,$08,$01,$01,$0B,  (* [ 6090] OBJ_brainpoolP384r1 *)
    $2B,$24,$03,$03,$02,$08,$01,$01,$0C,  (* [ 6099] OBJ_brainpoolP384t1 *)
    $2B,$24,$03,$03,$02,$08,$01,$01,$0D,  (* [ 6108] OBJ_brainpoolP512r1 *)
    $2B,$24,$03,$03,$02,$08,$01,$01,$0E,  (* [ 6117] OBJ_brainpoolP512t1 *)
    $2A,$86,$48,$86,$F7,$0D,$01,$01,$09,  (* [ 6126] OBJ_pSpecified *)
    $2B,$81,$05,$10,$86,$48,$3F,$00,$02,  (* [ 6135] OBJ_dhSinglePass_stdDH_sha1kdf_scheme *)
    $2B,$81,$04,$01,$0B,$00,                 (* [ 6144] OBJ_dhSinglePass_stdDH_sha224kdf_scheme *)
    $2B,$81,$04,$01,$0B,$01,                 (* [ 6150] OBJ_dhSinglePass_stdDH_sha256kdf_scheme *)
    $2B,$81,$04,$01,$0B,$02,                 (* [ 6156] OBJ_dhSinglePass_stdDH_sha384kdf_scheme *)
    $2B,$81,$04,$01,$0B,$03,                 (* [ 6162] OBJ_dhSinglePass_stdDH_sha512kdf_scheme *)
    $2B,$81,$05,$10,$86,$48,$3F,$00,$03,  (* [ 6168] OBJ_dhSinglePass_cofactorDH_sha1kdf_scheme *)
    $2B,$81,$04,$01,$0E,$00,                 (* [ 6177] OBJ_dhSinglePass_cofactorDH_sha224kdf_scheme *)
    $2B,$81,$04,$01,$0E,$01,                 (* [ 6183] OBJ_dhSinglePass_cofactorDH_sha256kdf_scheme *)
    $2B,$81,$04,$01,$0E,$02,                 (* [ 6189] OBJ_dhSinglePass_cofactorDH_sha384kdf_scheme *)
    $2B,$81,$04,$01,$0E,$03,                 (* [ 6195] OBJ_dhSinglePass_cofactorDH_sha512kdf_scheme *)
    $2B,$06,$01,$04,$01,$D6,$79,$02,$04,$02,  (* [ 6201] OBJ_ct_precert_scts *)
    $2B,$06,$01,$04,$01,$D6,$79,$02,$04,$03,  (* [ 6211] OBJ_ct_precert_poison *)
    $2B,$06,$01,$04,$01,$D6,$79,$02,$04,$04,  (* [ 6221] OBJ_ct_precert_signer *)
    $2B,$06,$01,$04,$01,$D6,$79,$02,$04,$05,  (* [ 6231] OBJ_ct_cert_scts *)
    $2B,$06,$01,$04,$01,$82,$37,$3C,$02,$01,$01,  (* [ 6241] OBJ_jurisdictionLocalityName *)
    $2B,$06,$01,$04,$01,$82,$37,$3C,$02,$01,$02,  (* [ 6252] OBJ_jurisdictionStateOrProvinceName *)
    $2B,$06,$01,$04,$01,$82,$37,$3C,$02,$01,$03,  (* [ 6263] OBJ_jurisdictionCountryName *)
    $03,$A2,$31,$05,$03,$01,$09,$06,       (* [ 6274] OBJ_camellia_128_gcm *)
    $03,$A2,$31,$05,$03,$01,$09,$07,       (* [ 6282] OBJ_camellia_128_ccm *)
    $03,$A2,$31,$05,$03,$01,$09,$09,       (* [ 6290] OBJ_camellia_128_ctr *)
    $03,$A2,$31,$05,$03,$01,$09,$0A,       (* [ 6298] OBJ_camellia_128_cmac *)
    $03,$A2,$31,$05,$03,$01,$09,$1A,       (* [ 6306] OBJ_camellia_192_gcm *)
    $03,$A2,$31,$05,$03,$01,$09,$1B,       (* [ 6314] OBJ_camellia_192_ccm *)
    $03,$A2,$31,$05,$03,$01,$09,$1D,       (* [ 6322] OBJ_camellia_192_ctr *)
    $03,$A2,$31,$05,$03,$01,$09,$1E,       (* [ 6330] OBJ_camellia_192_cmac *)
    $03,$A2,$31,$05,$03,$01,$09,$2E,       (* [ 6338] OBJ_camellia_256_gcm *)
    $03,$A2,$31,$05,$03,$01,$09,$2F,       (* [ 6346] OBJ_camellia_256_ccm *)
    $03,$A2,$31,$05,$03,$01,$09,$31,       (* [ 6354] OBJ_camellia_256_ctr *)
    $03,$A2,$31,$05,$03,$01,$09,$32,       (* [ 6362] OBJ_camellia_256_cmac *)
    $2B,$06,$01,$04,$01,$DA,$47,$04,$0B,  (* [ 6370] OBJ_id_scrypt *)
    $2A,$85,$03,$07,$01,                      (* [ 6379] OBJ_id_tc26 *)
    $2A,$85,$03,$07,$01,$01,                 (* [ 6384] OBJ_id_tc26_algorithms *)
    $2A,$85,$03,$07,$01,$01,$01,            (* [ 6390] OBJ_id_tc26_sign *)
    $2A,$85,$03,$07,$01,$01,$01,$01,       (* [ 6397] OBJ_id_GostR3410_2012_256 *)
    $2A,$85,$03,$07,$01,$01,$01,$02,       (* [ 6405] OBJ_id_GostR3410_2012_512 *)
    $2A,$85,$03,$07,$01,$01,$02,            (* [ 6413] OBJ_id_tc26_digest *)
    $2A,$85,$03,$07,$01,$01,$02,$02,       (* [ 6420] OBJ_id_GostR3411_2012_256 *)
    $2A,$85,$03,$07,$01,$01,$02,$03,       (* [ 6428] OBJ_id_GostR3411_2012_512 *)
    $2A,$85,$03,$07,$01,$01,$03,            (* [ 6436] OBJ_id_tc26_signwithdigest *)
    $2A,$85,$03,$07,$01,$01,$03,$02,       (* [ 6443] OBJ_id_tc26_signwithdigest_gost3410_2012_256 *)
    $2A,$85,$03,$07,$01,$01,$03,$03,       (* [ 6451] OBJ_id_tc26_signwithdigest_gost3410_2012_512 *)
    $2A,$85,$03,$07,$01,$01,$04,            (* [ 6459] OBJ_id_tc26_mac *)
    $2A,$85,$03,$07,$01,$01,$04,$01,       (* [ 6466] OBJ_id_tc26_hmac_gost_3411_2012_256 *)
    $2A,$85,$03,$07,$01,$01,$04,$02,       (* [ 6474] OBJ_id_tc26_hmac_gost_3411_2012_512 *)
    $2A,$85,$03,$07,$01,$01,$05,            (* [ 6482] OBJ_id_tc26_cipher *)
    $2A,$85,$03,$07,$01,$01,$06,            (* [ 6489] OBJ_id_tc26_agreement *)
    $2A,$85,$03,$07,$01,$01,$06,$01,       (* [ 6496] OBJ_id_tc26_agreement_gost_3410_2012_256 *)
    $2A,$85,$03,$07,$01,$01,$06,$02,       (* [ 6504] OBJ_id_tc26_agreement_gost_3410_2012_512 *)
    $2A,$85,$03,$07,$01,$02,                 (* [ 6512] OBJ_id_tc26_constants *)
    $2A,$85,$03,$07,$01,$02,$01,            (* [ 6518] OBJ_id_tc26_sign_constants *)
    $2A,$85,$03,$07,$01,$02,$01,$02,       (* [ 6525] OBJ_id_tc26_gost_3410_2012_512_constants *)
    $2A,$85,$03,$07,$01,$02,$01,$02,$00,  (* [ 6533] OBJ_id_tc26_gost_3410_2012_512_paramSetTest *)
    $2A,$85,$03,$07,$01,$02,$01,$02,$01,  (* [ 6542] OBJ_id_tc26_gost_3410_2012_512_paramSetA *)
    $2A,$85,$03,$07,$01,$02,$01,$02,$02,  (* [ 6551] OBJ_id_tc26_gost_3410_2012_512_paramSetB *)
    $2A,$85,$03,$07,$01,$02,$02,            (* [ 6560] OBJ_id_tc26_digest_constants *)
    $2A,$85,$03,$07,$01,$02,$05,            (* [ 6567] OBJ_id_tc26_cipher_constants *)
    $2A,$85,$03,$07,$01,$02,$05,$01,       (* [ 6574] OBJ_id_tc26_gost_28147_constants *)
    $2A,$85,$03,$07,$01,$02,$05,$01,$01,  (* [ 6582] OBJ_id_tc26_gost_28147_param_Z *)
    $2A,$85,$03,$03,$81,$03,$01,$01,       (* [ 6591] OBJ_INN *)
    $2A,$85,$03,$64,$01,                      (* [ 6599] OBJ_OGRN *)
    $2A,$85,$03,$64,$03,                      (* [ 6604] OBJ_SNILS *)
    $2A,$85,$03,$64,$6F,                      (* [ 6609] OBJ_subjectSignTool *)
    $2A,$85,$03,$64,$70,                      (* [ 6614] OBJ_issuerSignTool *)
    $2B,$06,$01,$05,$05,$07,$01,$18,       (* [ 6619] OBJ_tlsfeature *)
    $2B,$06,$01,$05,$05,$07,$03,$11,       (* [ 6627] OBJ_ipsec_IKE *)
    $2B,$06,$01,$05,$05,$07,$03,$12,       (* [ 6635] OBJ_capwapAC *)
    $2B,$06,$01,$05,$05,$07,$03,$13,       (* [ 6643] OBJ_capwapWTP *)
    $2B,$06,$01,$05,$05,$07,$03,$15,       (* [ 6651] OBJ_sshClient *)
    $2B,$06,$01,$05,$05,$07,$03,$16,       (* [ 6659] OBJ_sshServer *)
    $2B,$06,$01,$05,$05,$07,$03,$17,       (* [ 6667] OBJ_sendRouter *)
    $2B,$06,$01,$05,$05,$07,$03,$18,       (* [ 6675] OBJ_sendProxiedRouter *)
    $2B,$06,$01,$05,$05,$07,$03,$19,       (* [ 6683] OBJ_sendOwner *)
    $2B,$06,$01,$05,$05,$07,$03,$1A,       (* [ 6691] OBJ_sendProxiedOwner *)
    $2B,$06,$01,$05,$02,$03,                 (* [ 6699] OBJ_id_pkinit *)
    $2B,$06,$01,$05,$02,$03,$04,            (* [ 6705] OBJ_pkInitClientAuth *)
    $2B,$06,$01,$05,$02,$03,$05,            (* [ 6712] OBJ_pkInitKDC *)
    $2B,$65,$6E,                                (* [ 6719] OBJ_X25519 *)
    $2B,$65,$6F,                                (* [ 6722] OBJ_X448 *)
    $2B,$06,$01,$04,$01,$8D,$3A,$0C,$02,$01,$10,  (* [ 6725] OBJ_blake2b512 *)
    $2B,$06,$01,$04,$01,$8D,$3A,$0C,$02,$02,$08,  (* [ 6736] OBJ_blake2s256 *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$01,$13,  (* [ 6747] OBJ_id_smime_ct_contentCollection *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$01,$17,  (* [ 6758] OBJ_id_smime_ct_authEnvelopedData *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$01,$1C,  (* [ 6769] OBJ_id_ct_xml *)
    $2A,$83,$1A,$8C,$9A,$6E,$01,$01,$01,  (* [ 6780] OBJ_aria_128_ecb *)
    $2A,$83,$1A,$8C,$9A,$6E,$01,$01,$02,  (* [ 6789] OBJ_aria_128_cbc *)
    $2A,$83,$1A,$8C,$9A,$6E,$01,$01,$03,  (* [ 6798] OBJ_aria_128_cfb128 *)
    $2A,$83,$1A,$8C,$9A,$6E,$01,$01,$04,  (* [ 6807] OBJ_aria_128_ofb128 *)
    $2A,$83,$1A,$8C,$9A,$6E,$01,$01,$05,  (* [ 6816] OBJ_aria_128_ctr *)
    $2A,$83,$1A,$8C,$9A,$6E,$01,$01,$06,  (* [ 6825] OBJ_aria_192_ecb *)
    $2A,$83,$1A,$8C,$9A,$6E,$01,$01,$07,  (* [ 6834] OBJ_aria_192_cbc *)
    $2A,$83,$1A,$8C,$9A,$6E,$01,$01,$08,  (* [ 6843] OBJ_aria_192_cfb128 *)
    $2A,$83,$1A,$8C,$9A,$6E,$01,$01,$09,  (* [ 6852] OBJ_aria_192_ofb128 *)
    $2A,$83,$1A,$8C,$9A,$6E,$01,$01,$0A,  (* [ 6861] OBJ_aria_192_ctr *)
    $2A,$83,$1A,$8C,$9A,$6E,$01,$01,$0B,  (* [ 6870] OBJ_aria_256_ecb *)
    $2A,$83,$1A,$8C,$9A,$6E,$01,$01,$0C,  (* [ 6879] OBJ_aria_256_cbc *)
    $2A,$83,$1A,$8C,$9A,$6E,$01,$01,$0D,  (* [ 6888] OBJ_aria_256_cfb128 *)
    $2A,$83,$1A,$8C,$9A,$6E,$01,$01,$0E,  (* [ 6897] OBJ_aria_256_ofb128 *)
    $2A,$83,$1A,$8C,$9A,$6E,$01,$01,$0F,  (* [ 6906] OBJ_aria_256_ctr *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$02,$2F,  (* [ 6915] OBJ_id_smime_aa_signingCertificateV2 *)
    $2B,$65,$70,                                (* [ 6926] OBJ_ED25519 *)
    $2B,$65,$71,                                (* [ 6929] OBJ_ED448 *)
    $55,$04,$61,                                (* [ 6932] OBJ_organizationIdentifier *)
    $55,$04,$62,                                (* [ 6935] OBJ_countryCode3c *)
    $55,$04,$63,                                (* [ 6938] OBJ_countryCode3n *)
    $55,$04,$64,                                (* [ 6941] OBJ_dnsName *)
    $2B,$24,$08,$03,$03,                      (* [ 6944] OBJ_x509ExtAdmission *)
    $60,$86,$48,$01,$65,$03,$04,$02,$05,  (* [ 6949] OBJ_sha512_224 *)
    $60,$86,$48,$01,$65,$03,$04,$02,$06,  (* [ 6958] OBJ_sha512_256 *)
    $60,$86,$48,$01,$65,$03,$04,$02,$07,  (* [ 6967] OBJ_sha3_224 *)
    $60,$86,$48,$01,$65,$03,$04,$02,$08,  (* [ 6976] OBJ_sha3_256 *)
    $60,$86,$48,$01,$65,$03,$04,$02,$09,  (* [ 6985] OBJ_sha3_384 *)
    $60,$86,$48,$01,$65,$03,$04,$02,$0A,  (* [ 6994] OBJ_sha3_512 *)
    $60,$86,$48,$01,$65,$03,$04,$02,$0B,  (* [ 7003] OBJ_shake128 *)
    $60,$86,$48,$01,$65,$03,$04,$02,$0C,  (* [ 7012] OBJ_shake256 *)
    $60,$86,$48,$01,$65,$03,$04,$02,$0D,  (* [ 7021] OBJ_hmac_sha3_224 *)
    $60,$86,$48,$01,$65,$03,$04,$02,$0E,  (* [ 7030] OBJ_hmac_sha3_256 *)
    $60,$86,$48,$01,$65,$03,$04,$02,$0F,  (* [ 7039] OBJ_hmac_sha3_384 *)
    $60,$86,$48,$01,$65,$03,$04,$02,$10,  (* [ 7048] OBJ_hmac_sha3_512 *)
    $60,$86,$48,$01,$65,$03,$04,$03,$03,  (* [ 7057] OBJ_dsa_with_SHA384 *)
    $60,$86,$48,$01,$65,$03,$04,$03,$04,  (* [ 7066] OBJ_dsa_with_SHA512 *)
    $60,$86,$48,$01,$65,$03,$04,$03,$05,  (* [ 7075] OBJ_dsa_with_SHA3_224 *)
    $60,$86,$48,$01,$65,$03,$04,$03,$06,  (* [ 7084] OBJ_dsa_with_SHA3_256 *)
    $60,$86,$48,$01,$65,$03,$04,$03,$07,  (* [ 7093] OBJ_dsa_with_SHA3_384 *)
    $60,$86,$48,$01,$65,$03,$04,$03,$08,  (* [ 7102] OBJ_dsa_with_SHA3_512 *)
    $60,$86,$48,$01,$65,$03,$04,$03,$09,  (* [ 7111] OBJ_ecdsa_with_SHA3_224 *)
    $60,$86,$48,$01,$65,$03,$04,$03,$0A,  (* [ 7120] OBJ_ecdsa_with_SHA3_256 *)
    $60,$86,$48,$01,$65,$03,$04,$03,$0B,  (* [ 7129] OBJ_ecdsa_with_SHA3_384 *)
    $60,$86,$48,$01,$65,$03,$04,$03,$0C,  (* [ 7138] OBJ_ecdsa_with_SHA3_512 *)
    $60,$86,$48,$01,$65,$03,$04,$03,$0D,  (* [ 7147] OBJ_RSA_SHA3_224 *)
    $60,$86,$48,$01,$65,$03,$04,$03,$0E,  (* [ 7156] OBJ_RSA_SHA3_256 *)
    $60,$86,$48,$01,$65,$03,$04,$03,$0F,  (* [ 7165] OBJ_RSA_SHA3_384 *)
    $60,$86,$48,$01,$65,$03,$04,$03,$10,  (* [ 7174] OBJ_RSA_SHA3_512 *)
    $2A,$83,$1A,$8C,$9A,$6E,$01,$01,$25,  (* [ 7183] OBJ_aria_128_ccm *)
    $2A,$83,$1A,$8C,$9A,$6E,$01,$01,$26,  (* [ 7192] OBJ_aria_192_ccm *)
    $2A,$83,$1A,$8C,$9A,$6E,$01,$01,$27,  (* [ 7201] OBJ_aria_256_ccm *)
    $2A,$83,$1A,$8C,$9A,$6E,$01,$01,$22,  (* [ 7210] OBJ_aria_128_gcm *)
    $2A,$83,$1A,$8C,$9A,$6E,$01,$01,$23,  (* [ 7219] OBJ_aria_192_gcm *)
    $2A,$83,$1A,$8C,$9A,$6E,$01,$01,$24,  (* [ 7228] OBJ_aria_256_gcm *)
    $2B,$06,$01,$05,$05,$07,$03,$1B,       (* [ 7237] OBJ_cmcCA *)
    $2B,$06,$01,$05,$05,$07,$03,$1C,       (* [ 7245] OBJ_cmcRA *)
    $2A,$81,$1C,$CF,$55,$01,$68,$01,       (* [ 7253] OBJ_sm4_ecb *)
    $2A,$81,$1C,$CF,$55,$01,$68,$02,       (* [ 7261] OBJ_sm4_cbc *)
    $2A,$81,$1C,$CF,$55,$01,$68,$03,       (* [ 7269] OBJ_sm4_ofb128 *)
    $2A,$81,$1C,$CF,$55,$01,$68,$05,       (* [ 7277] OBJ_sm4_cfb1 *)
    $2A,$81,$1C,$CF,$55,$01,$68,$04,       (* [ 7285] OBJ_sm4_cfb128 *)
    $2A,$81,$1C,$CF,$55,$01,$68,$06,       (* [ 7293] OBJ_sm4_cfb8 *)
    $2A,$81,$1C,$CF,$55,$01,$68,$07,       (* [ 7301] OBJ_sm4_ctr *)
    $2A,$81,$1C,                                (* [ 7309] OBJ_ISO_CN *)
    $2A,$81,$1C,$CF,$55,                      (* [ 7312] OBJ_oscca *)
    $2A,$81,$1C,$CF,$55,$01,                 (* [ 7317] OBJ_sm_scheme *)
    $2A,$81,$1C,$CF,$55,$01,$83,$11,       (* [ 7323] OBJ_sm3 *)
    $2A,$81,$1C,$CF,$55,$01,$83,$78,       (* [ 7331] OBJ_sm3WithRSAEncryption *)
    $2A,$86,$48,$86,$F7,$0D,$01,$01,$0F,  (* [ 7339] OBJ_sha512_224WithRSAEncryption *)
    $2A,$86,$48,$86,$F7,$0D,$01,$01,$10,  (* [ 7348] OBJ_sha512_256WithRSAEncryption *)
    $2A,$85,$03,$07,$01,$02,$01,$01,       (* [ 7357] OBJ_id_tc26_gost_3410_2012_256_constants *)
    $2A,$85,$03,$07,$01,$02,$01,$01,$01,  (* [ 7365] OBJ_id_tc26_gost_3410_2012_256_paramSetA *)
    $2A,$85,$03,$07,$01,$02,$01,$02,$03,  (* [ 7374] OBJ_id_tc26_gost_3410_2012_512_paramSetC *)
    $2A,$86,$24,                                (* [ 7383] OBJ_ISO_UA *)
    $2A,$86,$24,$02,$01,$01,$01,            (* [ 7386] OBJ_ua_pki *)
    $2A,$86,$24,$02,$01,$01,$01,$01,$01,$01,  (* [ 7393] OBJ_dstu28147 *)
    $2A,$86,$24,$02,$01,$01,$01,$01,$01,$01,$02,  (* [ 7403] OBJ_dstu28147_ofb *)
    $2A,$86,$24,$02,$01,$01,$01,$01,$01,$01,$03,  (* [ 7414] OBJ_dstu28147_cfb *)
    $2A,$86,$24,$02,$01,$01,$01,$01,$01,$01,$05,  (* [ 7425] OBJ_dstu28147_wrap *)
    $2A,$86,$24,$02,$01,$01,$01,$01,$01,$02,  (* [ 7436] OBJ_hmacWithDstu34311 *)
    $2A,$86,$24,$02,$01,$01,$01,$01,$02,$01,  (* [ 7446] OBJ_dstu34311 *)
    $2A,$86,$24,$02,$01,$01,$01,$01,$03,$01,$01,  (* [ 7456] OBJ_dstu4145le *)
    $2A,$86,$24,$02,$01,$01,$01,$01,$03,$01,$01,$01,$01,  (* [ 7467] OBJ_dstu4145be *)
    $2A,$86,$24,$02,$01,$01,$01,$01,$03,$01,$01,$02,$00,  (* [ 7480] OBJ_uacurve0 *)
    $2A,$86,$24,$02,$01,$01,$01,$01,$03,$01,$01,$02,$01,  (* [ 7493] OBJ_uacurve1 *)
    $2A,$86,$24,$02,$01,$01,$01,$01,$03,$01,$01,$02,$02,  (* [ 7506] OBJ_uacurve2 *)
    $2A,$86,$24,$02,$01,$01,$01,$01,$03,$01,$01,$02,$03,  (* [ 7519] OBJ_uacurve3 *)
    $2A,$86,$24,$02,$01,$01,$01,$01,$03,$01,$01,$02,$04,  (* [ 7532] OBJ_uacurve4 *)
    $2A,$86,$24,$02,$01,$01,$01,$01,$03,$01,$01,$02,$05,  (* [ 7545] OBJ_uacurve5 *)
    $2A,$86,$24,$02,$01,$01,$01,$01,$03,$01,$01,$02,$06,  (* [ 7558] OBJ_uacurve6 *)
    $2A,$86,$24,$02,$01,$01,$01,$01,$03,$01,$01,$02,$07,  (* [ 7571] OBJ_uacurve7 *)
    $2A,$86,$24,$02,$01,$01,$01,$01,$03,$01,$01,$02,$08,  (* [ 7584] OBJ_uacurve8 *)
    $2A,$86,$24,$02,$01,$01,$01,$01,$03,$01,$01,$02,$09,  (* [ 7597] OBJ_uacurve9 *)
    $2B,$6F,                                     (* [ 7610] OBJ_ieee *)
    $2B,$6F,$02,$8C,$53,                      (* [ 7612] OBJ_ieee_siswg *)
    $2A,$81,$1C,$CF,$55,$01,$82,$2D,       (* [ 7617] OBJ_sm2 *)
    $2A,$85,$03,$07,$01,$01,$05,$01,       (* [ 7625] OBJ_id_tc26_cipher_gostr3412_2015_magma *)
    $2A,$85,$03,$07,$01,$01,$05,$01,$01,  (* [ 7633] OBJ_magma_ctr_acpkm *)
    $2A,$85,$03,$07,$01,$01,$05,$01,$02,  (* [ 7642] OBJ_magma_ctr_acpkm_omac *)
    $2A,$85,$03,$07,$01,$01,$05,$02,       (* [ 7651] OBJ_id_tc26_cipher_gostr3412_2015_kuznyechik *)
    $2A,$85,$03,$07,$01,$01,$05,$02,$01,  (* [ 7659] OBJ_kuznyechik_ctr_acpkm *)
    $2A,$85,$03,$07,$01,$01,$05,$02,$02,  (* [ 7668] OBJ_kuznyechik_ctr_acpkm_omac *)
    $2A,$85,$03,$07,$01,$01,$07,            (* [ 7677] OBJ_id_tc26_wrap *)
    $2A,$85,$03,$07,$01,$01,$07,$01,       (* [ 7684] OBJ_id_tc26_wrap_gostr3412_2015_magma *)
    $2A,$85,$03,$07,$01,$01,$07,$01,$01,  (* [ 7692] OBJ_magma_kexp15 *)
    $2A,$85,$03,$07,$01,$01,$07,$02,       (* [ 7701] OBJ_id_tc26_wrap_gostr3412_2015_kuznyechik *)
    $2A,$85,$03,$07,$01,$01,$07,$02,$01,  (* [ 7709] OBJ_kuznyechik_kexp15 *)
    $2A,$85,$03,$07,$01,$02,$01,$01,$02,  (* [ 7718] OBJ_id_tc26_gost_3410_2012_256_paramSetB *)
    $2A,$85,$03,$07,$01,$02,$01,$01,$03,  (* [ 7727] OBJ_id_tc26_gost_3410_2012_256_paramSetC *)
    $2A,$85,$03,$07,$01,$02,$01,$01,$04,  (* [ 7736] OBJ_id_tc26_gost_3410_2012_256_paramSetD *)
    $2A,$86,$48,$86,$F7,$0D,$02,$0C,       (* [ 7745] OBJ_hmacWithSHA512_224 *)
    $2A,$86,$48,$86,$F7,$0D,$02,$0D,       (* [ 7753] OBJ_hmacWithSHA512_256 *)
    $28,$CC,$45,$03,$04,                      (* [ 7761] OBJ_gmac *)
    $60,$86,$48,$01,$65,$03,$04,$02,$13,  (* [ 7766] OBJ_kmac128 *)
    $60,$86,$48,$01,$65,$03,$04,$02,$14,  (* [ 7775] OBJ_kmac256 *)
    $2B,$06,$01,$04,$01,$8D,$3A,$0C,$02,$01,  (* [ 7784] OBJ_blake2bmac *)
    $2B,$06,$01,$04,$01,$8D,$3A,$0C,$02,$02,  (* [ 7794] OBJ_blake2smac *)
    $2A,$81,$1C,$CF,$55,$01,$83,$75,       (* [ 7804] OBJ_SM2_with_SM3 *)
    $2B,$06,$01,$05,$05,$07,$08,$09,       (* [ 7812] OBJ_id_on_SmtpUTF8Mailbox *)
    $2B,$06,$01,$05,$05,$07,$08,$05,       (* [ 7820] OBJ_XmppAddr *)
    $2B,$06,$01,$05,$05,$07,$08,$07,       (* [ 7828] OBJ_SRVName *)
    $2B,$06,$01,$05,$05,$07,$08,$08,       (* [ 7836] OBJ_NAIRealm *)
    $2B,$06,$01,$05,$05,$07,$03,$1D,       (* [ 7844] OBJ_cmcArchive *)
    $2B,$06,$01,$05,$05,$07,$03,$1E,       (* [ 7852] OBJ_id_kp_bgpsec_router *)
    $2B,$06,$01,$05,$05,$07,$03,$1F,       (* [ 7860] OBJ_id_kp_BrandIndicatorforMessageIdentification *)
    $2B,$06,$01,$05,$05,$07,$03,$20,       (* [ 7868] OBJ_cmKGA *)
    $2B,$06,$01,$05,$05,$07,$04,$11,       (* [ 7876] OBJ_id_it_caCerts *)
    $2B,$06,$01,$05,$05,$07,$04,$12,       (* [ 7884] OBJ_id_it_rootCaKeyUpdate *)
    $2B,$06,$01,$05,$05,$07,$04,$13,       (* [ 7892] OBJ_id_it_certReqTemplate *)
    $2A,$85,$03,$64,$05,                      (* [ 7900] OBJ_OGRNIP *)
    $2A,$85,$03,$64,$71,                      (* [ 7905] OBJ_classSignTool *)
    $2A,$85,$03,$64,$71,$01,                 (* [ 7910] OBJ_classSignToolKC1 *)
    $2A,$85,$03,$64,$71,$02,                 (* [ 7916] OBJ_classSignToolKC2 *)
    $2A,$85,$03,$64,$71,$03,                 (* [ 7922] OBJ_classSignToolKC3 *)
    $2A,$85,$03,$64,$71,$04,                 (* [ 7928] OBJ_classSignToolKB1 *)
    $2A,$85,$03,$64,$71,$05,                 (* [ 7934] OBJ_classSignToolKB2 *)
    $2A,$85,$03,$64,$71,$06,                 (* [ 7940] OBJ_classSignToolKA1 *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$01,$18,  (* [ 7946] OBJ_id_ct_routeOriginAuthz *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$01,$1A,  (* [ 7957] OBJ_id_ct_rpkiManifest *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$01,$23,  (* [ 7968] OBJ_id_ct_rpkiGhostbusters *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$01,$24,  (* [ 7979] OBJ_id_ct_resourceTaggedAttest *)
    $2B,$06,$01,$05,$05,$07,$0E,            (* [ 7990] OBJ_id_cp *)
    $2B,$06,$01,$05,$05,$07,$01,$1C,       (* [ 7997] OBJ_sbgp_ipAddrBlockv2 *)
    $2B,$06,$01,$05,$05,$07,$01,$1D,       (* [ 8005] OBJ_sbgp_autonomousSysNumv2 *)
    $2B,$06,$01,$05,$05,$07,$0E,$02,       (* [ 8013] OBJ_ipAddr_asNumber *)
    $2B,$06,$01,$05,$05,$07,$0E,$03,       (* [ 8021] OBJ_ipAddr_asNumberv2 *)
    $2B,$06,$01,$05,$05,$07,$30,$0A,       (* [ 8029] OBJ_rpkiManifest *)
    $2B,$06,$01,$05,$05,$07,$30,$0B,       (* [ 8037] OBJ_signedObject *)
    $2B,$06,$01,$05,$05,$07,$30,$0D,       (* [ 8045] OBJ_rpkiNotify *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$01,$2F,  (* [ 8053] OBJ_id_ct_geofeedCSVwithCRLF *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$01,$30,  (* [ 8064] OBJ_id_ct_signedChecklist *)
    $2A,$81,$1C,$CF,$55,$01,$68,$08,       (* [ 8075] OBJ_sm4_gcm *)
    $2A,$81,$1C,$CF,$55,$01,$68,$09,       (* [ 8083] OBJ_sm4_ccm *)
    $2A,$86,$48,$86,$F7,$0D,$01,$09,$10,$01,$31  (* [ 8091] OBJ_id_ct_ASPA *)
);
 NUM_SN = 1242;
 sn_objs: array[0..NUM_SN-1] of Uint32 = (
     364,    (* 'AD_DVCS' *)
     419,    (* 'AES-128-CBC' *)
     916,    (* 'AES-128-CBC-HMAC-SHA1' *)
     948,    (* 'AES-128-CBC-HMAC-SHA256' *)
     421,    (* 'AES-128-CFB' *)
     650,    (* 'AES-128-CFB1' *)
     653,    (* 'AES-128-CFB8' *)
     904,    (* 'AES-128-CTR' *)
     418,    (* 'AES-128-ECB' *)
     958,    (* 'AES-128-OCB' *)
     420,    (* 'AES-128-OFB' *)
    1198,    (* 'AES-128-SIV' *)
     913,    (* 'AES-128-XTS' *)
     423,    (* 'AES-192-CBC' *)
     917,    (* 'AES-192-CBC-HMAC-SHA1' *)
     949,    (* 'AES-192-CBC-HMAC-SHA256' *)
     425,    (* 'AES-192-CFB' *)
     651,    (* 'AES-192-CFB1' *)
     654,    (* 'AES-192-CFB8' *)
     905,    (* 'AES-192-CTR' *)
     422,    (* 'AES-192-ECB' *)
     959,    (* 'AES-192-OCB' *)
     424,    (* 'AES-192-OFB' *)
    1199,    (* 'AES-192-SIV' *)
     427,    (* 'AES-256-CBC' *)
     918,    (* 'AES-256-CBC-HMAC-SHA1' *)
     950,    (* 'AES-256-CBC-HMAC-SHA256' *)
     429,    (* 'AES-256-CFB' *)
     652,    (* 'AES-256-CFB1' *)
     655,    (* 'AES-256-CFB8' *)
     906,    (* 'AES-256-CTR' *)
     426,    (* 'AES-256-ECB' *)
     960,    (* 'AES-256-OCB' *)
     428,    (* 'AES-256-OFB' *)
    1200,    (* 'AES-256-SIV' *)
     914,    (* 'AES-256-XTS' *)
    1066,    (* 'ARIA-128-CBC' *)
    1120,    (* 'ARIA-128-CCM' *)
    1067,    (* 'ARIA-128-CFB' *)
    1080,    (* 'ARIA-128-CFB1' *)
    1083,    (* 'ARIA-128-CFB8' *)
    1069,    (* 'ARIA-128-CTR' *)
    1065,    (* 'ARIA-128-ECB' *)
    1123,    (* 'ARIA-128-GCM' *)
    1068,    (* 'ARIA-128-OFB' *)
    1071,    (* 'ARIA-192-CBC' *)
    1121,    (* 'ARIA-192-CCM' *)
    1072,    (* 'ARIA-192-CFB' *)
    1081,    (* 'ARIA-192-CFB1' *)
    1084,    (* 'ARIA-192-CFB8' *)
    1074,    (* 'ARIA-192-CTR' *)
    1070,    (* 'ARIA-192-ECB' *)
    1124,    (* 'ARIA-192-GCM' *)
    1073,    (* 'ARIA-192-OFB' *)
    1076,    (* 'ARIA-256-CBC' *)
    1122,    (* 'ARIA-256-CCM' *)
    1077,    (* 'ARIA-256-CFB' *)
    1082,    (* 'ARIA-256-CFB1' *)
    1085,    (* 'ARIA-256-CFB8' *)
    1079,    (* 'ARIA-256-CTR' *)
    1075,    (* 'ARIA-256-ECB' *)
    1125,    (* 'ARIA-256-GCM' *)
    1078,    (* 'ARIA-256-OFB' *)
    1064,    (* 'AuthANY' *)
    1049,    (* 'AuthDSS' *)
    1047,    (* 'AuthECDSA' *)
    1050,    (* 'AuthGOST01' *)
    1051,    (* 'AuthGOST12' *)
    1053,    (* 'AuthNULL' *)
    1048,    (* 'AuthPSK' *)
    1046,    (* 'AuthRSA' *)
    1052,    (* 'AuthSRP' *)
      91,    (* 'BF-CBC' *)
      93,    (* 'BF-CFB' *)
      92,    (* 'BF-ECB' *)
      94,    (* 'BF-OFB' *)
    1201,    (* 'BLAKE2BMAC' *)
    1202,    (* 'BLAKE2SMAC' *)
    1056,    (* 'BLAKE2b512' *)
    1057,    (* 'BLAKE2s256' *)
      14,    (* 'C' *)
     751,    (* 'CAMELLIA-128-CBC' *)
     962,    (* 'CAMELLIA-128-CCM' *)
     757,    (* 'CAMELLIA-128-CFB' *)
     760,    (* 'CAMELLIA-128-CFB1' *)
     763,    (* 'CAMELLIA-128-CFB8' *)
     964,    (* 'CAMELLIA-128-CMAC' *)
     963,    (* 'CAMELLIA-128-CTR' *)
     754,    (* 'CAMELLIA-128-ECB' *)
     961,    (* 'CAMELLIA-128-GCM' *)
     766,    (* 'CAMELLIA-128-OFB' *)
     752,    (* 'CAMELLIA-192-CBC' *)
     966,    (* 'CAMELLIA-192-CCM' *)
     758,    (* 'CAMELLIA-192-CFB' *)
     761,    (* 'CAMELLIA-192-CFB1' *)
     764,    (* 'CAMELLIA-192-CFB8' *)
     968,    (* 'CAMELLIA-192-CMAC' *)
     967,    (* 'CAMELLIA-192-CTR' *)
     755,    (* 'CAMELLIA-192-ECB' *)
     965,    (* 'CAMELLIA-192-GCM' *)
     767,    (* 'CAMELLIA-192-OFB' *)
     753,    (* 'CAMELLIA-256-CBC' *)
     970,    (* 'CAMELLIA-256-CCM' *)
     759,    (* 'CAMELLIA-256-CFB' *)
     762,    (* 'CAMELLIA-256-CFB1' *)
     765,    (* 'CAMELLIA-256-CFB8' *)
     972,    (* 'CAMELLIA-256-CMAC' *)
     971,    (* 'CAMELLIA-256-CTR' *)
     756,    (* 'CAMELLIA-256-ECB' *)
     969,    (* 'CAMELLIA-256-GCM' *)
     768,    (* 'CAMELLIA-256-OFB' *)
     108,    (* 'CAST5-CBC' *)
     110,    (* 'CAST5-CFB' *)
     109,    (* 'CAST5-ECB' *)
     111,    (* 'CAST5-OFB' *)
     894,    (* 'CMAC' *)
      13,    (* 'CN' *)
     141,    (* 'CRLReason' *)
     417,    (* 'CSPName' *)
    1019,    (* 'ChaCha20' *)
    1018,    (* 'ChaCha20-Poly1305' *)
     367,    (* 'CrlID' *)
     391,    (* 'DC' *)
      31,    (* 'DES-CBC' *)
     643,    (* 'DES-CDMF' *)
      30,    (* 'DES-CFB' *)
     656,    (* 'DES-CFB1' *)
     657,    (* 'DES-CFB8' *)
      29,    (* 'DES-ECB' *)
      32,    (* 'DES-EDE' *)
      43,    (* 'DES-EDE-CBC' *)
      60,    (* 'DES-EDE-CFB' *)
      62,    (* 'DES-EDE-OFB' *)
      33,    (* 'DES-EDE3' *)
      44,    (* 'DES-EDE3-CBC' *)
      61,    (* 'DES-EDE3-CFB' *)
     658,    (* 'DES-EDE3-CFB1' *)
     659,    (* 'DES-EDE3-CFB8' *)
      63,    (* 'DES-EDE3-OFB' *)
      45,    (* 'DES-OFB' *)
      80,    (* 'DESX-CBC' *)
     380,    (* 'DOD' *)
     116,    (* 'DSA' *)
      66,    (* 'DSA-SHA' *)
     113,    (* 'DSA-SHA1' *)
      70,    (* 'DSA-SHA1-old' *)
      67,    (* 'DSA-old' *)
     297,    (* 'DVCS' *)
    1087,    (* 'ED25519' *)
    1088,    (* 'ED448' *)
    1195,    (* 'GMAC' *)
      99,    (* 'GN' *)
    1036,    (* 'HKDF' *)
     855,    (* 'HMAC' *)
     780,    (* 'HMAC-MD5' *)
     781,    (* 'HMAC-SHA1' *)
     381,    (* 'IANA' *)
      34,    (* 'IDEA-CBC' *)
      35,    (* 'IDEA-CFB' *)
      36,    (* 'IDEA-ECB' *)
      46,    (* 'IDEA-OFB' *)
    1004,    (* 'INN' *)
     181,    (* 'ISO' *)
    1140,    (* 'ISO-CN' *)
    1150,    (* 'ISO-UA' *)
     183,    (* 'ISO-US' *)
     645,    (* 'ITU-T' *)
     646,    (* 'JOINT-ISO-ITU-T' *)
     773,    (* 'KISA' *)
    1196,    (* 'KMAC128' *)
    1197,    (* 'KMAC256' *)
    1063,    (* 'KxANY' *)
    1039,    (* 'KxDHE' *)
    1041,    (* 'KxDHE-PSK' *)
    1038,    (* 'KxECDHE' *)
    1040,    (* 'KxECDHE-PSK' *)
    1045,    (* 'KxGOST' *)
    1218,    (* 'KxGOST18' *)
    1043,    (* 'KxPSK' *)
    1037,    (* 'KxRSA' *)
    1042,    (* 'KxRSA_PSK' *)
    1044,    (* 'KxSRP' *)
      15,    (* 'L' *)
     856,    (* 'LocalKeySet' *)
       3,    (* 'MD2' *)
     257,    (* 'MD4' *)
       4,    (* 'MD5' *)
     114,    (* 'MD5-SHA1' *)
      95,    (* 'MDC2' *)
     911,    (* 'MGF1' *)
     388,    (* 'Mail' *)
     393,    (* 'NULL' *)
     404,    (* 'NULL' *)
      57,    (* 'Netscape' *)
     366,    (* 'Nonce' *)
      17,    (* 'O' *)
     178,    (* 'OCSP' *)
     180,    (* 'OCSPSigning' *)
    1005,    (* 'OGRN' *)
    1226,    (* 'OGRNIP' *)
     379,    (* 'ORG' *)
      18,    (* 'OU' *)
     749,    (* 'Oakley-EC2N-3' *)
     750,    (* 'Oakley-EC2N-4' *)
       9,    (* 'PBE-MD2-DES' *)
     168,    (* 'PBE-MD2-RC2-64' *)
      10,    (* 'PBE-MD5-DES' *)
     169,    (* 'PBE-MD5-RC2-64' *)
     147,    (* 'PBE-SHA1-2DES' *)
     146,    (* 'PBE-SHA1-3DES' *)
     170,    (* 'PBE-SHA1-DES' *)
     148,    (* 'PBE-SHA1-RC2-128' *)
     149,    (* 'PBE-SHA1-RC2-40' *)
      68,    (* 'PBE-SHA1-RC2-64' *)
     144,    (* 'PBE-SHA1-RC4-128' *)
     145,    (* 'PBE-SHA1-RC4-40' *)
     161,    (* 'PBES2' *)
      69,    (* 'PBKDF2' *)
     162,    (* 'PBMAC1' *)
     127,    (* 'PKIX' *)
     935,    (* 'PSPECIFIED' *)
    1061,    (* 'Poly1305' *)
      98,    (* 'RC2-40-CBC' *)
     166,    (* 'RC2-64-CBC' *)
      37,    (* 'RC2-CBC' *)
      39,    (* 'RC2-CFB' *)
      38,    (* 'RC2-ECB' *)
      40,    (* 'RC2-OFB' *)
       5,    (* 'RC4' *)
      97,    (* 'RC4-40' *)
     915,    (* 'RC4-HMAC-MD5' *)
     120,    (* 'RC5-CBC' *)
     122,    (* 'RC5-CFB' *)
     121,    (* 'RC5-ECB' *)
     123,    (* 'RC5-OFB' *)
     117,    (* 'RIPEMD160' *)
      19,    (* 'RSA' *)
       7,    (* 'RSA-MD2' *)
     396,    (* 'RSA-MD4' *)
       8,    (* 'RSA-MD5' *)
      96,    (* 'RSA-MDC2' *)
     104,    (* 'RSA-NP-MD5' *)
     119,    (* 'RSA-RIPEMD160' *)
      42,    (* 'RSA-SHA' *)
      65,    (* 'RSA-SHA1' *)
     115,    (* 'RSA-SHA1-2' *)
     671,    (* 'RSA-SHA224' *)
     668,    (* 'RSA-SHA256' *)
     669,    (* 'RSA-SHA384' *)
     670,    (* 'RSA-SHA512' *)
    1145,    (* 'RSA-SHA512/224' *)
    1146,    (* 'RSA-SHA512/256' *)
    1144,    (* 'RSA-SM3' *)
     919,    (* 'RSAES-OAEP' *)
     912,    (* 'RSASSA-PSS' *)
     777,    (* 'SEED-CBC' *)
     779,    (* 'SEED-CFB' *)
     776,    (* 'SEED-ECB' *)
     778,    (* 'SEED-OFB' *)
      41,    (* 'SHA' *)
      64,    (* 'SHA1' *)
     675,    (* 'SHA224' *)
     672,    (* 'SHA256' *)
    1096,    (* 'SHA3-224' *)
    1097,    (* 'SHA3-256' *)
    1098,    (* 'SHA3-384' *)
    1099,    (* 'SHA3-512' *)
     673,    (* 'SHA384' *)
     674,    (* 'SHA512' *)
    1094,    (* 'SHA512-224' *)
    1095,    (* 'SHA512-256' *)
    1100,    (* 'SHAKE128' *)
    1101,    (* 'SHAKE256' *)
    1172,    (* 'SM2' *)
    1204,    (* 'SM2-SM3' *)
    1143,    (* 'SM3' *)
    1134,    (* 'SM4-CBC' *)
    1249,    (* 'SM4-CCM' *)
    1137,    (* 'SM4-CFB' *)
    1136,    (* 'SM4-CFB1' *)
    1138,    (* 'SM4-CFB8' *)
    1139,    (* 'SM4-CTR' *)
    1133,    (* 'SM4-ECB' *)
    1248,    (* 'SM4-GCM' *)
    1135,    (* 'SM4-OFB' *)
     188,    (* 'SMIME' *)
     167,    (* 'SMIME-CAPS' *)
     100,    (* 'SN' *)
    1006,    (* 'SNILS' *)
    1203,    (* 'SSHKDF' *)
    1205,    (* 'SSKDF' *)
      16,    (* 'ST' *)
     143,    (* 'SXNetID' *)
    1062,    (* 'SipHash' *)
    1021,    (* 'TLS1-PRF' *)
     458,    (* 'UID' *)
       0,    (* 'UNDEF' *)
    1034,    (* 'X25519' *)
    1035,    (* 'X448' *)
      11,    (* 'X500' *)
     378,    (* 'X500algorithms' *)
      12,    (* 'X509' *)
     184,    (* 'X9-57' *)
    1207,    (* 'X942KDF' *)
    1206,    (* 'X963KDF' *)
     185,    (* 'X9cm' *)
     125,    (* 'ZLIB' *)
     478,    (* 'aRecord' *)
     289,    (* 'aaControls' *)
     287,    (* 'ac-auditEntity' *)
     397,    (* 'ac-proxying' *)
     288,    (* 'ac-targeting' *)
     368,    (* 'acceptableResponses' *)
     446,    (* 'account' *)
     363,    (* 'ad_timestamping' *)
     376,    (* 'algorithm' *)
     405,    (* 'ansi-X9-62' *)
     910,    (* 'anyExtendedKeyUsage' *)
     746,    (* 'anyPolicy' *)
     370,    (* 'archiveCutoff' *)
     484,    (* 'associatedDomain' *)
     485,    (* 'associatedName' *)
     501,    (* 'audio' *)
     177,    (* 'authorityInfoAccess' *)
      90,    (* 'authorityKeyIdentifier' *)
     882,    (* 'authorityRevocationList' *)
      87,    (* 'basicConstraints' *)
     365,    (* 'basicOCSPResponse' *)
     285,    (* 'biometricInfo' *)
     921,    (* 'brainpoolP160r1' *)
     922,    (* 'brainpoolP160t1' *)
     923,    (* 'brainpoolP192r1' *)
     924,    (* 'brainpoolP192t1' *)
     925,    (* 'brainpoolP224r1' *)
     926,    (* 'brainpoolP224t1' *)
     927,    (* 'brainpoolP256r1' *)
     928,    (* 'brainpoolP256t1' *)
     929,    (* 'brainpoolP320r1' *)
     930,    (* 'brainpoolP320t1' *)
     931,    (* 'brainpoolP384r1' *)
     932,    (* 'brainpoolP384t1' *)
     933,    (* 'brainpoolP512r1' *)
     934,    (* 'brainpoolP512t1' *)
     494,    (* 'buildingName' *)
     860,    (* 'businessCategory' *)
     691,    (* 'c2onb191v4' *)
     692,    (* 'c2onb191v5' *)
     697,    (* 'c2onb239v4' *)
     698,    (* 'c2onb239v5' *)
     684,    (* 'c2pnb163v1' *)
     685,    (* 'c2pnb163v2' *)
     686,    (* 'c2pnb163v3' *)
     687,    (* 'c2pnb176v1' *)
     693,    (* 'c2pnb208w1' *)
     699,    (* 'c2pnb272w1' *)
     700,    (* 'c2pnb304w1' *)
     702,    (* 'c2pnb368w1' *)
     688,    (* 'c2tnb191v1' *)
     689,    (* 'c2tnb191v2' *)
     690,    (* 'c2tnb191v3' *)
     694,    (* 'c2tnb239v1' *)
     695,    (* 'c2tnb239v2' *)
     696,    (* 'c2tnb239v3' *)
     701,    (* 'c2tnb359v1' *)
     703,    (* 'c2tnb431r1' *)
    1090,    (* 'c3' *)
     881,    (* 'cACertificate' *)
     483,    (* 'cNAMERecord' *)
     179,    (* 'caIssuers' *)
     785,    (* 'caRepository' *)
    1023,    (* 'capwapAC' *)
    1024,    (* 'capwapWTP' *)
     443,    (* 'caseIgnoreIA5StringSyntax' *)
     152,    (* 'certBag' *)
     677,    (* 'certicom-arc' *)
     771,    (* 'certificateIssuer' *)
      89,    (* 'certificatePolicies' *)
     883,    (* 'certificateRevocationList' *)
      54,    (* 'challengePassword' *)
     407,    (* 'characteristic-two-field' *)
    1227,    (* 'classSignTool' *)
    1233,    (* 'classSignToolKA1' *)
    1231,    (* 'classSignToolKB1' *)
    1232,    (* 'classSignToolKB2' *)
    1228,    (* 'classSignToolKC1' *)
    1229,    (* 'classSignToolKC2' *)
    1230,    (* 'classSignToolKC3' *)
     395,    (* 'clearance' *)
     130,    (* 'clientAuth' *)
    1222,    (* 'cmKGA' *)
    1219,    (* 'cmcArchive' *)
    1131,    (* 'cmcCA' *)
    1132,    (* 'cmcRA' *)
     131,    (* 'codeSigning' *)
      50,    (* 'contentType' *)
      53,    (* 'countersignature' *)
     153,    (* 'crlBag' *)
     103,    (* 'crlDistributionPoints' *)
      88,    (* 'crlNumber' *)
     884,    (* 'crossCertificatePair' *)
     806,    (* 'cryptocom' *)
     805,    (* 'cryptopro' *)
     954,    (* 'ct_cert_scts' *)
     952,    (* 'ct_precert_poison' *)
     951,    (* 'ct_precert_scts' *)
     953,    (* 'ct_precert_signer' *)
     500,    (* 'dITRedirect' *)
     451,    (* 'dNSDomain' *)
     495,    (* 'dSAQuality' *)
     434,    (* 'data' *)
     390,    (* 'dcobject' *)
     140,    (* 'deltaCRL' *)
     891,    (* 'deltaRevocationList' *)
     107,    (* 'description' *)
     871,    (* 'destinationIndicator' *)
     947,    (* 'dh-cofactor-kdf' *)
     946,    (* 'dh-std-kdf' *)
      28,    (* 'dhKeyAgreement' *)
     941,    (* 'dhSinglePass-cofactorDH-sha1kdf-scheme' *)
     942,    (* 'dhSinglePass-cofactorDH-sha224kdf-scheme' *)
     943,    (* 'dhSinglePass-cofactorDH-sha256kdf-scheme' *)
     944,    (* 'dhSinglePass-cofactorDH-sha384kdf-scheme' *)
     945,    (* 'dhSinglePass-cofactorDH-sha512kdf-scheme' *)
     936,    (* 'dhSinglePass-stdDH-sha1kdf-scheme' *)
     937,    (* 'dhSinglePass-stdDH-sha224kdf-scheme' *)
     938,    (* 'dhSinglePass-stdDH-sha256kdf-scheme' *)
     939,    (* 'dhSinglePass-stdDH-sha384kdf-scheme' *)
     940,    (* 'dhSinglePass-stdDH-sha512kdf-scheme' *)
     920,    (* 'dhpublicnumber' *)
     382,    (* 'directory' *)
     887,    (* 'distinguishedName' *)
     892,    (* 'dmdName' *)
     174,    (* 'dnQualifier' *)
    1092,    (* 'dnsName' *)
     447,    (* 'document' *)
     471,    (* 'documentAuthor' *)
     468,    (* 'documentIdentifier' *)
     472,    (* 'documentLocation' *)
     502,    (* 'documentPublisher' *)
     449,    (* 'documentSeries' *)
     469,    (* 'documentTitle' *)
     470,    (* 'documentVersion' *)
     392,    (* 'domain' *)
     452,    (* 'domainRelatedObject' *)
     802,    (* 'dsa_with_SHA224' *)
     803,    (* 'dsa_with_SHA256' *)
    1152,    (* 'dstu28147' *)
    1154,    (* 'dstu28147-cfb' *)
    1153,    (* 'dstu28147-ofb' *)
    1155,    (* 'dstu28147-wrap' *)
    1157,    (* 'dstu34311' *)
    1159,    (* 'dstu4145be' *)
    1158,    (* 'dstu4145le' *)
     791,    (* 'ecdsa-with-Recommended' *)
     416,    (* 'ecdsa-with-SHA1' *)
     793,    (* 'ecdsa-with-SHA224' *)
     794,    (* 'ecdsa-with-SHA256' *)
     795,    (* 'ecdsa-with-SHA384' *)
     796,    (* 'ecdsa-with-SHA512' *)
     792,    (* 'ecdsa-with-Specified' *)
      48,    (* 'emailAddress' *)
     132,    (* 'emailProtection' *)
     885,    (* 'enhancedSearchGuide' *)
     389,    (* 'enterprises' *)
     384,    (* 'experimental' *)
     172,    (* 'extReq' *)
      56,    (* 'extendedCertificateAttributes' *)
     126,    (* 'extendedKeyUsage' *)
     372,    (* 'extendedStatus' *)
     867,    (* 'facsimileTelephoneNumber' *)
     462,    (* 'favouriteDrink' *)
    1126,    (* 'ffdhe2048' *)
    1127,    (* 'ffdhe3072' *)
    1128,    (* 'ffdhe4096' *)
    1129,    (* 'ffdhe6144' *)
    1130,    (* 'ffdhe8192' *)
     857,    (* 'freshestCRL' *)
     453,    (* 'friendlyCountry' *)
     490,    (* 'friendlyCountryName' *)
     156,    (* 'friendlyName' *)
     509,    (* 'generationQualifier' *)
     815,    (* 'gost-mac' *)
     976,    (* 'gost-mac-12' *)
     811,    (* 'gost2001' *)
     851,    (* 'gost2001cc' *)
     979,    (* 'gost2012_256' *)
     980,    (* 'gost2012_512' *)
     813,    (* 'gost89' *)
    1009,    (* 'gost89-cbc' *)
     814,    (* 'gost89-cnt' *)
     975,    (* 'gost89-cnt-12' *)
    1011,    (* 'gost89-ctr' *)
    1010,    (* 'gost89-ecb' *)
     812,    (* 'gost94' *)
     850,    (* 'gost94cc' *)
    1156,    (* 'hmacWithDstu34311' *)
     797,    (* 'hmacWithMD5' *)
     163,    (* 'hmacWithSHA1' *)
     798,    (* 'hmacWithSHA224' *)
     799,    (* 'hmacWithSHA256' *)
     800,    (* 'hmacWithSHA384' *)
     801,    (* 'hmacWithSHA512' *)
    1193,    (* 'hmacWithSHA512-224' *)
    1194,    (* 'hmacWithSHA512-256' *)
     432,    (* 'holdInstructionCallIssuer' *)
     430,    (* 'holdInstructionCode' *)
     431,    (* 'holdInstructionNone' *)
     433,    (* 'holdInstructionReject' *)
     486,    (* 'homePostalAddress' *)
     473,    (* 'homeTelephoneNumber' *)
     466,    (* 'host' *)
     889,    (* 'houseIdentifier' *)
     442,    (* 'iA5StringSyntax' *)
     783,    (* 'id-DHBasedMac' *)
     824,    (* 'id-Gost28147-89-CryptoPro-A-ParamSet' *)
     825,    (* 'id-Gost28147-89-CryptoPro-B-ParamSet' *)
     826,    (* 'id-Gost28147-89-CryptoPro-C-ParamSet' *)
     827,    (* 'id-Gost28147-89-CryptoPro-D-ParamSet' *)
     819,    (* 'id-Gost28147-89-CryptoPro-KeyMeshing' *)
     829,    (* 'id-Gost28147-89-CryptoPro-Oscar-1-0-ParamSet' *)
     828,    (* 'id-Gost28147-89-CryptoPro-Oscar-1-1-ParamSet' *)
     830,    (* 'id-Gost28147-89-CryptoPro-RIC-1-ParamSet' *)
     820,    (* 'id-Gost28147-89-None-KeyMeshing' *)
     823,    (* 'id-Gost28147-89-TestParamSet' *)
     849,    (* 'id-Gost28147-89-cc' *)
     840,    (* 'id-GostR3410-2001-CryptoPro-A-ParamSet' *)
     841,    (* 'id-GostR3410-2001-CryptoPro-B-ParamSet' *)
     842,    (* 'id-GostR3410-2001-CryptoPro-C-ParamSet' *)
     843,    (* 'id-GostR3410-2001-CryptoPro-XchA-ParamSet' *)
     844,    (* 'id-GostR3410-2001-CryptoPro-XchB-ParamSet' *)
     854,    (* 'id-GostR3410-2001-ParamSet-cc' *)
     839,    (* 'id-GostR3410-2001-TestParamSet' *)
     817,    (* 'id-GostR3410-2001DH' *)
     832,    (* 'id-GostR3410-94-CryptoPro-A-ParamSet' *)
     833,    (* 'id-GostR3410-94-CryptoPro-B-ParamSet' *)
     834,    (* 'id-GostR3410-94-CryptoPro-C-ParamSet' *)
     835,    (* 'id-GostR3410-94-CryptoPro-D-ParamSet' *)
     836,    (* 'id-GostR3410-94-CryptoPro-XchA-ParamSet' *)
     837,    (* 'id-GostR3410-94-CryptoPro-XchB-ParamSet' *)
     838,    (* 'id-GostR3410-94-CryptoPro-XchC-ParamSet' *)
     831,    (* 'id-GostR3410-94-TestParamSet' *)
     845,    (* 'id-GostR3410-94-a' *)
     846,    (* 'id-GostR3410-94-aBis' *)
     847,    (* 'id-GostR3410-94-b' *)
     848,    (* 'id-GostR3410-94-bBis' *)
     818,    (* 'id-GostR3410-94DH' *)
     822,    (* 'id-GostR3411-94-CryptoProParamSet' *)
     821,    (* 'id-GostR3411-94-TestParamSet' *)
     807,    (* 'id-GostR3411-94-with-GostR3410-2001' *)
     853,    (* 'id-GostR3411-94-with-GostR3410-2001-cc' *)
     808,    (* 'id-GostR3411-94-with-GostR3410-94' *)
     852,    (* 'id-GostR3411-94-with-GostR3410-94-cc' *)
     810,    (* 'id-HMACGostR3411-94' *)
     782,    (* 'id-PasswordBasedMAC' *)
     266,    (* 'id-aca' *)
     355,    (* 'id-aca-accessIdentity' *)
     354,    (* 'id-aca-authenticationInfo' *)
     356,    (* 'id-aca-chargingIdentity' *)
     399,    (* 'id-aca-encAttrs' *)
     357,    (* 'id-aca-group' *)
     358,    (* 'id-aca-role' *)
     176,    (* 'id-ad' *)
     896,    (* 'id-aes128-CCM' *)
     895,    (* 'id-aes128-GCM' *)
     788,    (* 'id-aes128-wrap' *)
     897,    (* 'id-aes128-wrap-pad' *)
     899,    (* 'id-aes192-CCM' *)
     898,    (* 'id-aes192-GCM' *)
     789,    (* 'id-aes192-wrap' *)
     900,    (* 'id-aes192-wrap-pad' *)
     902,    (* 'id-aes256-CCM' *)
     901,    (* 'id-aes256-GCM' *)
     790,    (* 'id-aes256-wrap' *)
     903,    (* 'id-aes256-wrap-pad' *)
     262,    (* 'id-alg' *)
     893,    (* 'id-alg-PWRI-KEK' *)
     323,    (* 'id-alg-des40' *)
     326,    (* 'id-alg-dh-pop' *)
     325,    (* 'id-alg-dh-sig-hmac-sha1' *)
     324,    (* 'id-alg-noSignature' *)
     907,    (* 'id-camellia128-wrap' *)
     908,    (* 'id-camellia192-wrap' *)
     909,    (* 'id-camellia256-wrap' *)
     268,    (* 'id-cct' *)
     361,    (* 'id-cct-PKIData' *)
     362,    (* 'id-cct-PKIResponse' *)
     360,    (* 'id-cct-crs' *)
      81,    (* 'id-ce' *)
     680,    (* 'id-characteristic-two-basis' *)
     263,    (* 'id-cmc' *)
     334,    (* 'id-cmc-addExtensions' *)
     346,    (* 'id-cmc-confirmCertAcceptance' *)
     330,    (* 'id-cmc-dataReturn' *)
     336,    (* 'id-cmc-decryptedPOP' *)
     335,    (* 'id-cmc-encryptedPOP' *)
     339,    (* 'id-cmc-getCRL' *)
     338,    (* 'id-cmc-getCert' *)
     328,    (* 'id-cmc-identification' *)
     329,    (* 'id-cmc-identityProof' *)
     337,    (* 'id-cmc-lraPOPWitness' *)
     344,    (* 'id-cmc-popLinkRandom' *)
     345,    (* 'id-cmc-popLinkWitness' *)
     343,    (* 'id-cmc-queryPending' *)
     333,    (* 'id-cmc-recipientNonce' *)
     341,    (* 'id-cmc-regInfo' *)
     342,    (* 'id-cmc-responseInfo' *)
     340,    (* 'id-cmc-revokeRequest' *)
     332,    (* 'id-cmc-senderNonce' *)
     327,    (* 'id-cmc-statusInfo' *)
     331,    (* 'id-cmc-transactionId' *)
    1238,    (* 'id-cp' *)
    1250,    (* 'id-ct-ASPA' *)
     787,    (* 'id-ct-asciiTextWithCRLF' *)
    1246,    (* 'id-ct-geofeedCSVwithCRLF' *)
    1237,    (* 'id-ct-resourceTaggedAttest' *)
    1234,    (* 'id-ct-routeOriginAuthz' *)
    1236,    (* 'id-ct-rpkiGhostbusters' *)
    1235,    (* 'id-ct-rpkiManifest' *)
    1247,    (* 'id-ct-signedChecklist' *)
    1060,    (* 'id-ct-xml' *)
    1108,    (* 'id-dsa-with-sha3-224' *)
    1109,    (* 'id-dsa-with-sha3-256' *)
    1110,    (* 'id-dsa-with-sha3-384' *)
    1111,    (* 'id-dsa-with-sha3-512' *)
    1106,    (* 'id-dsa-with-sha384' *)
    1107,    (* 'id-dsa-with-sha512' *)
     408,    (* 'id-ecPublicKey' *)
    1112,    (* 'id-ecdsa-with-sha3-224' *)
    1113,    (* 'id-ecdsa-with-sha3-256' *)
    1114,    (* 'id-ecdsa-with-sha3-384' *)
    1115,    (* 'id-ecdsa-with-sha3-512' *)
     508,    (* 'id-hex-multipart-message' *)
     507,    (* 'id-hex-partial-message' *)
    1102,    (* 'id-hmacWithSHA3-224' *)
    1103,    (* 'id-hmacWithSHA3-256' *)
    1104,    (* 'id-hmacWithSHA3-384' *)
    1105,    (* 'id-hmacWithSHA3-512' *)
     260,    (* 'id-it' *)
    1223,    (* 'id-it-caCerts' *)
     302,    (* 'id-it-caKeyUpdateInfo' *)
     298,    (* 'id-it-caProtEncCert' *)
    1225,    (* 'id-it-certReqTemplate' *)
     311,    (* 'id-it-confirmWaitTime' *)
     303,    (* 'id-it-currentCRL' *)
     300,    (* 'id-it-encKeyPairTypes' *)
     310,    (* 'id-it-implicitConfirm' *)
     308,    (* 'id-it-keyPairParamRep' *)
     307,    (* 'id-it-keyPairParamReq' *)
     312,    (* 'id-it-origPKIMessage' *)
     301,    (* 'id-it-preferredSymmAlg' *)
     309,    (* 'id-it-revPassphrase' *)
    1224,    (* 'id-it-rootCaKeyUpdate' *)
     299,    (* 'id-it-signKeyPairTypes' *)
     305,    (* 'id-it-subscriptionRequest' *)
     306,    (* 'id-it-subscriptionResponse' *)
     784,    (* 'id-it-suppLangTags' *)
     304,    (* 'id-it-unsupportedOIDs' *)
     128,    (* 'id-kp' *)
    1221,    (* 'id-kp-BrandIndicatorforMessageIdentification' *)
    1220,    (* 'id-kp-bgpsec-router' *)
     280,    (* 'id-mod-attribute-cert' *)
     274,    (* 'id-mod-cmc' *)
     277,    (* 'id-mod-cmp' *)
     284,    (* 'id-mod-cmp2000' *)
     273,    (* 'id-mod-crmf' *)
     283,    (* 'id-mod-dvcs' *)
     275,    (* 'id-mod-kea-profile-88' *)
     276,    (* 'id-mod-kea-profile-93' *)
     282,    (* 'id-mod-ocsp' *)
     278,    (* 'id-mod-qualified-cert-88' *)
     279,    (* 'id-mod-qualified-cert-93' *)
     281,    (* 'id-mod-timestamp-protocol' *)
     264,    (* 'id-on' *)
    1211,    (* 'id-on-NAIRealm' *)
    1208,    (* 'id-on-SmtpUTF8Mailbox' *)
    1210,    (* 'id-on-dnsSRV' *)
     858,    (* 'id-on-permanentIdentifier' *)
     347,    (* 'id-on-personalData' *)
    1209,    (* 'id-on-xmppAddr' *)
     265,    (* 'id-pda' *)
     352,    (* 'id-pda-countryOfCitizenship' *)
     353,    (* 'id-pda-countryOfResidence' *)
     348,    (* 'id-pda-dateOfBirth' *)
     351,    (* 'id-pda-gender' *)
     349,    (* 'id-pda-placeOfBirth' *)
     175,    (* 'id-pe' *)
    1031,    (* 'id-pkinit' *)
     261,    (* 'id-pkip' *)
     258,    (* 'id-pkix-mod' *)
     269,    (* 'id-pkix1-explicit-88' *)
     271,    (* 'id-pkix1-explicit-93' *)
     270,    (* 'id-pkix1-implicit-88' *)
     272,    (* 'id-pkix1-implicit-93' *)
     662,    (* 'id-ppl' *)
     664,    (* 'id-ppl-anyLanguage' *)
     667,    (* 'id-ppl-independent' *)
     665,    (* 'id-ppl-inheritAll' *)
     267,    (* 'id-qcs' *)
     359,    (* 'id-qcs-pkixQCSyntax-v1' *)
     259,    (* 'id-qt' *)
     164,    (* 'id-qt-cps' *)
     165,    (* 'id-qt-unotice' *)
     313,    (* 'id-regCtrl' *)
     316,    (* 'id-regCtrl-authenticator' *)
     319,    (* 'id-regCtrl-oldCertID' *)
     318,    (* 'id-regCtrl-pkiArchiveOptions' *)
     317,    (* 'id-regCtrl-pkiPublicationInfo' *)
     320,    (* 'id-regCtrl-protocolEncrKey' *)
     315,    (* 'id-regCtrl-regToken' *)
     314,    (* 'id-regInfo' *)
     322,    (* 'id-regInfo-certReq' *)
     321,    (* 'id-regInfo-utf8Pairs' *)
    1116,    (* 'id-rsassa-pkcs1-v1_5-with-sha3-224' *)
    1117,    (* 'id-rsassa-pkcs1-v1_5-with-sha3-256' *)
    1118,    (* 'id-rsassa-pkcs1-v1_5-with-sha3-384' *)
    1119,    (* 'id-rsassa-pkcs1-v1_5-with-sha3-512' *)
     973,    (* 'id-scrypt' *)
     512,    (* 'id-set' *)
     191,    (* 'id-smime-aa' *)
     215,    (* 'id-smime-aa-contentHint' *)
     218,    (* 'id-smime-aa-contentIdentifier' *)
     221,    (* 'id-smime-aa-contentReference' *)
     240,    (* 'id-smime-aa-dvcs-dvc' *)
     217,    (* 'id-smime-aa-encapContentType' *)
     222,    (* 'id-smime-aa-encrypKeyPref' *)
     220,    (* 'id-smime-aa-equivalentLabels' *)
     232,    (* 'id-smime-aa-ets-CertificateRefs' *)
     233,    (* 'id-smime-aa-ets-RevocationRefs' *)
     238,    (* 'id-smime-aa-ets-archiveTimeStamp' *)
     237,    (* 'id-smime-aa-ets-certCRLTimestamp' *)
     234,    (* 'id-smime-aa-ets-certValues' *)
     227,    (* 'id-smime-aa-ets-commitmentType' *)
     231,    (* 'id-smime-aa-ets-contentTimestamp' *)
     236,    (* 'id-smime-aa-ets-escTimeStamp' *)
     230,    (* 'id-smime-aa-ets-otherSigCert' *)
     235,    (* 'id-smime-aa-ets-revocationValues' *)
     226,    (* 'id-smime-aa-ets-sigPolicyId' *)
     229,    (* 'id-smime-aa-ets-signerAttr' *)
     228,    (* 'id-smime-aa-ets-signerLocation' *)
     219,    (* 'id-smime-aa-macValue' *)
     214,    (* 'id-smime-aa-mlExpandHistory' *)
     216,    (* 'id-smime-aa-msgSigDigest' *)
     212,    (* 'id-smime-aa-receiptRequest' *)
     213,    (* 'id-smime-aa-securityLabel' *)
     239,    (* 'id-smime-aa-signatureType' *)
     223,    (* 'id-smime-aa-signingCertificate' *)
    1086,    (* 'id-smime-aa-signingCertificateV2' *)
     224,    (* 'id-smime-aa-smimeEncryptCerts' *)
     225,    (* 'id-smime-aa-timeStampToken' *)
     192,    (* 'id-smime-alg' *)
     243,    (* 'id-smime-alg-3DESwrap' *)
     246,    (* 'id-smime-alg-CMS3DESwrap' *)
     247,    (* 'id-smime-alg-CMSRC2wrap' *)
     245,    (* 'id-smime-alg-ESDH' *)
     241,    (* 'id-smime-alg-ESDHwith3DES' *)
     242,    (* 'id-smime-alg-ESDHwithRC2' *)
     244,    (* 'id-smime-alg-RC2wrap' *)
     193,    (* 'id-smime-cd' *)
     248,    (* 'id-smime-cd-ldap' *)
     190,    (* 'id-smime-ct' *)
     210,    (* 'id-smime-ct-DVCSRequestData' *)
     211,    (* 'id-smime-ct-DVCSResponseData' *)
     208,    (* 'id-smime-ct-TDTInfo' *)
     207,    (* 'id-smime-ct-TSTInfo' *)
     205,    (* 'id-smime-ct-authData' *)
    1059,    (* 'id-smime-ct-authEnvelopedData' *)
     786,    (* 'id-smime-ct-compressedData' *)
    1058,    (* 'id-smime-ct-contentCollection' *)
     209,    (* 'id-smime-ct-contentInfo' *)
     206,    (* 'id-smime-ct-publishCert' *)
     204,    (* 'id-smime-ct-receipt' *)
     195,    (* 'id-smime-cti' *)
     255,    (* 'id-smime-cti-ets-proofOfApproval' *)
     256,    (* 'id-smime-cti-ets-proofOfCreation' *)
     253,    (* 'id-smime-cti-ets-proofOfDelivery' *)
     251,    (* 'id-smime-cti-ets-proofOfOrigin' *)
     252,    (* 'id-smime-cti-ets-proofOfReceipt' *)
     254,    (* 'id-smime-cti-ets-proofOfSender' *)
     189,    (* 'id-smime-mod' *)
     196,    (* 'id-smime-mod-cms' *)
     197,    (* 'id-smime-mod-ess' *)
     202,    (* 'id-smime-mod-ets-eSigPolicy-88' *)
     203,    (* 'id-smime-mod-ets-eSigPolicy-97' *)
     200,    (* 'id-smime-mod-ets-eSignature-88' *)
     201,    (* 'id-smime-mod-ets-eSignature-97' *)
     199,    (* 'id-smime-mod-msg-v3' *)
     198,    (* 'id-smime-mod-oid' *)
     194,    (* 'id-smime-spq' *)
     250,    (* 'id-smime-spq-ets-sqt-unotice' *)
     249,    (* 'id-smime-spq-ets-sqt-uri' *)
     974,    (* 'id-tc26' *)
     991,    (* 'id-tc26-agreement' *)
     992,    (* 'id-tc26-agreement-gost-3410-2012-256' *)
     993,    (* 'id-tc26-agreement-gost-3410-2012-512' *)
     977,    (* 'id-tc26-algorithms' *)
     990,    (* 'id-tc26-cipher' *)
    1001,    (* 'id-tc26-cipher-constants' *)
    1176,    (* 'id-tc26-cipher-gostr3412-2015-kuznyechik' *)
    1173,    (* 'id-tc26-cipher-gostr3412-2015-magma' *)
     994,    (* 'id-tc26-constants' *)
     981,    (* 'id-tc26-digest' *)
    1000,    (* 'id-tc26-digest-constants' *)
    1002,    (* 'id-tc26-gost-28147-constants' *)
    1003,    (* 'id-tc26-gost-28147-param-Z' *)
    1147,    (* 'id-tc26-gost-3410-2012-256-constants' *)
    1148,    (* 'id-tc26-gost-3410-2012-256-paramSetA' *)
    1184,    (* 'id-tc26-gost-3410-2012-256-paramSetB' *)
    1185,    (* 'id-tc26-gost-3410-2012-256-paramSetC' *)
    1186,    (* 'id-tc26-gost-3410-2012-256-paramSetD' *)
     996,    (* 'id-tc26-gost-3410-2012-512-constants' *)
     998,    (* 'id-tc26-gost-3410-2012-512-paramSetA' *)
     999,    (* 'id-tc26-gost-3410-2012-512-paramSetB' *)
    1149,    (* 'id-tc26-gost-3410-2012-512-paramSetC' *)
     997,    (* 'id-tc26-gost-3410-2012-512-paramSetTest' *)
     988,    (* 'id-tc26-hmac-gost-3411-2012-256' *)
     989,    (* 'id-tc26-hmac-gost-3411-2012-512' *)
     987,    (* 'id-tc26-mac' *)
     978,    (* 'id-tc26-sign' *)
     995,    (* 'id-tc26-sign-constants' *)
     984,    (* 'id-tc26-signwithdigest' *)
     985,    (* 'id-tc26-signwithdigest-gost3410-2012-256' *)
     986,    (* 'id-tc26-signwithdigest-gost3410-2012-512' *)
    1179,    (* 'id-tc26-wrap' *)
    1182,    (* 'id-tc26-wrap-gostr3412-2015-kuznyechik' *)
    1180,    (* 'id-tc26-wrap-gostr3412-2015-magma' *)
     676,    (* 'identified-organization' *)
    1170,    (* 'ieee' *)
    1171,    (* 'ieee-siswg' *)
     461,    (* 'info' *)
     748,    (* 'inhibitAnyPolicy' *)
     101,    (* 'initials' *)
     647,    (* 'international-organizations' *)
     869,    (* 'internationaliSDNNumber' *)
     142,    (* 'invalidityDate' *)
    1241,    (* 'ipAddr-asNumber' *)
    1242,    (* 'ipAddr-asNumberv2' *)
     294,    (* 'ipsecEndSystem' *)
    1022,    (* 'ipsecIKE' *)
     295,    (* 'ipsecTunnel' *)
     296,    (* 'ipsecUser' *)
      86,    (* 'issuerAltName' *)
    1008,    (* 'issuerSignTool' *)
     770,    (* 'issuingDistributionPoint' *)
     492,    (* 'janetMailbox' *)
     957,    (* 'jurisdictionC' *)
     955,    (* 'jurisdictionL' *)
     956,    (* 'jurisdictionST' *)
     150,    (* 'keyBag' *)
      83,    (* 'keyUsage' *)
    1015,    (* 'kuznyechik-cbc' *)
    1016,    (* 'kuznyechik-cfb' *)
    1013,    (* 'kuznyechik-ctr' *)
    1177,    (* 'kuznyechik-ctr-acpkm' *)
    1178,    (* 'kuznyechik-ctr-acpkm-omac' *)
    1012,    (* 'kuznyechik-ecb' *)
    1183,    (* 'kuznyechik-kexp15' *)
    1017,    (* 'kuznyechik-mac' *)
    1014,    (* 'kuznyechik-ofb' *)
     477,    (* 'lastModifiedBy' *)
     476,    (* 'lastModifiedTime' *)
     157,    (* 'localKeyID' *)
     480,    (* 'mXRecord' *)
    1190,    (* 'magma-cbc' *)
    1191,    (* 'magma-cfb' *)
    1188,    (* 'magma-ctr' *)
    1174,    (* 'magma-ctr-acpkm' *)
    1175,    (* 'magma-ctr-acpkm-omac' *)
    1187,    (* 'magma-ecb' *)
    1181,    (* 'magma-kexp15' *)
    1192,    (* 'magma-mac' *)
    1189,    (* 'magma-ofb' *)
     460,    (* 'mail' *)
     493,    (* 'mailPreferenceOption' *)
     467,    (* 'manager' *)
     982,    (* 'md_gost12_256' *)
     983,    (* 'md_gost12_512' *)
     809,    (* 'md_gost94' *)
     875,    (* 'member' *)
     182,    (* 'member-body' *)
      51,    (* 'messageDigest' *)
     383,    (* 'mgmt' *)
     504,    (* 'mime-mhs' *)
     506,    (* 'mime-mhs-bodies' *)
     505,    (* 'mime-mhs-headings' *)
     488,    (* 'mobileTelephoneNumber' *)
    1212,    (* 'modp_1536' *)
    1213,    (* 'modp_2048' *)
    1214,    (* 'modp_3072' *)
    1215,    (* 'modp_4096' *)
    1216,    (* 'modp_6144' *)
    1217,    (* 'modp_8192' *)
     136,    (* 'msCTLSign' *)
     135,    (* 'msCodeCom' *)
     134,    (* 'msCodeInd' *)
     138,    (* 'msEFS' *)
     171,    (* 'msExtReq' *)
     137,    (* 'msSGC' *)
     648,    (* 'msSmartcardLogin' *)
     649,    (* 'msUPN' *)
    1091,    (* 'n3' *)
     481,    (* 'nSRecord' *)
     173,    (* 'name' *)
     666,    (* 'nameConstraints' *)
     369,    (* 'noCheck' *)
     403,    (* 'noRevAvail' *)
      72,    (* 'nsBaseUrl' *)
      76,    (* 'nsCaPolicyUrl' *)
      74,    (* 'nsCaRevocationUrl' *)
      58,    (* 'nsCertExt' *)
      79,    (* 'nsCertSequence' *)
      71,    (* 'nsCertType' *)
      78,    (* 'nsComment' *)
      59,    (* 'nsDataType' *)
      75,    (* 'nsRenewalUrl' *)
      73,    (* 'nsRevocationUrl' *)
     139,    (* 'nsSGC' *)
      77,    (* 'nsSslServerName' *)
     681,    (* 'onBasis' *)
    1089,    (* 'organizationIdentifier' *)
     491,    (* 'organizationalStatus' *)
    1141,    (* 'oscca' *)
     475,    (* 'otherMailbox' *)
     876,    (* 'owner' *)
     489,    (* 'pagerTelephoneNumber' *)
     374,    (* 'path' *)
     112,    (* 'pbeWithMD5AndCast5CBC' *)
     499,    (* 'personalSignature' *)
     487,    (* 'personalTitle' *)
     464,    (* 'photo' *)
     863,    (* 'physicalDeliveryOfficeName' *)
     437,    (* 'pilot' *)
     439,    (* 'pilotAttributeSyntax' *)
     438,    (* 'pilotAttributeType' *)
     479,    (* 'pilotAttributeType27' *)
     456,    (* 'pilotDSA' *)
     441,    (* 'pilotGroups' *)
     444,    (* 'pilotObject' *)
     440,    (* 'pilotObjectClass' *)
     455,    (* 'pilotOrganization' *)
     445,    (* 'pilotPerson' *)
    1032,    (* 'pkInitClientAuth' *)
    1033,    (* 'pkInitKDC' *)
       2,    (* 'pkcs' *)
     186,    (* 'pkcs1' *)
      27,    (* 'pkcs3' *)
     187,    (* 'pkcs5' *)
      20,    (* 'pkcs7' *)
      21,    (* 'pkcs7-data' *)
      25,    (* 'pkcs7-digestData' *)
      26,    (* 'pkcs7-encryptedData' *)
      23,    (* 'pkcs7-envelopedData' *)
      24,    (* 'pkcs7-signedAndEnvelopedData' *)
      22,    (* 'pkcs7-signedData' *)
     151,    (* 'pkcs8ShroudedKeyBag' *)
      47,    (* 'pkcs9' *)
     401,    (* 'policyConstraints' *)
     747,    (* 'policyMappings' *)
     862,    (* 'postOfficeBox' *)
     861,    (* 'postalAddress' *)
     661,    (* 'postalCode' *)
     683,    (* 'ppBasis' *)
     872,    (* 'preferredDeliveryMethod' *)
     873,    (* 'presentationAddress' *)
     816,    (* 'prf-gostr3411-94' *)
     406,    (* 'prime-field' *)
     409,    (* 'prime192v1' *)
     410,    (* 'prime192v2' *)
     411,    (* 'prime192v3' *)
     412,    (* 'prime239v1' *)
     413,    (* 'prime239v2' *)
     414,    (* 'prime239v3' *)
     415,    (* 'prime256v1' *)
     385,    (* 'private' *)
      84,    (* 'privateKeyUsagePeriod' *)
     886,    (* 'protocolInformation' *)
     663,    (* 'proxyCertInfo' *)
     510,    (* 'pseudonym' *)
     435,    (* 'pss' *)
     286,    (* 'qcStatements' *)
     457,    (* 'qualityLabelledData' *)
     450,    (* 'rFC822localPart' *)
     870,    (* 'registeredAddress' *)
     400,    (* 'role' *)
     877,    (* 'roleOccupant' *)
     448,    (* 'room' *)
     463,    (* 'roomNumber' *)
    1243,    (* 'rpkiManifest' *)
    1245,    (* 'rpkiNotify' *)
       6,    (* 'rsaEncryption' *)
     644,    (* 'rsaOAEPEncryptionSET' *)
     377,    (* 'rsaSignature' *)
       1,    (* 'rsadsi' *)
     482,    (* 'sOARecord' *)
     155,    (* 'safeContentsBag' *)
     291,    (* 'sbgp-autonomousSysNum' *)
    1240,    (* 'sbgp-autonomousSysNumv2' *)
     290,    (* 'sbgp-ipAddrBlock' *)
    1239,    (* 'sbgp-ipAddrBlockv2' *)
     292,    (* 'sbgp-routerIdentifier' *)
     159,    (* 'sdsiCertificate' *)
     859,    (* 'searchGuide' *)
     704,    (* 'secp112r1' *)
     705,    (* 'secp112r2' *)
     706,    (* 'secp128r1' *)
     707,    (* 'secp128r2' *)
     708,    (* 'secp160k1' *)
     709,    (* 'secp160r1' *)
     710,    (* 'secp160r2' *)
     711,    (* 'secp192k1' *)
     712,    (* 'secp224k1' *)
     713,    (* 'secp224r1' *)
     714,    (* 'secp256k1' *)
     715,    (* 'secp384r1' *)
     716,    (* 'secp521r1' *)
     154,    (* 'secretBag' *)
     474,    (* 'secretary' *)
     717,    (* 'sect113r1' *)
     718,    (* 'sect113r2' *)
     719,    (* 'sect131r1' *)
     720,    (* 'sect131r2' *)
     721,    (* 'sect163k1' *)
     722,    (* 'sect163r1' *)
     723,    (* 'sect163r2' *)
     724,    (* 'sect193r1' *)
     725,    (* 'sect193r2' *)
     726,    (* 'sect233k1' *)
     727,    (* 'sect233r1' *)
     728,    (* 'sect239k1' *)
     729,    (* 'sect283k1' *)
     730,    (* 'sect283r1' *)
     731,    (* 'sect409k1' *)
     732,    (* 'sect409r1' *)
     733,    (* 'sect571k1' *)
     734,    (* 'sect571r1' *)
    1025,    (* 'secureShellClient' *)
    1026,    (* 'secureShellServer' *)
     386,    (* 'security' *)
     878,    (* 'seeAlso' *)
     394,    (* 'selected-attribute-types' *)
    1029,    (* 'sendOwner' *)
    1030,    (* 'sendProxiedOwner' *)
    1028,    (* 'sendProxiedRouter' *)
    1027,    (* 'sendRouter' *)
     105,    (* 'serialNumber' *)
     129,    (* 'serverAuth' *)
     371,    (* 'serviceLocator' *)
     625,    (* 'set-addPolicy' *)
     515,    (* 'set-attr' *)
     518,    (* 'set-brand' *)
     638,    (* 'set-brand-AmericanExpress' *)
     637,    (* 'set-brand-Diners' *)
     636,    (* 'set-brand-IATA-ATA' *)
     639,    (* 'set-brand-JCB' *)
     641,    (* 'set-brand-MasterCard' *)
     642,    (* 'set-brand-Novus' *)
     640,    (* 'set-brand-Visa' *)
     517,    (* 'set-certExt' *)
     513,    (* 'set-ctype' *)
     514,    (* 'set-msgExt' *)
     516,    (* 'set-policy' *)
     607,    (* 'set-policy-root' *)
     624,    (* 'set-rootKeyThumb' *)
     620,    (* 'setAttr-Cert' *)
     631,    (* 'setAttr-GenCryptgrm' *)
     623,    (* 'setAttr-IssCap' *)
     628,    (* 'setAttr-IssCap-CVM' *)
     630,    (* 'setAttr-IssCap-Sig' *)
     629,    (* 'setAttr-IssCap-T2' *)
     621,    (* 'setAttr-PGWYcap' *)
     635,    (* 'setAttr-SecDevSig' *)
     632,    (* 'setAttr-T2Enc' *)
     633,    (* 'setAttr-T2cleartxt' *)
     634,    (* 'setAttr-TokICCsig' *)
     627,    (* 'setAttr-Token-B0Prime' *)
     626,    (* 'setAttr-Token-EMV' *)
     622,    (* 'setAttr-TokenType' *)
     619,    (* 'setCext-IssuerCapabilities' *)
     615,    (* 'setCext-PGWYcapabilities' *)
     616,    (* 'setCext-TokenIdentifier' *)
     618,    (* 'setCext-TokenType' *)
     617,    (* 'setCext-Track2Data' *)
     611,    (* 'setCext-cCertRequired' *)
     609,    (* 'setCext-certType' *)
     608,    (* 'setCext-hashedRoot' *)
     610,    (* 'setCext-merchData' *)
     613,    (* 'setCext-setExt' *)
     614,    (* 'setCext-setQualf' *)
     612,    (* 'setCext-tunneling' *)
     540,    (* 'setct-AcqCardCodeMsg' *)
     576,    (* 'setct-AcqCardCodeMsgTBE' *)
     570,    (* 'setct-AuthReqTBE' *)
     534,    (* 'setct-AuthReqTBS' *)
     527,    (* 'setct-AuthResBaggage' *)
     571,    (* 'setct-AuthResTBE' *)
     572,    (* 'setct-AuthResTBEX' *)
     535,    (* 'setct-AuthResTBS' *)
     536,    (* 'setct-AuthResTBSX' *)
     528,    (* 'setct-AuthRevReqBaggage' *)
     577,    (* 'setct-AuthRevReqTBE' *)
     541,    (* 'setct-AuthRevReqTBS' *)
     529,    (* 'setct-AuthRevResBaggage' *)
     542,    (* 'setct-AuthRevResData' *)
     578,    (* 'setct-AuthRevResTBE' *)
     579,    (* 'setct-AuthRevResTBEB' *)
     543,    (* 'setct-AuthRevResTBS' *)
     573,    (* 'setct-AuthTokenTBE' *)
     537,    (* 'setct-AuthTokenTBS' *)
     600,    (* 'setct-BCIDistributionTBS' *)
     558,    (* 'setct-BatchAdminReqData' *)
     592,    (* 'setct-BatchAdminReqTBE' *)
     559,    (* 'setct-BatchAdminResData' *)
     593,    (* 'setct-BatchAdminResTBE' *)
     599,    (* 'setct-CRLNotificationResTBS' *)
     598,    (* 'setct-CRLNotificationTBS' *)
     580,    (* 'setct-CapReqTBE' *)
     581,    (* 'setct-CapReqTBEX' *)
     544,    (* 'setct-CapReqTBS' *)
     545,    (* 'setct-CapReqTBSX' *)
     546,    (* 'setct-CapResData' *)
     582,    (* 'setct-CapResTBE' *)
     583,    (* 'setct-CapRevReqTBE' *)
     584,    (* 'setct-CapRevReqTBEX' *)
     547,    (* 'setct-CapRevReqTBS' *)
     548,    (* 'setct-CapRevReqTBSX' *)
     549,    (* 'setct-CapRevResData' *)
     585,    (* 'setct-CapRevResTBE' *)
     538,    (* 'setct-CapTokenData' *)
     530,    (* 'setct-CapTokenSeq' *)
     574,    (* 'setct-CapTokenTBE' *)
     575,    (* 'setct-CapTokenTBEX' *)
     539,    (* 'setct-CapTokenTBS' *)
     560,    (* 'setct-CardCInitResTBS' *)
     566,    (* 'setct-CertInqReqTBS' *)
     563,    (* 'setct-CertReqData' *)
     595,    (* 'setct-CertReqTBE' *)
     596,    (* 'setct-CertReqTBEX' *)
     564,    (* 'setct-CertReqTBS' *)
     565,    (* 'setct-CertResData' *)
     597,    (* 'setct-CertResTBE' *)
     586,    (* 'setct-CredReqTBE' *)
     587,    (* 'setct-CredReqTBEX' *)
     550,    (* 'setct-CredReqTBS' *)
     551,    (* 'setct-CredReqTBSX' *)
     552,    (* 'setct-CredResData' *)
     588,    (* 'setct-CredResTBE' *)
     589,    (* 'setct-CredRevReqTBE' *)
     590,    (* 'setct-CredRevReqTBEX' *)
     553,    (* 'setct-CredRevReqTBS' *)
     554,    (* 'setct-CredRevReqTBSX' *)
     555,    (* 'setct-CredRevResData' *)
     591,    (* 'setct-CredRevResTBE' *)
     567,    (* 'setct-ErrorTBS' *)
     526,    (* 'setct-HODInput' *)
     561,    (* 'setct-MeAqCInitResTBS' *)
     522,    (* 'setct-OIData' *)
     519,    (* 'setct-PANData' *)
     521,    (* 'setct-PANOnly' *)
     520,    (* 'setct-PANToken' *)
     556,    (* 'setct-PCertReqData' *)
     557,    (* 'setct-PCertResTBS' *)
     523,    (* 'setct-PI' *)
     532,    (* 'setct-PI-TBS' *)
     524,    (* 'setct-PIData' *)
     525,    (* 'setct-PIDataUnsigned' *)
     568,    (* 'setct-PIDualSignedTBE' *)
     569,    (* 'setct-PIUnsignedTBE' *)
     531,    (* 'setct-PInitResData' *)
     533,    (* 'setct-PResData' *)
     594,    (* 'setct-RegFormReqTBE' *)
     562,    (* 'setct-RegFormResTBS' *)
     606,    (* 'setext-cv' *)
     601,    (* 'setext-genCrypt' *)
     602,    (* 'setext-miAuth' *)
     604,    (* 'setext-pinAny' *)
     603,    (* 'setext-pinSecure' *)
     605,    (* 'setext-track2' *)
    1244,    (* 'signedObject' *)
      52,    (* 'signingTime' *)
     454,    (* 'simpleSecurityObject' *)
     496,    (* 'singleLevelQuality' *)
    1142,    (* 'sm-scheme' *)
     387,    (* 'snmpv2' *)
     660,    (* 'street' *)
      85,    (* 'subjectAltName' *)
     769,    (* 'subjectDirectoryAttributes' *)
     398,    (* 'subjectInfoAccess' *)
      82,    (* 'subjectKeyIdentifier' *)
    1007,    (* 'subjectSignTool' *)
     498,    (* 'subtreeMaximumQuality' *)
     497,    (* 'subtreeMinimumQuality' *)
     890,    (* 'supportedAlgorithms' *)
     874,    (* 'supportedApplicationContext' *)
     402,    (* 'targetInformation' *)
     864,    (* 'telephoneNumber' *)
     866,    (* 'teletexTerminalIdentifier' *)
     865,    (* 'telexNumber' *)
     459,    (* 'textEncodedORAddress' *)
     293,    (* 'textNotice' *)
     133,    (* 'timeStamping' *)
     106,    (* 'title' *)
    1020,    (* 'tlsfeature' *)
     682,    (* 'tpBasis' *)
     375,    (* 'trustRoot' *)
    1151,    (* 'ua-pki' *)
    1160,    (* 'uacurve0' *)
    1161,    (* 'uacurve1' *)
    1162,    (* 'uacurve2' *)
    1163,    (* 'uacurve3' *)
    1164,    (* 'uacurve4' *)
    1165,    (* 'uacurve5' *)
    1166,    (* 'uacurve6' *)
    1167,    (* 'uacurve7' *)
    1168,    (* 'uacurve8' *)
    1169,    (* 'uacurve9' *)
     436,    (* 'ucl' *)
     102,    (* 'uid' *)
     888,    (* 'uniqueMember' *)
      55,    (* 'unstructuredAddress' *)
      49,    (* 'unstructuredName' *)
     880,    (* 'userCertificate' *)
     465,    (* 'userClass' *)
     879,    (* 'userPassword' *)
     373,    (* 'valid' *)
     678,    (* 'wap' *)
     679,    (* 'wap-wsg' *)
     735,    (* 'wap-wsg-idm-ecid-wtls1' *)
     743,    (* 'wap-wsg-idm-ecid-wtls10' *)
     744,    (* 'wap-wsg-idm-ecid-wtls11' *)
     745,    (* 'wap-wsg-idm-ecid-wtls12' *)
     736,    (* 'wap-wsg-idm-ecid-wtls3' *)
     737,    (* 'wap-wsg-idm-ecid-wtls4' *)
     738,    (* 'wap-wsg-idm-ecid-wtls5' *)
     739,    (* 'wap-wsg-idm-ecid-wtls6' *)
     740,    (* 'wap-wsg-idm-ecid-wtls7' *)
     741,    (* 'wap-wsg-idm-ecid-wtls8' *)
     742,    (* 'wap-wsg-idm-ecid-wtls9' *)
     804,    (* 'whirlpool' *)
     868,    (* 'x121Address' *)
     503,    (* 'x500UniqueIdentifier' *)
     158,    (* 'x509Certificate' *)
     160,    (* 'x509Crl' *)
    1093    (* 'x509ExtAdmission' *)
);
type
  Tdoall = procedure(p1: PADDED_OBJ);
var

   obj_lock_initialise_ossl_ret_: int = 0;
   ossl_obj_lock: PCRYPTO_RWLOCK  = nil;
   ossl_obj_lock_init: CRYPTO_ONCE  = CRYPTO_ONCE_STATIC_INIT;
   added: Plhash_st_ADDED_OBJ = nil;
   nid_objs :array of TASN1_OBJECT;

function OBJ_obj2nid(const a : PASN1_OBJECT):integer;
function ossl_obj_obj2nid(const a : PASN1_OBJECT; lock : integer):integer;
function OBJ_bsearch_obj( key : PPASN1_OBJECT; const base: Puint32; num : integer):Puint32;
function obj_cmp_BSEARCH_CMP_FN(const a_, b_ : Pointer):integer;
function obj_cmp(const ap : PPASN1_OBJECT; bp : Puint32):integer;
function OBJ_nid2ln( n : integer):PUTF8Char;
function OBJ_obj2txt(buf : PUTF8Char; buf_len : integer;const a : PASN1_OBJECT; no_name : integer):integer;
 function OBJ_sn2nid(const s : PUTF8Char):integer;
  function OBJ_bsearch_sn(const key : PPASN1_OBJECT; base : Puint32; num : integer):Puint32;
function sn_cmp_BSEARCH_CMP_FN(const a_, b_ : Pointer):integer;
function sn_cmp(const a : PPASN1_OBJECT; b : Puint32):integer;
function OBJ_ln2nid(const s : PUTF8Char):integer;
 function ln_cmp_BSEARCH_CMP_FN(const a_, b_ : Pointer):integer;
  function OBJ_bsearch_ln(const key : PPASN1_OBJECT; base : Puint32; num : integer):Puint32;
 function ln_cmp(const a : PPASN1_OBJECT; b : Puint32):integer;
 function OBJ_txt2obj(const s : PUTF8Char; no_name : integer):PASN1_OBJECT;
function OBJ_txt2nid(const s : PUTF8Char):integer;
function OBJ_create(const oid, sn, ln : PUTF8Char):integer;
function ossl_obj_write_lock( lock : integer):int;
function OBJ_new_nid( num : integer):integer;
function ossl_obj_add_object(const obj : PASN1_OBJECT; lock : integer):integer;
function lh_ADDED_OBJ_insert(lh: Plhash_st_ADDED_OBJ; d : PADDED_OBJ):PADDED_OBJ;
function lh_ADDED_OBJ_new(hfn: TOPENSSL_LH_HASHFUNC; cfn: TOPENSSL_LH_COMPFUNC):Plhash_st_ADDED_OBJ;
function added_obj_hash(const ca : Pointer{PADDED_OBJ}):Cardinal;
function added_obj_cmp(const ca, cb : Pointer{PADDED_OBJ}):integer;
procedure ossl_obj_cleanup_int;
procedure lh_ADDED_OBJ_set_down_load( lh : Plhash_st_ADDED_OBJ; dl : Cardinal);
procedure lh_ADDED_OBJ_doall( lh : Plhash_st_ADDED_OBJ; doall: Tdoall);
procedure cleanup1_doall( a : PADDED_OBJ);
  procedure cleanup2_doall( a : PADDED_OBJ);
  procedure cleanup3_doall( a : PADDED_OBJ);

procedure lh_ADDED_OBJ_free( lh : Plhash_st_ADDED_OBJ);

procedure objs_free_locks;

implementation


uses openssl3.crypto.bsearch, openssl3.crypto.init, OpenSSL3.threads_none,
     OpenSSL3.Err, openssl3.crypto.lhash, openssl3.crypto.o_str,
     openssl3.crypto.bn.bn_word,          openssl3.crypto.bn.bn_lib,
     openssl3.crypto.mem,                 openssl3.crypto.bio.bio_print,
     openssl3.crypto.ctype,               openssl3.crypto.asn1.a_object,
     openssl3.crypto.asn1.asn1_lib,       openssl3.tsan_assist,
     openssl3.crypto.objects.obj_lib,
     openssl3.crypto.bn.bn_shift, openssl3.crypto.bn.bn_conv;

var
  {$IFNDEF FPC}[Volatile]{$ENDIF} new_nid: int = NUM_NID;




procedure objs_free_locks;
begin
    CRYPTO_THREAD_lock_free(ossl_obj_lock);
    ossl_obj_lock := nil;
{$IFDEF TSAN_REQUIRES_LOCKING}
    CRYPTO_THREAD_lock_free(ossl_obj_nid_lock);
    ossl_obj_nid_lock := nil;
{$ENDIF}
end;




procedure lh_ADDED_OBJ_free( lh : Plhash_st_ADDED_OBJ);
begin
 OPENSSL_LH_free(POPENSSL_LHASH (lh));
end;

procedure cleanup1_doall( a : PADDED_OBJ);
begin
    a.obj.nid := 0;
    a.obj.flags := a.obj.flags or ASN1_OBJECT_FLAG_DYNAMIC or
        ASN1_OBJECT_FLAG_DYNAMIC_STRINGS or ASN1_OBJECT_FLAG_DYNAMIC_DATA;
end;


procedure cleanup2_doall( a : PADDED_OBJ);
begin
    PostInc(a.obj.nid);
end;


procedure cleanup3_doall( a : PADDED_OBJ);
begin
    if PreDec(a.obj.nid) = 0  then
        ASN1_OBJECT_free(a.obj);
    OPENSSL_free(Pointer(a));
end;



procedure lh_ADDED_OBJ_doall( lh : Plhash_st_ADDED_OBJ; doall: Tdoall);
begin
 OPENSSL_LH_doall(POPENSSL_LHASH (lh), TOPENSSL_LH_DOALL_FUNC(doall));
end;




procedure lh_ADDED_OBJ_set_down_load( lh : Plhash_st_ADDED_OBJ; dl : Cardinal);
begin
 OPENSSL_LH_set_down_load(POPENSSL_LHASH (lh), dl);
end;



procedure ossl_obj_cleanup_int;
begin
    if added <> nil then
    begin
        lh_ADDED_OBJ_set_down_load(added, 0);
        lh_ADDED_OBJ_doall(added, cleanup1_doall); { zero counters }
        lh_ADDED_OBJ_doall(added, cleanup2_doall); { set counters }
        lh_ADDED_OBJ_doall(added, cleanup3_doall); { free objects }
        lh_ADDED_OBJ_free(added);
        added := nil;
    end;
    objs_free_locks();
end;


function added_obj_cmp(const ca, cb : Pointer{PADDED_OBJ}):integer;
var
  a, b : PASN1_OBJECT;
  i : integer;
begin
    i := PADDED_OBJ(ca).&type - PADDED_OBJ(cb).&type;
    if i > 0 then Exit(i);
    a := PADDED_OBJ(ca).obj;
    b := PADDED_OBJ(cb).obj;
    case PADDED_OBJ(ca).&type of
    ADDED_DATA:
    begin
        i := (a.length - b.length);
        if i > 0 then Exit(i);
        Exit(memcmp(a.data, b.data, size_t(a.length)));
    end;
    ADDED_SNAME:
    begin
        if a.sn = nil then
           Exit(-1)
        else if (b.sn = nil) then
            Exit(1)
        else
            Exit(strcmp(a.sn, b.sn));
    end;
    ADDED_LNAME:
    begin
        if a.ln = nil then
           Exit(-1)
        else if (b.ln = nil) then
            Exit(1)
        else
            Exit(strcmp(a.ln, b.ln));
    end;
    ADDED_NID:
        Exit(a.nid - b.nid);
    else
        { abort; }
        Exit(0);
    end;
end;


function added_obj_hash(const ca : Pointer{PADDED_OBJ}):Cardinal;
var
  a : PASN1_OBJECT;
  i : integer;
  ret : Cardinal;
  p : PByte;
begin
    ret := 0;
    a := PADDED_OBJ(ca).obj;
    case PADDED_OBJ(ca).&type of
    ADDED_DATA:
    begin
        ret := a.length shl 20;
        p := PByte(a.data);
        for i := 0 to a.length-1 do
            ret  := ret xor (p[i] shl ((i * 3) mod 24));
    end;
    ADDED_SNAME:
        ret := OPENSSL_LH_strhash(a.sn);
        //break;
    ADDED_LNAME:
        ret := OPENSSL_LH_strhash(a.ln);
        //break;
    ADDED_NID:
        ret := a.nid;
        //break;
    else
        { abort; }
        Exit(0);
    end;
    ret := ret and  $3fffffff;
    ret  := ret  or ((ulong(PADDED_OBJ(ca).&type)) shl 30);
    Result := ret;
end;



function lh_ADDED_OBJ_new(hfn: TOPENSSL_LH_HASHFUNC; cfn: TOPENSSL_LH_COMPFUNC):Plhash_st_ADDED_OBJ;
begin
 Result := Plhash_st_ADDED_OBJ(OPENSSL_LH_new(TOPENSSL_LH_HASHFUNC(hfn), TOPENSSL_LH_COMPFUNC(cfn)));
end;



function lh_ADDED_OBJ_insert(lh: Plhash_st_ADDED_OBJ; d : PADDED_OBJ):PADDED_OBJ;
begin
   Result := PADDED_OBJ (OPENSSL_LH_insert(POPENSSL_LHASH(lh), d));
end;



function ossl_obj_add_object(const obj : PASN1_OBJECT; lock : integer):integer;
var
  o : PASN1_OBJECT;
  ao : array[0..3] of PADDED_OBJ;
  aop : PADDED_OBJ;
  i : integer;
  label _err, _err2;
begin
{$POINTERMATH ON}
    o := nil;
    ao[0] := nil; ao[1] := nil;ao[2] := nil;ao[3] := nil;
    o := OBJ_dup(obj);
    if o = nil then
        Exit(NID_undef);
    ao[ADDED_NID] := OPENSSL_malloc(sizeof( ao[0]^));
    ao[ADDED_DATA] := OPENSSL_malloc(sizeof( ao[0]^));
    ao[ADDED_SNAME] := OPENSSL_malloc(sizeof( ao[0]^));
    ao[ADDED_LNAME] := OPENSSL_malloc(sizeof( ao[0]^));
    if (ao[ADDED_NID] = nil)
             or ( (o.length <> 0)
                 and  (obj.data <> nil)
                 and  (ao[ADDED_DATA] = nil) )
             or ( (o.sn <> nil)
                 and  (ao[ADDED_SNAME] = nil) )
             or ( (o.ln <> nil)
                 and  (ao[ADDED_LNAME] = nil) ) then
    begin
        ERR_raise(ERR_LIB_OBJ, ERR_R_MALLOC_FAILURE);
        goto _err2;
    end;
    if 0>=ossl_obj_write_lock(lock) then begin
        ERR_raise(ERR_LIB_OBJ, ERR_R_UNABLE_TO_GET_WRITE_LOCK);
         goto _err2;
    end;
    if added = nil then
    begin
        added := lh_ADDED_OBJ_new(added_obj_hash, added_obj_cmp);
        if added = nil then
        begin
            ERR_raise(ERR_LIB_OBJ, ERR_R_MALLOC_FAILURE);
            goto _err;
        end;
    end;
    for i := ADDED_DATA to ADDED_NID do
    begin
        if ao[i] <> nil then
        begin
            ao[i].&type := i;
            ao[i].obj := o;
            aop := lh_ADDED_OBJ_insert(added, ao[i]);
            { memory leak, but should not normally matter }
            OPENSSL_free(Pointer(aop));
        end;
    end;
    o.flags := o.flags and
            not (ASN1_OBJECT_FLAG_DYNAMIC or ASN1_OBJECT_FLAG_DYNAMIC_STRINGS or
          ASN1_OBJECT_FLAG_DYNAMIC_DATA);
    ossl_obj_unlock(lock);
    Exit(o.nid);
 _err:
    ossl_obj_unlock(lock);
 _err2:
    for i := ADDED_DATA to ADDED_NID do
        OPENSSL_free(Pointer(ao[i]));
    ASN1_OBJECT_free(o);
    Result := NID_undef;
 {$POINTERMATH OFF}
end;

function OBJ_new_nid( num : integer):integer;
var
  i : integer;
begin

{$IFDEF TSAN_REQUIRES_LOCKING}
    if  not CRYPTO_THREAD_write_lock(ossl_obj_nid_lock then ) begin
        ERR_raise(ERR_LIB_OBJ, ERR_R_UNABLE_TO_GET_WRITE_LOCK);
        Exit(NID_undef);
    end;
    i := new_nid;
    new_nid  := new_nid + num;
    CRYPTO_THREAD_unlock(ossl_obj_nid_lock);
    Exit(i);
{$ELSE}
    Exit(tsan_add(@new_nid, num, SizeOf(new_nid)));
{$ENDIF}
end;


function ossl_obj_write_lock( lock : integer):int;
begin
    if 0>=lock then Exit(1);
    if 0>=ossl_init_added_lock then Exit(0);
    Result := CRYPTO_THREAD_write_lock(ossl_obj_lock);
end;




function OBJ_create(const oid, sn, ln : PUTF8Char):integer;
var
  tmpoid : PASN1_OBJECT;
  ok : integer;
  label _err;
begin
    tmpoid := nil;
    ok := 0;
    { Check to see if short or long name already present }
    if ( (sn <> nil)  and  (OBJ_sn2nid(sn) <> NID_undef) )
             or ( (ln <> nil)  and  (OBJ_ln2nid(ln) <> NID_undef) ) then
    begin
        ERR_raise(ERR_LIB_OBJ, OBJ_R_OID_EXISTS);
        Exit(0);
    end;
    { Convert numerical OID string to an ASN1_OBJECT structure }
    tmpoid := OBJ_txt2obj(oid, 1);
    if tmpoid = nil then Exit(0);
    if 0>=ossl_obj_write_lock(1) then
    begin
        ERR_raise(ERR_LIB_OBJ, ERR_R_UNABLE_TO_GET_WRITE_LOCK);
        ASN1_OBJECT_free(tmpoid);
        Exit(0);
    end;
    { If NID is not NID_undef then object already exists }
    if ossl_obj_obj2nid(tmpoid, 0) <> NID_undef  then
    begin
        ERR_raise(ERR_LIB_OBJ, OBJ_R_OID_EXISTS);
        goto _err;
    end;
    tmpoid.nid := OBJ_new_nid(1);
    tmpoid.sn := PUTF8Char( sn);
    tmpoid.ln := PUTF8Char( ln);
    ok := ossl_obj_add_object(tmpoid, 0);
    tmpoid.sn := nil;
    tmpoid.ln := nil;
 _err:
    ossl_obj_unlock(1);
    ASN1_OBJECT_free(tmpoid);
    Result := ok;
end;


function OBJ_txt2nid(const s : PUTF8Char):integer;
var
  obj : PASN1_OBJECT;

  nid : integer;
begin
    obj := OBJ_txt2obj(s, 0);
    nid := NID_undef;
    if obj <> nil then begin
        nid := OBJ_obj2nid(obj);
        ASN1_OBJECT_free(obj);
    end;
    Result := nid;
end;




function OBJ_txt2obj(const s : PUTF8Char; no_name : integer):PASN1_OBJECT;
var
  nid : integer;
  op : PASN1_OBJECT;
  buf, p, cp : PByte;
  i, j : integer;
begin
    nid := NID_undef;
    op := nil;
    if 0>= no_name then
    begin
        nid := OBJ_sn2nid(s);
        if (nid <> NID_undef)  then
           Exit(OBJ_nid2obj(nid));
        nid := OBJ_ln2nid(s);
        if (nid <> NID_undef) then
           Exit(OBJ_nid2obj(nid));

        if not ossl_isdigit(s^) then
        begin
            ERR_raise(ERR_LIB_OBJ, OBJ_R_UNKNOWN_OBJECT_NAME);
            Exit(nil);
        end;
    end;
    { Work out size of content octets }
    i := a2d_ASN1_OBJECT(nil, 0, s, -1);
    if i <= 0 then Exit(nil);
    { Work out total size }
    j := ASN1_object_size(0, i, V_ASN1_OBJECT);
    if j < 0 then Exit(nil);
    buf := OPENSSL_malloc(j);
    if buf = nil then
    begin
        ERR_raise(ERR_LIB_OBJ, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    p := buf;
    { Write out tag+length }
    ASN1_put_object(@p, 0, i, V_ASN1_OBJECT, V_ASN1_UNIVERSAL);
    { Write out contents }
    a2d_ASN1_OBJECT(p, i, s, -1);
    cp := buf;
    op := d2i_ASN1_OBJECT(nil, @cp, j);
    OPENSSL_free(Pointer(buf));
    Result := op;
end;


function ln_cmp(const a : PPASN1_OBJECT; b : Puint32):integer;
begin
    Result := strcmp((a^).ln, nid_objs[b^].ln);
end;


function ln_cmp_BSEARCH_CMP_FN(const a_, b_ : Pointer):integer;
var
  a : PPASN1_OBJECT;
  b : Puint32;
begin
  a := a_;
  b := b_;
  Result := ln_cmp(a,b);
end;


function OBJ_bsearch_ln(const key : PPASN1_OBJECT; base : Puint32; num : integer):Puint32;
begin
   Result := Puint32(OBJ_bsearch_(key, base, num, sizeof(uint32) , ln_cmp_BSEARCH_CMP_FN));
end;




function OBJ_ln2nid(const s : PUTF8Char):integer;
var
    o        : TASN1_OBJECT;
    oo       : PASN1_OBJECT;
    ad       : TADDED_OBJ;
    adp      : PADDED_OBJ;
    op       : Puint32;
    nid      : integer;

begin
    oo := @o;
    nid := NID_undef;
    o.ln := s;
    op := OBJ_bsearch_ln(@oo, @ln_objs, NUM_LN);
    if op <> nil then
       Exit(nid_objs[op^].nid);
    if 0>= ossl_obj_read_lock(1) then
    begin
        ERR_raise(ERR_LIB_OBJ, ERR_R_UNABLE_TO_GET_READ_LOCK);
        Exit(NID_undef);
    end;
    if added <> nil then
    begin
        ad.&type := ADDED_LNAME;
        ad.obj := @o;
        adp := lh_ADDED_OBJ_retrieve(added, @ad);
        if adp <> nil then
           nid := adp.obj.nid;
    end;
    ossl_obj_unlock(1);
    Result := nid;
end;



function sn_cmp(const a : PPASN1_OBJECT; b : Puint32):integer;
begin
    Result := strcmp((a^).sn, nid_objs[b^].sn);
end;




function sn_cmp_BSEARCH_CMP_FN(const a_, b_ : Pointer):integer;
var
  a : PPASN1_OBJECT;
  b : Puint32;
begin
   a := a_;
   b := b_;
   result := sn_cmp(a,b);
end;


 function OBJ_bsearch_sn(const key : PPASN1_OBJECT; base : Puint32; num : integer):Puint32;
begin
    result := Puint32(OBJ_bsearch_(key, base, num, sizeof(uint32) , sn_cmp_BSEARCH_CMP_FN));
end;




function OBJ_sn2nid(const s : PUTF8Char):integer;
var
    o        : TASN1_OBJECT;
    oo       : PASN1_OBJECT;
    ad       : TADDED_OBJ;
    adp      : PADDED_OBJ;
    op       : Puint32;
    nid      : integer;

begin
    oo := @o;
    nid := NID_undef;
    o.sn := s;
    op := OBJ_bsearch_sn(@oo, @sn_objs, NUM_SN);
    if op <> nil then
       Exit(nid_objs[op^].nid);
    if 0>= ossl_obj_read_lock(1) then
    begin
        ERR_raise(ERR_LIB_OBJ, ERR_R_UNABLE_TO_GET_READ_LOCK);
        Exit(NID_undef);
    end;
    if added <> nil then
    begin
        ad.&type := ADDED_SNAME;
        ad.obj := @o;
        adp := lh_ADDED_OBJ_retrieve(added, @ad);
        if adp <> nil then
           nid := adp.obj.nid;
    end;
    ossl_obj_unlock(1);
    Result := nid;
end;

function DECIMAL_SIZE(sz: byte) :uint32;
begin
   Result := ((sz*8+2) div 3+1)
end;

function OBJ_obj2txt(buf : PUTF8Char; buf_len : integer;const a : PASN1_OBJECT; no_name : integer):integer;
var
  i, len, nid, first, use_bn, n : integer;
  bl : PBIGNUM;
  l : Cardinal;
  p : PByte;
  tbuf : PUTF8Char;
  s : PUTF8Char;
  c : Byte;
  bndec : PUTF8Char;
  label _err;
begin
    tbuf := AllocMem(DECIMAL_SIZE(SizeOf(int)) + DECIMAL_SIZE(SizeOf(uint32)) + 2-1);
    n := 0;
    { Ensure that, at every state, |buf| is NUL-terminated. }
    if (buf <> nil)  and  (buf_len > 0) then
        buf[0] := #0;
    if (a = nil)  or  (a.data = nil) then Exit(0);
    nid := OBJ_obj2nid(a);
    if (0>= no_name)  and  (nid <> NID_undef) then
    begin
        s := OBJ_nid2ln(nid);
        if s = nil then
           s := OBJ_nid2sn(nid);
        if s <> nil then
        begin
            if buf <> nil then
                OPENSSL_strlcpy(buf, s, buf_len);
            Exit(Length(s));
        end;
    end;
    len := a.length;
    p := a.data;
    first := 1;
    bl := nil;
    while len > 0 do
    begin
        l := 0;
        use_bn := 0;
        while true do
        begin
            c := PostInc(p)^;
            //Inc(p);
            Dec(len);
            if (len = 0)  and  ( (c and $80) <> 0) then
                goto _err ;
            if use_bn > 0 then
            begin
                if 0>= BN_add_word(bl, c and $7f) then
                    goto _err ;
            end
            else
            begin
                l  := l  or (c and $7f);
            end;
            if (c and $80) = 0 then
                break;
            if (0>= use_bn)  and  (l > (ULONG_MAX  shr  7) ) then
            begin

                if (bl = nil) then
                begin
                    bl := BN_new();
                    if bl = nil then
                       goto _err ;
                end;
                if 0>= BN_set_word(bl, l) then
                    goto _err ;
                use_bn := 1;
            end;
            if use_bn > 0 then
            begin
                if 0>= BN_lshift(bl, bl, 7) then
                    goto _err ;
            end
            else
            begin
                l := l shl Int(7);
            end;
        end;
        if first >0 then
        begin
            first := 0;
            if l >= 80 then
            begin
                i := 2;
                if use_bn >0 then
                begin
                    if 0>= BN_sub_word(bl, 80) then
                        goto _err ;
                end
                else
                begin
                    l  := l - 80;
                end;
            end
            else
            begin
                i := int (l div 40);
                l  := l - (long(i * 40));
            end;
            if (buf <> nil)  and  (buf_len > 1) then
            begin
                PostInc(buf)^ := UTF8Char(i + ord('0'));
                buf^ := #0;
                Dec(buf_len);
            end;
            Inc(n);
        end;
        if use_bn > 0 then
        begin
            bndec := BN_bn2dec(bl);
            if nil = bndec then
               goto _err ;
            i := Length(bndec);
            if buf <> nil then
            begin
                if buf_len > 1 then
                begin
                    PostInc(buf)^ := '.';
                    buf^ := #0;
                    Dec(buf_len);
                end;
                OPENSSL_strlcpy(buf, bndec, buf_len);
                if i > buf_len then
                begin
                    buf  := buf + buf_len;
                    buf_len := 0;
                end
                else
                begin
                    buf  := buf + i;
                    buf_len  := buf_len - i;
                end;
            end;
            Inc(n);
            n  := n + i;
            OPENSSL_free(Pointer(bndec));
        end
        else
        begin  //在delphi中正确，fpc下不对？？？
            BIO_snprintf(tbuf, sizeof(tbuf), '.%lu', [l]);
            i := Length(tbuf);
            if (buf <> nil)  and  (buf_len > 0) then
            begin
                OPENSSL_strlcpy(buf, tbuf, buf_len);
                if i > buf_len then
                begin
                    buf  := buf + buf_len;
                    buf_len := 0;
                end
                else
                begin
                    buf  := buf + i;
                    buf_len  := buf_len - i;
                end;
            end;
            n  := n + i;
            l := 0;
        end;
    end;
    BN_free(bl);
    FreeMem(tbuf);
    Exit(n);
 _err:
    BN_free(bl);
    FreeMem(tbuf);
    Result := -1;
end;

function OBJ_nid2ln( n : integer):PUTF8Char;
var
  ob : PASN1_OBJECT;
begin
    ob := OBJ_nid2obj(n);
    if ob = nil then
       Result := nil
    else
       Result := ob.ln;
end;

function obj_cmp(const ap : PPASN1_OBJECT; bp : Puint32):integer;
var
  j : integer;
  a, b : PASN1_OBJECT;
begin
    a := ap^;
    b := @nid_objs[bp^];
    j := (a.length - b.length);
    if j >0 then Exit(j);
    if a.length = 0 then Exit(0);
    Result := memcmp(a.data, b.data, a.length);
end;

function obj_cmp_BSEARCH_CMP_FN(const a_, b_ : Pointer):integer;
var
  a : PPASN1_OBJECT;
  b : Puint32;
begin
   a := PPASN1_OBJECT(a_);
   b := b_;
   Result := obj_cmp(a,b);
end;


function OBJ_bsearch_obj( key : PPASN1_OBJECT; const base: Puint32; num : integer):Puint32;
begin
   Result := Puint32(OBJ_bsearch_(key, base, num, sizeof(uint32), obj_cmp_BSEARCH_CMP_FN));
end;


function ossl_obj_obj2nid(const a : PASN1_OBJECT; lock : integer):integer;
var
  nid      : integer;
  ad,
  adp      : PADDED_OBJ;
  op       : Puint32;
begin
    nid := NID_undef;
    if a = nil then Exit(NID_undef);
    if a.nid <> NID_undef then Exit(a.nid);
    if a.length = 0 then Exit(NID_undef);
    op := OBJ_bsearch_obj(@a, @obj_objs, NUM_OBJ);
    if op <> nil then Exit(nid_objs[op^].nid);
    if 0>= ossl_obj_read_lock(lock)  then
    begin
        ERR_raise(ERR_LIB_OBJ, ERR_R_UNABLE_TO_GET_READ_LOCK);
        Exit(NID_undef);
    end;
    if added <> nil then
    begin
        ad.&type := ADDED_DATA;
        ad.obj := PASN1_OBJECT(a); { casting away const is harmless here }
        adp := lh_ADDED_OBJ_retrieve(added, @ad);
        if adp <> nil then
           nid := adp.obj.nid;
    end;
    ossl_obj_unlock(lock);
    Result := nid;
end;

function OBJ_obj2nid(const a : PASN1_OBJECT):integer;
begin
    Result := ossl_obj_obj2nid(a, 1);
end;


procedure ossl_obj_unlock( lock : integer);
begin
    if lock >0 then
       CRYPTO_THREAD_unlock(ossl_obj_lock);
end;






function lh_ADDED_OBJ_retrieve(lh : Plhash_st_ADDED_OBJ;const d : PADDED_OBJ):PADDED_OBJ;
begin
   Result := PADDED_OBJ(OPENSSL_LH_retrieve(POPENSSL_LHASH(lh), d));
end;





function obj_lock_initialise:integer;
begin
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, nil);
    ossl_obj_lock := CRYPTO_THREAD_lock_new();
    if ossl_obj_lock = nil then
        Exit(0);
    Result := 1;
end;




procedure obj_lock_initialise_ossl_;
begin
  obj_lock_initialise_ossl_ret_ := obj_lock_initialise();
end;





function ossl_init_added_lock:integer;
begin
    Result := get_result(CRYPTO_THREAD_run_once(@ossl_obj_lock_init, obj_lock_initialise_ossl_) >0,
                            obj_lock_initialise_ossl_ret_ , 0);
end;



function ossl_obj_read_lock( lock : integer):integer;
begin
    if 0>= lock then Exit(1);
    if 0>= ossl_init_added_lock()  then
        Exit(0);
    Result := CRYPTO_THREAD_read_lock(ossl_obj_lock);
end;

function OBJ_nid2obj( n : integer):PASN1_OBJECT;
var
  ad: TADDED_OBJ;
  adp : PADDED_OBJ;
  ob : TASN1_OBJECT;
begin
    adp := nil;
    if n = NID_undef then Exit(nil);
    if (n >= 0)  and  (n < NUM_NID)  and  (nid_objs[n].nid = n) then
       Exit(@nid_objs[n]);

    ad.&type := ADDED_NID;
    ad.obj := @ob;
    ob.nid := n;
    if 0>= ossl_obj_read_lock(1)  then
    begin
        ERR_raise(ERR_LIB_OBJ, ERR_R_UNABLE_TO_GET_READ_LOCK);
        Exit(nil);
    end;
    if (added <> nil) then
       adp := lh_ADDED_OBJ_retrieve(added, @ad);
    ossl_obj_unlock(1);
    if adp <> nil then Exit(adp.obj);
    ERR_raise(ERR_LIB_OBJ, OBJ_R_UNKNOWN_NID);
    Result := nil;
end;

function OBJ_nid2sn( n : integer):PUTF8Char;
var
  ob : PASN1_OBJECT;
begin
    ob := OBJ_nid2obj(n);
    if ob = nil then
       Result := nil
    else
       Result := ob.sn;
end;



function OBJ_length(const obj : PASN1_OBJECT):size_t;
begin
    if obj = Pointer(0 ) then
        Exit(0);
    Result := obj.length;
end;




function OBJ_get0_data(const obj : PASN1_OBJECT):PByte;
begin
    if obj = Pointer(0 )then
        Exit(Pointer(0) );
    Result := obj.data;
end;

function OBJ_bsearch_ex_(const key, base : Pointer; num, size : integer; cmp : Tcmp_func; flags : integer):Pointer;
var
  p : PUTF8Char;
begin
     p := ossl_bsearch(key, base, num, size, cmp, flags);
    Result := p;
end;

function OBJ_bsearch_(const key, base : Pointer; num, size : integer; cmp: Tcmp_func):Pointer;
begin
    Result := OBJ_bsearch_ex_(key, base, num, size, cmp, 0);
end;

initialization
  {$IFNDEF FPC}
     {$I nidobjs-delphi.inc}
  {$ELSE}
     {$I nidobjs-fpc.inc}
  {$ENDIF}

end.
