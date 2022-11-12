unit openssl3.crypto.x509.x509_trust;

interface
uses OpenSSL.Api;

type
  Tdefault_trust_fn = function( id : integer; x : PX509; flags : integer):integer;

function X509_check_trust( x : PX509; id, flags : integer):integer;
function trust_compat( trust : PX509_TRUST; x : PX509; flags : integer):integer;
function obj_trust( id : integer; x : PX509; flags : integer):integer;
function X509_TRUST_get_by_id( id : integer):integer;
function X509_TRUST_get0( idx : integer):PX509_TRUST;
 function trust_1oidany( trust : PX509_TRUST; x : PX509; flags : integer):integer;
 function trust_1oid( trust : PX509_TRUST; x : PX509; flags : integer):integer;


var
   trtable: Pstack_st_X509_TRUST  = nil;
   trstandard: array of TX509_TRUST ;
   default_trust: Tdefault_trust_fn = obj_trust;

implementation
uses OpenSSL3.include.openssl.asn1, openssl3.crypto.objects.obj_dat,
     OpenSSL3.crypto.x509.v3_purp, OpenSSL3.crypto.x509.x509_vfy;





function trust_1oid( trust : PX509_TRUST; x : PX509; flags : integer):integer;
begin
    {
     * Declare the chain verified only if the desired trust OID is not
     * rejected and is expressly trusted.  Neither 'anyEKU' nor 'compat'
     * trust in self-signed certificates apply.
     }
    flags := flags and  not (X509_TRUST_DO_SS_COMPAT or X509_TRUST_OK_ANY_EKU);
    Result := obj_trust(trust.arg1, x, flags);
end;




function trust_1oidany( trust : PX509_TRUST; x : PX509; flags : integer):integer;
begin
    {
     * Declare the chain verified if the desired trust OID is not rejected in
     * any auxiliary trust info for this certificate, and the OID is either
     * expressly trusted, or else either 'anyEKU' is trusted, or the
     * certificate is self-signed and X509_TRUST_NO_SS_COMPAT is not set.
     }
    flags  := flags  or (X509_TRUST_DO_SS_COMPAT or X509_TRUST_OK_ANY_EKU);
    Result := obj_trust(trust.arg1, x, flags);
end;



function X509_TRUST_get0( idx : integer):PX509_TRUST;
begin
{$POINTERMATH ON}
    if idx < 0 then Exit(nil);
    if idx < Length(trstandard) then
       Exit(PX509_TRUST(@trstandard) + idx);
    Result := sk_X509_TRUST_value(trtable, idx - Length(trstandard){X509_TRUST_COUNT});
{$POINTERMATH OFF}
end;




function X509_TRUST_get_by_id( id : integer):integer;
var
  tmp : TX509_TRUST;

  idx : integer;
begin
    if (id >= X509_TRUST_MIN)  and  (id <= X509_TRUST_MAX) then
        Exit(id - X509_TRUST_MIN);
    if trtable = nil then Exit(-1);
    tmp.trust := id;
    idx := sk_X509_TRUST_find(trtable, @tmp);
    if idx < 0 then Exit(-1);
    Result := idx + Length(trstandard){X509_TRUST_COUNT};
end;


function trust_compat( trust : PX509_TRUST; x : PX509; flags : integer):integer;
begin
    { Call for side-effect of setting EXFLAG_SS for self-signed-certs }
    if X509_check_purpose(x, -1, 0) <> 1  then
        Exit(X509_TRUST_UNTRUSTED);
    if (flags and X509_TRUST_NO_SS_COMPAT = 0)  and  (x.ex_flags and EXFLAG_SS > 0) then
        Exit(X509_TRUST_TRUSTED)
    else
        Result := X509_TRUST_UNTRUSTED;
end;

function obj_trust( id : integer; x : PX509; flags : integer):integer;
var
  ax : PX509_CERT_AUX;
  i : integer;
  obj : PASN1_OBJECT;
  nid : integer;

begin
    ax := x.aux;
    if (ax <> nil) and  (ax.reject <> nil) then
    begin
        for i := 0 to sk_ASN1_OBJECT_num(ax.reject)-1 do
        begin
            obj := sk_ASN1_OBJECT_value(ax.reject, i);
            nid := OBJ_obj2nid(obj);
            if (nid = id)  or ( (nid = NID_anyExtendedKeyUsage)  and
                                ((flags and X509_TRUST_OK_ANY_EKU)>0) ) then
                Exit(X509_TRUST_REJECTED);
        end;
    end;
    if (ax <>nil)  and  (ax.trust <> nil) then
    begin
        for i := 0 to sk_ASN1_OBJECT_num(ax.trust)-1 do
        begin
            obj := sk_ASN1_OBJECT_value(ax.trust, i);
            nid := OBJ_obj2nid(obj);
            if (nid = id)  or ( (nid = NID_anyExtendedKeyUsage)  and
                                (flags and X509_TRUST_OK_ANY_EKU > 0 ))then
                Exit(X509_TRUST_TRUSTED);
        end;
        {
         * Reject when explicit trust EKU are set and none match.
         *
         * Returning untrusted is enough for for full chains that end in
         * self-signed roots, because when explicit trust is specified it
         * suppresses the default blanket trust of self-signed objects.
         *
         * But for partial chains, this is not enough, because absent a similar
         * trust-self-signed policy, non matching EKUs are indistinguishable
         * from lack of EKU constraints.
         *
         * Therefore, failure to match any trusted purpose must trigger an
         * explicit reject.
         }
        Exit(X509_TRUST_REJECTED);
    end;
    if flags and X509_TRUST_DO_SS_COMPAT = 0 then
        Exit(X509_TRUST_UNTRUSTED);
    {
     * Not rejected, and there is no list of accepted uses, try compat.
     }
    Result := trust_compat(nil, x, flags);
end;



function X509_check_trust( x : PX509; id, flags : integer):integer;
var
  pt : PX509_TRUST;
  idx : integer;
begin
    { We get this as a default value }
    if id = X509_TRUST_DEFAULT then
       Exit(obj_trust(NID_anyExtendedKeyUsage, x, flags or X509_TRUST_DO_SS_COMPAT));
    idx := X509_TRUST_get_by_id(id);
    if idx = -1 then
       Exit(default_trust(id, x, flags));
    pt := X509_TRUST_get0(idx);
    Result := pt.check_trust(pt, x, flags);
end;

initialization
  trstandard := [
    get_X509_TRUST(X509_TRUST_COMPAT, 0, trust_compat, 'compatible', 0, nil),
    get_X509_TRUST(X509_TRUST_SSL_CLIENT, 0, trust_1oidany, 'SSL Client', NID_client_auth, nil),
    get_X509_TRUST(X509_TRUST_SSL_SERVER, 0, trust_1oidany, 'SSL Server', NID_server_auth, nil),
    get_X509_TRUST(X509_TRUST_EMAIL, 0, trust_1oidany, 'S/MIME email', NID_email_protect, nil),
    get_X509_TRUST(X509_TRUST_OBJECT_SIGN, 0, trust_1oidany, 'Object Signer', NID_code_sign, nil),
    get_X509_TRUST(X509_TRUST_OCSP_SIGN, 0, trust_1oid, 'OCSP responder', NID_OCSP_sign, nil),
    get_X509_TRUST(X509_TRUST_OCSP_REQUEST, 0, trust_1oid, 'OCSP request', NID_ad_OCSP, nil),
    get_X509_TRUST(X509_TRUST_TSA, 0, trust_1oidany, 'TSA server', NID_time_stamp, nil)
];

end.
