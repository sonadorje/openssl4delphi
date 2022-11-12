unit OpenSSL3.crypto.x509.x509_req;

interface
 uses OpenSSL.Api;

 function X509_REQ_get_subject_name(const req : PX509_REQ):PX509_NAME;

implementation


function X509_REQ_get_subject_name(const req : PX509_REQ):PX509_NAME;
begin
    Result := req.req_info.subject;
end;



end.
