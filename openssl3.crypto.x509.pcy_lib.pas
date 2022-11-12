unit openssl3.crypto.x509.pcy_lib;

interface
uses OpenSSL.Api;

function X509_policy_tree_get0_user_policies(const tree : PX509_POLICY_TREE):Pstack_st_X509_POLICY_NODE;

implementation


function X509_policy_tree_get0_user_policies(const tree : PX509_POLICY_TREE):Pstack_st_X509_POLICY_NODE;
begin
    if nil = tree then
       Exit(nil);
    if tree.flags and POLICY_FLAG_ANY_POLICY > 0 then
       Exit(tree.auth_policies)
    else
        Result := tree.user_policies;
end;


end.
