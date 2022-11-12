unit rand_status_test;

interface
uses openssl.api;

function setup_tests:integer;

implementation
uses openssl3.crypto.params,           openssl3.crypto.rand.rand_lib,
     openssl3.test.testutil.tests,     openssl3.crypto.evp.evp_rand,
     openssl3.test.testutil.driver;

function test_rand_status:integer;
begin
    Result := TEST_true('RAND_status()', RAND_status);
end;


function setup_tests:integer;
begin
    ADD_TEST('test_rand_status', test_rand_status);
    Result := 1;
end;

end.
