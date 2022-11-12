unit openssl3.test.testutil.test_options;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.api, app.lib.opt;

function test_get_options: POPTIONS;

implementation


function test_get_options: POPTIONS;
const
   default_options: array[0..8] of TOPTIONS = (
    (name: OPT_HELP_STR; retval: 1; valtype: '-'; helpstr :'Usage: %s [options]'#10 ),
    (name: OPT_HELP_STR; retval: 1;  valtype: '-'; helpstr :'Valid options are:'#10 ),
    (name: 'help'; retval: Int(OPT_TEST_HELP); valtype: '-'; helpstr :'Display this summary' ),
    (name: 'list'; retval: Int(OPT_TEST_LIST); valtype: '-'; helpstr :'Display the list of tests available' ),
    (name: 'test'; retval: Int(OPT_TEST_SINGLE); valtype: 's'; helpstr :'Run a single test by id or name' ),
    (name: 'iter'; retval: Int(OPT_TEST_ITERATION); valtype: 'n'; helpstr :'Run a single iteration of a test' ),
    (name: 'indent'; retval: Int(OPT_TEST_INDENT); valtype: 'p'; helpstr :'Number of tabs added to output' ),
    (name: 'seed'; retval: Int(OPT_TEST_SEED); valtype: 'n'; helpstr :'Seed value to randomize tests with' ),
    (name: nil; retval: -2; valtype: #0; helpstr :nil ));
begin
   Result := @default_options;
end;

end.
