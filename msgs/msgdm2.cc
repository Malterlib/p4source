/*
 * Copyright 2019 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * msgdm2.cc - definitions of errors for overflow data manager core subsystem.
 *
 * Note:
 *
 * Never re-use an error code value,  these may have already been 
 * translated, so using it for a different error is not OK.
 *
 * ErrorIds which are no longer used should be moved to the bottom
 * of the list, with a trailing comment like this: // DEPRECATED.
 * We keep these to maintain compatibility between newer api clients
 * and older servers which send old ErrorIds.
 *
 * Its okay to add a message in the middle of the file.
 *
 * When adding a new error make sure its greater than the current high
 * value and update the following number:
 *
 * Current high value for a MsgDm2 error code is: 45
 *                                               Max code is 1023!!!
 */

# include <error.h>
# include <errornum.h>
# include <msgdm2.h>

ErrorId MsgDm2::ExistingStorage         = { ErrorOf( ES_DM2, 1, E_FAILED, EV_EMPTY, 1 ), "Bad zero count storage (%type%) record detected after file transfer." } ;
ErrorId MsgDm2::ConfigHistData          = { ErrorOf( ES_DM2, 2, E_INFO, EV_EMPTY, 8 ), "%sname%#%name% changed from '%ovalue%' to '%nvalue%' (iteration %version%) by '%user%' on %date% local to server %server%" };
ErrorId MsgDm2::LbrScanBadState         = { ErrorOf( ES_DM2, 3, E_FAILED, EV_NONE, 2 ), "Lbrscan cannot change state from '%oldstate%' to '%newstate%'." } ;
ErrorId MsgDm2::LbrScanCtlNotFound      = { ErrorOf( ES_DM2, 4, E_FAILED, EV_NONE, 1 ), "No current scan for path (%record%)" } ;
ErrorId MsgDm2::RequiresAutoIdCode      = { ErrorOf( ES_DM2, 5, E_FAILED, EV_FAULT, 0 ), "New field code in '%type%' spec must be entered as 'NNN'" } ;
ErrorId MsgDm2::SpecMissingBuiltin      = { ErrorOf( ES_DM2, 6, E_FAILED, EV_FAULT, 1 ), "Spec is missing builtin field: '%field%'" } ;
ErrorId MsgDm2::RequiresAutoIdOrPosCode = { ErrorOf( ES_DM2, 7, E_FAILED, EV_FAULT, 0 ), "New field code in '%type%' spec must be entered as 'NNN' or positive int." } ;
ErrorId MsgDm2::CannotRecreateDeleteField = { ErrorOf( ES_DM2, 8, E_FAILED, EV_FAULT, 0 ), "New field code '%code% %tag%' was previously deleted and may not be recreated." } ;
ErrorId MsgDm2::SpecRepairDisallowNNN = { ErrorOf( ES_DM2, 18, E_FAILED, EV_FAULT, 1 ), "'NNN' fields are disallowd during 'p4 spec --repair' :  field '%tag%'." } ;
ErrorId MsgDm2::SpecRepairNoCustomSpec = { ErrorOf( ES_DM2, 19, E_FAILED, EV_FAULT, 0 ), "--repair disallowed on default spec." } ;
ErrorId MsgDm2::UnshelveStreamResolve   = { ErrorOf( ES_DM2, 9, E_INFO, EV_USAGE, 3 ), "%streamSpec% - must resolve shelved stream spec %streamSpec%@%change% before submitting" } ;
ErrorId MsgDm2::StreamSpecIntegOkay     = { ErrorOf( ES_DM2, 10, E_INFO, EV_NONE, 8 ), "Stream spec %targetStreamSpec%@%targetChange% - %action% field %field% from %sourceStreamSpec%@%fromChange%[ using base %baseStreamSpec%][@%baseChange%]" } ;
ErrorId MsgDm2::CheckFailedNoDB         = { ErrorOf( ES_DM2, 11, E_FAILED, EV_NONE, 1 ), "%table% not found in default/specified server root" } ;
ErrorId MsgDm2::NoStreamSpecPermsWarn   = { ErrorOf( ES_DM2, 12, E_INFO, EV_PROTECT, 0 ), "You don't have streamspec permission for this operation." } ;
ErrorId MsgDm2::StreamSpecProtectsNotCompatible   = { ErrorOf( ES_DM2, 13, E_FAILED, EV_ADMIN, 0 ), "Helix P4Admin tool version is not compatible with streamSpec permissions.\nThe protection table currently contains streamspec permissions.\nYou must use P4Admin with release >= 2020.1 or p4 to administer the protection table." } ;
ErrorId MsgDm2::StreamOpenedByUser      = { ErrorOf( ES_DM2, 14, E_INFO, EV_NONE, 5 ), "Stream %stream%[@%haveChange%] - %action% stream spec %change% by %user%" } ;
ErrorId MsgDm2::StreamOpenReOpen        = { ErrorOf( ES_DM2, 15, E_INFO, EV_NONE, 3 ), "%stream%[@%haveChange%] - reopened for %action%" } ;
ErrorId MsgDm2::RemoteLabelOpenFailed   = { ErrorOf( ES_DM2, 16, E_FAILED, EV_FAULT, 1 ), "Failed to get global label %domainName% on commit server." } ;
ErrorId MsgDm2::RemoteLabelUpdateFailed = { ErrorOf( ES_DM2, 17, E_FAILED, EV_FAULT, 1 ), "Failed to update global label %domainName% on commit server." } ;
ErrorId MsgDm2::RemoteStreamUpdateFailed = { ErrorOf( ES_DM2, 20, E_FAILED, EV_FAULT, 1 ), "Failed to update stream %streamName% on commit server." } ;
ErrorId MsgDm2::StreamParentViewNoChange = { ErrorOf( ES_DM2, 21, E_FAILED, EV_FAULT, 1 ), "Failed to change the ParentView field to %value%.\nThe ParentView property of a stream specification can only be changed using the command\n  'p4 stream parentview'\nSee 'p4 help stream' for details." } ;
ErrorId MsgDm2::LbrRevVerOutOfRange     = { ErrorOf( ES_DM2, 22, E_FAILED, EV_NONE, 1 ), "LbrRev suffix has reached the Max limit %oname%. The shelf Suffix cannot be incremented." } ;
ErrorId MsgDm2::GblLockIndexMismatch    = { ErrorOf( ES_DM2, 23, E_FAILED, EV_FAULT, 2 ), "Index mismatch! Wrong depotFile: expected '%file1%', got '%file2%'" } ;
ErrorId MsgDm2::GblLockIndexMissing     = { ErrorOf( ES_DM2, 24, E_FAILED, EV_FAULT, 1 ), "Index missing! No index found for depotFile'%dfile%'" } ;
ErrorId MsgDm2::GblLockMissing          = { ErrorOf( ES_DM2, 25, E_FAILED, EV_FAULT, 1 ), "Commit server didn't report back on locking '%dfile%'" } ;
ErrorId MsgDm2::StreamlogInteg          = { ErrorOf( ES_DM2, 26, E_INFO, EV_UNKNOWN, 4 ), "%how% %fromFile%%fromRev% '%field%' " } ;
ErrorId MsgDm2::RemoteAutoGenSpecFailed = { ErrorOf( ES_DM2, 27, E_FAILED, EV_FAULT, 1 ), "Failed to autogen field id in %specName% spec on commit server." } ;
ErrorId MsgDm2::StreamParentViewMustBeOpen = { ErrorOf( ES_DM2, 28, E_FAILED, EV_FAULT, 1 ), "Stream spec %streamname% must be open in the current client to change the Parent View field." } ;
ErrorId MsgDm2::StreamPVSourceComment = { ErrorOf( ES_DM2, 29, E_INFO, EV_EMPTY, 2 ), " %how% %streamname%@%change%" } ;
ErrorId MsgDm2::BeginUpgradeStep        = { ErrorOf( ES_DM2, 30, E_INFO, EV_NONE, 2 ), "Upgrade step \"%description%\" beginning on pid %pid%." } ;
ErrorId MsgDm2::EndUpgradeStep          = { ErrorOf( ES_DM2, 31, E_INFO, EV_NONE, 2 ), "Upgrade step \"%description%\" ended with status \"%status%\"." } ;
ErrorId MsgDm2::StreamNoCmtClientBadSave= { ErrorOf( ES_DM2, 32, E_FAILED, EV_UPGRADE, 1 ), "The stream specification for %stream% contains comments.\nThis client program is too old to update this stream spec.\nThe client program must be fully compatible with the 2020.2 server release in order to update a stream specification with comments." } ;
ErrorId MsgDm2::ConnNeedsFwdCrypto      = { ErrorOf( ES_DM2, 33, E_FAILED, EV_UNKNOWN, 0 ), "Connection to upstream is already established without required authentication parameters!" } ;
ErrorId MsgDm2::NoStreamTypeChangePV    = { ErrorOf( ES_DM2, 34, E_FAILED, EV_NOTYET, 2 ), "Failed to change stream %stream% to type %streamType% because it has a noinherit ParentView.  Change the ParentView to inherit with the command 'p4 stream parentview --inherit' first, then change the stream type.\nSee 'p4 help stream' for details." } ;
ErrorId MsgDm2::StreamAtChangeDeleted   = { ErrorOf( ES_DM2, 42, E_FAILED, EV_CONTEXT, 2 ), "Stream '%stream%' was deleted after change %change%" } ;
ErrorId MsgDm2::StreamNotOpenInChange   = { ErrorOf( ES_DM2, 43, E_FAILED, EV_CONTEXT, 2 ), "Stream '%stream%' not open in change %change%" } ;
ErrorId MsgDm2::IdHasWhitespace         = { ErrorOf( ES_DM2, 44, E_FAILED, EV_USAGE, 1 ), "Whitespace characters not allowed in '%id%'." } ;
ErrorId MsgDm2::IdHasEquals             = { ErrorOf( ES_DM2, 45, E_FAILED, EV_USAGE, 1 ), "Equals character not allowed in '%id%'." } ;
