/*
 * Copyright 2019 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * msgdm2.h - overflow definitions of errors for data manager core subsystem.
 */

class MsgDm2 {
    public:
	static ErrorId ExistingStorage;
	static ErrorId ConfigHistData;
	static ErrorId LbrScanBadState;
	static ErrorId LbrScanCtlNotFound;
	static ErrorId UnshelveStreamResolve;
	static ErrorId RequiresAutoIdCode;
	static ErrorId SpecMissingBuiltin;
	static ErrorId StreamSpecIntegOkay;
	static ErrorId CheckFailedNoDB;
	static ErrorId RequiresAutoIdOrPosCode;
	static ErrorId CannotRecreateDeleteField;
	static ErrorId SpecRepairDisallowNNN; 
	static ErrorId SpecRepairNoCustomSpec; 
	static ErrorId NoStreamSpecPermsWarn;
	static ErrorId StreamSpecProtectsNotCompatible;
	static ErrorId StreamOpenedByUser;
	static ErrorId StreamOpenReOpen;
	static ErrorId RemoteLabelOpenFailed;
	static ErrorId RemoteLabelUpdateFailed;
	static ErrorId RemoteStreamUpdateFailed;
	static ErrorId StreamAtChangeDeleted;
	static ErrorId StreamNotOpenInChange;
	static ErrorId StreamNotInShelf;
	static ErrorId IdHasWhitespace;
	static ErrorId IdHasEquals;
	static ErrorId LockNameNull;
	static ErrorId WorkRecNotFound;
} ;
