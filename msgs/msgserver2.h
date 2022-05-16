/*
 * Copyright 1995, 2019 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * msgserver2.h - More definitions of errors for server subsystem.
 * The MsgServer2 class contains overflow messages from MsgServer.
 */

class MsgServer2 {

    public:
	static ErrorId ExtensionDeletePreview;
	static ErrorId ExtensionInstallPreview;
	static ErrorId WarnPreviewMode;
	static ErrorId UseReopen2;
	static ErrorId UseReopen3;
	static ErrorId StgKeyMiss;
	static ErrorId StgBadCount;
	static ErrorId StgOrphan;
	static ErrorId UseResolve2;
	static ErrorId UseOpened3;
	static ErrorId StorageUpgradeInProgress;
	static ErrorId StorageEdgeFailure;
	static ErrorId UseStreamlog;
	static ErrorId SubmitNoBgXferTarget;
	static ErrorId SubmitBgXferNoConfig;
	static ErrorId SubmitBgNotEdge;
	static ErrorId SubmitBgNotConfigured;
	static ErrorId UsePullt;
	static ErrorId SubmitNoBackgroundThreads;
	static ErrorId StorageNoUpgrade;
	static ErrorId FailoverForced;
	static ErrorId FailoverWriteServerID;
	static ErrorId FailoverServerIDBad;
	static ErrorId FailoverMasterTooOld;
	static ErrorId ServerIDReused;
	static ErrorId StorageRestoreDigest;
	static ErrorId xuUpstream;
	static ErrorId xuAtStart;
	static ErrorId xuUpstream2;
	static ErrorId xuAtStart2;
	static ErrorId JournalRequired;
	static ErrorId ShelvedStreamDeleted;
	static ErrorId NoShelvedStreamDelete;
	static ErrorId DescribeShelvedStream;
	static ErrorId ShelveCompleteStream;
	static ErrorId ShelveCompleteBoth;
	static ErrorId ShelveDeleteJustFiles;
	static ErrorId StorageWaitComplete;
	static ErrorId ExtensionNameCfgUniq;
	static ErrorId UpgradeWarning;
	static ErrorId BadUpLbr;
	static ErrorId MissingLbr;
	static ErrorId NoStreamFieldsResolve;
	static ErrorId UseDiffA;
	static ErrorId UseDiff2A;
	static ErrorId NoStreamDefaultShelve;
	static ErrorId NoStreamShelve;
	static ErrorId ShelveStreamBegin;
	static ErrorId StreamShelfOccupied;
	static ErrorId StreamShelfReadOnly;
	static ErrorId ServiceNotSupported;
	static ErrorId NoRplMissingMandatory;
	static ErrorId UnexpectedRotJnlChange;
	static ErrorId RunExtErrorWarning;
	static ErrorId RunExtErrorFailed;
	static ErrorId RunExtErrorFatal;
	static ErrorId StorageCleanupWarn;
	static ErrorId VerifyDataProblem;
	static ErrorId VerifyData;
	static ErrorId ExtensionPostInstallMsg;
	static ErrorId UseStreamSpec;
	static ErrorId UseLbrScan;
	static ErrorId LbrScanBusy;
	static ErrorId LbrScanBadDepot;
	static ErrorId LbrScanPathInUse;
	static ErrorId LbrScanUnderPath;
	static ErrorId LbrScanBadState;
	static ErrorId LbrScanNotFound;
	static ErrorId LbrScanBadPath;
	static ErrorId StorageZeroRefClean;
	static ErrorId StorageZeroCount;
	static ErrorId StorageDupZero;
	static ErrorId ExtensionRunFunction;
	static ErrorId StringTooLarge;
	static ErrorId ExtensionNonUTF8Data;
	static ErrorId StorageShareRep;
	static ErrorId StorageSingle;
	static ErrorId StorageSymlink;
	static ErrorId ExtMissingCfg;
	static ErrorId ExtMissingCfgEvent;
	static ErrorId MissingMovedFilesHeader;
	static ErrorId MissingMovedFile;
	static ErrorId UpdatedLbrType;
	static ErrorId InvalidExtName;
	static ErrorId DigestFail;
	static ErrorId DigestFail2;
	static ErrorId NoFilesInSvrRtForVal;
	static ErrorId UseHeartbeat;
	static ErrorId UseHeartbeatWait;
	static ErrorId UseHeartbeatInterval;
	static ErrorId UseHeartbeatCount;
	static ErrorId HeartbeatNoTarget;
	static ErrorId HeartbeatExiting;
	static ErrorId HeartbeatAccessFailed;
	static ErrorId HeartbeatMaxWait;
	static ErrorId HeartbeatTargetTooOld;
	static ErrorId SkippedKeyed;
	static ErrorId EndOfStorePhase1;
	static ErrorId BadExternalAddr;
	static ErrorId StreamSpecPermsDisabled;
	static ErrorId FailedToUpdUnExpKtextDigest;
	static ErrorId ExtCfgMissing;
	static ErrorId SwitchStreamUnrelated;
	static ErrorId UnknownContext;
};
