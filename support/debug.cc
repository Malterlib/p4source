/*
 * Copyright 1995, 2003 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# define NEED_SOCKETPAIR
# define NEED_TIME
# define NEED_TIME_HP
# define NEED_MIMALLOC
# define NEED_SMARTHEAP
# define NEED_ERRNO

# if defined( OS_NT )
# include <winsock2.h>
# endif

# include <stdhdrs.h>
# include <strbuf.h>
# include <stdarg.h>
# include <ctype.h>
# include <error.h>
# include <errorlog.h>
# include <pid.h>
# include <datetime.h>

# include <msgconfig.h>
# include <msgsupp.h>

# include "debug.h"
# include "tunable.h"

P4Debug p4debug;
P4Tunable p4tunable;
MT_STATIC P4DebugConfig *p4debughelp;

# define SMAX 64*1024

# define B1K 1024
# define B2K 2048
# define B4K 4096
# define B8K 8192
# define B16K 16*1024
# define B32K 32*1024
# define B64K 64*1024
# define B224K 224*1024
# define B512K 512*1024
# define B576K 576*1024
# define B1M 1024*1024
# define B2M 1024*2048
# define B4M 1024*4096
# define B10M 10*1024*1024
# define B100M 100*1024*1024
# define B256M 256*1024*1024
# define B1G 1024*1024*1024
# define BBIG 2147483647 /* (2^31-1) */

# define R1K        1000
# define R4K        4000
# define R10K      10000
# define R50K      50000
# define R100K    100000
# define R1M     1000000
# define R4M     4000000
# define R10M   10000000
# define R100M 100000000
# define R1G  1000000000
# define RBIG 2147483647 /* 2^32-1 */

// Initial values for the Smart Heap tunables.  A "0" setting indicates
// no tunable is set.  All settings are multiplied by 1024 in
// sys/shhandler.cc except the Subpool, Growinc, Flush and List settings.
// Subpool settings are only on Windows.  The Linux Smart Heap library
// is old enough, it does not have the Subpool and Growinc APIs.
# ifdef HAVE_SMARTHEAP
# ifdef OS_LINUX
# ifdef OS_LINUXX86
#  define SHPROC	B1M
#  define SHPOOL	0
#  define SHGROW1	0
#  define SHGROW2	0
#  define SHSUBP	0
# else
#  define SHPROC	0
#  define SHPOOL	0
#  define SHGROW1	0
#  define SHGROW2	0
#  define SHSUBP	0
# endif
# endif // OS_LINUX
# ifdef OS_NTX86
#  define SHPROC	B1M
#  define SHPOOL	0
#  define SHGROW1	0
#  define SHGROW2	0
#  define SHSUBP	64
# endif
# ifdef OS_NTX64
#  define SHPROC	B32K
#  define SHPOOL	B16K
#  define SHGROW1	B1K
#  define SHGROW2	B4K
#  define SHSUBP	64
# endif
# endif // HAVE_SMARTHEAP
# ifndef SHPROC
#  define SHPROC	0
#  define SHPOOL	0
#  define SHGROW1	0
#  define SHGROW2	0
#  define SHSUBP	0
# endif

# ifdef OS_NTX86
# define MAX_SHARED_MONITOR	4096
# else
# define MAX_SHARED_MONITOR	32768
# endif

P4Tunable::tunable P4Tunable::list[] = {

	// P4Debug's collection.  When adding new entries, make sure to expand
	// list2.

	{ "db",		0, -1, -1, 10, 1, 1, 0, 1, &MsgConfig::Db,	0, CONFIG_APPLY_SERVER, CONFIG_RESTART_NO_RESTART, CONFIG_SUPPORT_NODOC, CONFIG_CAT_ADMIN },
	{ "diff",	0, -1, -1, 10, 1, 1, 0, 1, &MsgConfig::Diff,	0, CONFIG_APPLY_SERVER|CONFIG_APPLY_CLIENT, CONFIG_RESTART_NO_RESTART, CONFIG_SUPPORT_NODOC, CONFIG_CAT_ADMIN },
	{ "dm",		0, -1, -1, 10, 1, 1, 0, 1, &MsgConfig::Dm,	0, CONFIG_APPLY_SERVER, CONFIG_RESTART_NO_RESTART, CONFIG_SUPPORT_NODOC, CONFIG_CAT_ADMIN },
	{ "dmc",	0, -1, -1, 10, 1, 1, 0, 1, &MsgConfig::Dmc,	0, CONFIG_APPLY_SERVER, CONFIG_RESTART_NO_RESTART, CONFIG_SUPPORT_NODOC, CONFIG_CAT_ADMIN },
	{ "ftp",	0, -1, -1, 10, 1, 1, 0, 1, &MsgConfig::Ftp,	0, CONFIG_APPLY_NONE,   CONFIG_RESTART_NO_RESTART, CONFIG_SUPPORT_NODOC, CONFIG_CAT_ADMIN },
	{ "handle",	0, -1, -1, 10, 1, 1, 0, 1, &MsgConfig::Handle,	0, CONFIG_APPLY_SERVER|CONFIG_APPLY_CLIENT|CONFIG_APPLY_PROXY, CONFIG_RESTART_NO_RESTART, CONFIG_SUPPORT_NODOC, CONFIG_CAT_ADMIN },
	{ "lbr", 	0, -1, -1, 10, 1, 1, 0, 1, &MsgConfig::Lbr,	0, CONFIG_APPLY_SERVER, CONFIG_RESTART_NO_RESTART, CONFIG_SUPPORT_NODOC, CONFIG_CAT_ADMIN },
	{ "map",	0, -1, -1, 10, 1, 1, 0, 1, &MsgConfig::Map,	0, CONFIG_APPLY_SERVER|CONFIG_APPLY_CLIENT, CONFIG_RESTART_NO_RESTART, CONFIG_SUPPORT_NODOC, CONFIG_CAT_ADMIN },
	{ "net",	0, -1, -1, 10, 1, 1, 0, 1, &MsgConfig::Net,	0, CONFIG_APPLY_SERVER|CONFIG_APPLY_CLIENT|CONFIG_APPLY_PROXY|CONFIG_APPLY_BROKER, CONFIG_RESTART_NO_RESTART, CONFIG_SUPPORT_NODOC, CONFIG_CAT_ADMIN },
	{ "options",	0, -1, -1, 10, 1, 1, 0, 1, &MsgConfig::Options,	0, CONFIG_APPLY_NONE,   CONFIG_RESTART_NO_RESTART, CONFIG_SUPPORT_NODOC, CONFIG_CAT_ADMIN },
	{ "peek",	0, -1, -1, 10, 1, 1, 0, 1, &MsgConfig::Peek,	0, CONFIG_APPLY_SERVER, CONFIG_RESTART_NO_RESTART, CONFIG_SUPPORT_NODOC, CONFIG_CAT_ADMIN },
	{ "rcs",	0, -1, -1, 10, 1, 1, 0, 1, &MsgConfig::Rcs,	0, CONFIG_APPLY_SERVER, CONFIG_RESTART_NO_RESTART, CONFIG_SUPPORT_NODOC, CONFIG_CAT_ADMIN },
	{ "records",	0, -1, -1, 10, 1, 1, 0, 1, &MsgConfig::Records,	0, CONFIG_APPLY_SERVER, CONFIG_RESTART_NO_RESTART, CONFIG_SUPPORT_NODOC, CONFIG_CAT_ADMIN },
	{ "rpc", 	0, -1, -1, 10, 1, 1, 0, 1, &MsgConfig::Rpc,	0, CONFIG_APPLY_SERVER|CONFIG_APPLY_CLIENT|CONFIG_APPLY_PROXY|CONFIG_APPLY_BROKER, CONFIG_RESTART_NO_RESTART, CONFIG_SUPPORT_UNDOC, CONFIG_CAT_ADMIN },
	{ "server",	0, -1, -1, 10, 1, 1, 0, 1, &MsgConfig::Server,	0, CONFIG_APPLY_SERVER|CONFIG_APPLY_PROXY|CONFIG_APPLY_BROKER, CONFIG_RESTART_NO_RESTART, CONFIG_SUPPORT_DOC, CONFIG_CAT_ADMIN },
	{ "spec", 	0, -1, -1, 10, 1, 1, 0, 1, &MsgConfig::Spec,	0, CONFIG_APPLY_SERVER, CONFIG_RESTART_NO_RESTART, CONFIG_SUPPORT_NODOC, CONFIG_CAT_ADMIN },
	{ "track",	0, -1, -1, 10, 1, 1, 0, 1, &MsgConfig::Track,	0, CONFIG_APPLY_SERVER, CONFIG_RESTART_NO_RESTART, CONFIG_SUPPORT_DOC, CONFIG_CAT_ADMIN },
	{ "ob",		0, -1, -1, 10, 1, 1, 0, 1, &MsgConfig::Ob,	0, CONFIG_APPLY_NONE,   CONFIG_RESTART_NO_RESTART, CONFIG_SUPPORT_NODOC, CONFIG_CAT_ADMIN },
	{ "viewgen",	0, -1, -1, 10, 1, 1, 0, 1, &MsgConfig::Viewgen,	0, CONFIG_APPLY_SERVER, CONFIG_RESTART_NO_RESTART, CONFIG_SUPPORT_NODOC, CONFIG_CAT_ADMIN },
	{ "rpl",	0, -1, -1, 10, 1, 1, 0, 1, &MsgConfig::Rpl,	0, CONFIG_APPLY_SERVER, CONFIG_RESTART_NO_RESTART, CONFIG_SUPPORT_UNDOC, CONFIG_CAT_ADMIN },
	{ "ssl",	0, -1, -1, 10, 1, 1, 0, 1, &MsgConfig::Ssl,	0, CONFIG_APPLY_SERVER|CONFIG_APPLY_CLIENT|CONFIG_APPLY_PROXY|CONFIG_APPLY_BROKER, CONFIG_RESTART_NO_RESTART, CONFIG_SUPPORT_UNDOC, CONFIG_CAT_ADMIN },
	{ "time",	0, -1, -1, 10, 1, 1, 0, 1, &MsgConfig::Time,	0, CONFIG_APPLY_SERVER|CONFIG_APPLY_CLIENT|CONFIG_APPLY_PROXY|CONFIG_APPLY_BROKER, CONFIG_RESTART_NO_RESTART, CONFIG_SUPPORT_UNDOC, CONFIG_CAT_ADMIN },
	{ "cluster",	0, -1, -1, 10, 1, 1, 0, 1, &MsgConfig::Cluster,	0, CONFIG_APPLY_SERVER, CONFIG_RESTART_NO_RESTART, CONFIG_SUPPORT_NODOC, CONFIG_CAT_ADMIN },
	{ "zk",		0, -1, -1, 10, 1, 1, 0, 1, &MsgConfig::Zk,	0, CONFIG_APPLY_NONE,   CONFIG_RESTART_NO_RESTART, CONFIG_SUPPORT_NODOC, CONFIG_CAT_ADMIN },
	{ "ldap",	0, -1, -1, 10, 1, 1, 0, 1, &MsgConfig::Ldap,	0, CONFIG_APPLY_SERVER, CONFIG_RESTART_NO_RESTART, CONFIG_SUPPORT_UNDOC, CONFIG_CAT_ADMIN },
	{ "dvcs",	0, -1, -1, 10, 1, 1, 0, 1, &MsgConfig::Dvcs,	0, CONFIG_APPLY_SERVER, CONFIG_RESTART_NO_RESTART, CONFIG_SUPPORT_NODOC, CONFIG_CAT_ADMIN },
	{ "graph",	0, -1, -1, 10, 1, 1, 0, 1, &MsgConfig::Graph,	0, CONFIG_APPLY_SERVER, CONFIG_RESTART_NO_RESTART, CONFIG_SUPPORT_NODOC, CONFIG_CAT_ADMIN },
	{ "gconn",	0, -1, -1, 10, 1, 1, 0, 1, &MsgConfig::Gconn,	0, CONFIG_APPLY_SERVER, CONFIG_RESTART_NO_RESTART, CONFIG_SUPPORT_NODOC, CONFIG_CAT_ADMIN },
	{ "fovr",	0, -1, -1, 10, 1, 1, 0, 1, &MsgConfig::Fovr,	0, CONFIG_APPLY_SERVER, CONFIG_RESTART_NO_RESTART, CONFIG_SUPPORT_NODOC, CONFIG_CAT_ADMIN },
	{ "script",	0, -1, -1, 10, 1, 1, 0, 1, &MsgConfig::Script,	0, CONFIG_APPLY_SERVER|CONFIG_APPLY_CLIENT, CONFIG_RESTART_NO_RESTART, CONFIG_SUPPORT_NODOC, CONFIG_CAT_ADMIN },
	{ "stg",	0, -1, -1, 30, 1, 1, 0, 1, &MsgConfig::Stg,	0, CONFIG_APPLY_SERVER, CONFIG_RESTART_NO_RESTART, CONFIG_SUPPORT_NODOC, CONFIG_CAT_ADMIN },
	{ "thread",	0, -1, -1, 10, 1, 1, 0, 1, &MsgConfig::Thread,	0, CONFIG_APPLY_SERVER|CONFIG_APPLY_CLIENT, CONFIG_RESTART_NO_RESTART, CONFIG_SUPPORT_NODOC, CONFIG_CAT_ADMIN },
	{ "exts",	0, -1, -1, 10, 1, 1, 0, 1, &MsgConfig::Exts,	0, CONFIG_APPLY_SERVER|CONFIG_APPLY_CLIENT, CONFIG_RESTART_NO_RESTART, CONFIG_SUPPORT_NODOC, CONFIG_CAT_ADMIN },
	{ "protect",	0,  1, -1, 10, 1, 1, 0, 1, &MsgConfig::Protect,	0, CONFIG_APPLY_SERVER, CONFIG_RESTART_NO_RESTART, CONFIG_SUPPORT_NODOC, CONFIG_CAT_ADMIN }, // Enabled until paranoia passes
	{ "heartbeat",	0, -1, -1, 10, 1, 1, 0, 1, &MsgConfig::Heartbeat,0, CONFIG_APPLY_SERVER, CONFIG_RESTART_NO_RESTART, CONFIG_SUPPORT_NODOC, CONFIG_CAT_ADMIN },
	{ "shelve",	0, -1, -1, 10, 1, 1, 0, 1, &MsgConfig::Shelve,	0, CONFIG_APPLY_SERVER, CONFIG_RESTART_NO_RESTART, CONFIG_SUPPORT_NODOC, CONFIG_CAT_ADMIN },
	{ "sqw",	0, -1, -1, 10, 1, 1, 0, 1, &MsgConfig::Sqw,	0, CONFIG_APPLY_SERVER, CONFIG_RESTART_NO_RESTART, CONFIG_SUPPORT_NODOC, CONFIG_CAT_ADMIN },
	{ "stm",	0, -1, -1, 10, 1, 1, 0, 1, &MsgConfig::Stm,	0, CONFIG_APPLY_SERVER, CONFIG_RESTART_NO_RESTART, CONFIG_SUPPORT_NODOC, CONFIG_CAT_ADMIN },
	{ "pcheck",	0, -1, -1, 10, 1, 1, 0, 1, &MsgConfig::Pcheck,	0, CONFIG_APPLY_SERVER, CONFIG_RESTART_NO_RESTART, CONFIG_SUPPORT_NODOC, CONFIG_CAT_ADMIN },
	{ "topology",	0, -1, -1, 10, 1, 1, 0, 1, &MsgConfig::Topology,0, CONFIG_APPLY_SERVER, CONFIG_RESTART_NO_RESTART, CONFIG_SUPPORT_NODOC, CONFIG_CAT_ADMIN },
	{ "resource",	0, -1, -1, 10, 1, 1, 0, 1, &MsgConfig::Resource,0, CONFIG_APPLY_SERVER, CONFIG_RESTART_NO_RESTART, CONFIG_SUPPORT_NODOC, CONFIG_CAT_ADMIN },
	{ "s3",		0, -1, -1, 10, 1, 1, 0, 1, &MsgConfig::S3,	0, CONFIG_APPLY_SERVER, CONFIG_RESTART_NO_RESTART, CONFIG_SUPPORT_UNDOC, CONFIG_CAT_ADMIN },

	// P4Tunable's collection
	//
	// name				isSet,	value,	min,	max,	mod,	k,	orig,	sensitive, desc					recommend,applicability,	restart,			doc,			category

	{ "cluster.journal.shared",	0,	0,	0,	1,	1,	1,	0,	1,	&MsgConfig::ClusterJournalShared,	0,	CONFIG_APPLY_SERVER|CONFIG_APPLY_BROKER, CONFIG_RESTART_NO_RESTART, CONFIG_SUPPORT_UNDOC, CONFIG_CAT_ADMIN },
	{ "db.checkpoint.bufsize",	0,	B224K,	B16K,	BBIG,	1,	B1K,	0,	1,	&MsgConfig::DbCheckpointBufsize,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "db.checkpoint.threads",	0,	0,	0,	B4K,	1,	1,	0,	1,	&MsgConfig::DbCheckpointThreads,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "db.checkpoint.worklevel",	0,	3,	2,	20,	1,	1,	0,	1,	&MsgConfig::DbCheckpointWorklevel,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "db.checkpoint.reqlevel",	0,	4,	2,	20,	1,	1,	0,	1,	&MsgConfig::DbCheckpointReqlevel,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "db.checkpoint.numfiles",	0,	10,	1,	20000,	1,	1,	0,	1,	&MsgConfig::DbCheckpointNumfiles,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "db.experimental.logging",	0,	0,	0,	1,	1,	1,	0,	1,	&MsgConfig::DbExperimentalLogging,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "db.internal.repair",		0,	0,	0,	1,	1,	1,	0,	1,	&MsgConfig::DbInternalRepair,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "db.isalive",			0,	R10K,	1,	RBIG,	1,	R1K,	0,	1,	&MsgConfig::DbIsalive,			0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "db.jnlack.shared",		0,	16,	0,	2048,	1,	B1K,	0,	1,	&MsgConfig::DbJnlackShared,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "db.monitor.addthresh",	0,	0,	0,	RBIG,	1,	B1K,	0,	1,	&MsgConfig::DbMonitorAddthresh,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "db.monitor.interval",	0,	30,	0,	900,	1,	1,	0,	1,	&MsgConfig::DbMonitorInterval,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "db.monitor.minruntime",	0,	10,	1,	120,	1,	1,	0,	1,	&MsgConfig::DbMonitorMinruntime,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "db.monitor.term.allow",	0,	0,	0,	2,	1,	1,	0,	1,	&MsgConfig::DbMonitorTermallow,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "db.monitor.shared",		0,	256, 0, MAX_SHARED_MONITOR, 1, 	B1K,	0,	1,	&MsgConfig::DbMonitorShared,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_STOP,		CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "db.page.migrate",		0,	0,	0,	80,	1,	1,	0,	1,	&MsgConfig::DbPageMigrate,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "db.peeking",			0,	2,	0,	3,	1,	1,	0,	1,	&MsgConfig::DbPeeking,			0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "db.peeking.usemaxlock",	0,	0,	0,	1,	1,	1,	0,	1,	&MsgConfig::DbPeekingUsemaxlock,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "db.reorg.disable",		0,	1,	0,	1,	1,	1,	0,	1,	&MsgConfig::DbReorgDisable,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "db.reorg.misorder",		0,	80,	0,	100,	1,	1,	0,	1,	&MsgConfig::DbReorgMisorder,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "db.reorg.occup",		0,	8,	0,	100,	1,	1,	0,	1,	&MsgConfig::DbReorgOccup,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "db.rt.io",			0,	0,	0,	1,	1,	1,	0,	0,	&MsgConfig::DbRtIo,			0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_STOP,		CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "db.trylock",			0,	3,	0,	RBIG,	1,	R1K,	0,	1,	&MsgConfig::DbTrylock,			0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "dbarray.putcheck",		0,	R4K,	1,	RBIG,	1,	R1K,	0,	1,	&MsgConfig::DbarrayPutcheck,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "dbarray.reserve",		0,	B4M,	B4K,	BBIG,	1,	B1K,	0,	1,	&MsgConfig::DbarrayReserve,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "dbjournal.bufsize",		0,	B16K,	1,	BBIG,	1,	B1K,	0,	1,	&MsgConfig::DbjournalBufsize,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "dbjournal.wordsize",		0,	B4K,	1,	BBIG,	1,	B1K,	0,	1,	&MsgConfig::DbjournalWordsize,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "dbopen.cache",		0,	96,	1,	RBIG,	1,	R1K,	0,	1,	&MsgConfig::DbopenCache,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "dbopen.cache.wide",		0,	192,	1,	RBIG,	1,	R1K,	0,	1,	&MsgConfig::DbopenCacheWide,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "dbopen.freepct",		0,	0,	0,	99,	1,	1,	0,	1,	&MsgConfig::DbopenFreepct,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "dbopen.mismatch.delay",	0,	300,	10,	RBIG,	1,	1,	0,	1,	&MsgConfig::DbopenMismatchDelay,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "dbopen.nofsync",		0,	0,	0,	1,	1,	1,	0,	1,	&MsgConfig::DbopenNofsync,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "dbopen.pagesize",		0,	B8K,	B8K,	B16K,	B8K,	B1K,	0,	1,	&MsgConfig::DbopenPagesize,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "dbopen.retry",		0,	10,	0,	100,	1,	1,	0,	1,	&MsgConfig::DbopenRetry,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "diff.binary.rcs",		0,	0,	0,	1,	1,	1,	0,	0,	&MsgConfig::DiffBinaryRcs,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "diff.slimit1",		0,	R10M,	R10K,	RBIG,	1,	R1K,	0,	0,	&MsgConfig::DiffSlimit1,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "diff.slimit2",		0,	R100M,	R10K,	RBIG,	1,	R1K,	0,	0,	&MsgConfig::DiffSlimit2,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "diff.sthresh",		0,	R50K,	R1K,	RBIG,	1,	R1K,	0,	0,	&MsgConfig::DiffSthresh,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "dm.altsync.enforce",		0,	1,	0,	1,	1,	1,	0,	0,	&MsgConfig::DmAltsyncEnforce,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "dm.annotate.maxsize",	0,	B10M,	0,	BBIG,	1,	B1K,	0,	0,	&MsgConfig::DmAnnotateMaxsize,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "dm.batch.domains",		0,	0,	0,	RBIG,	1,	R1K,	0,	0,	&MsgConfig::DmBatchDomains,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "dm.batch.net",		0,	R10K,	1,	RBIG,	1,	R1K,	0,	0,	&MsgConfig::DmBatchNet,			0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "dm.change.restrict.pending",	0,	0,	0,	1,	1,	1,	0,	0,	&MsgConfig::DmChangeRestrictPending,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "dm.change.skipkeyed",	0,	0,	0,	1,	1,	1,	0,	0,	&MsgConfig::DmChangeSkipkeyed,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "dm.changes.thresh1",		0,	R50K,	1,	RBIG,	1,	R1K,	0,	0,	&MsgConfig::DmChangesThresh1,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "dm.changes.thresh2",		0,	R10K,	1,	RBIG,	1,	R1K,	0,	0,	&MsgConfig::DmChangesThresh2,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "dm.changeview.openable",	0,	0,	0,	1,	1,	1,	0,	0,	&MsgConfig::DmChangeviewOpenable,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "dm.client.initroot",		0,	0,	0,	1,	1,	1,	0,	0,	&MsgConfig::DmClientInitroot,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "dm.client.limitprotects",	0,	0,	0,	RBIG,	1,	1,	0,	0,	&MsgConfig::DmClientLimitprotects,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "dm.copy.movewarn",		0,	0,	0,	1,	1,	1,	0,	0,	&MsgConfig::DmCopyMovewarn,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "dm.domain.accessupdate",	0,	300,	1,	RBIG,	1,	1,	0,	0,	&MsgConfig::DmDomainAccessupdate,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "dm.domain.accessforce",	0,	3600,	1,	RBIG,	1,	1,	0,	0,	&MsgConfig::DmDomainAccessforce,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "dm.fetch.preservechangenumbers",0,	0,	0,	1,	1,	1,	0,	0,	&MsgConfig::DmFetchPreservechangenumbers, 0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "dm.flushforce",		0,	R10K,	1,	RBIG,	1,	R1K,	0,	0,	&MsgConfig::DmFlushforce,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "dm.flushtry",		0,	100,	1,	RBIG,	1,	R1K,	0,	0,	&MsgConfig::DmFlushtry,			0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "dm.fstat.maxcontent",	0,	B4M,	0,	B10M,	1,	B1K,	0,	0,	&MsgConfig::DmFstatMaxcontent,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "dm.graph.enabled",		0,	1,	0,	1,	1,	1,	0,	0,	&MsgConfig::DmGraphEnabled,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "dm.grep.maxlinelength",	0,	B4K,	128,	B16K,	1,	B1K,	0,	0,	&MsgConfig::DmGrepMaxlinelength,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "dm.grep.maxrevs",		0,	R10K,	0,	RBIG,	1,	R1K,	0,	0,	&MsgConfig::DmGrepMaxrevs,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "dm.grep.maxcontext",		0,	R1K,	0,	B16K,	1,	R1K,	0,	0,	&MsgConfig::DmGrepMaxcontext,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "dm.info.hide",		0,	0,	0,	1,	1,	1,	0,	1,	&MsgConfig::DmInfoHide,			0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "dm.integ.engine",		0,	3,	0,	3,	1,	1,	0,	0,	&MsgConfig::DmIntegEngine,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "dm.integ.maxact",		0,	R100K,	1,	RBIG,	1,	R1K,	0,	0,	&MsgConfig::DmIntegMaxact,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "dm.integ.maxbranch",		0,	100,	2,	RBIG,	1,	R1K,	0,	0,	&MsgConfig::DmIntegMaxbranch,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "dm.integ.streamspec",	0,	1,	0,	2,	1,	1,	0,	0,	&MsgConfig::DmIntegStreamspec,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "dm.integ.tweaks",		0,	0,	0,	256,	1,	1,	0,	0,	&MsgConfig::DmIntegTweaks,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "dm.integ.undo",		0,	0,	0,	1,	1,	1,	0,	0,	&MsgConfig::DmIntegUndo,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "dm.integ.multiplestreams",	0,	0,	0,	1,	1,	1,	0,	0,	&MsgConfig::DmIntegMultipleStreams,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "dm.isalive",			0,	R50K,	1,	RBIG,	1,	R1K,	0,	0,	&MsgConfig::DmIsalive,			0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "dm.keys.hide",		0,	0,	0,	2,	1,	1,	0,	0,	&MsgConfig::DmKeysHide,			0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "dm.labels.search.autoreload",0,	0,	0,	2,	1,	1,	0,	0,	&MsgConfig::DmLabelsSearchAutoreload,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "dm.lock.batch",		0,	R10K,	1,	RBIG,	1,	R1K,	0,	0,	&MsgConfig::DmLockBatch,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "dm.locks.excl.batch.net",	0,	R10K,	1,	RBIG,	1,	R1K,	0,	0,	&MsgConfig::DmLocksExclBatchNet,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "dm.locks.global.batch.net",	0,	R10K,	1,	RBIG,	1,	R1K,	0,	0,	&MsgConfig::DmLocksGlobalBatchNet,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "dm.locks.global.result.batch.net", 0, R10K,	1,	RBIG,	1,	R1K,	0,	0,	&MsgConfig::DmLocksGlobalResultBatchNet,0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "dm.maxkey",			0,	B1K,	64,	B4K,	1,	B1K,	0,	1,	&MsgConfig::DmMaxkey,			0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN }, // B4K = max(dbopen.pagesize) / 4
	{ "dm.open.show.globallocks",	0,	0,	0,	1,	1,	1,	0,	0,	&MsgConfig::DmOpenShowGloballocks,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "dm.password.minlength",	0,	8,	0,	1024,	1,	1,	0,	0,	&MsgConfig::DmPasswordMinlength,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "dm.populate.skipkeyed",	0,	0,	0,	1,	1,	1,	0,	0,	&MsgConfig::DmPopulateSkipkeyed,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "dm.protects.allow.admin",	0,	0,	0,	1,	1,	1,	0,	0,	&MsgConfig::DmProtectsAllowAdmin,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "dm.protects.exclusioncheck",	0,	1,	0,	1,	1,	1,	0,	1,	&MsgConfig::DmProtectsExclusioncheck,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "dm.protects.hide",		0,	0,	0,	1,	1,	1,	0,	0,	&MsgConfig::DmProtectsHide,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "dm.protects.streamspec",	0,	0,	0,	1,	1,	1,	0,	0,	&MsgConfig::DmProtectsStreamspec,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "dm.proxy.protects",		0,	1,	0,	1,	1,	1,	0,	0,	&MsgConfig::DmProxyProtects,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "dm.quick.clients",		0,	R10M,	1,	RBIG,	1,	R1K,	0,	0,	&MsgConfig::DmQuickClients,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "dm.quick.domains",		0,	R10M,	1,	RBIG,	1,	R1K,	0,	0,	&MsgConfig::DmQuickDomains,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "dm.quick.have",		0,	R1M,	1,	RBIG,	1,	R1K,	0,	0,	&MsgConfig::DmQuickHave,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "dm.quick.integ",		0,	R1M,	1,	RBIG,	1,	R1K,	0,	0,	&MsgConfig::DmQuickInteg,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "dm.quick.resolve",		0,	R1K,	1,	RBIG,	1,	R1K,	0,	0,	&MsgConfig::DmQuickResolve,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "dm.quick.rev",		0,	R1M,	1,	RBIG,	1,	R1K,	0,	0,	&MsgConfig::DmQuickRev,			0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "dm.quick.working",		0,	R1K,	1,	RBIG,	1,	R1K,	0,	0,	&MsgConfig::DmQuickWorking,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "dm.repo.noautocreate",	0,	0,	0,	1,	1,	1,	0,	0,	&MsgConfig::DmRepoNoautocreate,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "dm.repo.unpack",		0,	1,	0,	2,	1,	1,	0,	0,	&MsgConfig::DmRepoUnpack,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "dm.resolve.attrib",		0,	1,	0,	1,	1,	1,	0,	0,	&MsgConfig::DmResolveAttrib,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "dm.resolve.ignoredeleted",	0,	0,	0,	1,	1,	1,	0,	0,	&MsgConfig::DmResolveIgnoredeleted,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "dm.rev.scan.thresh",		0,	1,	0,	RBIG,	1,	1,	0,	0,	&MsgConfig::DmRevScanThresh,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "dm.revcx.thresh1",		0,	R4K,	1,	RBIG,	1,	R1K,	0,	0,	&MsgConfig::DmRevcxThresh1,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "dm.revcx.thresh2",		0,	R1K,	1,	RBIG,	1,	R1K,	0,	0,	&MsgConfig::DmRevcxThresh2,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "dm.revert.batch",		0,	R10K,	1,	RBIG,	1,	R1K,	0,	0,	&MsgConfig::DmRevertBatch,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "dm.rotatelogwithjnl",	0,	1,	0,	1,	1,	1,	0,	0,	&MsgConfig::DmRotatelogwithjnl,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "dm.shelve.accessupdate",	0,	300,	1,	RBIG,	1,	1,	0,	0,	&MsgConfig::DmShelveAccessupdate,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "dm.shelve.maxfiles",		0,	R10M,	0,	RBIG,	1,	R1K,	0,	0,	&MsgConfig::DmShelveMaxfiles,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "dm.shelve.maxsize",		0,	0,	0,	BBIG,	1,	B1K,	0,	0,	&MsgConfig::DmShelveMaxsize,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "dm.shelve.promote",		0,	0,	0,	1,	1,	1,	0,	0,	&MsgConfig::DmShelvePromote,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "dm.status.matchlines",	0,	80,	0,	100,	1,	1,	0,	0,	&MsgConfig::DmStatusMatchlines,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "dm.status.matchsize",	0,	10,	0,	R1G,	1,	R1K,	0,	0,	&MsgConfig::DmStatusMatchsize,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "dm.stream.parentview",	0,	0,	0,	2,	1,	1,	0,	0,	&MsgConfig::DmStreamParentview,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "dm.stream.components",	0,	0,	0,	1,	1,	1,	0,	0,	&MsgConfig::DmStreamComponents,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "dm.sync.streamchange",	0,	0,	0,	1,	1,	1,	0,	0,	&MsgConfig::DmSyncStreamChange,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "dm.subprotects.grant.admin",	0,	1,	0,	1,	1,	1,	0,	0,	&MsgConfig::DmSubprotectsGrantAdmin,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "dm.topology.lastseenupdate",	0,	300,	1,	RBIG,	1,	1,	0,	0,	&MsgConfig::DmTopologyLastseenupdate,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "dm.user.accessupdate",	0,	300,	1,	RBIG,	1,	1,	0,	0,	&MsgConfig::DmUserAccessupdate,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "dm.user.accessforce",	0,	3600,	1,	RBIG,	1,	1,	0,	0,	&MsgConfig::DmUserAccessforce,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "dm.user.allowselfupdate",	0,	1,	0,	1,	1,	1,	0,	0,	&MsgConfig::DmUserAllowselfupdate,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "dm.user.insecurelogin",	0,	0,	0,	1,	1,	1,	0,	1,	&MsgConfig::DmUserInsecurelogin,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "dm.user.loginattempts",	0,	3,	0,	10000,	1,	1,	0,	1,	&MsgConfig::DmUserLoginattempts,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "dm.user.noautocreate",	0,	0,	0,	2,	1,	1,	0,	0,	&MsgConfig::DmUserNoautocreate,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "dm.user.numeric",		0,	0,	0,	1,	1,	1,	0,	0,	&MsgConfig::DmUserNumeric,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "dm.user.resetpassword",	0,	0,	0,	1,	1,	1,	0,	0,	&MsgConfig::DmUserResetpassword,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "dm.user.setinitialpasswd",	0,	1,	0,	1,	1,	1,	0,	0,	&MsgConfig::DmUserSetinitialpasswd,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
# ifdef OS_NT
	{ "filesys.atomic.rename",	0,	1,	0,	1,	1,	1,	0,	0,	&MsgConfig::FilesysAtomicRename,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_RESTART,		CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
# endif
	{ "filesys.binaryscan",		0,	B64K,	0,	BBIG,	1,	B1K,	0,	0,	&MsgConfig::FilesysBinaryscan,		0,	CONFIG_APPLY_SERVER|CONFIG_APPLY_CLIENT, CONFIG_RESTART_NO_RESTART, CONFIG_SUPPORT_DOC, CONFIG_CAT_ADMIN },
	{ "filesys.bufsize",		0,	B64K,	B4K,	B10M,	1,	B1K,	0,	0,	&MsgConfig::FilesysBufsize,		0,	CONFIG_APPLY_SERVER|CONFIG_APPLY_CLIENT, CONFIG_RESTART_NO_RESTART, CONFIG_SUPPORT_DOC, CONFIG_CAT_ADMIN },
	{ "filesys.cachehint",		0,	0,	0,	1,	1,	1,	0,	0,	&MsgConfig::FilesysCachehint,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "filesys.checklinks",		0,	0,	0,	4,	1,	1,	0,	0,	&MsgConfig::FilesysChecklinks,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "filesys.detectunicode",	0,	1,	0,	1,	1,	1,	0,	0,	&MsgConfig::FilesysDetectunicode,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "filesys.detectutf8",		0,	2,	0,	2,	1,	1,	0,	0,	&MsgConfig::FilesysDetectutf8,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "filesys.lockdelay",		0,	90,	1,	RBIG,	1,	1,	0,	0,	&MsgConfig::FilesysLockdelay,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "filesys.locktimeout",	0,	1000,	0,	RBIG,	1,	1,	0,	0,	&MsgConfig::FilesysLocktimeout,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "filesys.locktry",		0,	100,	1,	RBIG,	1,	1,	0,	0,	&MsgConfig::FilesysLocktry,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "filesys.maketmp",		0,	10,	1,	RBIG,	1,	R1K,	0,	0,	&MsgConfig::FilesysMaketmp,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "filesys.maxmap",		0,	B1G,	0,	BBIG,	1,	B1K,	0,	0,	&MsgConfig::FilesysMaxmap,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "filesys.maxsymlink",		0,	B1K,	1,	BBIG,	1,	B1K,	0,	0,	&MsgConfig::FilesysMaxsymlink,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "filesys.maxtmp",		0,	R1M,	1,	RBIG,	1,	R1K,	0,	0,	&MsgConfig::FilesysMaxtmp,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "filesys.restrictsymlinks",	0,	1,	0,	1,	1,	1,	0,	0,	&MsgConfig::FilesysRestrictsymlinks,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "filesys.utf8bom",		0,	1,	0,	2,	1,	1,	0,	0,	&MsgConfig::FilesysUtf8Bom,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "filesys.extendlowmark",	0,	B32K,	0,	BBIG,	B1K,	B1K,	0,	0,	&MsgConfig::FilesysExtendlowmark,	0,	CONFIG_APPLY_CLIENT,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "filesys.windows.lfn",	0,	1,	0,	10,	1,	1,	0,	0,	&MsgConfig::FilesysWindowsLfn,		0,	CONFIG_APPLY_SERVER|CONFIG_APPLY_CLIENT|CONFIG_APPLY_PROXY, CONFIG_RESTART_NO_RESTART, CONFIG_SUPPORT_DOC, CONFIG_CAT_ADMIN },
	{ "filesys.client.nullsync",	0,	0,	0,	1,	1,	1,	0,	0,	&MsgConfig::FilesysClientNullsync,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "index.domain.owner",		0,	0,	0,	1,	1,	1,	0,	0,	&MsgConfig::IndexDomainOwner,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "lbr.autocompress",		0,	1,	0,	1,	1,	1,	0,	0,	&MsgConfig::LbrAutocompress,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "lbr.bufsize",		0,	B64K,	1,	BBIG,	1,	B1K,	0,	0,	&MsgConfig::LbrBufsize,			0,	CONFIG_APPLY_SERVER|CONFIG_APPLY_PROXY, CONFIG_RESTART_NO_RESTART, CONFIG_SUPPORT_DOC, CONFIG_CAT_ADMIN },
	{ "lbr.fabricate",		0,	0,	0,	1,	1,	1,	0,	0,	&MsgConfig::LbrFabricate,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "lbr.proxy.case",		0,	1,	1,	3,	1,	1,	0,	0,	&MsgConfig::LbrProxyCase,		0,	CONFIG_APPLY_PROXY,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "lbr.rcs.existcheck",		0,	1,	0,	1,	1,	1,	0,	0,	&MsgConfig::LbrRcsExistcheck,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "lbr.rcs.maxlen",		0,	B10M,	0,	BBIG,	1,	1,	0,	0,	&MsgConfig::LbrRcsMaxlen,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "lbr.replica.notransfer",	0,	0,	0,	1,	1,	1,	0,	0,	&MsgConfig::LbrReplicaNotransfer,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "lbr.retry.max",		0,	50,	1,	BBIG,	1,	R1K,	0,	0,	&MsgConfig::LbrRetryMax,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "lbr.stat.interval",		0,	0,	0,	999,	1,	1,	0,	0,	&MsgConfig::LbrStatInterval,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "lbr.verify.in",		0,	1,	0,	1,	1,	1,	0,	0,	&MsgConfig::LbrVerifyIn,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "lbr.verify.out",		0,	1,	0,	1,	1,	1,	0,	0,	&MsgConfig::LbrVerifyOut,		0,	CONFIG_APPLY_SERVER|CONFIG_APPLY_CLIENT, CONFIG_RESTART_NO_RESTART, CONFIG_SUPPORT_DOC, CONFIG_CAT_ADMIN },
	{ "lbr.verify.script.out",	0,	1,	0,	1,	1,	1,	0,	0,	&MsgConfig::LbrVerifyScriptOut,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "lbr.storage.delay",		0,	86400,	0,	BBIG,	1,	1,	0,	0,	&MsgConfig::LbrStorageDelay,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "lbr.storage.allowsymlink",	0,	0,	0,	BBIG,	1,	1,	0,	0,	&MsgConfig::LbrStorageAllowsymlink,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "lbr.storage.skipkeyed",	0,	2,	0,	BBIG,	1,	1,	0,	0,	&MsgConfig::LbrStorageSkipkeyed,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_STOP,		CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "lbr.storage.threads",	0,	0,	0,	B4K,	1,	1,	0,	0,	&MsgConfig::LbrStorageThreads,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "lbr.rcs.locking",		0,	0,	0,	1,	1,	1,	0,	0,	&MsgConfig::LbrRcsLocking,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "log.cmdgrp.maxlength",	0,	128,	0,	B8K,	1,	1,	0,	0,	&MsgConfig::LogGroupMaxlen,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "log.originhost",		0,	1,	0,	1,	1,	1,	0,	0,	&MsgConfig::LogOriginhost,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "map.joinmax1",		0,	R10K,	1,	200000, 1,	R1K,	0,	0,	&MsgConfig::MapJoinmax1,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_NODOC,	CONFIG_CAT_ADMIN },
	{ "map.joinmax2",		0,	R1M,	1,	RBIG,	1,	R1K,	0,	0,	&MsgConfig::MapJoinmax2,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_NODOC,	CONFIG_CAT_ADMIN },
	{ "map.maxwild",		0,	10,	1,	10,	1,	1,	0,	0,	&MsgConfig::MapMaxwild,			0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_NODOC,	CONFIG_CAT_ADMIN },
	// map.overlay.legacy to be removed in 2025-ish once overlay fixes are accepted
	{ "map.overlay.legacy", 	0,	0,	0,	1,	1,	1,	0,	0,	&MsgConfig::MapOverlayLegacy,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_NODOC,	CONFIG_CAT_ADMIN },
	{ "merge.dl.endeol",		0,	0,	0,	1,	1,	1,	0,	0,	&MsgConfig::MergeDlEndeol,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_NODOC,	CONFIG_CAT_ADMIN },
	{ "net.autotune",		0,	1,	0,	2,	1,	1,	0,	0,	&MsgConfig::NetAutotune,		0,	CONFIG_APPLY_SERVER|CONFIG_APPLY_CLIENT| CONFIG_APPLY_PROXY|CONFIG_APPLY_BROKER, CONFIG_RESTART_NO_RESTART, CONFIG_SUPPORT_DOC, CONFIG_CAT_ADMIN },
	{ "net.bufsize",		0,	B64K,	1,	BBIG,	1,	B1K,	0,	0,	&MsgConfig::NetBufsize,			0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_NODOC,	CONFIG_CAT_ADMIN },
	{ "net.keepalive.disable",	0,	0,	0,	1,	1,	R1K,	0,	0,	&MsgConfig::NetKeepaliveDisable,	0,	CONFIG_APPLY_SERVER|CONFIG_APPLY_CLIENT, CONFIG_RESTART_NO_RESTART, CONFIG_SUPPORT_DOC, CONFIG_CAT_ADMIN },
	{ "net.keepalive.idle",		0,	0,	0,	BBIG,	1,	R1K,	0,	0,	&MsgConfig::NetKeepaliveIdle,		0,	CONFIG_APPLY_SERVER|CONFIG_APPLY_CLIENT, CONFIG_RESTART_NO_RESTART, CONFIG_SUPPORT_DOC, CONFIG_CAT_ADMIN },
	{ "net.keepalive.interval",	0,	0,	0,	BBIG,	1,	R1K,	0,	0,	&MsgConfig::NetKeepaliveInterval,	0,	CONFIG_APPLY_SERVER|CONFIG_APPLY_CLIENT, CONFIG_RESTART_NO_RESTART, CONFIG_SUPPORT_DOC, CONFIG_CAT_ADMIN },
	{ "net.keepalive.count",	0,	0,	0,	BBIG,	1,	R1K,	0,	0,	&MsgConfig::NetKeepaliveCount,		0,	CONFIG_APPLY_SERVER|CONFIG_APPLY_CLIENT, CONFIG_RESTART_NO_RESTART, CONFIG_SUPPORT_DOC, CONFIG_CAT_ADMIN },
	{ "net.heartbeat.interval",	0,	2000,	1,	RBIG,	1,	R1K,	0,	1,	&MsgConfig::NetHeartbeatInterval,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_REF_DOC,		CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "net.heartbeat.wait",		0,	2000,	1,	RBIG,	1,	R1K,	0,	1,	&MsgConfig::NetHeartbeatWait,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_REF_DOC,		CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "net.heartbeat.missing.interval",0,	2000,	1,	RBIG,	1,	R1K,	0,	1,	&MsgConfig::NetHeartbeatMissingInterval, 0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_REF_DOC,		CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "net.heartbeat.missing.wait",	0,	4000,	1,	RBIG,	1,	R1K,	0,	1,	&MsgConfig::NetHeartbeatMissingWait,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_REF_DOC,		CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "net.heartbeat.missing.count",0,	5,	1,	100,	1,	1,	0,	1,	&MsgConfig::NetHeartbeatMissingCount,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_REF_DOC,		CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "net.maxfaultpub",		0,	100,	0,	BBIG,	1,	1,	0,	0,	&MsgConfig::NetMaxFaultPub,		0,	CONFIG_APPLY_PROXY,	CONFIG_RESTART_STOP,		CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "net.maxclosewait",		0,	1000,	0,	BBIG,	1,	B1K,	0,	0,	&MsgConfig::NetMaxclosewait,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "net.maxwait",		0,	0,	0,	BBIG,	1,	B1K,	0,	0,	&MsgConfig::NetMaxwait,			0,	CONFIG_APPLY_SERVER|CONFIG_APPLY_CLIENT|CONFIG_APPLY_PROXY, CONFIG_RESTART_STOP, CONFIG_SUPPORT_DOC, CONFIG_CAT_ADMIN },
	{ "net.parallel.max",		0,	0,	0,	100,	1,	1,	0,	0,	&MsgConfig::NetParallelMax,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "net.parallel.threads",	0,	0,	0,	100,	1,	1,	0,	0,	&MsgConfig::NetParallelThreads,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "net.parallel.batch",		0,	8,	1,	RBIG,	1,	R1K,	0,	0,	&MsgConfig::NetParallelBatch,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "net.parallel.batchsize",	0,	B512K,	1,	BBIG,	1,	B1K,	0,	0,	&MsgConfig::NetParallelBatchsize,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "net.parallel.min",		0,	9,	2,	RBIG,	1,	R1K,	0,	0,	&MsgConfig::NetParallelMin,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "net.parallel.minsize",	0,	B576K,	1,	BBIG,	1,	B1K,	0,	0,	&MsgConfig::NetParallelMinsize,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "net.parallel.shelve.threads",0,	0,	0,	100,	1,	B1K,	0,	0,	&MsgConfig::NetParallelShelveThreads,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "net.parallel.shelve.batch",	0,	8,	1,	RBIG,	1,	R1K,	0,	0,	&MsgConfig::NetParallelShelveBatch,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "net.parallel.shelve.min",	0,	9,	2,	RBIG,	1,	R1K,	0,	0,	&MsgConfig::NetParallelShelveMin,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "net.parallel.submit.threads",0,	0,	0,	100,	1,	1,	0,	0,	&MsgConfig::NetParallelSubmitThreads,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "net.parallel.submit.batch",	0,	8,	1,	RBIG,	1,	R1K,	0,	0,	&MsgConfig::NetParallelSubmitBatch,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "net.parallel.submit.min",	0,	9,	2,	RBIG,	1,	R1K,	0,	0,	&MsgConfig::NetParallelSubmitMin,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "net.parallel.sync.svrthreads",0,	0,	0,	RBIG,	1,	1,	0,	0,	&MsgConfig::NetParallelSyncSvrthreads,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "net.rcvbuflowmark",		0,	0,	0,	B32K,	1,	B1K,	0,	0,	&MsgConfig::NetRcvbuflowmark,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "net.rcvbufmaxsize",		0,	B100M,	1,	B1G,	1,	B1K,	0,	0,	&MsgConfig::NetRcvbufmaxsize,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "net.rcvbufsize",		0,	B1M,	1,	BBIG,	1,	B1K,	0,	0,	&MsgConfig::NetRcvbufsize,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "net.reuseport",		0,	0,	0,	1,	1,	1,	0,	0,	&MsgConfig::NetReuseport,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_STOP,		CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "net.rfc3484",		0,	0,	0,	1,	1,	1,	0,	0,	&MsgConfig::NetReuseport,		0,	CONFIG_APPLY_SERVER|CONFIG_APPLY_CLIENT, CONFIG_RESTART_STOP, CONFIG_SUPPORT_DOC, CONFIG_CAT_ADMIN },
	{ "net.sendlimit",		0,	B4K,	1,	BBIG,	1,	B1K,	0,	0,	&MsgConfig::NetSendlimit,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "net.tcpsize",		0,	B512K,	B1K,	B256M,	B1K,	B1K,	0,	0,	&MsgConfig::NetTcpsize,			0,	CONFIG_APPLY_SERVER|CONFIG_APPLY_CLIENT|CONFIG_APPLY_PROXY, CONFIG_RESTART_STOP, CONFIG_SUPPORT_DOC, CONFIG_CAT_ADMIN },
	{ "net.backlog",		0,	128,	1,      SMAX,   1,	B1K,	0,	0,	&MsgConfig::NetBacklog,			0,	CONFIG_APPLY_SERVER|CONFIG_APPLY_PROXY, CONFIG_RESTART_NO_RESTART, CONFIG_SUPPORT_DOC, CONFIG_CAT_ADMIN },
	{ "net.x3.minsize",		0,	B512K,	0,	RBIG,	B1K,	B1K,	0,	1,	&MsgConfig::NetX3Minsize,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "proxy.deliver.fix",		0,	1,	0,	1,	1,	1,	0,	1,	&MsgConfig::ProxyDeliverFix,		0,	CONFIG_APPLY_PROXY,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "proxy.monitor.interval",	0,	10,	1,	999,	1,	1,	0,	1,	&MsgConfig::ProxyMonitorInterval,	0,	CONFIG_APPLY_PROXY,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "proxy.monitor.level",	0,	0,	0,	3,	1,	1,	0,	1,	&MsgConfig::ProxyMonitorLevel,		0,	CONFIG_APPLY_PROXY,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "proxy.clearcachethresh",	0,	0,	0,	RBIG,	1,	1,	0,	1,	&MsgConfig::ProxyClearcachethresh,	0,	CONFIG_APPLY_PROXY,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "rcs.maxinsert",		0,	R1G,	1,	RBIG,	1,	R1K,	0,	1,	&MsgConfig::RcsMaxinsert,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "rcs.nofsync",		0,	0,	0,	1,	1,	1,	0,	1,	&MsgConfig::RcsNofsync,			0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "rpc.delay",			0,	0,	0,	RBIG,	1,	1,	0,	0,	&MsgConfig::RpcDelay,			0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "rpc.durablewait",		0,	0,	0,	1,	1,	1,	0,	0,	&MsgConfig::RpcDurablewait,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "rpc.himark",			0,	2000,	2000,	BBIG,	1,	B1K,	0,	0,	&MsgConfig::RpcHimark,			0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "rpc.lowmark",		0,	700,	700,	BBIG,	1,	B1K,	0,	0,	&MsgConfig::RpcLowmark,			0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "rpc.ipaddr.mismatch",	0,	0,	0,	1,	1,	1,	0,	1,	&MsgConfig::RpcIpaddrMismatch,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "rpl.archive.graph",		0,	2,	0,	2,	1,	1,	0,	1,	&MsgConfig::RplArchiveGraph,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "rpl.awaitjnl.count",		0,	100,	1,	RBIG,	1,	R1K,	0,	1,	&MsgConfig::RplAwaitjnlCount,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "rpl.awaitjnl.interval",	0,	50,	1,	RBIG,	1,	R1K,	0,	1,	&MsgConfig::RplAwaitjnlInterval,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "rpl.buffer.release",		0,	R1M,	1,	RBIG,	1,	R1K,	0,	1,	&MsgConfig::RplBufferRelease,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "rpl.checksum.auto",		0,	0,	0,	3,	1,	1,	0,	1,	&MsgConfig::RplChecksumAuto,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "rpl.checksum.change",	0,	0,	0,	3,	1,	1,	0,	1,	&MsgConfig::RplChecksumChange,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "rpl.checksum.table",		0,	0,	0,	2,	1,	1,	0,	1,	&MsgConfig::RplChecksumTable,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "rpl.compress",		0,	0,	0,	4,	1,	1,	0,	1,	&MsgConfig::RplCompress,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "rpl.counter.hook",		0,	1,	0,	1,	1,	1,	0,	1,	&MsgConfig::RplCounterHook,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "rpl.deferred.sends",		0,	0,	0,	1,	1,	1,	0,	1,	&MsgConfig::RplDeferredSends,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "rpl.jnl.batch.size",		0,	R100M,	0,	RBIG,	1,	R1K,	0,	1,	&MsgConfig::RplJnlBatchSize,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_REF_DOC,		CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "rpl.jnlwait.adjust",		0,	25,	0,	RBIG,	1,	R1K,	0,	1,	&MsgConfig::RplJnlwaitAdjust,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "rpl.jnlwait.interval",	0,	50,	50,	RBIG,	1,	R1K,	0,	1,	&MsgConfig::RplJnlwaitInterval,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "rpl.jnlwait.max",		0,	1000,	100,	RBIG,	1,	R1K,	0,	1,	&MsgConfig::RplJnlwaitMax,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "rpl.journal.ack",		0,	0,	0,	B1M,	1,	1,	0,	1,	&MsgConfig::RplJournalAck,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "rpl.journal.ack.min",	0,	0,	0,	B1M,	1,	1,	0,	1,	&MsgConfig::RplJournalAckMin,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "rpl.journalcopy.location",	0,	0,	0,	1,	1,	1,	0,	1,	&MsgConfig::RplJournalcopyLocation,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "rpl.labels.global",		0,	0,	0,	1,	1,	1,	0,	0,	&MsgConfig::RplLabelsGlobal,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "rpl.replay.userrp",		0,	0,	0,	1,	1,	1,	0,	0,	&MsgConfig::RplReplayUserrp,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "rpl.track.behind",		0,	0,	0,	2,	1,	1,	0,	0,	&MsgConfig::RplTrackBehind,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_STOP,		CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "rpl.track.behind.interval",	0,	R10K,	0,	RBIG,	1,	R1K,	0,	0,	&MsgConfig::RplTrackBehindInterval,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_STOP,		CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "rpl.verify.cache",		0,	0,	0,	1,	1,	1,	0,	0,	&MsgConfig::RplVerifyCache,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "rpl.verify.shared",		0,	1,	0,	1,	1,	1,	0,	0,	&MsgConfig::RplVerifyShared,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "rpl.pull.archivedepots",	0,	0,	0,	1,	1,	1,	0,	0,	&MsgConfig::RplPullArchivedepots,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_REF_DOC,		CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "run.clientexts.allow",	0,	1,	0,	1,	1,	1,	0,	0,	&MsgConfig::RunClientextsAllow,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "run.move.allow",		0,	1,	0,	2,	1,	1,	0,	0,	&MsgConfig::RunMoveAllow,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "run.obliterate.allow",	0,	1,	0,	1,	1,	1,	0,	0,	&MsgConfig::RunObliterateAllow,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "run.prune.allow",		0,	1,	0,	1,	1,	1,	0,	0,	&MsgConfig::RunPruneAllow,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "run.renameclient.allow",	0,	1,	0,	3,	1,	1,	0,	0,	&MsgConfig::RunRenameclientAllow,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "run.unzip.user.allow",	0,	0,	0,	1,	1,	1,	0,	0,	&MsgConfig::RunUnzipUserAllow,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "run.users.authorize",	0,	0,	0,	1,	1,	1,	0,	1,	&MsgConfig::RunUsersAuthorize,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "server.commandlimits",	0,	0,	0,	2,	1,	1,	0,	1,	&MsgConfig::ServerCommandlimits,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "server.ctrlc.filecleanup",	0,	0,	0,	1,	1,	1,	0,	0,	&MsgConfig::ServerCtrlcFilecleanup,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "server.extensions.allow.admin",0,	1,	0,	1,	1,	1,	0,	1,	&MsgConfig::ServerExtsAllowAdmin,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "server.extensions.allow.unsigned",0,	0,	0,	1,	1,	1,	0,	1,	&MsgConfig::ServerExtsAllowUnsigned,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "server.filecharset",		0,	0,	0,	1,	1,	1,	0,	0,	&MsgConfig::ServerFilecharset,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "server.locks.archive",	0,	1,	0,	1,	1,	1,	0,	0,	&MsgConfig::ServerLocksArchive,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "server.locks.sync",		0,	0,	0,	1,	1,	1,	0,	0,	&MsgConfig::ServerLocksSync,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "server.locks.global",	0,	0,	0,	1,	1,	1,	0,	0,	&MsgConfig::ServerLocksGlobal,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "server.allowfetch",		0,	0,	0,	3,	1,	1,	0,	0,	&MsgConfig::ServerAllowfetch,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "server.allowpush",		0,	0,	0,	3,	1,	1,	0,	0,	&MsgConfig::ServerAllowpush,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "server.allowremotelocking",	0,	0,	0,	1,	1,	1,	0,	0,	&MsgConfig::ServerAllowremotelocking,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "server.allowrewrite",	0,	0,	0,	1,	1,	1,	0,	0,	&MsgConfig::ServerAllowrewrite,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "server.global.client.views",	0,	0,	0,	1,	1,	1,	0,	0,	&MsgConfig::ServerGlobalClientViews,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "server.oom_adj_score",	0,	-1000,	-1000,	1000,	1,	1,	-1000,	0,	&MsgConfig::ServerOomAdjScore,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "server.maxcommands",		0,	0,	0,	RBIG,	1,	R1K,	0,	1,	&MsgConfig::ServerMaxcommands,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_STOP,		CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "server.maxcommands.allow",	0,	1,	0,	1,	1,	1,	0,	1,	&MsgConfig::ServerMaxcommandsAllow,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_STOP,		CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "server.start.unlicensed",	0,	0,	0,	1,	1,	1,	0,	1,	&MsgConfig::ServerStartUnlicensed,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "filetype.bypasslock",	0,	0,	0,	1,	1,	1,	0,	1,	&MsgConfig::FiletypeBypasslock,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "filetype.maxtextsize",	0,	B10M,	0,	RBIG,	1,	R1K,	0,	0,	&MsgConfig::FiletypeMaxtextsize,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "spec.hashbuckets",		0,	99,	0,	999,	1,	1,	0,	0,	&MsgConfig::SpecHashbuckets,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "spec.custom",		0,	0,	0,	1,	1,	1,	0,	0,	&MsgConfig::SpecCustom,			0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "streamview.dots.low",	0,	0,	0,	1,	1,	1,	0,	0,	&MsgConfig::StreamviewDotsLow,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "streamview.sort.remap",	0,	0,	0,	1,	1,	1,	0,	0,	&MsgConfig::StreamviewSortRemap,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "submit.collision.check",	0,	1,	0,	1,	1,	1,	0,	0,	&MsgConfig::SubmitCollisioncheck,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "submit.forcenoretransfer",	0,	0,	0,	2,	1,	1,	0,	0,	&MsgConfig::SubmitForcenoretransfer,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "submit.noretransfer",	0,	0,	0,	1,	1,	1,	0,	0,	&MsgConfig::SubmitNoretransfer,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_STOP,		CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "submit.allowbgtransfer",	0,	0,	0,	1,	1,	1,	0,	0,	&MsgConfig::SubmitAllowbgtransfer,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_STOP,		CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "submit.autobgtransfer",	0,	0,	0,	1,	1,	1,	0,	0,	&MsgConfig::SubmitAutobgtransfer,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_STOP,		CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "submit.unlocklocked",	0,	0,	0,	1,	1,	1,	0,	0,	&MsgConfig::SubmitUnlockLocked,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "submit.storagefields",	0,	0,	0,	1,	1,	1,	0,	0,	&MsgConfig::SubmitStoragefields,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "trait.storagedepot.min",	0,	0,	0,	RBIG,	1,	R1K,	0,	0,	&MsgConfig::TraitStoredepot,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "switch.stream.unrelated",	0,	0,	0,	1,	1,	1,	0,	0,	&MsgConfig::SwitchStreamUnrelated,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "push.unlocklocked",		0,	0,	0,	1,	1,	1,	0,	0,	&MsgConfig::PushUnlockLocked,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	// vv Smart Heap tunables must be a continuous group vv
	{ "sys.memory.poolfree",	0,	SHPOOL,	0,	BBIG,	1,	B1K,	0,	1,	&MsgConfig::SysMemoryPoolfree,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_NODOC,	CONFIG_CAT_ADMIN },
	{ "sys.memory.procfree",	0,	SHPROC,	0,	BBIG,	1,	B1K,	0,	1,	&MsgConfig::SysMemoryProcfree,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_NODOC,	CONFIG_CAT_ADMIN },
	{ "sys.memory.poolgrowinc",	0,	SHGROW1,0,	BBIG,	1,	B1K,	0,	1,	&MsgConfig::SysMemoryPoolgrowinc,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_NODOC,	CONFIG_CAT_ADMIN },
	{ "sys.memory.procgrowinc",	0,	SHGROW2,0,	BBIG,	1,	B1K,	0,	1,	&MsgConfig::SysMemoryProcgrowinc,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_NODOC,	CONFIG_CAT_ADMIN },
	{ "sys.memory.subpools",	0,	SHSUBP,	0,	BBIG,	1,	B1K,	0,	1,	&MsgConfig::SysMemorySubpools,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_NODOC,	CONFIG_CAT_ADMIN },
	{ "sys.memory.limit",		0,	0,	0,	BBIG,	1,	B1K,	0,	1,	&MsgConfig::SysMemoryLimit,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_NODOC,	CONFIG_CAT_ADMIN },
	{ "sys.memory.debug",		0,	0,	0,	1,	1,	1,	0,	1,	&MsgConfig::SysMemoryDebug,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_NODOC,	CONFIG_CAT_ADMIN },
	{ "cmd.memory.poolfree",	0,	0,	0,	BBIG,	1,	B1K,	0,	1,	&MsgConfig::CmdMemoryPoolfree,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_NODOC,	CONFIG_CAT_ADMIN },
	{ "cmd.memory.procfree",	0,	0,	0,	BBIG,	1,	B1K,	0,	1,	&MsgConfig::CmdMemoryProcfree,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_NODOC,	CONFIG_CAT_ADMIN },
	{ "cmd.memory.limit",		0,	0,	0,	BBIG,	1,	B1K,	0,	1,	&MsgConfig::CmdMemoryLimit,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_NODOC,	CONFIG_CAT_ADMIN },
	{ "cmd.memory.flushpool",	0,	0,	0,	BBIG,	1,	B1K,	0,	1,	&MsgConfig::CmdMemoryFlushpool,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_NODOC,	CONFIG_CAT_ADMIN },
	{ "cmd.memory.listpools",	0,	0,	0,	BBIG,	1,	B1K,	0,	1,	&MsgConfig::CmdMemoryListpools,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_NODOC,	CONFIG_CAT_ADMIN },
	{ "cmd.memory.chkpt",		0,	0,	0,	BBIG,	1,	B1K,	0,	1,	&MsgConfig::CmdMemoryChkpt,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_NODOC,	CONFIG_CAT_ADMIN },
	// ^^ Smart Heap tunables must be a continuous group ^^
	// vv mimalloc tunables must be a continuous group vv
	// mimalloc settings are first defined in mem/mimalloc/mimalloc.h's
	// mi_option_t.  Defaults are in mem/mimalloc/options.c
# if defined(_DEBUG) || defined(MEM_DEBUG)
	{ "sys.memory.mi.showerrors",	0,	1,	0,	1,	1,	1,	0,	1,	&MsgConfig::SysMemoryMiShowerrors,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_NODOC,	CONFIG_CAT_ADMIN },
# else
	{ "sys.memory.mi.showerrors",	0,	0,	0,	1,	1,	1,	0,	1,	&MsgConfig::SysMemoryMiShowerrors,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_NODOC,	CONFIG_CAT_ADMIN },
# endif
	{ "sys.memory.mi.showstats",	0,	0,	0,	1,	1,	1,	0,	1,	&MsgConfig::SysMemoryMiShowstats,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_NODOC,	CONFIG_CAT_ADMIN },
	{ "sys.memory.mi.verbose",	0,	0,	0,	1,	1,	1,	0,	1,	&MsgConfig::SysMemoryMiVerbose,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_NODOC,	CONFIG_CAT_ADMIN },
	{ "sys.memory.mi.eagercommit",	0,	1,	0,	1,	1,	1,	0,	1,	&MsgConfig::SysMemoryMiEagercommit,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_NODOC,	CONFIG_CAT_ADMIN },
	// NB: These two are deprecated in the mimalloc 2.x branch, and resetdecommits
	// crashes when set to 1.
# if defined(OS_NT) || (defined(OS_LINUX) && defined(__i386__))
	{ "sys.memory.mi.eagerregioncommit",0,	0,	0,	1,	1,	1,	0,	1,	&MsgConfig::SysMemoryMiEagerregioncommit, 0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_NODOC,	CONFIG_CAT_ADMIN },
	{ "sys.memory.mi.resetdecommits",0,	0,	0,	1,	1,	1,	0,	1,	&MsgConfig::SysMemoryMiShowerrors,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_NODOC,	CONFIG_CAT_ADMIN },
# else
	{ "sys.memory.mi.eagerregioncommit",0,	0,	0,	1,	1,	1,	0,	1,	&MsgConfig::SysMemoryMiEagerregioncommit, 0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_NODOC,	CONFIG_CAT_ADMIN },
	{ "sys.memory.mi.resetdecommits",0,	0,	0,	1,	1,	1,	0,	1,	&MsgConfig::SysMemoryMiShowerrors,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_NODOC,	CONFIG_CAT_ADMIN },
# endif
	{ "sys.memory.mi.largeospages",	0,	0,	0,	1,	1,	1,	0,	1,	&MsgConfig::SysMemoryMiLargeospages,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_NODOC,	CONFIG_CAT_ADMIN },
	{ "sys.memory.mi.reservehugeospages",0,	0,	0,	RBIG,	1,	1,	0,	1,	&MsgConfig::SysMemoryMiReservehugeospages, 0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_NODOC,	CONFIG_CAT_ADMIN },
	{ "sys.memory.mi.reservehugeospagesat", 0, -1,	-1,	RBIG,	1,	1,	0,	1,	&MsgConfig::SysMemoryMiReservehugeospagesat, 0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_NODOC,	CONFIG_CAT_ADMIN },
	{ "sys.memory.mi.reserveosmemory", 0,	0,	0,	RBIG,	1,	1,	0,	1,	&MsgConfig::SysMemoryMiReserveosmemory,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_NODOC,	CONFIG_CAT_ADMIN },
	// Deprecated in mimalloc 2.x
	{ "sys.memory.mi.segmentcache",	0,	0,	0,	RBIG,	1,	1,	0,	1,	&MsgConfig::SysMemoryMiSegmentcache,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_NODOC,	CONFIG_CAT_ADMIN },
	{ "sys.memory.mi.pagereset",	0,	0,	0,	1,	1,	1,	0,	1,	&MsgConfig::SysMemoryMiPagereset,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_NODOC,	CONFIG_CAT_ADMIN },
	// This turned into abandoned_page_decommit in 2.x.
	{ "sys.memory.mi.abandonedpagereset",0,	0,	0,	1,	1,	1,	0,	1,	&MsgConfig::SysMemoryMiAbandonedpagereset, 0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_NODOC,	CONFIG_CAT_ADMIN },
	// Deprecated in mimalloc 2.x
	{ "sys.memory.mi.segmentreset",	0,	0,	0,	1,	1,	1,	0,	1,	&MsgConfig::SysMemoryMiSegmentreset,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_NODOC,	CONFIG_CAT_ADMIN },
# ifdef OS_NT
	{ "sys.memory.mi.eagercommitdelay",0,	4,	0,	RBIG,	1,	1,	0,	1,	&MsgConfig::SysMemoryMiEagercommitdelay, 0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_NODOC,	CONFIG_CAT_ADMIN },
# else
	{ "sys.memory.mi.eagercommitdelay",0,	1,	0,	RBIG,	1,	1,	0,	1,	&MsgConfig::SysMemoryMiEagercommitdelay, 0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_NODOC,	CONFIG_CAT_ADMIN },
# endif
	// This was reset_delay in 1.x.
	{ "sys.memory.mi.decommitdelay",0,	25,	0,	RBIG,	1,	1,	0,	1,	&MsgConfig::SysMemoryMiDecommitDelay,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_NODOC,	CONFIG_CAT_ADMIN },
	{ "sys.memory.mi.usenumanodes",	0,	0,	0,	RBIG,	1,	1,	0,	1,	&MsgConfig::SysMemoryMiUsenumanodes,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_NODOC,	CONFIG_CAT_ADMIN },
	{ "sys.memory.mi.limitosalloc",	0,	0,	0,	1,	1,	1,	0,	1,	&MsgConfig::SysMemoryMiLimitosalloc,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_NODOC,	CONFIG_CAT_ADMIN },
	{ "sys.memory.mi.ostag",	0,	100,	0,	RBIG,	1,	1,	0,	1,	&MsgConfig::SysMemoryMiOstag,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_NODOC,	CONFIG_CAT_ADMIN },
	{ "sys.memory.mi.maxerrors",	0,	16,	0,	RBIG,	1,	1,	0,	1,	&MsgConfig::SysMemoryMiMaxerrors,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_NODOC,	CONFIG_CAT_ADMIN },
	{ "sys.memory.mi.maxwarnings",	0,	16,	0,	RBIG,	1,	1,	0,	1,	&MsgConfig::SysMemoryMiMaxwarnings,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_NODOC,	CONFIG_CAT_ADMIN },
	{ "sys.memory.mi.maxsegmentreclaim",0, 8,	0,	RBIG,	1,	1,	0,	1,	&MsgConfig::SysMemoryMiMaxsegmentreclaim, 0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_NODOC,	CONFIG_CAT_ADMIN },
	{ "sys.memory.mi.allowdecommit",     0, 1,	0,	RBIG,	1,	1,	0,	1,	&MsgConfig::SysMemoryMiAllowdecommit,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_NODOC,	CONFIG_CAT_ADMIN },
	{ "sys.memory.mi.segmentdecommitdelay",0, 500,	0,	RBIG,	1,	1,	0,	1,	&MsgConfig::SysMemoryMiSegmentdecommitdelay, 0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_NODOC,	CONFIG_CAT_ADMIN },
	{ "sys.memory.mi.decommitextenddelay",0, 2,	0,	RBIG,	1,	1,	0,	1,	&MsgConfig::SysMemoryMiDecommitextenddelay, 0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_NODOC,	CONFIG_CAT_ADMIN },
	// ^^ mimalloc tunables must be a continuous group ^^
	{ "sys.memory.stacksize",	0,	0,	0,	B16K,	1,	B1K,	0,	1,	&MsgConfig::SysMemoryStacksize,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_NODOC,	CONFIG_CAT_ADMIN },
#ifndef OS_MACOSX
	{ "sys.pressure.max.pause.time",0,	300,	0,	RBIG,	1,	1,	300,	0,	&MsgConfig::SysPressureMaxPauseTime,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
#else
	// Pressure monitoring is not implemented on OSX.
	{ "sys.pressure.max.pause.time",0,	0,	0,	0,	1,	1,	0,	0,	&MsgConfig::SysPressureMaxPauseTime,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
#endif
	{ "sys.pressure.max.paused",	0,	1000,	0,	RBIG,	1,	1,	1000,	0,	&MsgConfig::SysPressureMaxPauseTime,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "sys.pressure.mem.high",	0,	95,	0,	100,	1,	1,	95,	0,	&MsgConfig::SysPressureMemHigh,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "sys.pressure.mem.high.duration",
	                                0,	1000,	100,	RBIG,	1,	1,	1000,	0,	&MsgConfig::SysPressureMemHighDuration,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "sys.pressure.mem.medium",	0,	80,	0,	100,	1,	1,	80,	0,	&MsgConfig::SysPressureMemMedium,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "sys.pressure.mem.medium.duration",
	                                0,	1000,	100,	RBIG,	1,	1,	1000,	0,	&MsgConfig::SysPressureMemMediumDuration, 0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "sys.pressure.os.cpu.high",	0,	100,	0,	100,	1,	1,	100,	0,	&MsgConfig::SysPressureOsCpuHigh,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "sys.pressure.os.cpu.high.duration",
	                                0,	2000,	100,	RBIG,	1,	1,	2000,	0,	&MsgConfig::SysPressureOsCpuHighDuration, 0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "sys.pressure.os.mem.high",	0,	70,	0,	100,	1,	1,	70,	0,	&MsgConfig::SysPressureOsMemHigh,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "sys.pressure.os.mem.high.duration",
	                                0,	2000,	100,	RBIG,	1,	1,	2000,	0,	&MsgConfig::SysPressureOsMemHighDuration, 0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "sys.pressure.os.mem.medium",	0,	40,	0,	100,	1,	1,	40,	0,	&MsgConfig::SysPressureOsMemMedium,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "sys.pressure.os.mem.medium.duration",
	                                0,	2000,	100,	RBIG,	1,	1,	2000,	0,	&MsgConfig::SysPressureOsMemMediumDuration, 0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "sys.rename.max",		0,	10,	10,	RBIG,	1,	R1K,	0,	1,	&MsgConfig::SysRenameMax,		0,	CONFIG_APPLY_SERVER|CONFIG_APPLY_CLIENT, CONFIG_RESTART_NO_RESTART, CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "sys.rename.wait",		0,	1000,	50,	RBIG,	1,	R1K,	0,	1,	&MsgConfig::SysRenameWait,		0,	CONFIG_APPLY_SERVER|CONFIG_APPLY_CLIENT, CONFIG_RESTART_NO_RESTART, CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "sys.threading.groups",	0,	0,	0,	1,	1,	1,	0,	1,	&MsgConfig::SysThreadingGroups,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_STOP,		CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "sys.types.allow64",		0,	0,	0,	3,	1,	1,	0,	1,	&MsgConfig::SysTypesAllow64,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "rpl.forward.all",		0,	0,	0,	1,	1,	1,	0,	0,	&MsgConfig::RplForwardAll,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_REF_DOC,		CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "rpl.forward.login",		0,	0,	0,	1,	1,	1,	0,	0,	&MsgConfig::RplForwardLogin,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_REF_DOC,		CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "rpl.pull.position",		0,	0,	0,	RBIG,	1,	R1K,	0,	0,	&MsgConfig::RplPullPosition,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_REF_DOC,		CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "rpl.pull.reload",		0,	60000,	0,	RBIG,	1,	R1K,	0,	0,	&MsgConfig::RplPullReload,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "ssl.secondary.suite",	0,	0,	0,	1,	1,	1,	0,	0,	&MsgConfig::SslSecondarySuite,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "ssl.client.timeout",		0,	30,	1,	RBIG,	1,	1,	0,	0,	&MsgConfig::SslClientTimeout,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "ssl.client.tls.version.min",	0,	12,	10,	13,	1,	1,	0,	1,	&MsgConfig::SslClientTlsVersionMin,	0,	CONFIG_APPLY_SERVER|CONFIG_APPLY_CLIENT, CONFIG_RESTART_STOP, CONFIG_SUPPORT_DOC, CONFIG_CAT_ADMIN },
	{ "ssl.client.tls.version.max",	0,	13,	10,	13,	1,	1,	0,	0,	&MsgConfig::SslClientTlsVersionMax,	0,	CONFIG_APPLY_SERVER|CONFIG_APPLY_CLIENT, CONFIG_RESTART_STOP, CONFIG_SUPPORT_DOC, CONFIG_CAT_ADMIN },
	{ "ssl.client.trust.name",	0,	1,	0,	2,	1,	1,	0,	0,	&MsgConfig::SslClientTrustName,		0,	CONFIG_APPLY_CLIENT,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "ssl.client.cert.validate",	0,	1,	0,	2,	1,	1,	0,	0,	&MsgConfig::SslClientCertValidate,	0,	CONFIG_APPLY_SERVER|CONFIG_APPLY_CLIENT, CONFIG_RESTART_STOP, CONFIG_SUPPORT_DOC, CONFIG_CAT_ADMIN },
	{ "ssl.tls.version.min",	0,	10,	10,	13,	1,	1,	0,	1,	&MsgConfig::SslTlsVersionMin,		0,	CONFIG_APPLY_SERVER|CONFIG_APPLY_CLIENT, CONFIG_RESTART_STOP, CONFIG_SUPPORT_DOC, CONFIG_CAT_ADMIN },
	{ "ssl.tls.version.max",	0,	12,	10,	13,	1,	1,	0,	0,	&MsgConfig::SslTlsVersionMax,		0,	CONFIG_APPLY_SERVER|CONFIG_APPLY_CLIENT, CONFIG_RESTART_STOP, CONFIG_SUPPORT_DOC, CONFIG_CAT_ADMIN },
	{ "ssl.enable.etm",		0,	1,	0,	1,	1,	1,	0,	0,	&MsgConfig::SslEnableEtm,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "triggers.io",		0,	0,	0,	1,	1,	1,	0,	0,	&MsgConfig::TriggersIo,			0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "istat.mimic.ichanges",	0,	0,	0,	1,	1,	1,	0,	0,	&MsgConfig::IstatMimicIchanges,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_UNDOC,	CONFIG_CAT_ADMIN },
	{ "info.p4auth.usercheck",	0,	1,	0,	1,	1,	1,	0,	0,	&MsgConfig::InfoP4AuthUsercheck,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "auth.autologinprompt",	0,	1,	0,	1,	1,	1,	0,	0,	&MsgConfig::AuthAutologinprompt,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "rpl.submit.nocopy",		0,	0,	0,	1,	1,	1,	0,	0,	&MsgConfig::RplSubmitNocopy,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "auth.2fa.persist",		0,	1,	0,	2,	1,	1,	0,	1,	&MsgConfig::Auth2FaPersist,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "auth.tickets.nounlocked",	0,	0,	0,	2,	1,	1,	0,	1,	&MsgConfig::AuthTicketsNounlocked,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "auth.licenseexpiry.warn",	0,	1,	0,	2,	1,	1,	0,	1,	&MsgConfig::AuthLicenseexpiryWarn,	0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "auth.licenseexpiry.warnthreshold",0,	7,	1,	365,	1,	1,	0,	1,	&MsgConfig::AuthLicenseexpiryWarnthreshold, 0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "auth.sso.allow.passwd",	0,	0,	0,	1,	1,	1,	0,	1,	&MsgConfig::AuthSsoAllowPasswd,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "auth.sso.nonldap",		0,	0,	0,	1,	1,	1,	0,	1,	&MsgConfig::AuthSsoNonldap,		0,	CONFIG_APPLY_SERVER,	CONFIG_RESTART_NO_RESTART,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	{ "zlib.compression.level",	0,	-1,	-1,	9,	1,	1,	-1,	0,	&MsgConfig::ZlibCompressionLevel,	0,	CONFIG_APPLY_SERVER|CONFIG_APPLY_CLIENT|CONFIG_APPLY_PROXY|CONFIG_APPLY_BROKER, CONFIG_RESTART_NO_RESTART, CONFIG_SUPPORT_DOC, CONFIG_CAT_ADMIN },
	{ "zlib.disable.optim",		0,	0,	0,	1,	1,	1,	0,	0,	&MsgConfig::ZlibDisableOptim,		0,	CONFIG_APPLY_SERVER|CONFIG_APPLY_CLIENT|CONFIG_APPLY_PROXY|CONFIG_APPLY_BROKER, CONFIG_RESTART_STOP, CONFIG_SUPPORT_UNDOC, CONFIG_CAT_ADMIN },

	{ 0, 0, 0, 0, 0, 0, 0, 0, 1 }

	// name				isSet,	value,	min,	max,	mod,	k,	orig,	sensitive

} ;

P4Tunable::stunable P4Tunable::slist[] = {

	// P4Debug's string collection

	// name				isSet,	default, *value, sensitive

	{ "ssl.client.ca.path",		0,	0,	0,	0,	&MsgConfig::SSLClientCAPath,	0,	CONFIG_APPLY_SERVER|CONFIG_APPLY_CLIENT,	CONFIG_RESTART_STOP,	CONFIG_SUPPORT_DOC,	CONFIG_CAT_ADMIN },
	
	{ 0,				0,	0,	0,	0 }

	// name				isSet,	default, *value, sensitive
} ;

// List of current values of P4Debug's integer collection
P4MT int
list2[] = { -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 }  ;

int
P4Tunable::IsKnown( const char *n )
{
	int i;
	for( i = 0; list[i].name; i++ )
	    if( !strcmp( list[i].name, n ) )
	        return DTT_INT;
	for( i = 0; slist[i].name; i++ )
	    if( !strcmp( slist[i].name, n ) )
	        return DTT_STR;
	return DTT_NONE;
}

int
P4Tunable::IsSet( const char * n ) const
{
	int i;
	for( i = 0; list[i].name; i++ )
	    if( !strcmp( list[i].name, n ) )
	    {
	        if( i < DT_LAST && list2[i] != -1 )
	            return 1;
	        return list[i].isSet;
	    }
	for( i = 0; slist[i].name; i++ )
	    if( !strcmp( slist[i].name, n ) )
	        return slist[i].isSet;
	return 0;
}

const P4Tunable::tunable* 
P4Tunable::GetTunable( int i ) const
{
	if( i >= 0 && i < P4TUNE_LAST && list[i].name )
	    return &list[i];
	
	return 0;
}

const P4Tunable::stunable* 
P4Tunable::GetStringTunable( int i ) const
{
	const int t = P4TUNE_LAST + 1 + i;
	if( t > P4TUNE_LAST && t < P4TUNE_LAST_STR && slist[i].name )
	    return &slist[i];
	
	return 0;
}

int
P4Tunable::GetLevel( const char *n ) const
{
	int i;
	for( i = 0; list[i].name; i++ )
	    if( !strcmp( list[i].name, n ) )
	    {
		if( i < DT_LAST && list2[i] != -1 )
		    return list2[i];
		return list[i].value;
	    }
	return 0;
}

StrBuf
P4Tunable::GetString( const char *n ) const
{
	StrBuf ret;
	int i;
	for( i = 0; slist[i].name; i++ )
	    if( !strcmp( slist[i].name, n ) )
	    {
	        if( slist[i].isSet && slist[i].value )
	            ret = slist[i].value;
	        else if( slist[i].def )
	            ret = slist[i].def;
	        return ret;
	    }
	return ret;
}

StrBuf
P4Tunable::GetString( int t ) const
{
	StrBuf ret;
	int i = t - ( P4TUNE_LAST + 1 );
	if( i >= 0 && t < P4TUNE_LAST_STR && slist[i].name )
	{
	    // Warning: potential race condition on read vs delete/replace
	    if( slist[i].isSet && slist[i].value )
	        ret = slist[i].value;
	    else if( slist[i].def )
	        ret = slist[i].def;
	    return ret;
	}
	return ret;
}

int
P4Tunable::GetIndex( const char *n ) const
{
	int i, j;
	for( i = 0; list[i].name; i++ )
	    if( !strcmp( list[i].name, n ) )
	        return i;
	for( j = 0, i = P4TUNE_LAST + 1; slist[j].name; i++, j++ )
	    if( !strcmp( slist[j].name, n ) )
	        return i;
	return -1;
}

void
P4Tunable::Unset( const char *n )
{
	int i;
	for( i = 0; list[i].name; i++ )
	{
	    if( !strcmp( list[i].name, n ) )
	    {
	        if( list[i].isSet )
	        {
	            list[i].value = list[i].original;
	            list[i].isSet = 0;
	        }
	        return;
	    }
	}
	for( i = 0; slist[i].name; i++ )
	{
	    if( !strcmp( slist[i].name, n ) )
	    {
	        if( slist[i].isSet )
	        {
	            // Warning: potential race condition on read vs delete
	            slist[i].isSet = 0;
	            char *val = slist[i].value;
	            slist[i].value = 0;
	            delete[] val;
	        }
	        return;
	    }
	}
}

void
P4Tunable::UnsetAll()
{
	int i;
	for( i = 0; list[i].name; i++ )
	{
	    if( list[i].isSet )
	    {
	        list[i].value = list[i].original;
	        list[i].isSet = 0;
	    }
	}
	for( i = 0; slist[i].name; i++ )
	{
	    if( slist[i].isSet )
	    {
	        // Warning: potential race condition on read vs delete
	        slist[i].isSet = 0;
	        char *val = slist[i].value;
	        slist[i].value = 0;
	        delete[] val;
	    }
	}
}

NO_SANITIZE_UNDEFINED
void
P4Tunable::Set( const char *set )
{
	while( *set )
	{
	    int i, j;
	    const char *comma, *equals;

	    if( !( comma = strchr( set, ',' ) ) )
		comma = set + strlen( set );
		
	    if( !( equals = strchr( set, '=' ) ) || equals > comma )
		equals = comma;

	    for( i = 0; list[i].name; i++ )
	    {
		if( strlen( list[i].name ) == equals - set && 
		    !strncmp( list[i].name, set, equals - set ) )
			break;
	    }

	    for( j = 0; i >= P4TUNE_LAST && slist[j].name; i++, j++ )
	    {
	    	if( i == P4TUNE_LAST ) // skip the separator
		    j--;
		else if( strlen( slist[j].name ) == equals - set && 
		    !strncmp( slist[j].name, set, equals - set ) )
			break;
	    }

	    if( i <= P4TUNE_LAST && list[i].name )
	    {
		int val = 0;
		int negative = 0;

		// Atoi()

		if( equals[1] == '-' )
		{
		    negative = 1;
		    equals++;
		}

		while( ++equals < comma && isdigit( *equals ) )
		    val = val * 10 + *equals - '0';

		if( negative )
		    val = -val;

		// k = *1000, m = *1000,000

		if( *equals == 'k' || *equals == 'K' )
		    val *= list[i].k, ++equals;

		if( *equals == 'm' || *equals == 'M' )
		    val *= list[i].k * list[i].k;

		// Min, max, and mod

		val = val < list[i].minVal ? list[i].minVal : val;
		val = val > list[i].maxVal ? list[i].maxVal : val;
		val = ( val + list[i].modVal - 1 ) & ~( list[i].modVal - 1 );

	        if( !list[i].isSet )
	            list[i].original = list[i].value;
		list[i].value = val;
		list[i].isSet = 1;

	        Unbuffer();
	    }

	    if( i > P4TUNE_LAST && i <= P4TUNE_LAST_STR && slist[j].name )
	    {
	        // Warning: potential race condition on read vs replace
	        StrBuf sval;
	        if( comma - (equals + 1) > 0 )
	            sval.Set( equals + 1, comma - (equals + 1) );

	        // Stash the pointer and "unset" the tunable
	        char *oval = slist[j].value;
	        slist[j].isSet = 0;
	        slist[j].value = 0;

	        // Do the time consuming stuff
	        char *nval = new char[sval.Length() + 1];
	        memcpy( nval, sval.Text(), sval.Length() + 1 );

	        // Replace the value and enable the tunable
	        slist[j].value = nval;
	        slist[j].isSet = 1;

	        // Free the old value
	        delete[] oval;
	        Unbuffer();
	    }

	    set = *comma ? comma + 1 : comma;
	}
}

void
P4Tunable::SetTLocal( const char *set )
{
	while( *set )
	{
	    int i;
	    const char *comma, *equals;

	    if( !( comma = strchr( set, ',' ) ) )
		comma = set + strlen( set );
		
	    if( !( equals = strchr( set, '=' ) ) || equals > comma )
		equals = comma;

	    for( i = 0; list[i].name; i++ )
	    {
		if( strlen( list[i].name ) == equals - set && 
		    !strncmp( list[i].name, set, equals - set ) )
			break;
	    }

	    // Only debug values!
	    if( i < DT_LAST && list[i].name )
	    {
		int val = 0;
		int negative = 0;

		// Atoi()

		if( equals[1] == '-' )
		{
		    negative = 1;
		    equals++;
		}

		while( ++equals < comma && isdigit( *equals ) )
		    val = val * 10 + *equals - '0';

		if( negative )
		    val = -val;

		// k = *1000, m = *1000,000

		if( *equals == 'k' || *equals == 'K' )
		    val *= list[i].k, ++equals;

		if( *equals == 'm' || *equals == 'M' )
		    val *= list[i].k * list[i].k;

		// Min, max, and mod

		val = val < list[i].minVal ? list[i].minVal : val;
		val = val > list[i].maxVal ? list[i].maxVal : val;
		val = ( val + list[i].modVal - 1 ) & ~( list[i].modVal - 1 );

		list2[i] = val;

	        Unbuffer();
	    }

	    set = *comma ? comma + 1 : comma;
	}
}

void
P4Tunable::SetActive( int t, int v )
{
	/*
	 * Set the active value for a tunable without normalizing against the
	 * tunable's 'minVal', 'maxVal', or 'modVal' defintions, nor altering
	 * the tunable's 'isSet' or 'original' attributes.
	 *
	 * The need to use this method should be rare. Its intended use
	 * is to set a tunable to a specific value that will be used at a
	 * lower layer and the value cannot otherwise be passed into the
	 * lower layer.
	 *
	 * The correctness of the value for the tunable is the
	 * responsibility of the caller!
	 */

	list[t].value = v;
}

int
P4Tunable::IsNumeric( const char *p )
{
	const char *s = p;
	long val = 0;
	int negative = 0;

	if( *p == '-' )
	{
	    negative = 1;
	    p++;
	}

	while( *p && isdigit( *p ) )
	{
	    if( val > BBIG / 10 )
	        return 0;
	    val = val * 10 + *p - '0';
	    if( val < 0 || val > BBIG )
	        return 0;
	    p++;
	}

	if( p == s )
	    return 0;

	if( *p && ( *p == 'k' || *p == 'K' || *p == 'm' || *p == 'M' ) )
	{
	    if( val >= BBIG / 1024 )
	        return 0;
	    val *= 1024;
	    if( *p == 'm' || *p == 'M' )
	    {
	        if( val >= BBIG / 1024 )
	            return 0;
	        val *= 1024;
	    }
	    if( (!negative && val < 0) || val > BBIG )
	        return 0;
	    p++;
	}

	return !(*p);
}

void
P4Tunable::IsValid( const char *n, const char *v, Error *e )
{
	int i = GetIndex( n );
	if( i < 0 || i == P4TUNE_LAST || i >= P4TUNE_LAST_STR )
	{
	    e->Set( MsgSupp::UnknownTunable ) << n;
	    return;
	}

	// No validation on strings
	if( i > P4TUNE_LAST )
	    return;
	
	long val = 0;
	int negative = 0;

	// Atoi()

	if( *v == '-' )
	{
	    negative = 1;
	    v++;
	}

	while( *v && isdigit( *v ) )
	{
	    val = val * 10 + *v - '0';
	    v++;
	}

	if( negative )
	    val = -val;

	// k = *1000, m = *1000,000

	if( *v == 'k' || *v == 'K' )
	    val *= list[i].k, ++v;

	if( *v == 'm' || *v == 'M' )
	    val *= list[i].k * list[i].k;

	// Min or max

	if( val < list[i].minVal )
	    e->Set(MsgSupp::TunableValueTooLow) << n << StrNum(list[i].minVal);
	if( !e->Test() && val > list[i].maxVal )
	    e->Set(MsgSupp::TunableValueTooHigh) << n <<StrNum(list[i].maxVal);
}

void
P4Tunable::Unbuffer()
{
	setbuf( stdout, 0 );
}

void
P4Debug::SetLevel( int l )
{
	for( int i = 0; i < DT_LAST; i++ )
	    list[i].value = l;

	Unbuffer();
}

void
P4Debug::SetLevel( const char *set )
{
	// -vx sets all debug levels to x
	// -vn=x sets tunable level n to x

	if( strchr( set, '=' ) )
	    Set( set );
	else
	    SetLevel( atoi( set ) );
}

void
P4Debug::ShowLevels( int showAll, StrBuf &buf )
{
	int i;
	for( i = 0; list[i].name; i++ )
	    if( showAll || list[i].isSet )
	        buf << list[i].name << ": " << list[i].value << "\n";
	for( i = 0; slist[i].name; i++ )
	    if( showAll || slist[i].isSet )
	    {
	        char *val = slist[i].isSet ? slist[i].value : 0;
	        buf << slist[i].name << ": "
	            << (val ? val : slist->def ? slist->def : "") << "\n";
	    }
}

void
P4Debug::Event()
{
	StrBuf prefix;
	P4DebugConfig::TsPid2StrBuf(prefix);

	printf( prefix.Text() );
}

void
P4Debug::printf( const char *fmt, ... )
{
# ifdef OS_NT
	DWORD saveError = GetLastError();
# else
	int saveError = errno;
# endif
	if( p4debughelp )
	{
	    StrBuf *buf = p4debughelp->Buffer();

	    int ssz = buf->Length();

	    if( ssz < 0 )
	    {
		ssz = 0;
		buf->Clear();
	    }

	    int asz = 80;
	    int sz, rsz;

	    sz = p4debughelp->Alloc( asz );

	    va_list l;

	    va_start( l, fmt );

	    rsz = vsnprintf( buf->Alloc( asz ), sz, fmt, l );

	    va_end( l );

# if defined(OS_NT) && defined(_MSC_VER) && _MSC_VER < 1910
	    // Depending on the version of Visual Studio, the behavior of
	    // vsnprintf() may differ.  On versions prior to VS2017, it will
	    // return -1 when the size is too small, unless the size is only
	    // 1 byte too small, then it returns sz, so we have to iterate
	    // getting more space until it works.

	    while( rsz == -1 || rsz == sz )
	    {
		buf->SetLength( ssz );

		asz *= 3;

		sz = p4debughelp->Alloc( asz );

	        va_start( l, fmt );

	        rsz = vsnprintf( buf->Alloc( asz ), sz, fmt, l );

	        va_end( l );
	    }
# else
	    if( rsz >= sz )
	    {
		buf->SetLength( ssz );

		rsz++;

		p4debughelp->Alloc( rsz );

		va_start( l, fmt );

		rsz = vsnprintf( buf->Alloc( rsz ), rsz, fmt, l );

		va_end( l );
	    }
# endif

	    buf->SetLength( rsz + ssz );

	    if( buf->Text()[ buf->Length() - 1 ] == '\n' )
	    {
		p4debughelp->Output();
		buf->Clear();
	    }
	}
	else
	{
	    va_list l;

	    va_start( l, fmt );

	    vprintf( fmt, l );

	    va_end( l );
	}
# ifdef OS_NT
	SetLastError( saveError );
# else
	errno = saveError;
# endif
}

P4DebugConfig::P4DebugConfig()
    : buf(NULL), msz(0), elog(NULL), hook(NULL), context(NULL), cloned(0)
{
}

P4DebugConfig::~P4DebugConfig()
{
	if( p4debughelp == this )
	    p4debughelp = NULL;

	delete buf;

	if( cloned && elog )
	    delete elog;
}

void
P4DebugConfig::Install()
{
	p4debughelp = this;
}

StrBuf *
P4DebugConfig::Buffer()
{
	if( !buf )
	    buf = new StrBuf;

	return buf;
}

int
P4DebugConfig::Alloc( int s )
{
	int l = buf->Length();

	if( l + s > msz )
	    msz = l + s;

	return msz - l;
}

void
P4DebugConfig::TsPid2StrBuf( StrBuf &prefix )
{
	Pid pid;
	DateTimeHighPrecision dt;
	char buf[ DTHighPrecisionBufSize ];
	char str[ DTHighPrecisionBufSize + 20];

	dt.Now();
	dt.Fmt( buf );
	sprintf( str, "%s pid %d: ", buf, pid.GetID() );
	prefix.Set(str);
}

void
P4DebugConfig::Output()
{
    if( buf )
    {
	if( hook )
	    (*hook)( context, buf );
	else
	{
	    StrBuf *output = buf;
	    StrBuf formattedBuf;
	    if( p4debug.GetLevel( DT_TIME ) >= 1 )
	    {
		TsPid2StrBuf( formattedBuf );
		formattedBuf.Append(buf);
		output = &formattedBuf;
	    }

	    if( elog )
		elog->LogWrite( *output );
	    else
		fputs( output->Text(), stdout );
	}
    }
}

P4DebugConfig *
P4DebugConfig::ThreadClone()
{
	if ( p4debughelp )
	{
	    return p4debughelp->Clone();
	}
	return NULL;
}

P4DebugConfig *
P4DebugConfig::Clone()
{
	P4DebugConfig *clone = new P4DebugConfig;

	if ( elog )
	{
	    // If there is an ErrorLog set, clone it into a new ErrorLog
	    // object and install.
	    // Writes to STDOUT maybe intermixed. The writes
	    // are typically small, so we will probably get
	    // away with it. No plans to protect against this.
	    clone->cloned = 1;
	    clone->elog = new ErrorLog( elog );
	}

	return clone;
}
