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

#include <msgsupp.h>

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

	// P4Debug's collection

	{ "db",		0, -1, -1, 10, 1, 1, 0, 1 },
	{ "diff",	0, -1, -1, 10, 1, 1, 0, 1 },
	{ "dm",		0, -1, -1, 10, 1, 1, 0, 1 },
	{ "dmc",	0, -1, -1, 10, 1, 1, 0, 1 },
	{ "ftp",	0, -1, -1, 10, 1, 1, 0, 1 },
	{ "handle",	0, -1, -1, 10, 1, 1, 0, 1 },
	{ "lbr", 	0, -1, -1, 10, 1, 1, 0, 1 },
	{ "map",	0, -1, -1, 10, 1, 1, 0, 1 },
	{ "net",	0, -1, -1, 10, 1, 1, 0, 1 },
	{ "options",	0, -1, -1, 10, 1, 1, 0, 1 },
	{ "peek",	0, -1, -1, 10, 1, 1, 0, 1 },
	{ "rcs",	0, -1, -1, 10, 1, 1, 0, 1 },
	{ "records",	0, -1, -1, 10, 1, 1, 0, 1 },
	{ "rpc", 	0, -1, -1, 10, 1, 1, 0, 1 },
	{ "server",	0, -1, -1, 10, 1, 1, 0, 1 },
	{ "spec", 	0, -1, -1, 10, 1, 1, 0, 1 },
	{ "track",	0, -1, -1, 10, 1, 1, 0, 1 },
	{ "ob",		0, -1, -1, 10, 1, 1, 0, 1 },
	{ "viewgen",	0, -1, -1, 10, 1, 1, 0, 1 },
	{ "rpl",	0, -1, -1, 10, 1, 1, 0, 1 },
	{ "ssl",	0, -1, -1, 10, 1, 1, 0, 1 },
	{ "time",	0, -1, -1, 10, 1, 1, 0, 1 },
	{ "cluster",	0, -1, -1, 10, 1, 1, 0, 1 },
	{ "zk",		0, -1, -1, 10, 1, 1, 0, 1 },
	{ "ldap",	0, -1, -1, 10, 1, 1, 0, 1 },
	{ "dvcs",	0, -1, -1, 10, 1, 1, 0, 1 },
	{ "graph",	0, -1, -1, 10, 1, 1, 0, 1 },
	{ "gconn",	0, -1, -1, 10, 1, 1, 0, 1 },
	{ "fovr",	0, -1, -1, 10, 1, 1, 0, 1 },
	{ "script",	0, -1, -1, 10, 1, 1, 0, 1 },
	{ "stg",	0, -1, -1, 30, 1, 1, 0, 1 },
	{ "thread",	0, -1, -1, 10, 1, 1, 0, 1 },
	{ "exts",	0, -1, -1, 10, 1, 1, 0, 1 },
	{ "protect",	0,  1, -1, 10, 1, 1, 0, 1 }, // Enabled until paranoia passes
	{ "heartbeat",	0, -1, -1, 10, 1, 1, 0, 1 },
	{ "shelve",	0, -1, -1, 10, 1, 1, 0, 1 },
	{ "sqw",	0, -1, -1, 10, 1, 1, 0, 1 },
	{ "stm",	0, -1, -1, 10, 1, 1, 0, 1 },
	{ "pcheck",	0, -1, -1, 10, 1, 1, 0, 1 },
	{ "topology",	0, -1, -1, 10, 1, 1, 0, 1 },

	// P4Tunable's collection
	//
	// name				isSet,	value,	min,	max,	mod,	k,	orig,	sensitive

	{ "cluster.journal.shared",	0,	0,	0,	1,	1,	1,	0,	1 },
	{ "db.checkpoint.bufsize",	0,	B224K,	B16K,	BBIG,	1,	B1K,	0,	1 },
	{ "db.checkpoint.threads",	0,	0,	0,	B4K,	1,	1,	0,	1 },
	{ "db.checkpoint.worklevel",	0,	3,	2,	20,	1,	1,	0,	1 },
	{ "db.checkpoint.reqlevel",	0,	4,	2,	20,	1,	1,	0,	1 },         
	{ "db.checkpoint.nofiles",	0,	10,	1,	20000,	1,	1,	0,	1 },               
	{ "db.experimental.logging",	0,	0,	0,	1,	1,	1,	0,	1 },
	{ "db.internal.repair",		0,	0,	0,	1,	1,	1,	0,	1 },
	{ "db.isalive",			0,	R10K,	1,	RBIG,	1,	R1K,	0,	1 },
	{ "db.jnlack.shared",		0,	16,	0,	2048,	1,	B1K,	0,	1 },
	{ "db.monitor.addthresh",	0,	0,	0,	RBIG,	1,	B1K,	0,	1 },
	{ "db.monitor.interval",	0,	30,	0,	900,	1,	1,	0,	1 },
	{ "db.monitor.minruntime",	0,	10,	1,	120,	1,	1,	0,	1 },
	{ "db.monitor.term.allow",	0,	0,	0,	2,	1,	1,	0,	1 },
	{ "db.monitor.shared",		0,	256, 0, MAX_SHARED_MONITOR, 1, 	B1K,	0,	1 },
	{ "db.page.migrate",		0,	0,	0,	80,	1,	1,	0,	1 },
	{ "db.peeking",			0,	2,	0,	3,	1,	1,	0,	1 },
	{ "db.peeking.usemaxlock",	0,	0,	0,	1,	1,	1,	0,	1 },
	{ "db.reorg.disable",		0,	1,	0,	1,	1,	1,	0,	1 },
	{ "db.reorg.misorder",		0,	80,	0,	100,	1,	1,	0,	1 },
	{ "db.reorg.occup",		0,	8,	0,	100,	1,	1,	0,	1 },
	{ "db.rt.io",			0,	0,	0,	1,	1,	1,	0,	0 },
	{ "db.trylock",			0,	3,	0,	RBIG,	1,	R1K,	0,	1 },
	{ "dbarray.putcheck",		0,	R4K,	1,	RBIG,	1,	R1K,	0,	1 },
	{ "dbarray.reserve",		0,	B4M,	B4K,	BBIG,	1,	B1K,	0,	1 },
	{ "dbjournal.bufsize",		0,	B16K,	1,	BBIG,	1,	B1K,	0,	1 },
	{ "dbjournal.wordsize",		0,	B4K,	1,	BBIG,	1,	B1K,	0,	1 },
	{ "dbopen.cache",		0,	96,	1,	RBIG,	1,	R1K,	0,	1 },
	{ "dbopen.cache.wide",		0,	192,	1,	RBIG,	1,	R1K,	0,	1 },
	{ "dbopen.freepct",		0,	0,	0,	99,	1,	1,	0,	1 },
	{ "dbopen.mismatch.delay",	0,	300,	10,	RBIG,	1,	1,	0,	1 },
	{ "dbopen.nofsync",		0,	0,	0,	1,	1,	1,	0,	1 },
	{ "dbopen.pagesize",		0,	B8K,	B8K,	B16K,	B8K,	B1K,	0,	1 },
	{ "dbopen.retry",		0,	10,	0,	100,	1,	1,	0,	1 },
	{ "diff.binary.rcs",		0,	0,	0,	1,	1,	1,	0,	0 },
	{ "diff.slimit1",		0,	R10M,	R10K,	RBIG,	1,	R1K,	0,	0 },
	{ "diff.slimit2",		0,	R100M,	R10K,	RBIG,	1,	R1K,	0,	0 },
	{ "diff.sthresh",		0,	R50K,	R1K,	RBIG,	1,	R1K,	0,	0 },
	{ "dm.annotate.maxsize",	0,	B10M,	0,	BBIG,	1,	B1K,	0,	0 },
	{ "dm.batch.domains",		0,	0,	R1K,	RBIG,	1,	R1K,	0,	0 },
	{ "dm.batch.net",		0,	R10K,	1,	RBIG,	1,	R1K,	0,	0 },
	{ "dm.change.restrict.pending",	0,	0,	0,	1,	1,	1,	0,	0 },
	{ "dm.change.skipkeyed",	0,	0,	0,	1,	1,	1,	0,	0 },
	{ "dm.changes.thresh1",		0,	R50K,	1,	RBIG,	1,	R1K,	0,	0 },
	{ "dm.changes.thresh2",		0,	R10K,	1,	RBIG,	1,	R1K,	0,	0 },
	{ "dm.changeview.openable",	0,	0,	0,	1,	1,	1,	0,	0 },
	{ "dm.client.initroot",	0,	0,	0,	1,	1,	1,	0,	0 },
	{ "dm.client.limitprotects",	0,	0,	0,	RBIG,	1,	1,	0,	0 },
	{ "dm.copy.movewarn",		0,	0,	0,	1,	1,	1,	0,	0 },
	{ "dm.domain.accessupdate",	0,	300,	1,	RBIG,	1,	1,	0,	0 },
	{ "dm.domain.accessforce",	0,	3600,	1,	RBIG,	1,	1,	0,	0 },
	{ "dm.flushforce",		0,	R10K,	1,	RBIG,	1,	R1K,	0,	0 },
	{ "dm.flushtry",		0,	100,	1,	RBIG,	1,	R1K,	0,	0 },
	{ "dm.fstat.maxcontent",	0,	B4M,	0,	B10M,	1,	B1K,	0,	0 },
	{ "dm.graph.enabled",		0,	1,	0,	1,	1,	1,	0,	0 },
	{ "dm.grep.maxlinelength",	0,	B4K,	128,	B16K,	1,	B1K,	0,	0 },
	{ "dm.grep.maxrevs",		0,	R10K,	0,	RBIG,	1,	R1K,	0,	0 },
	{ "dm.grep.maxcontext",		0,	R1K,	0,	B16K,	1,	R1K,	0,	0 },
	{ "dm.info.hide",		0,	0,	0,	1,	1,	1,	0,	1 },
	{ "dm.integ.engine",		0,	3,	0,	3,	1,	1,	0,	0 },
	{ "dm.integ.maxact",		0,	R100K,	1,	RBIG,	1,	R1K,	0,	0 },
	{ "dm.integ.streamspec",	0,	1,	0,	2,	1,	1,	0,	0 },
	{ "dm.integ.tweaks",		0,	0,	0,	256,	1,	1,	0,	0 },
	{ "dm.integ.undo",		0,	0,	0,	1,	1,	1,	0,	0 },
	{ "dm.integ.multiplestreams",	0,	0,	0,	1,	1,	1,	0,	0 },
	{ "dm.isalive",			0,	R50K,	1,	RBIG,	1,	R1K,	0,	0 },
	{ "dm.keys.hide",		0,	0,	0,	2,	1,	1,	0,	0 },
	{ "dm.labels.search.autoreload",	0,	0,	0,	2,	1,	1,	0,	0 },
	{ "dm.lock.batch",		0,	R10K,	1,	RBIG,	1,	R1K,	0,	0 },
	{ "dm.locks.excl.batch.net",		0,	R10K,	1,	RBIG,	1,	R1K,	0,	0 },
	{ "dm.locks.global.batch.net",		0,	R10K,	1,	RBIG,	1,	R1K,	0,	0 },
	{ "dm.locks.global.result.batch.net",	0,	R10K,	1,	RBIG,	1,	R1K,	0,	0 },
	{ "dm.maxkey",			0,	B1K,	64,	B4K,	1,	B1K,	0,	1 }, // B4K = max(dbopen.pagesize) / 4
	{ "dm.open.show.globallocks",	0,	0,	0,	1,	1,	1,	0,	0 },
	{ "dm.password.minlength",	0,	8,	0,	1024,	1,	1,	0,	0 },
	{ "dm.populate.skipkeyed",	0,	0,	0,	1,	1,	1,	0,	0 },
	{ "dm.protects.allow.admin",	0,	0,	0,	1,	1,	1,	0,	0 },
	{ "dm.protects.exclusioncheck",	0,	1,	0,	1,	1,	1,	0,	1 },
	{ "dm.protects.hide",		0,	0,	0,	1,	1,	1,	0,	0 },
	{ "dm.protects.streamspec",	0,	0,	0,	1,	1,	1,	0,	0 },
	{ "dm.proxy.protects",		0,	1,	0,	1,	1,	1,	0,	0 },
	{ "dm.quick.clients",		0,	R10M,	1,	RBIG,	1,	R1K,	0,	0 },
	{ "dm.quick.domains",		0,	R10M,	1,	RBIG,	1,	R1K,	0,	0 },
	{ "dm.quick.have",		0,	R1M,	1,	RBIG,	1,	R1K,	0,	0 },
	{ "dm.quick.integ",		0,	R1M,	1,	RBIG,	1,	R1K,	0,	0 },
	{ "dm.quick.resolve",		0,	R1K,	1,	RBIG,	1,	R1K,	0,	0 },
	{ "dm.quick.rev",		0,	R1M,	1,	RBIG,	1,	R1K,	0,	0 },
	{ "dm.quick.working",		0,	R1K,	1,	RBIG,	1,	R1K,	0,	0 },
	{ "dm.repo.noautocreate",	0,	0,	0,	1,	1,	1,	0,	0 },
	{ "dm.repo.unpack",		0,	1,	0,	2,	1,	1,	0,	0 },
	{ "dm.resolve.attrib",		0,	1,	0,	1,	1,	1,	0,	0 },
	{ "dm.resolve.ignoredeleted",	0,	0,	0,	1,	1,	1,	0,	0 },
	{ "dm.revcx.thresh1",		0,	R4K,	1,	RBIG,	1,	R1K,	0,	0 },
	{ "dm.revcx.thresh2",		0,	R1K,	1,	RBIG,	1,	R1K,	0,	0 },
	{ "dm.revert.batch",		0,	R10K,	1,	RBIG,	1,	R1K,	0,	0 },
	{ "dm.rotatelogwithjnl",	0,	1,	0,	1,	1,	1,	0,	0 },
	{ "dm.shelve.accessupdate",	0,	300,	1,	RBIG,	1,	1,	0,	0 },
	{ "dm.shelve.maxfiles",		0,	R10M,	0,	RBIG,	1,	R1K,	0,	0 },
	{ "dm.shelve.maxsize",		0,	0,	0,	BBIG,	1,	B1K,	0,	0 },
	{ "dm.shelve.promote",		0,	0,	0,	1,	1,	1,	0,	0 },
	{ "dm.status.matchlines",	0,	80,	0,	100,	1,	1,	0,	0 },
	{ "dm.status.matchsize",	0,	10,	0,	R1G,	1,	R1K,	0,	0 },
	{ "dm.stream.parentview",	0,	0,	0,	2,	1,	1,	0,	0 },
	{ "dm.stream.components",	0,	0,	0,	1,	1,	1,	0,	0 },
	{ "dm.sync.streamchange",	0,	0,	0,	1,	1,	1,	0,	0 },
	{ "dm.subprotects.grant.admin",	0,	1,	0,	1,	1,	1,	0,	0 },
	{ "dm.topology.lastseenupdate",	0,	300,	1,	RBIG,	1,	1,	0,	0 },
	{ "dm.user.accessupdate",	0,	300,	1,	RBIG,	1,	1,	0,	0 },
	{ "dm.user.accessforce",	0,	3600,	1,	RBIG,	1,	1,	0,	0 },
	{ "dm.user.allowselfupdate",	0,	1,	0,	1,	1,	1,	0,	0 },
	{ "dm.user.insecurelogin",	0,	0,	0,	1,	1,	1,	0,	1 },
	{ "dm.user.loginattempts",	0,	3,	0,	10000,	1,	1,	0,	1 },
	{ "dm.user.noautocreate",	0,	0,	0,	2,	1,	1,	0,	0 },
	{ "dm.user.numeric",		0,	0,	0,	1,	1,	1,	0,	0 },
	{ "dm.user.resetpassword",	0,	0,	0,	1,	1,	1,	0,	0 },
	{ "dm.user.setinitialpasswd",	0,	1,	0,	1,	1,	1,	0,	0 },
# ifdef OS_NT
	{ "filesys.atomic.rename",	0,	0,	0,	1,	1,	1,	0,	0 },
# endif
	{ "filesys.binaryscan",		0,	B64K,	0,	BBIG,	1,	B1K,	0,	0 },
	{ "filesys.bufsize",		0,	B64K,	B4K,	B10M,	1,	B1K,	0,	0 },
	{ "filesys.cachehint",		0,	0,	0,	1,	1,	1,	0,	0 },
	{ "filesys.checklinks",		0,	0,	0,	4,	1,	1,	0,	0 },
	{ "filesys.detectunicode",	0,	1,	0,	1,	1,	1,	0,	0 },
	{ "filesys.detectutf8",		0,	2,	0,	2,	1,	1,	0,	0 },
	{ "filesys.lockdelay",		0,	90,	1,	RBIG,	1,	1,	0,	0 },
	{ "filesys.locktry",		0,	100,	1,	RBIG,	1,	1,	0,	0 },
	{ "filesys.maketmp",		0,	10,	1,	RBIG,	1,	R1K,	0,	0 },
	{ "filesys.maxmap",		0,	B1G,	0,	BBIG,	1,	B1K,	0,	0 },
	{ "filesys.maxsymlink",		0,	B1K,	1,	BBIG,	1,	B1K,	0,	0 },
	{ "filesys.maxtmp",		0,	R1M,	1,	RBIG,	1,	R1K,	0,	0 },
	{ "filesys.restrictsymlinks",	0,	1,	0,	1,	1,	1,	0,	0 },
	{ "filesys.utf8bom",		0,	1,	0,	2,	1,	1,	0,	0 },
	{ "filesys.extendlowmark",	0,	B32K,	0,	BBIG,	B1K,	B1K,	0,	0 },
	{ "filesys.windows.lfn",	0,	1,	0,	10,	1,	1,	0,	0 },
	{ "filesys.client.nullsync",	0,	0,	0,	1,	1,	1,	0,	0 },
	{ "index.domain.owner",		0,	0,	0,	1,	1,	1,	0,	0 },
	{ "lbr.autocompress",		0,	1,	0,	1,	1,	1,	0,	0 },
	{ "lbr.bufsize",		0,	B64K,	1,	BBIG,	1,	B1K,	0,	0 },
	{ "lbr.fabricate",		0,	0,	0,	1,	1,	1,	0,	0 },
	{ "lbr.proxy.case",		0,	1,	1,	3,	1,	1,	0,	0 },
	{ "lbr.rcs.existcheck",		0,	1,	0,	1,	1,	1,	0,	0 },
	{ "lbr.rcs.maxlen",		0,	B10M,	0,	BBIG,	1,	1,	0,	0 },
	{ "lbr.replica.notransfer",	0,	0,	0,	1,	1,	1,	0,	0 },
	{ "lbr.retry.max",		0,	50,	1,	BBIG,	1,	R1K,	0,	0 },
	{ "lbr.stat.interval",		0,	0,	0,	999,	1,	1,	0,	0 },
	{ "lbr.verify.in",		0,	1,	0,	1,	1,	1,	0,	0 },
	{ "lbr.verify.out",		0,	1,	0,	1,	1,	1,	0,	0 },
	{ "lbr.verify.script.out",	0,	1,	0,	1,	1,	1,	0,	0 },
	{ "lbr.storage.delay",		0,	86400,	0,	BBIG,	1,	1,	0,	0 },
	{ "lbr.storage.allowsymlink",	0,	0,	0,	BBIG,	1,	1,	0,	0 },
	{ "lbr.storage.skipkeyed",	0,	2,	0,	BBIG,	1,	1,	0,	0 },
	{ "lbr.storage.threads",	0,	0,	0,	B4K,	1,	1,	0,	0 },        
	{ "lbr.rcs.locking",		0,	0,	0,	1,	1,	1,	0,	0 },
	{ "log.cmdgrp.maxlength",	0,	128,	0,	B8K,	1,	1,	0,	0 },
	{ "log.originhost",		0,	1,	0,	1,	1,	1,	0,	0 },
	{ "map.joinmax1",		0,	R10K,	1,	200000, 1,	R1K,	0,	0 },
	{ "map.joinmax2",		0,	R1M,	1,	RBIG,	1,	R1K,	0,	0 },
	{ "map.maxwild",		0,	10,	1,	10,	1,	1,	0,	0 },
	{ "merge.dl.endeol",		0,	0,	0,	1,	1,	1,	0,	0 },
	{ "net.autotune",		0,	1,	0,	1,	1,	1,	0,	0 },
	{ "net.bufsize",		0,	B64K,	1,	BBIG,	1,	B1K,	0,	0 },
	{ "net.keepalive.disable",	0,	0,	0,	1,	1,	R1K,	0,	0 },
	{ "net.keepalive.idle",		0,	0,	0,	BBIG,	1,	R1K,	0,	0 },
	{ "net.keepalive.interval",	0,	0,	0,	BBIG,	1,	R1K,	0,	0 },
	{ "net.keepalive.count",	0,	0,	0,	BBIG,	1,	R1K,	0,	0 },
	{ "net.heartbeat.interval",	0,	2000,	1,	RBIG,	1,	R1K,	0,	1 },
	{ "net.heartbeat.wait",		0,	2000,	1,	RBIG,	1,	R1K,	0,	1 },
	{ "net.heartbeat.missing.interval",0,	2000,	1,	RBIG,	1,	R1K,	0,	1 },
	{ "net.heartbeat.missing.wait",	0,	4000,	1,	RBIG,	1,	R1K,	0,	1 },
	{ "net.heartbeat.missing.count",0,	5,	1,	100,	1,	1,	0,	1 },
	{ "net.maxfaultpub",		0,	100,	0,	BBIG,	1,	1,	0,	0 },
	{ "net.maxclosewait",		0,	1000,	0,	BBIG,	1,	B1K,	0,	0 },
	{ "net.maxwait",		0,	0,	0,	BBIG,	1,	B1K,	0,	0 },
	{ "net.parallel.max",		0,	0,	0,	100,	1,	1,	0,	0 },
	{ "net.parallel.threads",	0,	0,	2,	100,	1,	1,	0,	0 },
	{ "net.parallel.batch",		0,	0,	1,	RBIG,	1,	R1K,	0,	0 },
	{ "net.parallel.batchsize",	0,	0,	1,	BBIG,	1,	B1K,	0,	0 },
	{ "net.parallel.min",		0,	0,	2,	RBIG,	1,	R1K,	0,	0 },
	{ "net.parallel.minsize",	0,	0,	1,	BBIG,	1,	B1K,	0,	0 },
	{ "net.parallel.shelve.threads",0,	0,	2,	100,	1,	B1K,	0,	0 },
	{ "net.parallel.shelve.batch",	0,	0,	1,	RBIG,	1,	R1K,	0,	0 },
	{ "net.parallel.shelve.min",	0,	0,	2,	RBIG,	1,	R1K,	0,	0 },
	{ "net.parallel.submit.threads",0,	0,	2,	100,	1,	1,	0,	0 },
	{ "net.parallel.submit.batch",	0,	0,	1,	RBIG,	1,	R1K,	0,	0 },
	{ "net.parallel.submit.min",	0,	0,	2,	RBIG,	1,	R1K,	0,	0 },
	{ "net.parallel.sync.svrthreads",0,	0,	2,	RBIG,	1,	1,	0,	0 },
	{ "net.rcvbuflowmark",		0,	0,	0,	B32K,	1,	B1K,	0,	0 },
	{ "net.rcvbufmaxsize",		0,	B100M,	1,	B1G,	1,	B1K,	0,	0 },
	{ "net.rcvbufsize",		0,	B1M,	1,	BBIG,	1,	B1K,	0,	0 },
	{ "net.reuseport",		0,	0,	0,	1,	1,	1,	0,	0 },
	{ "net.rfc3484",		0,	0,	0,	1,	1,	1,	0,	0 },
	{ "net.sendlimit",		0,	B4K,	1,	BBIG,	1,	B1K,	0,	0 },
	{ "net.tcpsize",		0,	B512K,	B1K,	B256M,	B1K,	B1K,	0,	0 },
	{ "net.backlog",		0,	128,	1,      SMAX,   1,	B1K,	0,	0 },
	{ "net.x3.minsize",		0,	B512K,	0,	RBIG,	B1K,	B1K,	0,	1 },
	{ "proxy.deliver.fix",		0,	1,	0,	1,	1,	1,	0,	1 },
	{ "proxy.monitor.interval",	0,	10,	1,	999,	1,	1,	0,	1 },
	{ "proxy.monitor.level",	0,	0,	0,	3,	1,	1,	0,	1 },
	{ "rcs.maxinsert",		0,	R1G,	1,	RBIG,	1,	R1K,	0,	1 },
	{ "rcs.nofsync",		0,	0,	0,	1,	1,	1,	0,	1 },
	{ "rpc.delay",		0,	0,	0,      RBIG,   1,	1,	0,	0 },
	{ "rpc.durablewait",		0,	0,	0,	1,	1,	1,	0,	0 },
	{ "rpc.himark",			0,	2000,	2000,	BBIG,	1,	B1K,	0,	0 },
	{ "rpc.lowmark",		0,	700,	700,	BBIG,	1,	B1K,	0,	0 },
	{ "rpc.ipaddr.mismatch",	0,	0,	0,	1,	1,	1,	0,	1 },
	{ "rpl.archive.graph",		0,	2,	0,	2,	1,	1,	0,	1 },
	{ "rpl.awaitjnl.count",		0,	100,	1,	RBIG,	1,	R1K,	0,	1 },
	{ "rpl.awaitjnl.interval",	0,	50,	1,	RBIG,	1,	R1K,	0,	1 },
	{ "rpl.checksum.auto",		0,	0,	0,	3,	1,	1,	0,	1 },
	{ "rpl.checksum.change",	0,	0,	0,	3,	1,	1,	0,	1 },
	{ "rpl.checksum.table",		0,	0,	0,	2,	1,	1,	0,	1 },
	{ "rpl.compress",		0,	0,	0,	4,	1,	1,	0,	1 },
	{ "rpl.counter.hook",		0,	1,	0,	1,	1,	1,	0,	1 },
	{ "rpl.deferred.sends",		0,	0,	0,	1,	1,	1,	0,	1 },
	{ "rpl.jnl.batch.size",		0,	R100M,	0,	RBIG,	1,	R1K,	0,	1 },
	{ "rpl.jnlwait.adjust",		0,	25,	0,	RBIG,	1,	R1K,	0,	1 },
	{ "rpl.jnlwait.interval",	0,	50,	50,	RBIG,	1,	R1K,	0,	1 },
	{ "rpl.jnlwait.max",		0,	1000,	100,	RBIG,	1,	R1K,	0,	1 },
	{ "rpl.journal.ack",		0,	0,	0,	B1M,	1,	1,	0,	1 },
	{ "rpl.journal.ack.min",	0,	0,	0,	B1M,	1,	1,	0,	1 },
	{ "rpl.journalcopy.location",	0,	0,	0,	1,	1,	1,	0,	1 },
	{ "rpl.labels.global",		0,	0,	0,	1,	1,	1,	0,	0 },
	{ "rpl.replay.userrp",		0,	0,	0,	1,	1,	1,	0,	0 },
	{ "rpl.track.behind",		0,	0,	0,	2,	1,	1,	0,	0 },
	{ "rpl.track.behind.interval",	0,	R10K,	0,	RBIG,	1,	R1K,	0,	0 },
	{ "rpl.verify.cache",		0,	0,	0,	1,	1,	1,	0,	0 },
	{ "rpl.verify.shared",		0,	1,	0,	1,	1,	1,	0,	0 },
	{ "rpl.pull.archivedepots",	0,	0,	0,	1,	1,	1,	0,	0 },
	{ "run.clientexts.allow",	0,	1,	0,	1,	1,	1,	0,	0 },
	{ "run.move.allow",		0,	1,	0,	2,	1,	1,	0,	0 },
	{ "run.obliterate.allow",	0,	1,	0,	1,	1,	1,	0,	0 },
	{ "run.prune.allow",		0,	1,	0,	1,	1,	1,	0,	0 },
	{ "run.renameclient.allow",	0,	1,	0,	3,	1,	1,	0,	0 },
	{ "run.unzip.user.allow",	0,	0,	0,	1,	1,	1,	0,	0 },
	{ "run.users.authorize",	0,	0,	0,	1,	1,	1,	0,	1 },
	{ "server.commandlimits",	0,	0,	0,	2,	1,	1,	0,	1 },
	{ "server.ctrlc.filecleanup",	0,	0,	0,	1,	1,	1,	0,	0 },
	{ "server.extensions.allow.admin",0,	1,	0,	1,	1,	1,	0,	1 },
	{ "server.extensions.allow.unsigned",0,	0,	0,	1,	1,	1,	0,	1 },
	{ "server.filecharset",		0,	0,	0,	1,	1,	1,	0,	0 },
	{ "server.locks.archive",	0,	1,	0,	1,	1,	1,	0,	0 },
	{ "server.locks.sync",		0,	0,	0,	1,	1,	1,	0,	0 },
	{ "server.locks.global",	0,	0,	0,	1,	1,	1,	0,	0 },
	{ "server.allowfetch",		0,	0,	0,	3,	1,	1,	0,	0 },
	{ "server.allowpush",		0,	0,	0,	3,	1,	1,	0,	0 },
	{ "server.allowremotelocking",	0,	0,	0,	1,	1,	1,	0,	0 },
	{ "server.allowrewrite",	0,	0,	0,	1,	1,	1,	0,	0 },
	{ "server.global.client.views",	0,	0,	0,	1,	1,	1,	0,	0 },
	{ "server.maxcommands",		0,	0,	0,	RBIG,	1,	R1K,	0,	1 },
	{ "server.maxcommands.allow",	0,	1,	0,	1,	1,	1,	0,	1 },
	{ "server.start.unlicensed",	0,	0,	0,	1,	1,	1,	0,	1 },
	{ "filetype.bypasslock",	0,	0,	0,	1,	1,	1,	0,	1 },
	{ "filetype.maxtextsize",	0,	B10M,	0,	RBIG,	1,	R1K,	0,	0 },
	{ "spec.hashbuckets",		0,	99,	0,	999,	1,	1,	0,	0 },
	{ "spec.custom",		0,	0,	0,	1,	1,	1,	0,	0 },
	{ "streamview.dots.low",	0,	0,	0,	1,	1,	1,	0,	0 },
	{ "streamview.sort.remap",	0,	0,	0,	1,	1,	1,	0,	0 },
	{ "submit.collision.check",	0,	1,	0,	1,	1,	1,	0,	0 },
	{ "submit.forcenoretransfer",	0,	0,	0,	2,	1,	1,	0,	0 },
	{ "submit.noretransfer",	0,	0,	0,	1,	1,	1,	0,	0 },
	{ "submit.allowbgtransfer",	0,	0,	0,	1,	1,	1,	0,	0 },
	{ "submit.autobgtransfer",	0,	0,	0,	1,	1,	1,	0,	0 },
	{ "submit.unlocklocked",	0,	0,	0,	1,	1,	1,	0,	0 },
	{ "submit.storagefields",	0,	0,	0,	1,	1,	1,	0,	0 },
	{ "switch.stream.unrelated",	0,	0,	0,	1,	1,	1,	0,	0 },
	{ "push.unlocklocked",		0,	0,	0,	1,	1,	1,	0,	0 },
	// vv Smart Heap tunables must be a continuous group vv
	{ "sys.memory.poolfree",	0,	SHPOOL,	0,	BBIG,	1,	B1K,	0,	1 },
	{ "sys.memory.procfree",	0,	SHPROC,	0,	BBIG,	1,	B1K,	0,	1 },
	{ "sys.memory.poolgrowinc",	0,	SHGROW1,0,	BBIG,	1,	B1K,	0,	1 },
	{ "sys.memory.procgrowinc",	0,	SHGROW2,0,	BBIG,	1,	B1K,	0,	1 },
	{ "sys.memory.subpools",	0,	SHSUBP,	0,	BBIG,	1,	B1K,	0,	1 },
	{ "sys.memory.limit",		0,	0,	0,	BBIG,	1,	B1K,	0,	1 },
	{ "sys.memory.debug",		0,	0,	0,	1,	1,	1,	0,	1 },
	{ "cmd.memory.poolfree",	0,	0,	0,	BBIG,	1,	B1K,	0,	1 },
	{ "cmd.memory.procfree",	0,	0,	0,	BBIG,	1,	B1K,	0,	1 },
	{ "cmd.memory.limit",		0,	0,	0,	BBIG,	1,	B1K,	0,	1 },
	{ "cmd.memory.flushpool",	0,	0,	0,	BBIG,	1,	B1K,	0,	1 },
	{ "cmd.memory.listpools",	0,	0,	0,	BBIG,	1,	B1K,	0,	1 },
	{ "cmd.memory.chkpt",		0,	0,	0,	BBIG,	1,	B1K,	0,	1 },
	// ^^ Smart Heap tunables must be a continuous group ^^
	// vv mimalloc tunables must be a continuous group vv
# if defined(_DEBUG) || defined(MEM_DEBUG)
	{ "sys.memory.mi.showerrors",	0,	1,	0,	1,	1,	1,	0,	1 },
# else
	{ "sys.memory.mi.showerrors",	0,	0,	0,	1,	1,	1,	0,	1 },
# endif
	{ "sys.memory.mi.showstats",	0,	0,	0,	1,	1,	1,	0,	1 },
	{ "sys.memory.mi.verbose",	0,	0,	0,	1,	1,	1,	0,	1 },
	{ "sys.memory.mi.eagercommit",	0,	1,	0,	1,	1,	1,	0,	1 },
# if defined(OS_NT) || (defined(OS_LINUX) && defined(__i386__))
	{ "sys.memory.mi.eagerregioncommit",0,	0,	0,	1,	1,	1,	0,	1 },
	{ "sys.memory.mi.resetdecommits",0,	1,	0,	1,	1,	1,	0,	1 },
# else
	{ "sys.memory.mi.eagerregioncommit",0,	1,	0,	1,	1,	1,	0,	1 },
	{ "sys.memory.mi.resetdecommits",0,	0,	0,	1,	1,	1,	0,	1 },
# endif
	{ "sys.memory.mi.largeospages",	0,	0,	0,	1,	1,	1,	0,	1 },
	{ "sys.memory.mi.reservehugeospages",0,	0,	0,	RBIG,	1,	1,	0,	1 },
	{ "sys.memory.mi.reservehugeospagesat",0,	-1,	-1,	RBIG,	1,	1,	0,	1 },
	{ "sys.memory.mi.reserveosmemory",0,	0,	0,	RBIG,	1,	1,	0,	1 },
	{ "sys.memory.mi.segmentcache",	0,	0,	0,	RBIG,	1,	1,	0,	1 },
	{ "sys.memory.mi.pagereset",	0,	1,	0,	1,	1,	1,	0,	1 },
	{ "sys.memory.mi.abandonedpagereset",0,	0,	0,	1,	1,	1,	0,	1 },
	{ "sys.memory.mi.segmentreset",	0,	0,	0,	1,	1,	1,	0,	1 },
	{ "sys.memory.mi.eagercommitdelay",0,	1,	0,	RBIG,	1,	1,	0,	1 },
	{ "sys.memory.mi.resetdelay",	0,	100,	0,	RBIG,	1,	1,	0,	1 },
	{ "sys.memory.mi.usenumanodes",	0,	0,	0,	RBIG,	1,	1,	0,	1 },
	{ "sys.memory.mi.limitosalloc",	0,	0,	0,	1,	1,	1,	0,	1 },
	{ "sys.memory.mi.ostag",	0,	100,	0,	RBIG,	1,	1,	0,	1 },
	{ "sys.memory.mi.maxerrors",	0,	16,	0,	RBIG,	1,	1,	0,	1 },
	{ "sys.memory.mi.maxwarnings",	0,	16,	0,	RBIG,	1,	1,	0,	1 },
	// ^^ mimalloc tunables must be a continuous group ^^
	{ "sys.memory.stacksize",	0,	0,	0,	B16K,	1,	B1K,	0,	1 },
	{ "sys.rename.max",		0,	10,	10,	RBIG,	1,	R1K,	0,	1 },
	{ "sys.rename.wait",		0,	1000,	50,	RBIG,	1,	R1K,	0,	1 },
	{ "sys.threading.groups",	0,	0,	0,	1,	1,	1,	0,	1 },
	{ "rpl.forward.all",		0,	0,	0,	1,	1,	1,	0,	0 },
	{ "rpl.forward.login",		0,	0,	0,	1,	1,	1,	0,	0 },
	{ "rpl.pull.position",		0,	0,	0,	RBIG,	1,	R1K,	0,	0 },
	{ "rpl.pull.reload",		0,	60000,	0,	RBIG,	1,	R1K,	0,	0 },
	{ "ssl.secondary.suite",	0,	0,	0,	1,	1,	1,	0,	0 },
	{ "ssl.client.timeout",		0,	30,	1,	RBIG,	1,	1,	0,	0 },
	{ "ssl.client.tls.version.min",	0,	12,	10,	13,	1,	1,	0,	1 },
	{ "ssl.client.tls.version.max",	0,	13,	10,	13,	1,	1,	0,	0 },
	{ "ssl.client.trust.name",	0,	1,	0,	2,	1,	1,	0,	0 },
	{ "ssl.client.cert.validate",	0,	1,	0,	2,	1,	1,	0,	0 },
	{ "ssl.tls.version.min",	0,	10,	10,	13,	1,	1,	0,	1 },
	{ "ssl.tls.version.max",	0,	12,	10,	13,	1,	1,	0,	0 },
	{ "ssl.enable.etm",		0,	1,	0,	1,	1,	1,	0,	0 },
	{ "triggers.io",		0,	0,	0,	1,	1,	1,	0,	0 },
	{ "istat.mimic.ichanges",	0,	0,	0,	1,	1,	1,	0,	0 },
	{ "info.p4auth.usercheck",	0,	1,	0,	1,	1,	1,	0,	0 },
	{ "auth.autologinprompt",	0,	1,	0,	1,	1,	1,	0,	0 },
	{ "rpl.submit.nocopy",		0,	0,	0,	1,	1,	1,	0,	0 },
	{ "auth.2fa.persist",		0,	1,	0,	2,	1,	1,	0,	1 },
	{ "auth.tickets.nounlocked",	0,	0,	0,	2,	1,	1,	0,	1 },
	{ "auth.licenseexpiry.warn",	0,	1,	0,	2,	1,	1,	0,	1 },
	{ "auth.licenseexpiry.warnthreshold",0,	7,	1,	365,	1,	1,	0,	1 },
	{ "auth.sso.allow.passwd",	0,	0,	0,	1,	1,	1,	0,	1 },
	{ "auth.sso.nonldap",		0,	0,	0,	1,	1,	1,	0,	1 },
	{ "zlib.disable.optim",		0,	0,	0,	1,	1,	1,	0,	0 },

	{ 0, 0, 0, 0, 0, 0, 0, 0, 1 }

	// name				isSet,	value,	min,	max,	mod,	k,	orig,	sensitive

} ;

P4Tunable::stunable P4Tunable::slist[] = {

	// P4Debug's string collection

	// name				isSet,	default, *value, sensitive

	{ "ssl.client.ca.path",		0,	0,	0,	0 },
	
	{ 0,				0,	0,	0,	0 }

	// name				isSet,	default, *value, sensitive
} ;

// List of current values of P4Debug's integer collection
P4MT int
list2[] = { -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 }  ;

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
