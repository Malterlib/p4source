/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */


# define NEED_FILE
# define NEED_FCNTL
# define NEED_FLOCK
# define NEED_STAT
# define NEED_WIN32FIO

# include <stdhdrs.h>
# include <largefile.h>
# include <fdutil.h>

# if defined( OS_SOLARIS ) && !defined( OS_SOLARIS25 )
# define flockL flock64
# define FL_SETLKW F_SETLKW64
# define FL_SETLK F_SETLK64
# define FL_GETLK F_GETLK64
# else
# define flockL flock
# define FL_SETLKW F_SETLKW
# define FL_SETLK F_SETLK
# define FL_GETLK F_GETLK
# endif

# if defined ( OS_BEOS )
#include <SupportDefs.h>
extern "C" status_t _klock_node_(int fd);
extern "C" status_t _kunlock_node_(int fd);
#endif

int
lockFile( FD_TYPE fd, int flag )
{

# if defined( OS_OS2 ) || defined( MAC_MWPEF ) || defined( OS_VMS62 )

	return 0;
# else 
# if defined ( OS_BEOS )

	switch( flag )
	{
	case LOCKF_UN:    return _kunlock_node_(fd); 
	case LOCKF_SH:    
	case LOCKF_SH_NB: 
	case LOCKF_EX:    
	case LOCKF_EX_NB: return _klock_node_(fd); 
	}

	return -1;

# else
# ifdef OS_NT

	return lockFileByHandle( fd->fh, flag );
# else
# if defined(LOCK_UN) && !defined(sgi) && !defined(OS_QNX) && !defined(OS_AIX)

	switch( flag )
	{
	case LOCKF_UN:    return flock(fd, LOCK_UN); break;
	case LOCKF_SH:    return flock(fd, LOCK_SH); break;
	case LOCKF_SH_NB: return flock(fd, LOCK_SH|LOCK_NB); break;
	case LOCKF_EX:    return flock(fd, LOCK_EX); break;
	case LOCKF_EX_NB: return flock(fd, LOCK_EX|LOCK_NB); break;
	}

	return -1;

# else 
# if defined(OS_SOLARIS10)

	// fcntl on Solaris-10 behaves differently to previous releases and 
	// does not gel well with our locking strategy.  The following code 
	// is an attempt to fake up the locking behaviour that we desire,  
	// while hopefully not leading to writer starvation.

	// Instead of locking the whole file for readers,  region locks of 
	// 1 byte are taken at the callers pid address which will allow for 
	// multiple readers in the system since potential writers now only 
	// block on the first reader's single byte region.  This requires 
	// the use of F_GETLK to acquire the first blocking reader.

	int pid = getpid();
	struct flockL f;

	if( flag != LOCKF_EX )
	{
	    f.l_whence = SEEK_SET;
	    f.l_pid = pid;

	    switch( flag )
	    {
	    case LOCKF_EX_NB: 
	        f.l_start = 0;   f.l_len = 0; f.l_type = F_WRLCK; 
	        return fcntl( fd, FL_SETLK, &f );
	    case LOCKF_SH_NB: 
	        f.l_start = pid; f.l_len = 1; f.l_type = F_RDLCK; 
	        return fcntl( fd, FL_SETLK, &f );
	    case LOCKF_SH:    
	        f.l_start = pid; f.l_len = 1; f.l_type = F_RDLCK;
	        return fcntl( fd, FL_SETLKW, &f );
	    case LOCKF_UN:    
	        f.l_start = 0;   f.l_len = 0; f.l_type = F_UNLCK; 
	        return fcntl( fd, FL_SETLKW, &f );
	    }
	}

	// Handle exclusive blocking lock

	int noOtherLocks = 0;

	for( ;; )
	{
	    f.l_type = F_WRLCK;
	    f.l_whence = SEEK_SET;
	    f.l_pid = pid;
	    f.l_start = 0;
	    f.l_len = 0;

	    if( noOtherLocks )
	        return fcntl( fd, FL_SETLKW, &f );

	    fcntl( fd, FL_GETLK, &f );

	    if( f.l_type == F_RDLCK )
	    {
	        // wait on this single byte

	        f.l_start = f.l_pid;
	        f.l_whence = SEEK_SET;
	        f.l_type = F_WRLCK;
	        f.l_len = 1;
	        f.l_pid = pid;

	        fcntl( fd, FL_SETLKW, &f );  // wait on locks
	        f.l_type = F_UNLCK;
	        fcntl( fd, FL_SETLKW, &f );  // release lock
	        continue;                    // check again
	    }

	    noOtherLocks++;
	}

# else

	int cmd;
	struct flockL f;
	f.l_start = 0;
	f.l_len = 0;
	f.l_pid = getpid();
	f.l_whence = 0;
	switch( flag )
	{
	case LOCKF_UN:    cmd = FL_SETLKW; f.l_type = F_UNLCK; break;
	case LOCKF_SH:    cmd = FL_SETLKW; f.l_type = F_RDLCK; break;
	case LOCKF_SH_NB: cmd = FL_SETLK;  f.l_type = F_RDLCK; break;
	case LOCKF_EX:    cmd = FL_SETLKW; f.l_type = F_WRLCK; break;
	case LOCKF_EX_NB: cmd = FL_SETLK;  f.l_type = F_WRLCK; break;
	default:	
	                  return -1;
	}

	return fcntl( fd, cmd, &f );

# endif
# endif /* LOCK_UN */
# endif /* OS_BEOS */
# endif /* OS_NT */
# endif /* MAC_MWPEF */

}

// Windows:
//    When running as a service, these are the handle values.
//	GetStdHandle( STD_INPUT_HANDLE ) = 0x0
//	GetStdHandle( STD_OUTPUT_HANDLE ) = 0x0
//	GetStdHandle( STD_ERROR_HANDLE ) = 0x0
//
//	(HANDLE)_get_osfhandle( 0 ) = 0xfffffffffffffffe
//	(HANDLE)_get_osfhandle( 1 ) = 0xfffffffffffffffe
//	(HANDLE)_get_osfhandle( 2 ) = 0xfffffffffffffffe
//
//	From the p4dposix tool on a Perforce Windows Service:
//	(//depot/main/p4-tools/debugging/p4dposix)
//	   __pioinfo[0] (blk 1: 3 out of 32 fds in use, 0 cs allocated):
//	   fd=0: cs=0 flags=0xc1, FOPEN FDEV FTEXT  oshnd=0xfffffffffffffffe
//	   fd=1: cs=0 flags=0xc1, FOPEN FDEV FTEXT  oshnd=0xfffffffffffffffe
//	   fd=2: cs=0 flags=0xc1, FOPEN FDEV FTEXT  oshnd=0xfffffffffffffffe
//
//	INVALID_HANDLE_VALUE = 0xffffffffffffffff
//	INVALID_HANDLE_VALUE = (HANDLE)(LONG_PTR)-1
//	(HANDLE)(LONG_PTR)-2 = 0xfffffffffffffffe
//
//    The HANDLE values 0x0 and 0xfffffffffffffffe are technically
//    invalid.  This is some sort of internal token MS is using to
//    avoid triggering the sanity checks.
//
//    Could not find a formal definition of the Handle values
//    returned by _get_osfhandle().  Based on the next paragraph
//    I think we can assume -2 is a special token.
//
//    The Handle values defined as -4, -5 and -6 are special values
//    for Process, Thread and Thread Effective tokens.
//    See the header processthreadsapi.h
//
//	From the p4dposix tool on a Perforce Windows Application:
//	    __pioinfo[0] (blk 1: 3 out of 32 fds in use, 4 cs allocated):
//	    fd=0: cs=1 flags=0xc1, FOPEN FDEV FTEXT  oshnd=0x0000000000000050
//	    fd=1: cs=1 flags=0xc1, FOPEN FDEV FTEXT  oshnd=0x0000000000000054
//	    fd=2: cs=1 flags=0xc1, FOPEN FDEV FTEXT  oshnd=0x0000000000000058
//
//    When running as an application, the first 3 file descriptors
//    are also allocated.
//
//    This indicates that when running as a Windows Service or as a
//    Windows application, the file descriptors 0, 1 and 2 are not
//    available for use.  For Windows checkStdio() and checkFd()
//    do not need to do anything.
//
FD_TYPE
checkFd( FD_TYPE fd )
{
# ifdef OS_NT
	return fd;
# else // OS_NT
        // If the fd > 2 then it's not stdio: continue

        if( fd < 0 || fd > 2 )
            return fd;

        // Lets dup the fd to the next available
        // Use this function to deal with more <=2 fds

        int newfd = checkFd( dup( fd ) );

        // Rather than straight close the old fd, lets assign it to /dev/null
        // Use w+ so we do the right thing regardless of STDIN or STDOUT/ERR

        int nulfd = openL( "/dev/null", O_RDWR );

        if( nulfd < 0 || dup2( nulfd, fd ) < 0 )
            close( fd );

        if( nulfd >= 0 )
            close( nulfd );

        return newfd;
# endif // OS_NT
}

void
checkStdio( FD_TYPE fd )
{
# ifdef OS_NT
	return;
# else // OS_NT
        if( fd < 0 || fd > 2 )
        {
            // Check them all
            checkStdio( 0 );
            checkStdio( 1 );
            checkStdio( 2 );
            return;
        }
    
        // First, fstat the fd (if it doesn't exist, the claim it)
        
	struct statbL sb;
	if( fstatL( fd, &sb ) < 0 ) {
            int nulfd = openL( "/dev/null", O_RDWR );
            if( nulfd >= 0 && nulfd != fd )
            {
                dup2( nulfd, fd );
                close( nulfd );
            }
            return;
        }
        
        // It's possible that if it exist, then it might be a file
        // but we probably don't care about that.
# endif // OS_NT
}

#ifdef OS_NT
// Primarily used from bt_fio.cc
//
int
lockFileByHandle(HANDLE h, int flag )
{

	/*
	 * NtFlock: flock for windows NT called by bt_fio.cc in dbopen2.
	 */

	OVERLAPPED	ol;
	DWORD		f;
	ol.Internal	= 0;
	ol.InternalHigh	= 0;
	ol.Offset	= 0xFFFFFFFF;
	ol.OffsetHigh	= 0xFFFFFFFF;
	ol.hEvent	= 0;

	switch( flag )
	{
	case LOCKF_UN:    return UnlockFileEx(h, 0, 1, 0, &ol) ? 0 : -1;

	case LOCKF_SH:    f = 0; break;
	case LOCKF_SH_NB: f = LOCKFILE_FAIL_IMMEDIATELY; break;
	case LOCKF_EX:    f = LOCKFILE_EXCLUSIVE_LOCK; break;
	case LOCKF_EX_NB: f = LOCKFILE_FAIL_IMMEDIATELY|LOCKFILE_EXCLUSIVE_LOCK;
	                  break;
	default:
	                  return -1;
	}

	return LockFileEx(h, f, 0, 1, 0, &ol) ? 0 : -1;
}
#endif
