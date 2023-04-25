/*
 * Copyright 1995, 2020 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

class SystemInfo
{
	public:

	    static void Collect( StrBufDict& output, Error* e );

# ifdef OS_NT
	    static int WindowsVersionInfo( DWORD &major, DWORD &minor,
	        DWORD &build, WORD &ptype );

	    static int CheckForAtomicRename( );
# endif

	private:

} ;
