/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * Signaler.cc - catch ^C and delete temp files
 */

# define NEED_SIGNAL

# ifdef OS_NT
# define WIN32_LEAN_AND_MEAN
# include <windows.h>
# endif // OS_NT

# include <stdhdrs.h>

# include <error.h>
# include <strbuf.h>

# include "signaler.h"

# ifdef HAS_CPP11
# include <system_error>
# endif

// Watcom on QNX doesn't declare SIG_DFL right - cast it.
// But it isn't (void (*)(int)) on some OS's, so only cast QNX and SUNOS.

# if defined( OS_SUNOS ) || defined( OS_QNX )
# define SIG_TYPECAST(x) (void (*)(int))(x)
# else
# define SIG_TYPECAST(x) (x)
# endif

// Global signaler.

constinit NStorage::TCAggregate<Signaler> signaler = {DAggregateInit};

// These two babies have C linkage for signal().
// In order to make use of onintr, the exit needed to be moved out.

extern "C" {
	static void (CLIB_CALLING_CONVENTION *istat)( int ) = SIG_TYPECAST( SIG_DFL );
	void CLIB_CALLING_CONVENTION onintr(int v) { (*signaler).Intr(); }
}

/*
 * SignalMan - control structure for deleting a single file.
 */

struct SignalMan {

	SignalMan	*next;

	SignalFunc	callback;
	void		*ptr;

} ;

Signaler::Signaler()
{
	Catch();

	list = 0;
	disable = 0;
	isIntr = false;

	// Not clear the legacy isIntr can be used for masking, define
	// a new flag for masking.  In onintr the exit needed to be
	// be moved so that a Control-C did not always end in termination.

	isMaskedIntr = false;
}

Signaler::~Signaler()
{
}

void
Signaler::Init()
{
}

void
Signaler::Mask()
{
	DMibLock(mutex);

	mask++;
}

void
Signaler::Unmask()
{
	DMibLock(mutex);

	if( mask > 0 ) --mask;
}

void
Signaler::Disable()
{
	disable = 1;
}

void
Signaler::Enable()
{
	disable = 0;
}

bool
Signaler::GetState() const
{
	return disable;
}

bool
Signaler::IsIntr() const
{
	return isIntr;
}

bool
Signaler::IsMaskedIntr() const
{
	return isMaskedIntr;
}

void
Signaler::Block()
{
	// Ignore signals
	// Apparently, if we just reinstall the default signal
	// handle (SIG_DFL) and we get a SIGINT while in system(),
	// it isn't ignored, dispite manual pages.  FreeBSD.

	signal( SIGINT, SIG_IGN );
}

void
Signaler::Catch()
{
	// Install our handler

	istat = signal( SIGINT, onintr );

	// But if we're not replacing SIG_DFL or SIG_IGN, leave it alone.

        if( istat != SIG_TYPECAST( SIG_DFL ) &&
	    istat != SIG_TYPECAST( SIG_IGN ) )
		signal( SIGINT, istat );
}

void
Signaler::OnIntr( SignalFunc callback, void *ptr )
{
	if( disable )
	    return;

	DMibLock(mutex);

	SignalMan *d = new SignalMan;

	d->next = list;
	d->callback = callback;
	d->ptr = ptr;
	list = d;
}

void
Signaler::DeleteOnIntr( void *ptr )
{
	if( disable )
	    return;

	DMibLock(mutex);

	SignalMan *p = 0;
	SignalMan *d = list;

	for( ; d; p = d, d = d->next )
	{
	    if( d->ptr == ptr )
	    {
		if( p ) p->next = d->next;
		else list = d->next;
		delete d;
		return;
	    }
	}
}

NO_SANITIZE_UNDEFINED
void runCallback( SignalMan* p )
{
	p->callback( p->ptr );	
}

// Before onintr() had the call to exit() remvoed, it called Intr()
// and then called exit().  This means when Intr() returned, exit()
// would have been called.  All return points on Intr() now call
// exit().

void
Signaler::Intr()
{
	if( mask )
	{
	    isMaskedIntr = true;
	    return;
	}

	isIntr = true;

	if( disable )
	    exit (-1);

	SignalMan *d = list;

	// Reset for sanity.

	signal( SIGINT, SIG_TYPECAST( istat ) );

	{
		DMibLock(mutex);
		while( d )
		{
		    // The callback may delete d
		    // so we save it's next pointer now.

		    SignalMan *p = d;
		    d = d->next;
		    runCallback( p );
		}
	}

	exit (-1);
}
