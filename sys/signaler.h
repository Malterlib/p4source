/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * Signaler.h - catch ^C and delete temp files
 *
 * A single Signaler is declared globally.
 *
 * Public methods:
 *
 *	Signaler::Block() -- don't catch the signal until Catch()
 *	Signaler::Catch() -- catch and handle SIGINT
 *	Signaler::OnIntr() -- call a designated function on SIGINT
 *	Signaler::DeleteOnIntr() -- undo OnIntr() call
 *
 *	Signaler::Intr() -- call functions registered by OnIntr()
 *
 * Requires cooperation from the TempFile objects to delete files.
 */

#include <Mib/Core/Core>

struct SignalMan;

typedef void (*SignalFunc)( void *ptr );

class Signaler {

    public:
			Signaler();
			~Signaler();
	void		Init();

	void		Block();
	void		Mask();
	void		Unmask();
	void		Catch();
	void		Disable();
	void		Enable();
	bool		GetState() const;
	bool		IsIntr() const;

	bool		IsMaskedIntr() const;

	void		OnIntr( SignalFunc callback, void *ptr );
	void		DeleteOnIntr( void *ptr );

	void		Intr();

    private:

	SignalMan	*list;
	int		mask;
	int		disable;
	bool		isIntr;

	// Before the fix for masking Control-C handling, it isn't
	// clear isIntr can ever be used as onintr() calls exit(-1)
	// right after setting isIntr.  See signaler.cc before this
	// change.  A separate variable is needed to store the occurence
	// of a Control-C when signals are masked.

	bool		isMaskedIntr;

	NMib::NThread::CMutual mutex;
} ;

extern NMib::NStorage::TCAggregate<Signaler> signaler;
