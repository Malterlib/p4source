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
	void		Catch();
	void		Disable();
	void		Enable();
	bool		GetState() const;
	bool		IsIntr() const;

	void		OnIntr( SignalFunc callback, void *ptr );
	void		DeleteOnIntr( void *ptr );

	void		Intr();

    private:

	SignalMan	*list;
	int		disable;
	bool		isIntr;

	NMib::NThread::CMutual mutex;
} ;

extern NMib::NStorage::TCAggregate<Signaler> signaler;
