/*
 * Copyright 1995, 2011 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# include <clientapi.h>
# include <clientprog.h>
# include <timer.h>
# include <progress.h>

bool ClientProgressText::InUse = false;

ClientProgressText::ClientProgressText( int ty )
    : cnt( 0 ), total( 0 ), typeOfProgress( ty ), backup( 0 ), done( false )
{
	InUse = true;
}

ClientProgressText::~ClientProgressText()
{
	if( !done )
	    InUse = false;
}

void
ClientProgressText::Description( const StrPtr *description, int units )
{
	desc.Set( description );
	printf( "%s ", desc.Text() );
	cnt = 0;
	backup = 0;
	total = 0;
	this->units = units;
}

void
ClientProgressText::Total( long t )
{
	total = t;
}

int
ClientProgressText::Update( long pos )
{
	// Safety to prevent multiple instances competing
	if( done )
	    return 0;
	
	StrBuf res;

	if( cnt == 40 )
	{
	    // every 40 updates, rewrite description

	    printf( "\r%s ", desc.Text() );
	    backup = 0;
	    cnt = 0;
	}
	if( total )
	{
	    int pct = int(100.0 * pos / total);

	    res << pct;
	    res.Extend( '%' );
	}
	else if( units )
	    res << pos;
	res.Extend( ' ' );
	res.Extend( "|/-\\"[ cnt++ & 3 ] );
	res.Terminate();

	while( backup-- > 0 )
		putchar( '\b' );

	fputs( res.Text(), stdout );
	backup = res.Length();

	fflush(stdout);

	return 0;
}

void
ClientProgressText::Done( int fail )
{
	if( backup )
	    putchar( '\b' );
	printf( fail == CPP_FAILDONE ? "failed!\n" : "finishing\n");

	// Let another instance take over
	done = true;
	InUse = false;
}

int
ClientProgressText::GetProgressType() const
{
	return typeOfProgress;
}
