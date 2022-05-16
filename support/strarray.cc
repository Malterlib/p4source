/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 */

# include <stdhdrs.h>
# include <strbuf.h>
# include <debug.h>
# include <vararray.h>
# include <strarray.h>

# define DEBUG_RECORDS  ( p4debug.GetLevel( DT_RECORDS ) >= 4 )
# define DEBUG_EXTEND   ( p4debug.GetLevel( DT_RECORDS ) >= 5 )

/*
 * strarray.cc - a 0 based array of StrBufs
 */

class StrVarArray : public VVarArray {

    public:
	void SetCaseFolding( int c ) 
	{
	    caseFolding = c;
	}

	virtual int Compare( const void *a, const void *b ) const 
	{
	    return caseFolding 
		    ? ((StrBuf *)a)->XCompare( *(StrBuf *)b )
		    : ((StrBuf *)a)->CCompare( *(StrBuf *)b );
	}

	virtual void	Destroy( void * ) const {}

	int caseFolding;

} ;

StrArray::StrArray()
{
	array = new StrVarArray;
}

StrArray::~StrArray()
{
	for( int i = 0; i < array->Count(); i++ )
	    delete (StrBuf *)array->Get(i);

	delete array;
}

void
StrArray::Clear()
{
	for( int i = 0; i < array->Count(); i++ )
	    delete (StrBuf *)array->Get(i);
	array->Clear();
}

const StrBuf *
StrArray::Get( int i ) const
{
	return (StrBuf *)array->Get(i);
}

StrBuf *
StrArray::Edit( int i )
{
	return (StrBuf *)array->Edit(i);
}

void
StrArray::Remove( int i )
{
	if( array->Get( i ) )
	{
	    delete Edit( i );
	    array->Remove( i );
	}
}

StrBuf *
StrArray::Put()
{
	return (StrBuf *)array->Put( new StrBuf );
}

int
StrArray::Count() const
{
	return array->Count();
}

void
StrArray::Sort( int caseFolding )
{
	array->SetCaseFolding( caseFolding );
	array->Sort();
}

int
StrArray::Search( const StrBuf *key )
{
	// Ye old binary search.
	// "Binary search routines are never written right the first time
	// around" - Robert G Sheldon.
	// This one has been fixed _3_ times since it was written.

	// Search until we converge on the first record >= the key.
	// Zero based indexing; 'hi' is one beyond the last valid record.

	int lo = 0;
	int hi = Count();

	for(;;)
	{
	    int index = ( lo + hi ) / 2;

	    // lo <= hi
	    // if index == hi then lo == hi
	    // if index == lo then hi == lo or hi == lo + 1

	    // Return if we've converged.

	    if( lo == hi )
		return index;

	    int cmp = array->Compare( key, Get( index ) );

	    // If cmp == 0 we treat it as cmp < 0 -- we're positioning
	    // before the first matching record.

	    // If cmp > 0 && index == lo we're converging one past this
	    // current record.  Set lo = hi so that we'll return index = hi.

	    if( cmp <= 0 )
		hi = index;
	    else if( index != lo )
		lo = index;
	    else
		lo = hi;
	}
}

const StrBuf *
StrArray::Find( const StrBuf *key )
{
	// Handy wrapper for Search() for when you just expect one record.
	// Return one matching record if found, otherwise return 0.

	int index = Search( key );
	const StrBuf *r = Get( index );

	if( r && array->Compare( key, r ) )
	    return 0;

	return r;
}

void
StrArray::Copy( const StrArray *other )
{
	for( int i = 0; i < other->Count(); i++ )
	    Put()->Set( other->Get( i ) );
}

/*
 * StrPtrArray -- an array of StrPtrs
 */

StrPtrArray::StrPtrArray()
{
	tabVal = 0;
	tabSize = 0;
	tabLength = 0;
}

StrPtrArray::~StrPtrArray()
{
	delete []tabVal;
}

void
StrPtrArray::Put( const StrPtr &val )
{
	if( tabLength == tabSize )
	{
	    // Realloc with spare room

	    // grow geometrically, please
	    int newSize = (tabSize + 50) * 3 / 2;
	    StrRef *newtabVal = new StrRef[newSize];

	    if( tabVal )
	    {
	         memcpy((StrRef *)newtabVal, (StrRef *)tabVal,
	                tabSize * sizeof(StrRef));
	         delete []tabVal;
	    }

	    tabVal = newtabVal;
	    tabSize = newSize;

	    if( DEBUG_EXTEND )
	        p4debug.printf("StrPtrArray extend %d\n", tabSize);
	}

	tabVal[ tabLength++ ] = val;
}
