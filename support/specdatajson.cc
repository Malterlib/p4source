/*
 * Copyright 2025 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# include <stdhdrs.h>
# include <charman.h>
# include <debug.h>

# include <strbuf.h>
# include <strdict.h>
# include <strtree.h>

# include <error.h>
# include <errorlog.h>

# include "spec.h"
# include <msgdb.h>
# include <msgsupp.h>
# include <msgserver2.h>
# include <p4tags.h>

# if defined( HAS_CPP11 ) && !defined( HAS_BROKEN_CPP11 )
#define HAS_JSON
# include <json.hpp>
# include <datetime.h>
# include <strops.h>
using json = nlohmann::json;
# endif

# include "specdatajson.h"


#ifdef HAS_JSON
class  JsonExtraTags : public StrDict {

public:
    /**
     * JsonExtraTags::JsonExtraTags -
     * Constructor
     *
     * @param[in] inJsonObj - Reference to a JSON object that will be populate
     *	                      with extra tag data
     */
    JsonExtraTags( json& inJsonObj )
	: jsonObj( inJsonObj )
    {
    }

protected:

    /**
     * JsonExtraTags::VGetVar -
     * Always returns null. This is a write-only class.
     *
     * @param[in] var - Dictionary key
     * @return StrPtr* - Always returns NULL
     */
    StrPtr* VGetVar( const StrPtr& var )
    {
	// This is a write-only operation... no need to return anything
	// from this.
	return NULL;
    }

    /**
     * JsonExtraTags::VSetVar -
     * Only saves values _not_ starting with 'ExtraTag'
     *
     * @param[in] var - Dictionary key
     * @param[in] val - Dictionary value for key
     */
    void VSetVar( const StrPtr& var, const StrPtr& val )
    {
	// var's that start with 'ExtraTag' are defining metadata about
	// tags not defined in the specification definition. Eg:
	//  extraTag0: firmerThanParent
	//  extraTagType0: word
	//  firmerThanParent: someValue
	// We do not want to save that extra metadata to the JSON, but will
	// instead need to figure out how to include that information in
	// the specification.
	int extraTagLen = strlen( P4Tag::v_extraTag );
	if( !var.StartsWith( P4Tag::v_extraTag, extraTagLen ) )
	    jsonObj[ var.Text() ] = val.Text();
    }

    /**
     * JsonExtraTags::VGetCount -
     * Returns the current size of the embedded jsonObject.
     *
     * @return int - Current size of the embedded jsonObject.
     */
    int VGetCount()
    {
	return jsonObj.size();
    }

private:
    json& jsonObj;
};
#endif // HAS_JSON

/**
 * JsonSpecData::JsonSpecData -
 * Constructor
 *
 * @param[in] inSpecData - Type specific SpecData object. This takes ownership
 *	                   of the SpecData object and ensures it gets deleted
 */
JsonSpecData::JsonSpecData( const SpecData* inSpecData )
	:
#ifdef HAS_JSON
	  jsonData(json::object()),
	  jsonExtraTags( new JsonExtraTags(jsonData ) ),
#else
	  jsonExtraTags( NULL ),
#endif
	  srcSpecData( inSpecData ),
	  arrayOffset( 0 )
{
}

/**
 * JsonSpecData::~JsonSpecData -
 * Destructor
 */
JsonSpecData::~JsonSpecData()
{
	delete jsonExtraTags;
	delete srcSpecData;
}

/**
 * JsonSpecData::Set -
 * Sets data onto the json object, ideally with appropriate typing
 *
 * @param[in] sd    - SpecElem with type information
 * @param[in] x     - Array index for the wv
 * @param[in] wv    - List of text values, value we need is typically at index
 *	              0. Last element in list is a null value.
 * @param[out] e    - Overall status of the operation
 */
void
JsonSpecData::Set( SpecElem* sd, int x, const char** wv, Error* e )
{
#ifndef HAS_JSON
	e->Set( MsgSupp::JsonNotEnabled );
#else
	if( sd->IsList() )
	{
	    CheckResetArrayOffset( sd->tag );

	    // The wv represents some kind of a list, possibly a list of words
	    // or possibly just a new line.
	    if( sd->IsWords() )
	    {
	        json wordArray = json::array();
	        const char** tmp = wv;
	        while( *tmp != 0 )
	        {
	            wordArray.push_back( *tmp );
	            tmp++;
	        }
	        SetWordListData( sd->tag.Text(), x, wordArray );
	    }
	    else
	    {
	        json& jArray = GetArray( sd->tag.Text() );
	        jArray.push_back( *wv );
	    }
	}
	else if( sd->IsDate() )
	{
	    // The wv is a date value, render it as ISO8601
	    DateTime dt( *wv, e );
	    if( !e->Test() )
	    {
	        char bufTime[ 32 ];
	        dt.FmtISO8601( bufTime );
	        jsonData[ sd->tag.Text() ] = bufTime;
	    }

	}
	else if( sd->IsLine() && sd->values.Length() > 0 )
	{
	    // This primarily is for 'Option' lines
	    StrBuf b;
	    char* words[ 10 ];
	    int nWords = StrOps::Words( b, *wv, words, 10 );

	    jsonData[ sd->tag.Text() ] = json::array();
	    for( int i = 0; i < nWords; ++i )
	    {
	        jsonData[ sd->tag.Text() ].push_back( words[ i ] );
	    }
	}
	else
	{
	    bool handled = false;

	    const JsonSpecHandling* srcSpecWithJson =
	        dynamic_cast<const JsonSpecHandling*>( srcSpecData );
	    if( srcSpecWithJson )
	    {
	        // Check to see if the srcSpecData has special handling for
	        // this spec field.
	        handled = srcSpecWithJson->SetJsonField( sd, x, wv, 
	                                                 jsonData, e );
	    }

	    if( !handled && !e->Test() )
	    {
	        // srcSpecData didn't have any special handling, and we don't
	        // have any errors, so lets just save this value as text.
	        jsonData[ sd->tag.Text() ] = *wv;
	    }
	}
#endif // HAS_JSON
}

/**
 * JsonSpecData::SetComment -
 * Sets comments in the appropriate location on the stored JSON object.
 *
 * @param[in] sd  - SpecElem with type information
 * @param[in] x   - Array index provided by Spec::Parse, see UpdateArrayOffset
 * @param[in] val - Comment value
 * @param[in] nl  - 1 = new line comment, 0 = inline comment
 * @param[out] e  - Overall status of the operation
 */
void
JsonSpecData::SetComment( SpecElem* sd, int x, const StrPtr* val, int nl, 
	                  Error* e )
{
#ifndef HAS_JSON
	e->Set( MsgSupp::JsonNotEnabled );
#else
	if( sd->IsList() )
	{
	    CheckResetArrayOffset( sd->tag );

	    if( sd->IsWords() )
	    {
	        UpdateArrayOffset( nl );

	        SetWordListComment( sd->tag.Text(),
	                            x,
	                            val->Text() );


	    }
	    else
	    {
	        json& jArray = GetArray( sd->tag.Text() );
	        jArray.push_back( val->Text() );
	    }
	}
	else
	{
	    StrBuf name;
	    name << sd->tag << "Comment";

	    jsonData[ name.Text() ] = val->Text();

	}
#endif // HAS_JSON
}

/**
 * JsonSpecData::Finalize -
 * Spec::Parse has been building up a json object, we need to render that
 * object to a text value. This function serializes the jsonData to text.
 *
 * @param[in] dict - Where to send the serialized data
 * @param[in] keyName - Name of the key to set on the provided dict
 * @param[out] e - Overall status of the operation
 */
void
JsonSpecData::Finalize( StrDict& dict, const char* keyName, Error& e )
{
#ifdef HAS_JSON
    try 
    {
	dict.SetVar( keyName, jsonData.dump().c_str() );
    }
    catch( nlohmann::json::type_error& ex )
    {
	e.Set( MsgSupp::JsonSerializationFailed )
	    << ex.what();
    }
#endif
}


/**
 * JsonSpecData::SetWordListComment -
 * Word lists can be created either by Set or SetComment. If Set created the
 * word list first, then this will merge in the comment to the existing
 * object
 *
 * @param[in out] fieldName - Name of the word list array
 * @param[in out] index     - Index provided by SetComment
 * @param[in out] comment   - Comment value to set
 */
void
JsonSpecData::SetWordListComment( const char* fieldName,
	                          const int index,
	                          const char* comment )
{
#ifdef HAS_JSON
	json& wordArray = GetArray( fieldName );
	int adjustedIndex = GetAdjustedIndex( wordArray, index );

	// If the wordArray size is less than, or equal to the index, 
	// this is a new value that hasn't been seen before.
	if( wordArray.size() == adjustedIndex )
	{
	    json newObj = json::object();
	    newObj[ "comment" ] = comment;
	    wordArray.push_back( newObj );
	}
	else
	{
	    // Else... we should have the object created already, and now we are going to
	    // set the comment on it.
	    wordArray[ adjustedIndex ][ "comment" ] = comment;
	}
#endif
}

/**
 * JsonSpecData::UpdateArrayOffset -
 * This exists because the Spec::Parse function has a bug where even if we are
 * NOT a new line comment, it increments the 'index' of the array. So we need
 * to ensure we set data based on the _real_ array index as opposed to the fake
 * one.
 *
 * I would prefer to fix the core issue in Spec::Parse, however it appears that
 * other code on the server is already hacking around the issue and an attempt
 * to 'fix the glitch' resulted in a cascade of other code changes. So for now
 * we live with the problem.
 *
 * This function updates an 'arrayOffset' value that keeps track how out of
 * sync Spec::Parse is from reality.
 *
 * Other functions that use or update the arrayOffset include:
 * - GetAdjustedIndex
 * - CheckResetArrayOffset
 *
 * @param[in] nl - Is this a new line? If so, Spec:Parse incremented the array
 *	           index even when there was new array value.
 */
void
JsonSpecData::UpdateArrayOffset( const int nl )
{
	if( !nl )
	{
	    // Note: This needs to happen before SetWordListComment
	    //       because SetWordList* uses the arrayOffset
	    // Note2: We can get away with using a single arrayOffset because
	    //    Spec::Parse fully processes a single array at a time.
	    //    CheckResetArrayOffset monitors to see if we switch arrays
	    //    and if we do it resets the arrayOffset back to 0.
	    //    If at some future date Spec::Parse starts processing arrays
	    //    in parallel or swapping back & forth between arrays, then we
	    //    will need to add more thorough offset tracking, maybe a map
	    //    of Name -> offset.
	    arrayOffset--;
	}
}


/**
 * JsonSpecData::CheckResetArrayOffset -
 * See UpdateArrayOffset for a detailed description of why this exists.
 *
 * This function monitors for the current array being processed changing, on
 * an array change it resets the arrayOffset to 0.
 *
 * @param[in] curArray - Tag name of the current array being processed
 */
void
JsonSpecData::CheckResetArrayOffset( const StrPtr& curArray )
{
	if( curArray.Compare( arrayName ) != 0 )
	{
	    arrayOffset = 0;
	    arrayName.Set( curArray );
	}
}

#ifdef HAS_JSON

/**
 * JsonSpecData::GetArray -
 * Returns a reference to an array with the provided key name. If an array
 * does not exist, it creates one first.
 *
 * @param[in] key - Name of the array to return a reference too
 * @return json - Returns a reference to a json array
 */
json&
JsonSpecData::GetArray( const char* key )
{
	if( !jsonData[ key ].is_array() )
	{
	    jsonData[ key ] = json::array();
	}

	return jsonData[ key ];
}

/**
 * JsonSpecData::SetWordListData -
 * Word lists can be created either by Set or SetComment. If SetComment created
 * the word list first, then this will merge in the 'data' to the existing
 * object.
 *
 * @param[in] fieldName - Name of the word list array
 * @param[in] index     - Index provided by Set
 * @param[in] dataArray - JSON array of data
 */
void
JsonSpecData::SetWordListData( const char* fieldName,
	                       const int index,
	                       json& dataArray )
{
	json& wordArray = GetArray( fieldName );
	int adjustedIndex = GetAdjustedIndex( wordArray, index );

	// If the wordArray size is equal to the index, this is a new value
	// that hasn't been seen before.
	if( wordArray.size() == adjustedIndex )
	{
	    json newObj = json::object();
	    newObj[ "data" ] = dataArray;
	    wordArray.push_back( newObj );
	}
	else
	{
	    // Else... we should have the object created already, and now we 
	    // are going to set the data on it.
	    wordArray[ adjustedIndex ][ "data" ] = dataArray;
	}
}

/**
 * JsonSpecData::GetAdjustedIndex -
 * See UpdateArrayOffset for a detailed description of why this exists.
 *
 * This function returns the adjusted index using the current arrayOffset.
 *
 * It also performs a sanity check to make sure that the adjusted index is at
 * most one more than the current size of the array
 *
 * @param[in] array - Array we are getting an adjusted index for, this is only
 *	              used as a sanity check to ensure we are not generating
 *	              an invalid adjusted index
 * @param[in] index - Index provided by Spec::Parse
 * @return int      - Actual adjusted index based on the arrayOffset
 */
int
JsonSpecData::GetAdjustedIndex( const json& array, const int index ) const
{
	int adjustedIndex = index + arrayOffset;

	// The new, adjusted index must be either inside the array's bounds
	// or at most 1 higher (indicating a new value). This should not be
	// able to happen unless there is a bug, hence the DevErr & report
	if( adjustedIndex < 0 ||
	    adjustedIndex > array.size() )
	{
	    Error e;
	    e.Set( MsgDb::DevErr ) <<
	        "Adjusted JSON array index out of bounds.";
	    AssertLog.Report( &e );

	    // Clamp the adjusted index to either the front or end of the array.
	    if( adjustedIndex < 0 )
	    {
	        adjustedIndex = 0;
	    }
	    else
	    {
	        adjustedIndex = array.size();
	    }
	}

	return adjustedIndex;
}

#endif // HAS_JSON
