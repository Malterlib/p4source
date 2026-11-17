/*
 * Copyright 2025 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# if defined( HAS_CPP11 ) && !defined( HAS_BROKEN_CPP11 )
#define HAS_JSON
# include <json.hpp>
using json = nlohmann::json;
# endif

class JsonSpecHandling {
public:
#ifdef HAS_JSON
    /**
     * JsonSpecHandling::SetJsonField -
     * Specific SpecData implementations can override this to handle specific
     * fields. For example, ChangeSpecData can know that CHANGE_SPEC_CHANGE is
     * typically numeric and it can set a json field as such rather than
     * setting a text value for that numeric field.
     *
     * @param[in] sd    - SpecDataElement that is currently being parsed.
     * @param[in] x     - Index of this element in an array (if in an array)
     * @param[in] wv    - Null terminated array of text values to parse for 
     *                    this element.
     * @param[in/out] ioJson - Reference to the JSON object to set data on
     * @param[out] e    - Overall status of this operation
     * @return bool     - Returns true if a JSON field was set from the spec 
     *                    data. Returns false otherwise.
     */
    virtual bool        SetJsonField( SpecElem* sd, int x, const char** wv,
	                              json& ioJson, Error* e ) const = 0;
#endif // HAS_JSON
};

 // This class exists to translate between the text based forms && JSON data
 // structures. In order for this to properly function, HAS_JSON must be
 // defined.
class JsonSpecData : public SpecData {

public:
    JsonSpecData( const SpecData* srcSpecData );
    virtual ~JsonSpecData();

    virtual void        Set( SpecElem* sd, int x, const char** wv, Error* e );
    virtual void        SetComment( SpecElem* sd,
	                            int x,
	                            const StrPtr* val,
	                            int nl,
	                            Error* e );

    void                Finalize( StrDict& dict, const char* keyName, 
				  Error& e );

    StrDict*            GetExtraTagDict() const { return jsonExtraTags; }
private:
    void                SetWordListComment( const char* fieldName,
	                                    const int index,
	                                    const char* comment );
    void                UpdateArrayOffset( const int nl );
    void                CheckResetArrayOffset( const StrPtr& curArray );

#ifdef HAS_JSON
    json&               GetArray( const char* key );
    void                SetWordListData( const char* fieldName,
	                                 const int index,
	                                 json& dataArray );
    int	                GetAdjustedIndex( const json& array,
	                                  const int index ) const;

    // This holds the JSON data we are building up or parsing.
    json                jsonData;
#endif // HAS_JSON

    // If we support JSON data, this is set to an instance of JsonExtraTags
    // that will collect the extra tag information, it is NULL otherwise.
    StrDict*            jsonExtraTags;

    // We own this reference to the original spec data object and must ensure
    // it gets properly cleaned up.
    const SpecData*     srcSpecData;

    // This 'arrayName' & 'arrayOffset' exists because of a very long 
    // standing issue in Spec::Parse when encountering inline comments it
    // increments the 'index' of the array even though an inline comment
    // shouldn't result in a new index. See UpdateArrayOffset for more
    // details.
    StrBuf              arrayName;
    int	                arrayOffset;
};