/*
 * This code wraps the SSL (libcrypt.a) SHA1 functions
 */

# include <stdhdrs.h>
# include <strbuf.h>
# include <strops.h>
# include <sha1.h>

# ifdef USE_SSL
# include <openssl/opensslv.h>
# if OPENSSL_VERSION_NUMBER < 0x30000000L
# include <openssl/sha.h>

Sha1Digester::Sha1Digester()
{
	ctx = malloc( sizeof( SHA_CTX ) );
	SHA1_Init( (SHA_CTX *)ctx );
}

Sha1Digester::~Sha1Digester()
{
	free( ctx );
}

void
Sha1Digester::Update( const StrPtr &buf )
{
	SHA1_Update( (SHA_CTX *)ctx, buf.Text(), buf.Length() );
}

void
Sha1Digester::Final( Sha1 &sha )
{
	Final( sha.data );
}

void
Sha1Digester::Final( unsigned char digest[ Sha1Length ] )
{
	SHA1_Final( digest, (SHA_CTX *)ctx );
}

void
Sha1Digester::Final( StrBuf &output )
{
	unsigned char digest[ Sha1Length ];
	SHA1_Final( digest, (SHA_CTX *)ctx );
	output.Clear();	
	StrOps::OtoXlower( digest, sizeof( digest ), output );
}

# else
# include <openssl/evp.h>
# include <error.h>
# include <errorlog.h>

Sha1Digester::Sha1Digester()
{
	const EVP_MD *md = EVP_get_digestbyname( "SHA1" );
	if( !md )
	{
	    ctx = 0;
	    return;
	}
	ctx = (void*)EVP_MD_CTX_new();
	EVP_DigestInit_ex( (EVP_MD_CTX *)ctx, md, 0 );
}

Sha1Digester::~Sha1Digester()
{
	if( ctx )
	    EVP_MD_CTX_free( (EVP_MD_CTX *)ctx );
}

void
Sha1Digester::Update( const StrPtr &buf )
{
	if( ctx )
	    EVP_DigestUpdate( (EVP_MD_CTX *)ctx, buf.Text(), buf.Length() );
}

void
Sha1Digester::Final( Sha1 &sha )
{
	if( ctx )
	    Final( sha.data );
}

void
Sha1Digester::Final( unsigned char digest[Sha1Length] )
{
	memset( digest, 0, Sha1Length );
	if( !ctx )
	    return;
	unsigned char c[EVP_MAX_MD_SIZE];
	unsigned int hash_len = 0;
	EVP_DigestFinal_ex( (EVP_MD_CTX*)ctx, c, &hash_len );
	if( hash_len <= Sha1Length )
	    memcpy( digest, c, hash_len );
}

void
Sha1Digester::Final( StrBuf &output )
{
	output.Clear();
	if( !ctx )
	    return;
	unsigned char c[EVP_MAX_MD_SIZE];
	unsigned int hash_len = 0;
	EVP_DigestFinal_ex( (EVP_MD_CTX*)ctx, c, &hash_len );
	StrOps::OtoXlower( c, hash_len, output );
}

# endif

# else

/* Stub implementation for non-SSL builds. Is a no-op if you try to run it. */

Sha1Digester::Sha1Digester()
{
}

Sha1Digester::~Sha1Digester()
{
}

void
Sha1Digester::Update( const StrPtr &buf )
{
}

void
Sha1Digester::Final( Sha1 &sha )
{
}

void
Sha1Digester::Final( unsigned char digest[ Sha1Length ] )
{
}

void
Sha1Digester::Final( StrBuf &output )
{
}

# endif

/**********************************************************************/

void
Sha1::FromString( const StrPtr *sha )
{
	int shaLen = sha->Length() / 2;
	StrOps::XtoO( sha->Text(), data, shaLen );
}

void
Sha1::Fmt( StrBuf &output ) const
{
	output.Clear();
	StrOps::OtoXlower( data, Sha1Length, output );
}

int
Sha1::IsSet() const
{
	for( int i = 0; i < Sha1Length; i++ )
	    if( data[i] )
		return 1;
	return 0;
}
