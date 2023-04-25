/*
 * This code wraps the SSL (libcrypt.a) SHA256 functions
 */

# include <stdhdrs.h>
# include <strbuf.h>
# include <strops.h>
# include <sha256.h>

# ifdef USE_SSL
# include <openssl/opensslv.h>
# if OPENSSL_VERSION_NUMBER < 0x30000000L
# include <openssl/sha.h>

Sha256Digester::Sha256Digester()
{
	ctx = malloc( sizeof( SHA256_CTX ) );
	SHA256_Init( (SHA256_CTX *)ctx );
}

Sha256Digester::~Sha256Digester()
{
	free( ctx );
}

void
Sha256Digester::Update( const StrPtr &buf )
{
	SHA256_Update( (SHA256_CTX *)ctx, buf.Text(), buf.Length() );
}

void
Sha256Digester::Final( Sha256 &sha )
{
	Final( sha.data );
}

void
Sha256Digester::Final( unsigned char digest[ Sha256Length ] )
{
	SHA256_Final( digest, (SHA256_CTX *)ctx );
}

void
Sha256Digester::Final( StrBuf &output )
{
	unsigned char digest[ Sha256Length ];
	SHA256_Final( digest, (SHA256_CTX *)ctx );
	output.Clear();	
	StrOps::OtoXlower( digest, sizeof( digest ), output );
}

# else
# include <openssl/evp.h>
# include <error.h>
# include <errorlog.h>

Sha256Digester::Sha256Digester()
{
	const EVP_MD *md = EVP_get_digestbyname( "SHA256" );
	if( !md )
	{
	    ctx = 0;
	    return;
	}
	ctx = (void*)EVP_MD_CTX_new();
	EVP_DigestInit_ex( (EVP_MD_CTX *)ctx, md, 0 );
}

Sha256Digester::~Sha256Digester()
{
	if( ctx )
	    EVP_MD_CTX_free( (EVP_MD_CTX *)ctx );
}

void
Sha256Digester::Update( const StrPtr &buf )
{
	if( ctx )
	    EVP_DigestUpdate( (EVP_MD_CTX *)ctx, buf.Text(), buf.Length() );
}

void
Sha256Digester::Final( Sha256 &sha )
{
	if( ctx )
	    Final( sha.data );
}

void
Sha256Digester::Final( unsigned char digest[Sha256Length] )
{
	memset( digest, 0, Sha256Length );
	if( !ctx )
	    return;
	unsigned char c[EVP_MAX_MD_SIZE];
	unsigned int hash_len = 0;
	EVP_DigestFinal_ex( (EVP_MD_CTX*)ctx, c, &hash_len );
	if( hash_len <= Sha256Length )
	    memcpy( digest, c, hash_len );
}

void
Sha256Digester::Final( StrBuf &output )
{
	output.Clear();
	if( !ctx )
	    return;
	unsigned char c[EVP_MAX_MD_SIZE];
	unsigned int hash_len = 0;
	EVP_DigestFinal_ex( (EVP_MD_CTX*)ctx, c, &hash_len );
	StrOps::OtoX( c, hash_len, output );
}

# endif

# else

/* Stub implementation for non-SSL builds. Is a no-op if you try to run it. */

Sha256Digester::Sha256Digester()
{
}

Sha256Digester::~Sha256Digester()
{
}

void
Sha256Digester::Update( const StrPtr &buf )
{
}

void
Sha256Digester::Final( Sha256 &sha )
{
}

void
Sha256Digester::Final( unsigned char digest[ Sha256Length ] )
{
}

void
Sha256Digester::Final( StrBuf &output )
{
}

# endif

/**********************************************************************/

void
Sha256::FromString( const StrPtr *sha )
{
	int shaLen = sha->Length() / 2;
	StrOps::XtoO( sha->Text(), data, shaLen );
}

void
Sha256::Fmt( StrBuf &output ) const
{
	output.Clear();
	StrOps::OtoXlower( data, Sha256Length, output );
}

int
Sha256::IsSet() const
{
	for( int i = 0; i < Sha256Length; i++ )
	    if( data[i] )
		return 1;
	return 0;
}
