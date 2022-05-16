/**
 * @file netssltransport.cc
 *
 * @brief SSL driver for NetTransport
 *	NetSslTransport - a TCP with SSL subclass of NetTcpTransport
 *
 * Threading: underlying SSL library contains threading
 *
 * @invariants:
 *
 * Copyright (c) 2011 Perforce Software
 * Confidential.  All Rights Reserved.
 * @author Wendy Heffner
 *
 * Creation Date: August 19, 2011
 */

/**
 * NOTE:
 * The following file only defined if USE_SSL true.
 * The setting of this definition is controlled by
 * the Jamrules file.  If the jam build is specified
 * with -sSSL=yes this class will be defined.
 */
# ifdef USE_SSL

# define NEED_ERRNO
# define NEED_SIGNAL
# ifdef OS_NT
# define NEED_FILE
# endif
# define NEED_FCNTL
# define NEED_IOCTL
# define NEED_TYPES
# define NEED_SOCKET_IO
# define NEED_SLEEP

# ifdef OS_MPEIX
# define _SOCKET_SOURCE /* for sys/types.h */
# endif

# define GET_MJR_SSL_VERSION(x) \
    (((x) >> 12) & 0xfffffL)

# include <stdhdrs.h>

# ifndef OS_NT
#   include <pthread.h>
#   if defined( OS_DARWIN ) || defined( OS_MACOSX )
#     include <Security/Security.h>
#     include <CoreFoundation/CoreFoundation.h>
#   endif
# else
#   include <wincrypt.h>
#undef X509_NAME
#undef X509_EXTENSIONS
#undef PKCS7_ISSUER_AND_SERIAL
#undef PKCS7_SIGNER_INFO
#undef OCSP_REQUEST
#undef OCSP_RESPONSE
# endif // not OS_NT

# include <error.h>
# include <strbuf.h>
# include <md5.h>
# include "netaddrinfo.h"
# include <errorlog.h>
# include <debug.h>
# include <vararray.h>
# include <bitarray.h>
# include <tunable.h>
# include <error.h>

# include <enviro.h>
# include <msgrpc.h>
# include <timer.h>
# include "datetime.h"
# include "filesys.h"
# include "pathsys.h"

# include <keepalive.h>
# include "netsupport.h"
# include "netport.h"
# include "netportparser.h"
# include "netconnect.h"
# include "nettcpendpoint.h"
# include "nettcptransport.h"
# include "netselect.h"
# include "netdebug.h"


extern "C"
{
    // OpenSSL
# include <openssl/ssl.h>
# include <openssl/err.h>
# include <openssl/x509v3.h>
# include <openssl/opensslv.h>
# include <openssl/crypto.h>
}
# include "netsslcredentials.h"
# include "netsslendpoint.h"
# include "netssltransport.h"
# include "netsslmacros.h"

# if OPENSSL_VERSION_NUMBER < 0x10100000L
extern "C" {

static int
InitLockCallbacks( Error *e );
static int
ShutdownLockCallbacks(void);
static void
LockingFunction(int mode, int n, const char *file, int line);
static unsigned long
IdFunction(void);
static struct CRYPTO_dynlock_value *
DynCreateFunction(const char *file, int line);
static void
DynLockFunction(int mode, struct CRYPTO_dynlock_value *l, const char *file, int line);
static void
DynDestroyFunction(struct CRYPTO_dynlock_value *l, const char *file, int line);

}

// OPENSSL_free was exposed in OpenSSL 1.1.0 for public use.
// In earlier versions it's marked as library internal.
# ifdef OPENSSL_free
# undef OPENSSL_free
# endif
# define OPENSSL_free free

# endif // !OpenSSL 1.1

static int LoadCACerts(SSL_CTX *ctx, const char *caPath )
{
	int loaded = 0;
	Error e;
	FileSys *f = FileSys::Create( FST_BINARY );
	f->Set( caPath );
	int stat = f->Stat();
	delete f;
	if( (stat & FSF_EXISTS) && (stat & FSF_DIRECTORY) )
	{
	    loaded = SSL_CTX_load_verify_locations(ctx, 0, caPath);
	    const char *msg = "NetSslTransport::LoadSystemCACerts "
	                      "SSL_CTX_load_verify_locations path";
	    SSLCHECKERROR( &e, msg, MsgRpc::SslInit, fail );
	    if( p4debug.GetLevel( DT_SSL ) == 2 )
                p4debug.printf( msg );
	}
	else if( (stat & FSF_EXISTS) )
	{
	    loaded = SSL_CTX_load_verify_locations(ctx, caPath, 0);
	    const char *msg = "NetSslTransport::LoadSystemCACerts "
	                      "SSL_CTX_load_verify_locations file";
	    SSLCHECKERROR( &e, msg, MsgRpc::SslInit, fail );
	    if( p4debug.GetLevel( DT_SSL ) == 2 )
                p4debug.printf( msg );
	}
fail:
	return loaded;
}

static void LoadSystemCACerts(SSL_CTX *ctx )
{
	Error e;
	StrBuf caPath = p4tunable.GetString( P4TUNE_SSL_CLIENT_CA_PATH );
	if( caPath.Length() && LoadCACerts( ctx, caPath.Text() ) )
	    return;

#ifdef OS_NT
	HCERTSTORE hStore = 0;
	PCCERT_CONTEXT pContext = 0;
	X509 *x509 = 0;
	X509_STORE *store = 0;
	int ok = 0;
	
	store = SSL_CTX_get_cert_store( ctx );
	if( !store )
	{
	    store = X509_STORE_new();
	    SSL_CTX_set_cert_store( ctx, store );
	}

	const char* locations[] = { "CA", "ROOT", "MY", 0 };
	for( int i = 0; locations[i]; i++ )
	{
	    hStore = CertOpenSystemStore( NULL, locations[i] );

	    if( !hStore )
	       continue;

	    while( pContext = CertEnumCertificatesInStore( hStore, pContext ) )
	    {
	        x509 = d2i_X509( NULL,
	                     (const unsigned char **)&pContext->pbCertEncoded,
	                     pContext->cbCertEncoded );
	        if( x509 )
	        {
	            ok = X509_STORE_add_cert( store, x509 );
	            char *str = X509_NAME_oneline(
	                X509_get_subject_name( x509 ), 0, 0 );
	            StrBuf msg = "NetSslTransport::LoadSystemCACerts "
	                         "SSL_CTX_set_options(";
	            msg << (str ? str : "null") << "): "
	                << (ok == 1 ? "success" : "failed");
	            OPENSSL_free( str );
	            SSLCHECKERROR( &e, msg.Text(), MsgRpc::SslInit, failLoad );
	            if( p4debug.GetLevel( DT_SSL ) == 2 && !e.Test() )
	                p4debug.printf("%s Successfully called.\n", msg.Text() );
failLoad:
	            X509_free( x509 );
	        }
	    }

	    CertFreeCertificateContext( pContext );
	    CertCloseStore( hStore, 0 );
	    hStore = 0;
	}
#elif defined( OS_MACOSX )
	CFArrayRef certs = NULL;
	CFIndex count, index;
	X509 *x509;
	X509_STORE *store = 0;
	int ok = 0;

	store = SSL_CTX_get_cert_store( ctx );
	if( !store )
	{
	    store = X509_STORE_new();
	    SSL_CTX_set_cert_store( ctx, store );
	}
	
	SecTrustSettingsDomain domain;
	SecTrustSettingsDomain domains[] = {
	    kSecTrustSettingsDomainUser,
	    kSecTrustSettingsDomainAdmin,
	    kSecTrustSettingsDomainSystem
	};
	int domainCount = sizeof( domains ) / sizeof( domain );

	for( int d = 0; d < domainCount; d++ )
	{
	    domain = domains[d];
	    if( !SecTrustSettingsCopyCertificates( domain, &certs ) )
	    {
	        count = CFArrayGetCount( certs );
	        for( index = 0; index < count; index++ )
	        {
	            SecCertificateRef cert =
	                (SecCertificateRef)CFArrayGetValueAtIndex(certs,index);
	            if( CFGetTypeID( cert ) != SecCertificateGetTypeID() )
	                continue;
#if defined( OS_MACOSX104 ) || defined( OS_MACOSX105 )
	            CSSM_DATA data;
	            SecCertificateGetData( cert, &data );
	            const unsigned char *buf = data.Data;
	            x509 = d2i_X509( NULL, &buf, data.Length );
#else
	            CFDataRef data = SecCertificateCopyData( cert );
	            const unsigned char *buf = CFDataGetBytePtr( data );
	            x509 = d2i_X509( NULL, &buf, CFDataGetLength( data ) );
#endif
	            if( x509 )
	            {
	                ok = X509_STORE_add_cert( store, x509 );
	                char *str = X509_NAME_oneline(
	                    X509_get_subject_name( x509 ), 0, 0 );
	                StrBuf msg = "NetSslTransport::LoadSystemCACerts "
	                    "SSL_CTX_set_options(";
	                msg << (str ? str : "null") << "): "
	                    << (ok == 1 ? "success" : "failed");
	                OPENSSL_free( str );
	                SSLCHECKERROR(&e,msg.Text(),MsgRpc::SslInit,failLoad);
	                if( p4debug.GetLevel( DT_SSL ) == 2 && !e.Test() )
	                    p4debug.printf( "%s Successfully called.\n",
	                                    msg.Text() );
failLoad:
	                X509_free( x509 );
	            }
#if !defined( OS_MACOSX104 ) && !defined( OS_MACOSX105 )
	            CFRelease( data );
#endif
	        }
	        CFRelease( certs );
	    }
	}
#else
	// Every distro has it's own place for SSL certs
	const char* locations[] = {
	    "/etc/pki/tls/certs/ca-bundle.crt",
	    "/etc/ssl/certs/ca-certificates.crt",
	    "/etc/openssl/certs/ca-certificates.crt",
	    "/etc/ssl/ca-bundle.pem",
	    "/etc/ssl/cacert.pem",
	    "/etc/pki/tls/cacert.pem",
	    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
	    "/etc/certs/ca-certificates.crt",
	    "/usr/local/share/certs/ca-root-nss.crt",
	    "/System/Library/OpenSSL/certs/",
	    "/etc/ssl/certs",
	    "/system/etc/security/cacerts",
	    "/usr/local/share/certs",
	    "/etc/pki/tls/certs",
	    "/etc/openssl/certs",
	    "/var/ssl/certs",
	    "/etc/ssl/cert.pem",
	    0
	};
	for( int i = 0; locations[i]; i++ )
	    if( LoadCACerts( ctx, locations[i] ) )
	        return;
#endif
}

////////////////////////////////////////////////////////////////////////////
//  Defines and Globals                                                   //
////////////////////////////////////////////////////////////////////////////

/*
 * Current Cypher Suite Configuration:
 * Primary:   AES256-SHA        SSLv3 Kx=RSA      Au=RSA  Enc=AES(256)      Mac=SHA1
 * Secondary: CAMELLIA256-SHA   SSLv3 Kx=RSA      Au=RSA  Enc=Camellia(256) Mac=SHA1
 */
# define SSL_PRIMARY_CIPHER_SUITE "AES256-SHA"
# define SSL_SECONDARY_CIPHER_SUITE "CAMELLIA256-SHA"

const char *P4SslVersionString = OPENSSL_VERSION_TEXT;
unsigned long sCompileVersion =  OPENSSL_VERSION_NUMBER;

unsigned long sVersion1_0_0 =  0x1000000f;
const char *sVerStr1_0_0 = "1.0.0";
# if OPENSSL_VERSION_NUMBER < 0x10100000L
# ifdef OS_NT
static HANDLE mutexArray[ CRYPTO_NUM_LOCKS ];
# else
static pthread_mutex_t mutexArray[ CRYPTO_NUM_LOCKS ];
# endif
# endif // !OpenSSL 1.1

typedef struct {
    int		value;
    const char	*name;
} SslErrorNames;

SslErrorNames	sslErrorNames[] = {
    {SSL_ERROR_NONE,			" (None)"},		// 0
    {SSL_ERROR_SSL,			" (SSL)"},		// 1
    {SSL_ERROR_WANT_READ,		" (Want_Read)"},	// 2
    {SSL_ERROR_WANT_WRITE,		" (Want_Write)"},	// 3
    {SSL_ERROR_WANT_X509_LOOKUP,	" (Want_X509_Lookup)"},	// 4
    {SSL_ERROR_SYSCALL,			" (Syscall)"},		// 5
    {SSL_ERROR_ZERO_RETURN,		" (Zero_Return)"},	// 6
    {SSL_ERROR_WANT_CONNECT,		" (Want_Connect)"},	// 7
    {SSL_ERROR_WANT_ACCEPT,		" (Want_Accept)"}	// 8
};

const char *
GetSslErrorName(int err)
{
    if( err < SSL_ERROR_NONE || err > SSL_ERROR_WANT_ACCEPT )
	return "";

    return sslErrorNames[err].name;
}

////////////////////////////////////////////////////////////////////////////
//  MutexLocker                                                           //
////////////////////////////////////////////////////////////////////////////
# ifdef OS_NT
# define ONE_SECOND 1000
class MutexLocker
{
    public:
	MutexLocker( HANDLE &mutex );
	~MutexLocker();

    private:
	DWORD   retval;
	HANDLE &mutex;
};

MutexLocker::MutexLocker( HANDLE &theLock )
    : mutex(theLock)
{
	retval = WaitForSingleObject( mutex, ONE_SECOND );
	if( retval != WAIT_OBJECT_0 )
	    DEBUGPRINT( SSLDEBUG_ERROR,
		    "Unable to acquire lock on windows." );
}

MutexLocker::~MutexLocker()
{
	if( retval == WAIT_OBJECT_0 )
	    ReleaseMutex( mutex );
}

# endif // OS_NT


////////////////////////////////////////////////////////////////////////////
//  Global                                                                //
////////////////////////////////////////////////////////////////////////////
# ifdef OS_NT
HANDLE                    sClientMutex = CreateMutex (NULL, FALSE, NULL);
HANDLE                    sServerMutex = CreateMutex (NULL, FALSE, NULL);
# endif // OS_NT

/**
 * MillisecondDifference
 *
 * @brief Utility to find the difference between two DateTimeHighPrecision
 * Note: Assumes that the difference is bounded by at most one second
 * since this is used to measure passage of time in a select with a 1/2 sec
 * timeout.
 *
 * @param lop left operator in subtraction
 * @param rop right operator in subtraction
 * @return count of milliseconds difference
 */
int
MillisecondDifference(const DateTimeHighPrecision &lop,
		      const DateTimeHighPrecision &rop)
{
    int sec = lop.Seconds() - rop.Seconds();
    int leftMs = (sec * 1000) + (lop.Nanos() / 1000000);
    int rightMs = (rop.Nanos() / 1000000);
    return (leftMs - rightMs);
}

////////////////////////////////////////////////////////////////////////////
//  NetSslTransport - STATIC MEMBERS                                      //
////////////////////////////////////////////////////////////////////////////
SSL_CTX *NetSslTransport::sServerCtx = NULL;
SSL_CTX *NetSslTransport::sClientCtx = NULL;


/**
 * NetSslTransport::constructor
 *
 * @brief constructor
 * @invariant assures that bio and ssl are NULL prior to use
 *
 * @param int socket
 * @param bool flag indicating if server or client side
 */
NetSslTransport::NetSslTransport( int t, bool fromClient, StrPtr *cipherList,
				StrPtr *cipherSuites )
    : NetTcpTransport( t, fromClient )
{
	this->bio = NULL;
	this->ssl = NULL;
	this->clientNotSsl = false;
	cipherSuite.Set("encrypted");
	customCipherList = cipherList;
	customCipherSuites = cipherSuites;
}

NetSslTransport::NetSslTransport( int t, bool fromClient,
				NetSslCredentials &cred, StrPtr *cipherList,
				StrPtr *cipherSuites )
    : NetTcpTransport( t, fromClient ), credentials(cred)
{
	this->bio = NULL;
	this->ssl = NULL;
	this->clientNotSsl = false;
	cipherSuite.Set("encrypted");
	customCipherList = cipherList;
	customCipherSuites = cipherSuites;
}
NetSslTransport::~NetSslTransport()
{
	Close();
}

// MS Visual Studio didn't implement snprintf until VS 2015.  Sigh.
# ifdef _MSC_VER
  #define SNPRINTF1(buf, len, msg, arg1)	sprintf(buf, msg, arg1)
  #define SNPRINTF2(buf, len, msg, arg1, arg2)	sprintf(buf, msg, arg1, arg2)
# else
  #define SNPRINTF1(buf, len, msg, arg1)	snprintf(buf, len, msg, arg1)
  #define SNPRINTF2(buf, len, msg, arg1, arg2)	snprintf(buf, len, msg, arg1, arg2)
# endif

SSL_CTX *
NetSslTransport::CreateAndInitializeSslContext( const char *conntypename )
{
    char	msgbuf[128];
    size_t	bufsize = sizeof( msgbuf ) - 1;

    SNPRINTF1( msgbuf, bufsize,
	       "NetSslTransport::Ssl%sInit - Initializing CTX structure.",
	       conntypename );
    TRANSPORT_PRINT_VAR( SSLDEBUG_FUNCTION, msgbuf );

    /*
     * In OpenSSL v1.1.0 we can use
     *	TLS_method()
     *	SSL_CTX_set_min_proto_version()
     *	SSL_CTX_set_max_proto_version()
     * instead of the deprecated
     * 	SSLv23_method()
     * and the not-recommended
     *	SSL_CTX_set_options( SSL_OP_NO_xxx )
     * but we still build with OpenSSL v1.0.x, so for now we'll stay
     * with the old way of doing things.
     *
     * See https://www.openssl.org/docs/man1.1.0/ssl/SSLv23_method.html
     * Note:
     *	"Clients should avoid creating "holes" in the set of protocols they support.
     *	When disabling a protocol, make sure that you also disable either all
     *	previous or all subsequent protocol versions. In clients, when a protocol
     *	version is disabled without disabling all previous protocol versions,
     *	the effect is to also disable all subsequent protocol versions."
     */

     /*
      * Start by allowing all protocol versions
      */

    SSL_CTX	*ctxp = SSL_CTX_new( SSLv23_method() );
    SNPRINTF1( msgbuf, bufsize, "NetSslTransport::Ssl%sInit SSL_CTX_new", conntypename );
    TRANSPORT_PRINT_VAR( SSLDEBUG_FUNCTION, msgbuf );

    SSL_CTX_set_mode(
	ctxp,
	SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER );
    SNPRINTF1( msgbuf, bufsize, "NetSslTransport::Ssl%sInit SSL_CTX_set_mode", conntypename );
    SSLLOGFUNCTION( msgbuf );

    /*
     * Now disable SSLv2 and SSLv3 (but still allow TLSv1.0 and later)
     */

    SSL_CTX_set_options( ctxp, SSL_OP_NO_SSLv2 );
    SNPRINTF1( msgbuf, bufsize, "NetSslTransport::Ssl%sInit SSL_CTX_set_options(NO_SSLv2)", conntypename );
    SSLLOGFUNCTION( msgbuf );

    SSL_CTX_set_options( ctxp, SSL_OP_NO_SSLv3 );
    SNPRINTF1( msgbuf, bufsize, "NetSslTransport::Ssl%sInit SSL_CTX_set_options(NO_SSLv3)", conntypename );
    SSLLOGFUNCTION( msgbuf );

    /*
     * Let the customer disable any protocols they don't want.
     * Allow only TLS versions in the (closed) range [tlsmin, tlsmax].
     */
    int	tlsmin = p4tunable.Get( P4TUNE_SSL_TLS_VERSION_MIN );
    int	tlsmax = p4tunable.Get( P4TUNE_SSL_TLS_VERSION_MAX );

    if( !strcmp( conntypename, "Client" ) )
    {
	/*
	 * Clients have a second min/max
	 * Setting ssl.tls.version.min/max overrides the client
	 * default, unless that is also set
	 */
	if( p4tunable.IsSet( P4TUNE_SSL_CLIENT_TLS_VERSION_MIN ) ||
	    !p4tunable.IsSet( P4TUNE_SSL_TLS_VERSION_MIN ) )
	    tlsmin = p4tunable.Get( P4TUNE_SSL_CLIENT_TLS_VERSION_MIN );

	if( p4tunable.IsSet( P4TUNE_SSL_CLIENT_TLS_VERSION_MAX ) ||
	    !p4tunable.IsSet( P4TUNE_SSL_TLS_VERSION_MAX ) )
	    tlsmax = p4tunable.Get( P4TUNE_SSL_CLIENT_TLS_VERSION_MAX );
    }

    struct TlsVersion {
	int		value;		// tunable value
	int		proto;		// OpenSSL protocol version value
	const char	*name;		// OpenSSL protocol version name
    };

    /*
     * Expand this table if and when new TLS protocol versions are available.
     * This table *must* be ordered by the "value" field
     * and terminated by a "value" of 0.
     */
    static TlsVersion	tlsVersions[] = {
	{ 10,	SSL_OP_NO_TLSv1,	"NO_TLSv1.0" },
	{ 11,	SSL_OP_NO_TLSv1_1,	"NO_TLSv1.1" },
	{ 12,	SSL_OP_NO_TLSv1_2,	"NO_TLSv1.2" },
# if OPENSSL_VERSION_NUMBER >= 0x10100000L
	{ 13,	SSL_OP_NO_TLSv1_3,	"NO_TLSv1.3" },
# endif
	{ 0,	0,			NULL}
    };

    /*
     * Pin the value to the legal range.
     * Update this code if new values are added to tlsVersions[].
     */
    if( tlsmin < 10 )
	tlsmin = 10;
    if( tlsmin > 13 )
	tlsmin = 13;

    if( tlsmax < 10 )
	tlsmax = 10;

    if( SSLDEBUG_FUNCTION )
    {
	p4debug.printf( "NetSslTransport::Ssl%sInit tlsmin=%d, tlsmax=%d\n",
			conntypename, tlsmin, tlsmax );
    }

    // disallow protocols below the requested minimum
    for( TlsVersion *vp = tlsVersions; vp->value; vp++ )
    {
	if( vp->value < tlsmin )
	{
	    SSL_CTX_set_options( ctxp, vp->proto );
	    SNPRINTF2( msgbuf, bufsize,
		       "NetSslTransport::Ssl%sInit SSL_CTX_set_options(%s)",
		       conntypename, vp->name );
	    SSLLOGFUNCTION( msgbuf );
	}
    }

    // disallow protocols above the requested maximum
    for( TlsVersion *vp = tlsVersions; vp->value; vp++ )
    {
	if( vp->value > tlsmax )
	{
	    SSL_CTX_set_options( ctxp, vp->proto );
	    SNPRINTF2( msgbuf, bufsize,
		       "NetSslTransport::Ssl%sInit SSL_CTX_set_options(%s)",
		       conntypename, vp->name );
	    SSLLOGFUNCTION( msgbuf );
	}
    }

#ifdef SSL_OP_NO_ENCRYPT_THEN_MAC
    if( !p4tunable.Get( P4TUNE_SSL_ENABLE_ETM ) )
    {
	SSL_CTX_set_options( ctxp, SSL_OP_NO_ENCRYPT_THEN_MAC );
	SNPRINTF2( msgbuf, bufsize,
		       "NetSslTransport::Ssl%sInit SSL_CTX_set_options(%s)",
		       conntypename,"SSL_OP_NO_ENCRYPT_THEN_MAC" );
	SSLLOGFUNCTION( msgbuf );
    }
#endif

    return ctxp;
}

/**
 * NetSslTransport::SslClientInit
 *
 * @brief static method to initialize the SSL client-side CTX structure
 *
 * @param error structure
 * @return none
 */

void
NetSslTransport::SslClientInit(Error *e)
{
	if( sClientCtx )
	    return;

# ifdef OS_NT
	/*
	 * Windows multi-threaded so must synchronize
	 * CTX creation, since we only want one.
	 */
	MutexLocker locker( sClientMutex );
	/*
	 * Now that we have the lock see if any
	 * thread created the CTX while we were
	 * waiting.
	 */
# endif // OS_NT

	if( !sClientCtx )
	{
# if OPENSSL_VERSION_NUMBER < 0x10100000L
	    // Silence -Wunused;
	    (void)&InitLockCallbacks;
	    (void)&ShutdownLockCallbacks;
# endif

# ifdef OS_NT
# if OPENSSL_VERSION_NUMBER < 0x10100000L
	    InitLockCallbacks( e );
	    if( e->Test())
		return;
# endif // !OpenSSL 1.1
# endif // OS_NT

	    ValidateRuntimeVsCompiletimeSSLVersion( e );
	    if( e->Test() )
	    {
		TRANSPORT_PRINT( SSLDEBUG_ERROR,
			"Version mismatch between compile OpenSSL version and runtime OpenSSL version." );
		return;
	    }

# if OPENSSL_VERSION_NUMBER < 0x10100000L
	    /*
	     * Added due to job084753: Swarm is a web app that reuses processes.
	     * For some reason in this environment the SSL error stack is not removed
	     * when the process is reused so we need to explicitly remove any previous
	     * state prior to setting up a new SSL Context.
	     *
	     * Deprecated in OpenSSL 1.1.0
	     */
	    ERR_remove_thread_state(NULL);
	    // probably cannot check for error return from this call :-)

	    // As of OpenSSL 1.1.0, SSL_load_error_strings() is not needed
	    SSL_load_error_strings();
	    SSLCHECKERROR( e,
	        "NetSslTransport::SslClientInit SSL_load_error_strings",
	         MsgRpc::SslInit,
	          fail );
# endif
# if OPENSSL_VERSION_NUMBER < 0x30000000L
	    // As of OpenSSL 3, ERR_load_*_strings() are not needed
	    ERR_load_BIO_strings();
	    SSLCHECKERROR( e,
	        "NetSslTransport::SslClientInit ERR_load_BIO_strings",
	        MsgRpc::SslInit,
	        fail );
# endif
# if OPENSSL_VERSION_NUMBER < 0x10100000L
	    // As of OpenSSL 1.1.0, SSL_library_init() is not needed
	    if ( !SSL_library_init() )
	    {
	        // executable not compiled supporting SSL
	        // need to link with open SSL libraries
	        e->Set(MsgRpc::SslNoSsl);
	        return;
	    }
	    SSLCHECKERROR( e, "NetSslTransport::SslClientInit SSL_library_init",
	        MsgRpc::SslInit,
	        fail );
# endif

	    // WSAstartup code in NetTcpEndPoint constructor

	    /*
	     * Allow TLSv1.0 and later but disable SSLv2 and SSLv3
	     * - Allow customers to further filter TLS protocol versions
	     */
	    if( (sClientCtx = CreateAndInitializeSslContext("Client")) == NULL )
		goto fail;

	    LoadSystemCACerts( sClientCtx );
	}
	return;

fail:
	e->Set( MsgRpc::SslCtx ) << "the connecting client";
	return;
}

void
NetSslTransport::GetPeerFingerprint(StrBuf &value)
{
	if( !isAccepted && credentials.GetFingerprint() &&
		credentials.GetFingerprint()->Length() )
	    value.Set( credentials.GetFingerprint()->Text() );
	else
	    value.Clear();
}


/**
 * NetSslTransport::SslServerInit
 *
 * @brief One time initialization for server side of connection for SSL.
 * @invariant Assures that the server-side SSL CTX structure has been initialized.
 *
 * @param error structure
 * @return nothing
 */

void
NetSslTransport::SslServerInit(StrPtr *hostname, Error *e)
{
	if( sServerCtx )
	    return;

	X509 *chainCert = 0;
	int i = 0;

# ifdef OS_NT
	/*
	 * Windows multi-threaded so must synchronize
	 * CTX creation, since we only want one.
	 */
	MutexLocker locker(sServerMutex);
	/*
	 * Now that we have the lock see if any
	 * thread created the CTX while we were
	 * waiting.
	 */
# endif // OS_NT

	if( !sServerCtx )
	{
# ifdef OS_NT
# if OPENSSL_VERSION_NUMBER < 0x10100000L
	    InitLockCallbacks( e );
	    if( e->Test())
		return;
# endif // !OpenSSL 1.1
# endif // OS_NT


# if OPENSSL_VERSION_NUMBER < 0x10100000L
	    /*
	     * Added due to job084753: Swarm is a web app that reuses processes.
	     * For some reason in this environment the SSL error stack is not removed
	     * when the process is reused so we need to explicitly remove any previous
	     * state prior to setting up a new SSL Context.
	     *
	     * Deprecated in OpenSSL 1.1.0
	     */
	    ERR_remove_thread_state( NULL );
	    // probably cannot check for error return from this call :-)

	    // As of OpenSSL 1.1.0, SSL_load_error_strings() is not needed
	    SSL_load_error_strings();
	    SSLCHECKERROR( e,
	        "NetSslTransport::SslClientInit SSL_load_error_strings",
	        MsgRpc::SslInit,
	        fail );
# endif
# if OPENSSL_VERSION_NUMBER < 0x30000000L
	    // As of OpenSSL 3, ERR_load_*_strings() are not needed
	    ERR_load_BIO_strings();
	    SSLCHECKERROR( e,
	        "NetSslTransport::SslClientInit ERR_load_BIO_strings",
	        MsgRpc::SslInit,
	        fail );
# endif
# if OPENSSL_VERSION_NUMBER < 0x10100000L
	    // As of OpenSSL 1.1.0, SSL_library_init() is not needed
	    if( !SSL_library_init() )
	    {
	        // executable not compiled supporting SSL
	        // need to link with open SSL libraries
	        e->Set( MsgRpc::SslNoSsl );
	        return;
	    }
	    SSLCHECKERROR( e, "NetSslTransport::SslClientInit SSL_library_init",
	        MsgRpc::SslInit,
	        fail );
# endif

	    /* Set up cert and key:
	     * Note that we have already verified in RpcService::Listen
	     * that sslKey and sslCert exist in P4SSLDIR and are valid.
	     * Since we are doing lazy init of the SslCtx the
	     * files could have been deleted before hitting this code.  We will do
	     * another verify check here when we finally load the credentials
	     * for the first read/write.
	     */
	    credentials.ReadCredentials(e);
	    P4CHECKERROR( e, "NetSslTransport::SslServerInit ReadCredentials", fail );

	    /*
	     * Allow TLSv1.0 and later but disable SSLv2 and SSLv3
	     * - Allow customers to further filter TLS protocol versions
	     */
	    if( (sServerCtx = CreateAndInitializeSslContext("Server")) == NULL )
		goto fail;

	    SSL_CTX_use_PrivateKey( sServerCtx, credentials.GetPrivateKey() );
	    SSLLOGFUNCTION(
		"NetSslTransport::SslServerInit SSL_CTX_use_PrivateKey" );
	    credentials.SetOwnKey(false);
	    /*
	     * Note: if want key passphrase protected then need to implement
	     * a callback function to supply the passphrase:
	     *     int passwd_cb(char *buf, int size, int flag, void *userdata);
	     *
	     * Alternatively strip the passphrase protection off the key via
	     *     cp server.key server.key.org
	     *     openssl [rsa|dsa] -in server.key.org -out server.key
	     */
	    SSL_CTX_use_certificate( sServerCtx, credentials.GetCertificate() );
	    SSLLOGFUNCTION(
		"NetSslTransport::SslServerInit SSL_CTX_use_certificate" );
	    credentials.SetOwnCert(false);

	    /*
	     * If we have a chain, add those certs to the context
	     */
	    while( ( chainCert = credentials.GetChain( i++ ) ) )
	    {
	        SSL_CTX_add_extra_chain_cert( sServerCtx, chainCert );
	        SSLLOGFUNCTION(
	           "NetSslTransport::SslServerInit SSL_CTX_add_extra_chain_cert" );
	    }

	    /*
	     * Set context to not verify certificate authentication with CA.
	     */
	    SSL_CTX_set_verify( sServerCtx, SSL_VERIFY_NONE, NULL /* no callback */);
	    SSLLOGFUNCTION(
		"NetSslTransport::SslServerInit SSL_CTX_set_verify server ctx" );

	    /*
	     * NOTE: The way this code is written there is no CA check on the cert.
	     * If want to do this then SSL_CTX_load_verify_locations(sServerCtx, NULL, sslCACert);
	     * The certificate authority certificate directory must be hashed:
	     *     c_rehash /path/to/certfolder
	     */
	}

	return;

fail:
	e->Set( MsgRpc::SslCtx ) << "the accepting server";
	return;
}

/**
 * NetSslTransport::DoHandshake
 *
 * @brief transport level method to invoke SSL handshake and provide debugging output
 * @invariant if SSL and CTX structures are non-null handshake has completed successfully
 *
 * @param error structure
 * @return none
 */
void
NetSslTransport::DoHandshake( Error *e )
{
	if(ssl)
	    return;

	/*
	 * Lazy initialization: If no SSL context has been created for
	 * this type of connection (server side or client side) then do it
	 * now, then use it to create an SSL structure for this connection.
	 */
	if( this->isAccepted )
	{
	    ssl = SSL_new( sServerCtx );
	    SSLNULLHANDLER( ssl, e, "NetSslTransport::DoHandshake SSL_new", fail );
	    if( customCipherList )
	    {
		SSL_set_cipher_list( ssl, customCipherList->Text() );
		SSLLOGFUNCTION( "NetSslTransport::DoHandshake SSL_set_cipher_list custom" );
	    }
	    else if ( p4tunable.Get( P4TUNE_SSL_SECONDARY_SUITE ) )
	    {
		SSL_set_cipher_list( ssl, SSL_SECONDARY_CIPHER_SUITE );
		SSLLOGFUNCTION( "NetSslTransport::DoHandshake SSL_set_cipher_list secondary" );
	    }
	    else
	    {
		SSL_set_cipher_list( ssl, SSL_PRIMARY_CIPHER_SUITE );
		SSLLOGFUNCTION( "NetSslTransport::DoHandshake SSL_set_cipher_list primary" );
	    }

# if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined (OPENSSL_IS_BORINGSSL)
	    // TLS 1.3 can send session-resumption info after the main handshake, which
	    // will cause us to hang, so since we don't use sessions, disable that.
	    SSL_set_num_tickets( ssl, 0 );
	    
	    if( customCipherSuites )
	    {
		SSL_set_ciphersuites( ssl, customCipherSuites->Text() );
		SSLLOGFUNCTION( "NetSslTransport::DoHandshake SSL_set_ciphersuites custom" );
	    }
# endif
	}
	else
	{
	    ssl = SSL_new( sClientCtx );
	    SSLNULLHANDLER( ssl, e, "NetSslTransport::DoHandshake SSL_new", fail );

	    StrBuf suites;
	    suites << SSL_PRIMARY_CIPHER_SUITE << ":"
	           << SSL_SECONDARY_CIPHER_SUITE << ":HIGH";
	    SSL_set_cipher_list( ssl, suites.Text() );
	    SSLLOGFUNCTION( "NetSslTransport::DoHandshake SSL_set_cipher_list primary+secondary+high" );

	    // SNI support
	    SSL_set_tlsext_host_name( ssl, GetPortParser().Host().Text() );
	    StrBuf msg = "NetSslTransport::DoHandshake SSL_set_tlsext_host_name ";
	    msg << GetPortParser().Host();
	    SSLLOGFUNCTION( msg.Text() );
	}

	/*
	 * If debugging output configured, dump prioritized list of
	 * supported cipher-suites.
	 */
	if( SSLDEBUG_TRANS )
	{
	    int priority = 0;
	    bool shouldContinue = true;
	    p4debug.printf( "List of Cipher Suites supported:\n" );
	    while( shouldContinue )
	    {
		const char *cipherStr = SSL_get_cipher_list( ssl, priority );
		priority++;
		shouldContinue = (cipherStr) ? true : false;
		if( shouldContinue )
		{
		    p4debug.printf( "  Priority %d: %s\n", priority, cipherStr );
		}
	    }
	}

	/* Create a bio for this new socket */
	bio = BIO_new_socket( t, BIO_NOCLOSE );
	SSLNULLHANDLER( bio, e, "NetSslTransport::DoHandshake BIO_new_socket",
                    fail );

	/**
	 * Hooks the BIO up with the SSL *. Note once this is called then the
	 * SSL * owns the BIOs and will cleanup their allocation in an SSL_free
	 * if the reference count becomes zero.
	 */
	SSL_set_bio( ssl, bio, bio );
	SSLLOGFUNCTION( "NetSslTransport::DoHandshake SSL_set_bio" );

	if( !SslHandshake(e) )
	    goto fail;

	if( !isAccepted )
	{
# if OPENSSL_VERSION_NUMBER < 0x30000000L
	    X509 *serverCert = SSL_get_peer_certificate( ssl );
# else
	    X509 *serverCert = SSL_get1_peer_certificate( ssl );
# endif
	    stack_st_X509 *serverCertChain = SSL_get_peer_cert_chain( ssl );
	    X509_STORE *store = SSL_CTX_get_cert_store( SSL_get_SSL_CTX( ssl ) );
	    credentials.SetCertificate( serverCert, serverCertChain, store, e );

	    if ( e->Test() )
	    {
		X509_free( serverCert );
		goto failNoRead;
	    }

	    SSLLOGFUNCTION( credentials.GetFingerprint()->Text() );
	    if( SSLDEBUG_CONNECT )
	        p4debug.printf(
	            "NetSslTransport::DoHandshake %s certificate received\n",
	            credentials.IsSelfSigned() ? "self-signed" : "chain" );

	    if( SSLDEBUG_CERT )
	    {
		char *str = NULL;
		// print out CERT info from server

		p4debug.printf( "Server certificate:\n" );
		str = X509_NAME_oneline( X509_get_subject_name( serverCert ), 0,
				     0 );
		SSLNULLHANDLER( str, e, "connect X509_get_subject_name", fail );
		p4debug.printf( "\t subject: %s\n", str );
		OPENSSL_free( str );
		str = X509_NAME_oneline( X509_get_issuer_name( serverCert ), 0,
				     0 );
		SSLNULLHANDLER( str, e, "connect X509_get_issuer_name", fail );
		p4debug.printf( "\t issuer: %s\n", str );
		OPENSSL_free( str );

	    }
	    X509_free( serverCert );
	    SSLLOGFUNCTION( "X509_free" );
	}

	return;

	/* Error Handling */
fail:
	lastRead = 1;

failNoRead:
	TRANSPORT_PRINT( SSLDEBUG_ERROR,
		"NetSslTransport::DoHandshake In fail error code." );
	if(ssl)
	{
	    SSL_free(ssl);
	    SSLLOGFUNCTION( "NetSslTransport::DoHandshake SSL_free" );
	    bio = NULL;
	    ssl = NULL;
	}
	// NET_CLOSE_SOCKET(t);
	if( isAccepted )
	{
	    TRANSPORT_PRINT( SSLDEBUG_ERROR,
		    "NetSslTransport::DoHandshake failed on server side.");
	    if( !e->Test() )
		e->Set( MsgRpc::SslAccept ) << "";
	}
	else
	{
	    TRANSPORT_PRINT( SSLDEBUG_ERROR,
		    "NetSslTransport::DoHandshake failed on client side.");
	    if( !e->Test() )
		e->Set( MsgRpc::SslConnect ) << GetPortParser().String() << "";
	}

}

/**
 * NetSslTransport::SslHandshake
 *
 * @brief low level method to invoke ssl handshake and handle asynchronous behavior of
 * the BIO structure.
 *
 * @param error structure
 * @return bool true = success, false = fail
 */
bool
NetSslTransport::SslHandshake( Error *e )
{
	bool      done = false;
	int       readable;
	int       writable;
	int       counter = 0;
	int	  sslClientTimeoutMs
	    = p4tunable.Get( P4TUNE_SSL_CLIENT_TIMEOUT ) * 1000;
	DateTimeHighPrecision dtBeforeSelect, dtAfterSelect;
	int maxwait = GetMaxWait();
	if( maxwait && maxwait > sslClientTimeoutMs )
	    sslClientTimeoutMs = maxwait;

	/* select timeout */
	const int tv = !maxwait || maxwait > HALF_SECOND ?
	    HALF_SECOND : maxwait;

	while ( !done )
	{
	    // Perform an SSL handshake.
	    int ret = 0;
	    int errorRet = 0;
	    if( isAccepted )
		ret = SSL_accept(ssl);
	    else
		ret = SSL_connect( ssl );

	    switch( errorRet = SSL_get_error( ssl, ret ) )
	    {
	    case SSL_ERROR_NONE:
		done = true;
		TRANSPORT_PRINTF( SSLDEBUG_CONNECT,
		    "NetSslTransport::SslHandshake protocol=%s", SSL_get_version(ssl) );
		break;

	    case SSL_ERROR_WANT_READ:
		{
		    readable = 1;
		    writable = 0;
# ifdef WSAEWOULDBLOCK
	            int error = WSAGetLastError();

# else
	            int error = errno;
# endif
	            dtBeforeSelect.Now();
		    int selectRet =
			    selector->Select( readable, writable, tv );
		    dtAfterSelect.Now();
		    counter += MillisecondDifference(dtAfterSelect, dtBeforeSelect);

		    if( selectRet < 0 )
		    {
			e->Sys( "select", "socket" );
			return false;
		    }
		    /*
		     * Changed to prevent a bad guy forming a DOS attack on
		     * Linux by running nc against a p4d.  Previous code
		     * executed a tight loop calling SSL_accept and erroring
		     * out with a WANT_WRITE and a EAGAIN error. We stop this
		     * by sleeping for a millisecond before trying again.
		     * Some OSs return EWOULDBLOCK under this same condition.
		     *
		     * Note POSIX 2008 spec prevents the select call in this
		     * case statement from returning prematurely with EAGAIN,
		     * but Ubuntu seems to follow an earlier version of the
		     * spec. It appears that Mac OS X is complient since this
		     * problem does not exist on that platform.
		     */
# ifdef WSAEWOULDBLOCK
		    if ( WSAEWOULDBLOCK == error)
# else
		    if(( EAGAIN == error ) || ( EWOULDBLOCK == error) )
# endif
		    {

			if( counter > 10 )
			{
			    // Timeout code for new client using SSL going against old server.
			    if(!isAccepted && (counter > sslClientTimeoutMs)) {
				TRANSPORT_PRINTF( SSLDEBUG_ERROR,
				    "NetSslTransport::SslHandshake failed on client side: %d (timeout after %dms)",
				    errorRet, counter);
				e->Set( MsgRpc::SslConnect) << GetPortParser().String();
				Close();
				return false;
			    }
			    msleep(1);
			    counter++;
			}
			else
			{
			    TRANSPORT_PRINT( SSLDEBUG_FUNCTION,
				"NetSslTransport::SslHandshake WANT_READ with EAGAIN or EWOULDBLOCK");
			}
		    }
		}
		break;

	    case SSL_ERROR_WANT_WRITE:
		readable = 0;
		writable = 1;
		if( selector->Select( readable, writable, tv ) < 0 )
		{
		    e->Sys( "select", "socket" );
		    return false;
		}
		TRANSPORT_PRINTF( SSLDEBUG_FUNCTION,"NetSslTransport::SslHandshake WANT_WRITE ret=%d", ret);
		break;
	    case SSL_ERROR_SSL:
		/* underlying protocol error dump error to 
		 * debug output
		 */

		// buffer for ssl protocol errors
		char	sslErrorBuf[256];
		ERR_error_string_n( ERR_get_error(), sslErrorBuf, 256 );
		TRANSPORT_PRINTF( SSLDEBUG_ERROR, "Handshake Failed: %s", sslErrorBuf );
		e->Set( MsgRpc::SslProtocolError ) << sslErrorBuf;
	    default:
		StrBuf errBuf;
		if( errorRet == SSL_ERROR_SSL )
		{
		    errBuf.Set( " (SSL protocol error)" );
		}
		else if( Error::IsNetError() )
		{
		    StrBuf tmp;
		    Error::StrNetError( tmp );
		    errBuf.Set( " (" );
		    errBuf.Append( &tmp );
		    errBuf.Append( ")" );
		}
		else
		{
		    StrBuf tmp;
		    Error::StrError( tmp );
		    errBuf.Set( " (" );
		    errBuf.Append( &tmp );
		    errBuf.Append( ")" );
		}
		if( isAccepted )
		{
		    TRANSPORT_PRINTF( SSLDEBUG_ERROR,
			"NetSslTransport::SslHandshake failed on server side: %d%s",
			errorRet, GetSslErrorName(errorRet) );
		    e->Set( MsgRpc::SslAccept) << errBuf;
		}
		else
		{
		    TRANSPORT_PRINTF( SSLDEBUG_ERROR,
		 	"NetSslTransport::SslHandshake failed on client side: %d%s",
			errorRet, GetSslErrorName(errorRet) );
		    e->Set( MsgRpc::SslConnect) << GetPortParser().String() << errBuf;
		}
		return false;
	    } // end switch - last SSL error
	} // end while - keep going until the handshake is done.
	return true;
}


/*
 * NetSslTransport::SendOrReceive() - send or receive data as ready
 *
 * If data to write and no room to read, block writing.
 * If room to read and no data to write, block reading.
 * If both data to write and room to read, block until one is ready.
 *
 * If neither data to write nor room to read, don't call this!
 *
 * Brain-dead version of NetSslSelector::Select() indicates both
 * read/write are ready.  To avoid blocking on read, we only do so
 * if not instructed to write.
 *
 * Returns 1 if either data read or written.
 * Returns 0 if neither, meaning EOF or error.
 */

int
NetSslTransport::SendOrReceive( NetIoPtrs &io, Error *se, Error *re )
{
	// Hacky solution to allow us to send out a cleartext error
	// message to the client if they are attempting a cleartext
	// connection to our SSL server.
	if( clientNotSsl )
	{
	    int retval = NetTcpTransport::SendOrReceive( io, se, re );
	    Close();
	    return retval;
	}
	if( t < 0 )
	{
	    TRANSPORT_PRINT( SSLDEBUG_ERROR,"NetSslTransport::SendOrReceive connection "
		    "closed, returning w/o doing anything." );
	    // Socket has been closed don't try to use
	    return 0;
	}
	StrBuf buf;
	int  doRead = 0;
	int  doWrite = 0;

	int dataReady;
	int maxwait = GetMaxWait();
	Timer waitTime;
	if( maxwait )
	{
	    waitTime.Start();
	}

	int  readable = 0;
	int  writable = 0;

	/* flags to mark all the combinations of why we're blocking */
	bool read_waiton_write = false;
	bool read_waiton_read = false;
	bool write_waiton_write = false;
	bool write_waiton_read = false;

	/* select timeout */
	int  tv;

	/* ssl status */
	int  sslError;
	int  sslPending;
	long errErrorNum;
	char errErrorStr[256];

	// Lazy call of handshake code.
	if( !ssl )
	{
	    DoHandshake( se );
	    if( se->Test() )
		goto end;
	}

	for ( ;; )
	{
	    doRead = io.recvPtr != io.recvEnd && !re->Test();
	    doWrite = io.sendPtr != io.sendEnd && !se->Test();

	    if( !doRead && !doWrite )
	    {
		// cannot read or write
		return 0;
	    }
	    /*
	     * If we enter this loop and are supposed to read AND
	     * there is something already in the SSL read buffers
	     * then don't wait in the select call for something
	     * to appear in the kernel buffers.
	     */
	    sslPending = SSL_pending( ssl );


	    /*
	     * Complex logic to check OS level buffers for
	     * read or write:
	     * For Write:
	     * - if entered this function to write then always check
	     * - if entered to read but handshake is blocking operation
	     *   then write before continue writing
	     * DO NOT check write otherwise since will cause tight loop
	     * burning CPU on interactive commands.
	     *
	     * For Read:
	     * - if entered this function to read then always check
	     * - if entered to write but handshake is blocking operation
	     *   then read before continue writing
	     */
	    readable =
		( doRead || write_waiton_read || read_waiton_read ) ? 1 : 0;
	    writable =
		( doWrite || write_waiton_write || read_waiton_write ) ? 1 : 0;

	    if (readable && sslPending)
		tv = 0;
	    else if( (readable && breakCallback) || maxwait )
	    {
		tv = !maxwait || maxwait > HALF_SECOND ? HALF_SECOND : maxwait;
		if( breakCallback )
		{
		    int p = breakCallback->PollMs();
		    if( p >= 1 )
			tv = p;
		}
	    }
	    else
		tv = -1;


	    if( ( dataReady = selector->Select( readable, writable, tv ) < 0 ) )
	    {
		re->Sys( "select", "socket" );
		return 0;
	    }

	    if( !dataReady && maxwait && waitTime.Time() >= maxwait )
	    {
	        lastRead = 0;
	        TRANSPORT_PRINT( SSLDEBUG_ERROR, "SSL SendOrReceive maxwait expired." );
	        if( doRead )
	            re->Set( MsgRpc::MaxWait ) << "receive" << ( maxwait / 1000 );
	        else
	            se->Set( MsgRpc::MaxWait ) << "send" << ( maxwait / 1000 );
		return 0;
	    }

	    // Before checking for data do the callback isalive test.
	    // If the user defined IsAlive() call returns a zero
	    // value then the user wants this request to terminate.

	    if( doRead && breakCallback && !breakCallback->IsAlive() )
	    {
		lastRead = 0;
		re->Set( MsgRpc::Break );
		return 0;
	    }

	    if( SSLDEBUG_BUFFER )
	    {
		DateTimeHighPrecision dt;
		char buftime[ DTHighPrecisionBufSize ];

		dt.Now();
		dt.Fmt( buftime );

		p4debug.printf(
		    "State status:	time: %s\n"
		    "\tsslPending         %d - is something in the SSL read buffer?\n"
		    "\treadable           %d - is something in the OS read buffer?\n"
		    "\twritable           %d - is there available room OS write buffer?\n"
		    "\tdoRead             %d - we have room in P4rpc read buffer\n"
		    "\tdoWrite            %d - we have stuff to write in P4rpc write buffer\n"
		    "\twrite_waiton_write %d - ssl write buffer not available, try again when net net write buffer ready\n"
		    "\twrite_waiton_read  %d - ssl write buffer not available due to handshake, try again when net read buffer ready\n"
		    "\tread_waiton_write  %d - ssl read buffer not available due to handshake, try again when net write buffer ready\n"
		    "\tread_waiton_read   %d - ssl read buffer not available, try again when net read buffer ready\n",
		    buftime, sslPending, readable, writable, doRead, doWrite,
		    write_waiton_write, write_waiton_read, read_waiton_write,
		    read_waiton_read );
	    }

	    /* This "if" statement reads data. It will only be entered if
	     * the following conditions are all true:
	     * 1. we're not in the middle of a write
	     * 2. there's space left in the recv buffer
	     * 3. the kernel write buffer is available signaling that a handshake
	     *    write has completed (this write had been blocking our read, and
	     *    now we are free to continue it), or either SSL or OS says we can
	     *    read regardless of whether we're blocking for availability to read.
	     */
	    if( !( write_waiton_read || write_waiton_write ) && doRead
            && ( sslPending || readable || ( writable && read_waiton_write )) )
	    {
		/* clear the flags since we'll set them based on the I/O call's
		 * return
		 */
		read_waiton_read = false;
		read_waiton_write = false;

		/* read into the buffer after the current position */

		int l = SSL_read( ssl, io.recvPtr, io.recvEnd - io.recvPtr );
		SSLLOGFUNCTION( "NetSslTransport::SendOrReceive SSL_read" );

		switch ( sslError = SSL_get_error( ssl, l ) )
		{
		case SSL_ERROR_NONE:
		    /*
		     * no errors occurred.  update the new buffer size and signal
		     * that "have data" by returning 1.
		     */
		    if( l > 0 )
			TRANSPORT_PRINTF( SSLDEBUG_TRANS,
			    "NetSslTransport::SendOrReceive recv %d bytes",
			    l );

		    lastRead = 1;
		    io.recvPtr += l;
		    return 1;

		    break;
		case SSL_ERROR_ZERO_RETURN:
		    /* connection closed */
		    TRANSPORT_PRINT( SSLDEBUG_ERROR, "SSL_read returned SSL_ERROR_ZERO_RETURN" );
		    goto end;
		    break;
		case SSL_ERROR_WANT_READ:
		    /*
		     * we need to retry the read after kernel buffer available for
		     * reading
		     */
		    TRANSPORT_PRINT( SSLDEBUG_ERROR, "SSL_read returned SSL_ERROR_WANT_READ" );
		    read_waiton_read = true;
		    break;
		case SSL_ERROR_WANT_WRITE:
		    /*
		     * we need to retry the read after kernel buffer is available for
		     * writing
		     */
		    TRANSPORT_PRINT( SSLDEBUG_ERROR, "SSL_read returned SSL_ERROR_WANT_WRITE" );
		    read_waiton_write = true;
		    break;
		case SSL_ERROR_SYSCALL:
		    /*
		     * an I/O error occurred check underlying SSL ERR for info
		     * if none then report StrNetError()
		     */
		    errErrorNum = ERR_get_error();
	            if ( errErrorNum == 0 )
	            {
	        	if( l == 0)
	        	{
	        	    re->Net( "read", "SSL_read encountered an EOF." );
	        	    TRANSPORT_PRINT( SSLDEBUG_ERROR, "SSL_read encountered an EOF." );
	        	}
	        	else if ( l < 0 )
	        	{
	        	    Error::StrNetError( buf );
	        	    re->Net( "read", buf.Text() );
	        	    TRANSPORT_PRINTF( SSLDEBUG_ERROR, "SSL_read encountered a system error: %s", buf.Text() );
	        	}
	        	else
	        	{
	        	    TRANSPORT_PRINT( SSLDEBUG_FUNCTION,
	        		    "SSL_read claims SSL_ERROR_SYSCALL but returns data." );
	        	    if( l > 0 )
	        		TRANSPORT_PRINTF( SSLDEBUG_TRANS,
	        			"NetSslTransport::SendOrReceive recv %d bytes\n",
	        			l );
	        	    lastRead = 1;
	        	    io.recvPtr += l;
	        	    return 1;
	        	}
	            }
	            else
	            {
	        	ERR_error_string_n( errErrorNum, errErrorStr, 256 );
	        	re->Net( "read", errErrorStr );
	        	TRANSPORT_PRINTF( SSLDEBUG_ERROR,
	        		"SSL_read encountered a syscall ERR: %s", errErrorStr );
	            }
	            re->Set( MsgRpc::SslRecv );
	            goto end;
	            break;
		default:
		    if( l == 0 )
		    {
			if( doWrite )
			{
			    // Error: connection was closed but we had stuff to write
			    re->Net( "read", "socket" );
			    re->Set( MsgRpc::SslRecv );
			}
			TRANSPORT_PRINT( SSLDEBUG_FUNCTION,
			    "SSL_read attempted on closed connection." );
			/*
			 * Connection closed but did not shutdown SSL cleanly.
			 * The p4 proxy will do this if the command issued by
			 * its client does not require forwarding to the p4d server.
			 */
			goto end;
		    }

		    /* ERROR */
		    re->Net( "read", "socket" );
		    re->Set( MsgRpc::SslRecv );
		    TRANSPORT_PRINTF( SSLDEBUG_ERROR,
			    "SSL_read returned unknown error: %d",
                                  sslError );
		    goto end;
		}
	    }

	    /* This "if" statement writes data. It will only be entered if
	     * the following conditions are all true:
	     * 1. we're not in the middle of a read
	     * 2. there's room in the buffer
	     * 3. the kernel read buffer is available signaling that a handshake
	     *    read has completed (this rad had been blocking our write, and
	     *    now we are free to continue it), or OS says we can write regardless
	     *    of whether we're blocking for availability to write.
	     */
	    if( !( read_waiton_write || read_waiton_read ) && doWrite
            && ( writable || ( readable && write_waiton_read )) )
	    {
		/* clear the flags */
		write_waiton_read = false;
		write_waiton_write = false;

		/* perform the write from the start of the buffer */
		int l = SSL_write( ssl, io.sendPtr, io.sendEnd - io.sendPtr );
		SSLLOGFUNCTION( "NetSslTransport::SendOrReceive SSL_write" );

		switch ( sslError = SSL_get_error( ssl, l ) )
		{
		case SSL_ERROR_NONE:
		    /*
		     * no errors occurred.  update the new buffer size and signal
		     * that "have data" by returning 1.
		     */
		    if( l > 0 )
			TRANSPORT_PRINTF( SSLDEBUG_TRANS,
				"NetSslTransport send %d bytes\n", l );
		    lastRead = 0;
		    io.sendPtr += l;
		    return 1;

		    break;
		case SSL_ERROR_ZERO_RETURN:
		    /* connection closed */
		    TRANSPORT_PRINT( SSLDEBUG_ERROR,
			    "SSL_write returned SSL_ERROR_ZERO_RETURN" );
		    goto end;
		case SSL_ERROR_WANT_READ:
		    /*
		     * we need to retry the write after A is available for
		     * reading
		     */
		    TRANSPORT_PRINT( SSLDEBUG_ERROR,
			    "SSL_write returned SSL_ERROR_WANT_READ" );
		    write_waiton_read = true;
		    break;
		case SSL_ERROR_WANT_WRITE:
		    /*
		     * we need to retry the write after A is available for
		     * writing
		     */
		    TRANSPORT_PRINT( SSLDEBUG_ERROR,
			    "SSL_write returned SSL_ERROR_WANT_WRITE" );
		    write_waiton_write = true;
		    break;
		case SSL_ERROR_SYSCALL:
		    /*
		     * an I/O error occurred check underlying SSL ERR for info
		     * if none then report StrNetError()
		     */
		    errErrorNum = ERR_get_error();
	            if ( errErrorNum == 0 )
	            {
	        	if( l == 0)
	        	{
	        	    se->Net( "write", "SSL_write encountered an EOF." );
	        	    TRANSPORT_PRINT( SSLDEBUG_ERROR, "SSL_write encountered an EOF." );
	        	}
	        	else if ( l < 0 )
	        	{
	        	    Error::StrNetError( buf );
	        	    se->Net( "write", buf.Text() );
	        	    TRANSPORT_PRINTF( SSLDEBUG_ERROR,
	        		    "SSL_write encountered a system error: %s", buf.Text() );
	        	}
	        	else
	        	{
	        	    TRANSPORT_PRINT( SSLDEBUG_ERROR,
	        		    "SSL_write claims SSL_ERROR_SYSCALL but returns data." );
	        	    if( l > 0 )
	        		TRANSPORT_PRINTF( SSLDEBUG_TRANS, "NetSslTransport send %d bytes", l );
	        	    lastRead = 0;
	        	    io.sendPtr += l;
	        	    return 1;
	        	}
	            }
	            else
	            {
	        	ERR_error_string_n( errErrorNum, errErrorStr, 256 );
	        	se->Net( "write", errErrorStr );
	        	TRANSPORT_PRINTF( SSLDEBUG_ERROR,
	        		"SSL_write encountered a syscall ERR: %s", errErrorStr );
	            }
	            se->Set( MsgRpc::SslSend );
	            goto end;
		    break;
		default:
		    if( l == 0 )
		    {
			/*
			 * Connection closed but did not shutdown SSL cleanly.
			 * The p4 proxy will do this if the command issued by
			 * its client does not require forwarding to the p4d server.
			 */
			TRANSPORT_PRINT( SSLDEBUG_FUNCTION,
			    "SSL_write attempted on closed connection." );
			goto end;
		    }

		    /* ERROR */
		    se->Net( "write", "socket" );
		    se->Set( MsgRpc::SslSend );
		    TRANSPORT_PRINTF( SSLDEBUG_ERROR,
			    "SSL_write returned unknown error: %d",
                                  sslError );
		    goto end;
		}
	    }
	}

end:
	Close();
	return 0;
}


/**
 * NetSslTransport::Close
 *
 * @brief handles teardown of the SSL connection and deletion of the
 * of the SSL and BIO structures, closes socket
 * @invariant SSL and BIO are NULL if the connection is closed
 *
 * @return none
 */
void
NetSslTransport::Close( void )
{
	if( t < 0 )
	    return;

	TRANSPORT_PRINTF( SSLDEBUG_CONNECT, "NetSslTransport %s closing %s",
                           GetAddress( RAF_PORT )->Text(),
                           GetPeerAddress( RAF_PORT )->Text() );

	// Avoid TIME_WAIT on the server by reading the EOF after
	// the last message sent by the client.  Getting the EOF
	// means we've received the TH_FIN packet, which means we
	// don't have to send our own on close().  He who sends
	// a TH_FIN goes into the 2 minute TIME_WAIT imposed by TCP.

	TRANSPORT_PRINTF( SSLDEBUG_TRANS, "NetSslTransport lastRead=%d", lastRead );

	// Only wait in select a second by default, since it's possible
	// we'll be in a state where the EOF never comes.
	const int max = p4tunable.Get( P4TUNE_NET_MAXCLOSEWAIT );

	if( lastRead )
	{
	    int  r = 1;
	    int  w = 0;
	    char buf[1];

	    if( selector->Select( r, w, max ) >= 0 && r )
		(void)(read( t, buf, 1 )+1);
	}

	if (ssl)
	{
	    if( SSL_get_shutdown( ssl ) & SSL_RECEIVED_SHUTDOWN )
	    {
		// clean shutdown
		SSL_shutdown( ssl );
		SSLLOGFUNCTION( "NetSslTransport::Close SSL_shutdown" );
	    }
	    else
	    {
		/*
		 * An error is causing this shutdown, so we remove session
		 * from cache.
		 */
		SSL_clear( ssl );
		SSLLOGFUNCTION( "NetSslTransport::Close SSL_clear" );
	    }
	    BIO_pop( bio );
	    SSLLOGFUNCTION( "NetSslTransport::Close BIO_pop" );
	    SSL_free( ssl );
	    SSLLOGFUNCTION( "NetSslTransport::Close SSL_free" );
	}

	bio = NULL;
	ssl = NULL;

	if( lastRead )
	{
	    int  r = 1;
	    int  w = 0;
	    char buf[1];

	    if( selector->Select( r, w, max ) >= 0 && r )
		(void)(read( t, buf, 1 )+1);
	}

	NET_CLOSE_SOCKET(t);
}


void
NetSslTransport::ClientMismatch( Error *e )
{
	if ( CheckForHandshake(t) == PeekCleartext )
	{
	    TRANSPORT_PRINT( SSLDEBUG_ERROR,
		    "Handshake peek appears not to be for SSL.");
	    // this is a non-ssl connection
	    e->Set( MsgRpc::SslCleartext );
	    clientNotSsl = true;
	}
}

void
NetSslTransport::ValidateRuntimeVsCompiletimeSSLVersion( Error *e )
{
	StrBuf sb;
# if OPENSSL_VERSION_NUMBER < 0x10100000L
	GetVersionString( sb, SSLeay() );
# else
	GetVersionString( sb, OpenSSL_version_num() );
# endif
	TRANSPORT_PRINTF( SSLDEBUG_ERROR,
		"OpenSSL runtime version %s", sb.Text() );
	sb.Clear();
	GetVersionString( sb, OPENSSL_VERSION_NUMBER );
	TRANSPORT_PRINTF( SSLDEBUG_ERROR,
		"OpenSSL compile version %s", sb.Text() );

# if OPENSSL_VERSION_NUMBER < 0x10100000L
	if ( GET_MJR_SSL_VERSION( SSLeay() ) <
# else
	if( GET_MJR_SSL_VERSION( OpenSSL_version_num() ) <
# endif
	    GET_MJR_SSL_VERSION( sVersion1_0_0 ) )
	{
	    e->Set(MsgRpc::SslLibMismatch) << sVerStr1_0_0;
	}
}

void
NetSslTransport::GetVersionString( StrBuf &sb, unsigned long version )
{
	/* Version numbering explanation from OpenSSL openssl/opensslv.h file:
	 *
	 * Numeric release version identifier:
	 * MNNFFPPS: major minor fix patch status
	 * The status nibble has one of the values 0 for development, 1 to e for betas
	 * 1 to 14, and f for release.  The patch level is exactly that.
	 * For example:
	 * 0.9.3-dev          0x00903000
	 * 0.9.3-beta1        0x00903001
	 * 0.9.3-beta2-dev    0x00903002
	 * 0.9.3-beta2        0x00903002 (same as ...beta2-dev)
	 * 0.9.3              0x0090300f
	 * 0.9.3a             0x0090301f
	 * 0.9.4              0x0090400f
	 * 1.2.3z             0x102031af
	 */
	unsigned long M = (version >> 28) & ~0xfffffff0L;
	unsigned long N = (version >> 20) & ~0xffffff00L;
	unsigned long P = (version >> 12) & ~0xffffff00L;
	sb << M << "." << N << "." << P;
}

////////////////////////////////////////////////////////////////////////////
//  OpenSSL Dynamic Locking Callback Functions                            //
////////////////////////////////////////////////////////////////////////////
// Dynamic locking code only being used on NT in 2012.1, will be used on
// other platforms in 2012.2 (by that time I will include pthreads to the
// HPUX build). In 2012.1 HPUX has many compile errors for pthreads.
//
// OpenSSL 1.1 handles these internally so are no longer required

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#ifndef OS_HPUX

static void LockingFunction( int mode, int n, const char *file, int line )
{
# ifdef OS_NT
    if (mode & CRYPTO_LOCK)
    {
	WaitForSingleObject( mutexArray[n], INFINITE );
    }
    else
    {
	ReleaseMutex( mutexArray[n] );
    }
# else
    if( mode & CRYPTO_LOCK )
    {
	pthread_mutex_lock( &mutexArray[n] );
    }
    else
    {
	pthread_mutex_unlock( &mutexArray[n] );
    }
# endif // OS_NT
}

/**
 * OpenSSL uniq id function.
 *
 * @return    thread id
 */
static unsigned long IdFunction( void )
{
# ifdef OS_NT
    return ((unsigned long) GetCurrentThreadId());
# else
    return ((unsigned long) pthread_self());
# endif
}

/**
 * OpenSSL allocate and initialize dynamic crypto lock.
 *
 * @param    file    source file name
 * @param    line    source file line number
 */
static struct CRYPTO_dynlock_value *
DynCreateFunction( const char *file, int line )
{
    struct CRYPTO_dynlock_value *value;

    value = (struct CRYPTO_dynlock_value *) malloc(
	    sizeof(struct CRYPTO_dynlock_value) );
    if( !value )
    {
	goto err;
    }
# ifdef OS_NT
    value->mutex = CreateMutex( NULL, FALSE, NULL );
# else
    pthread_mutex_init( &value->mutex, NULL );
# endif // OS_NT
    return value;

    err: return (NULL);
}

/**
 * OpenSSL dynamic locking function.
 *
 * @param    mode    lock mode
 * @param    l        lock structure pointer
 * @param    file    source file name
 * @param    line    source file line number
 * @return    none
 */
static void DynLockFunction(
        int mode,
        struct CRYPTO_dynlock_value *l,
        const char *file,
        int line )
{
# ifdef OS_NT
    if (mode & CRYPTO_LOCK)
    {
	WaitForSingleObject( l->mutex, INFINITE );
    }
    else
    {
	ReleaseMutex( l->mutex );
    }
# else
    if( mode & CRYPTO_LOCK )
    {
	pthread_mutex_lock( &l->mutex );
    }
    else
    {
	pthread_mutex_unlock( &l->mutex );
    }
# endif // OS_NT
}

/**
 * OpenSSL destroy dynamic crypto lock.
 *
 * @param    l        lock structure pointer
 * @param    file    source file name
 * @param    line    source file line number
 * @return    none
 */

static void DynDestroyFunction(
        struct CRYPTO_dynlock_value *l,
        const char *file,
        int line )
{
# ifdef OS_NT
    CloseHandle(l->mutex);
# else
    pthread_mutex_destroy( &l->mutex );
# endif // OS_NT
    free( l );
}

static int InitLockCallbacks( Error *e )
{
	for ( int i = 0; i < CRYPTO_num_locks(); i++ )
	{
# ifdef OS_NT
	    mutexArray[i] = CreateMutex( NULL, FALSE, NULL );
# else
	    pthread_mutex_init( &mutexArray[i], NULL );
# endif // OS_NT
	}
	/* static locks callbacks */
	CRYPTO_set_locking_callback( LockingFunction );
	CRYPTO_set_id_callback( IdFunction );
	/* dynamic locks callbacks */
	CRYPTO_set_dynlock_create_callback( DynCreateFunction );
	CRYPTO_set_dynlock_lock_callback( DynLockFunction );
	CRYPTO_set_dynlock_destroy_callback( DynDestroyFunction );

	return (0);
}

/**
 * Cleanup TLS library.
 *
 * @return    0
 */
static int ShutdownLockCallbacks( void )
{
    CRYPTO_set_dynlock_create_callback( NULL );
    CRYPTO_set_dynlock_lock_callback( NULL );
    CRYPTO_set_dynlock_destroy_callback( NULL );

    CRYPTO_set_locking_callback( NULL );
    CRYPTO_set_id_callback( NULL );

    for ( int i = 0; i < CRYPTO_num_locks(); i++ )
    {
# ifdef OS_NT
	CloseHandle( mutexArray[i] );
# else
	pthread_mutex_destroy( &mutexArray[i] );
# endif // OS_NT
    }

    return (0);
}

# endif // !OS_HPUX
# endif // !OpenSSL 1.1
# endif //USE_SSL
