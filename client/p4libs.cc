/*
 * Copyright 1995, 2019 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# include <stdhdrs.h>
# include <signaler.h>
# include <error.h>
# include <strbuf.h>
# include <netaddrinfo.h>
# include <netutils.h>
# include <i18napi.h>
# include <charcvt.h>
# include <msgclient.h>
# include <datetime.h>
# include "p4libs.h"

# ifdef HAS_EXTENSIONS
# include <sqlite3.h>
# include <curl/curl.h>
# endif

# ifdef USE_SSL
extern "C"
{
# include "openssl/opensslv.h"
# include "openssl/crypto.h"
# include "openssl/ssl.h"
# include "openssl/err.h"
# include "openssl/engine.h"
# include "openssl/conf.h"
}
# endif

extern bool P4FileSysCreateOnIntr;

# if ((defined(USE_SSL) && OPENSSL_VERSION_NUMBER >= 0x10100000L ) || \
     defined(HAS_EXTENSIONS)) && !defined(OPENSSL_IS_BORINGSSL)

static void* p4malloc( size_t s, const char *f, int l )
{
	return P4_MALLOC( s );
}

static void* p4realloc( void* p, size_t s, const char *f, int l )
{
	return P4_REALLOC( p, s );
}

static void p4free( void* p, const char *f, int l )
{
	P4_FREE( p );
}

# ifdef HAS_EXTENSIONS

static void* p4malloc( size_t s )
{
	return p4malloc( s, 0, 0 );
}

static void* p4realloc( void* p, size_t s )
{
	return p4realloc( p, s, 0, 0 );
}

static void p4free( void* p )
{
	p4free( p, 0, 0 );
}

static void* p4calloc( size_t n, size_t s )
{
	return P4_CALLOC( n, s );
}

static char* p4strdup( const char *s )
{
	return P4_STRDUP( s );
}

# endif
# endif

void P4Libraries::Initialize( const int libraries, Error* e )
{
	if( libraries & P4LIBRARIES_INIT_P4 )
	{
# ifdef HAS_RPMALLOC
	    // This should be the first thing done in a process.
	    rpmalloc_initialize();
# endif
	    x86_check_features();
	    DateTime::Centralize( 0 );
	    (*signaler).Init();
	    NetUtils::InitNetwork();
	    // Nothing for ErrorLog's global AssertLog instance.
	}

# ifdef USE_SSL
# if OPENSSL_VERSION_NUMBER >= 0x10100000L
	if( libraries & P4LIBRARIES_INIT_OPENSSL )
	{
#if !defined(OPENSSL_IS_BORINGSSL)
	    // This can fail if allocations have already been made by OpenSSL.
	    if( !CRYPTO_set_mem_functions( p4malloc, p4realloc, p4free ) )
	        e->Set( MsgClient::DevErr )
	            << "CRYPTO_set_mem_functions(): Could not set OpenSSL "
	               "allocation functions.";
#endif
	    OPENSSL_init_ssl( 0, NULL );
	}
# endif
# endif

# ifdef HAS_EXTENSIONS

	// https://www.sqlite.org/c3ref/initialize.html
	if( libraries & P4LIBRARIES_INIT_SQLITE )
	    sqlite3_initialize();

	// https://curl.haxx.se/libcurl/c/curl_global_init.html
	if( libraries & P4LIBRARIES_INIT_CURL )
	    curl_global_init_mem( CURL_GLOBAL_ALL, p4malloc, p4free, p4realloc, p4strdup, p4calloc );

# endif
}

// Note that the Error* may be NULL.
void P4Libraries::InitializeThread( const int libraries, Error* e )
{
	if( libraries & P4LIBRARIES_INIT_P4 )
	{
# ifdef HAS_RPMALLOC
	    // This should be the first thing done in a thread.
	    rpmalloc_thread_initialize();
# endif
	}
}

// Note that the Error* may be NULL.
void P4Libraries::ShutdownThread( const int libraries, Error* e )
{
# ifdef USE_SSL
	if( libraries & P4LIBRARIES_INIT_OPENSSL )
	{
# if OPENSSL_VERSION_NUMBER < 0x10100000L
	    CRYPTO_cleanup_all_ex_data();
	    ERR_remove_thread_state( NULL );
# endif
# if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(OPENSSL_IS_BORINGSSL)
	    OPENSSL_thread_stop();
# endif
	}
# endif

	if( libraries & P4LIBRARIES_INIT_P4 )
	{
# ifdef HAS_RPMALLOC
	    // This should be the last thing done in a thread.
	    rpmalloc_thread_finalize();
# endif
	}
}

void P4Libraries::Shutdown( const int libraries, Error* e )
{
# ifdef HAS_EXTENSIONS

	if( libraries & P4LIBRARIES_INIT_SQLITE )
	    sqlite3_shutdown();

	if( libraries & P4LIBRARIES_INIT_CURL )
	    curl_global_cleanup();

# endif

	if( libraries & P4LIBRARIES_INIT_P4 )
	{
	    (*signaler).Disable();

	    // The global CharSetCvtCache cleans itself up.

	    NetUtils::CleanupNetwork();
	}

# ifdef USE_SSL
	if( libraries & P4LIBRARIES_INIT_OPENSSL )
	{
	    // https://wiki.openssl.org/index.php/Library_Initialization#Cleanup
# if OPENSSL_VERSION_NUMBER < 0x30000000L
	    FIPS_mode_set( 0 );
# endif
# if OPENSSL_VERSION_NUMBER < 0x10100000L && !defined(OPENSSL_IS_BORINGSSL)
	    ENGINE_cleanup();
# endif
#if !defined(OPENSSL_IS_BORINGSSL)
	    CONF_modules_unload( 1 );
#endif
# if OPENSSL_VERSION_NUMBER < 0x10100000L
	    EVP_cleanup();
	    CRYPTO_cleanup_all_ex_data();
	    ERR_remove_thread_state( NULL );
# endif
# if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(OPENSSL_IS_BORINGSSL)
	    OPENSSL_thread_stop();
# endif
# if OPENSSL_VERSION_NUMBER < 0x10100000L
	    ERR_free_strings();
	    SSL_COMP_free_compression_methods();
# endif
	}
# endif

	if( libraries & P4LIBRARIES_INIT_P4 )
	{
# ifdef HAS_RPMALLOC
	    // This should be the last thing done in the process.
	    rpmalloc_finalize();
# endif
	}

}

void P4Libraries::DisableZlibOptimization()
{
}

void P4Libraries::DisableFileSysCreateOnIntr()
{
	P4FileSysCreateOnIntr = false;
}

void P4Libraries::EnableFileSysCreateOnIntr()
{
	P4FileSysCreateOnIntr = true;
}
