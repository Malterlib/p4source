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
# include "p4libs.h"

# ifdef HAS_EXTENSIONS
# include <sqlite3.h>
# include <curl/curl.h>
# endif

extern "C" {
# include <x86.h>
void x86_check_features();
}

# ifdef USE_SSL
extern "C"
{
# include "openssl/crypto.h"
# include "openssl/ssl.h"
# include "openssl/err.h"
# include "openssl/engine.h"
# include "openssl/conf.h"
}
# endif

extern bool P4FileSysCreateOnIntr;

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

void P4Libraries::Initialize( const int libraries, Error* e )
{
	if( libraries & P4LIBRARIES_INIT_P4 )
	{
# ifdef HAS_RPMALLOC
	    // This should be the first thing done in a process.
	    rpmalloc_initialize();
# endif
	    x86_check_features();
	    signaler.Init();
	    NetUtils::InitNetwork();
	    // Nothing for ErrorLog's global AssertLog instance.
	}

# ifdef USE_SSL
# if OPENSSL_VERSION_NUMBER >= 0x10100000L
	if( libraries & P4LIBRARIES_INIT_OPENSSL )
	{
	    // This can fail if allocations have already been made by OpenSSL.
	    if( !CRYPTO_set_mem_functions( p4malloc, p4realloc, p4free ) )
	        e->Set( MsgClient::DevErr )
	            << "CRYPTO_set_mem_functions(): Could not set OpenSSL "
	               "allocation functions.";
	    SSL_library_init();
	}
# endif
# endif

# ifdef HAS_EXTENSIONS

	// https://www.sqlite.org/c3ref/initialize.html
	if( libraries & P4LIBRARIES_INIT_SQLITE )
	    sqlite3_initialize();

	// https://curl.haxx.se/libcurl/c/curl_global_init.html
	if( libraries & P4LIBRARIES_INIT_CURL )
	    curl_global_init( CURL_GLOBAL_ALL );

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
	    CRYPTO_cleanup_all_ex_data();
# if OPENSSL_VERSION_NUMBER <= 0x10100000L
	    ERR_remove_thread_state( NULL );
# endif
# if OPENSSL_VERSION_NUMBER >= 0x10100000L
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
	    signaler.Disable();

	    // The global CharSetCvtCache cleans itself up.

	    NetUtils::CleanupNetwork();
	}

# ifdef USE_SSL
	if( libraries & P4LIBRARIES_INIT_OPENSSL )
	{
	    https://wiki.openssl.org/index.php/Library_Initialization#Cleanup
	    FIPS_mode_set( 0 );
	    ENGINE_cleanup();
	    CONF_modules_unload( 1 );
	    EVP_cleanup();
	    CRYPTO_cleanup_all_ex_data();
# if OPENSSL_VERSION_NUMBER <= 0x10100000L
	    ERR_remove_thread_state( NULL );
# endif
# if OPENSSL_VERSION_NUMBER >= 0x10100000L
	    OPENSSL_thread_stop();
# endif
	    ERR_free_strings();
	    SSL_COMP_free_compression_methods();
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
# ifndef USE_OPTIMIZED_ZLIB
	int x86_cpu_enable_ssse3 = 0;
# endif

	x86_check_features();
	x86_cpu_enable_ssse3 = 0;
	x86_cpu_enable_simd = 0;
}

void P4Libraries::DisableFileSysCreateOnIntr()
{
	P4FileSysCreateOnIntr = false;
}

void P4Libraries::EnableFileSysCreateOnIntr()
{
	P4FileSysCreateOnIntr = true;
}
