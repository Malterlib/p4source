/*
 * Copyright 1995, 2020 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# include <stdhdrs.h>
# include <error.h>
# include <strbuf.h>
# include <strdict.h>
# include <strtable.h>
# include "sysinfo.h"
# include "runcmd.h"
# include "pid.h"

# ifdef HAS_CPP11

# include <vector>
# include <regex>

static void run( StrBufDict& output, const std::vector< const char* > cmd,
	         const std::vector< std::string >& masks, Error* e )
{
	RunCommandIo io;
	RunArgv args;
	StrBuf name, out;

	for( const auto& a : cmd )
	{
	    args << a;
	    name << a << " ";
	}

	char* end = name.Text() + name.Length() - 1;
	*( end ) = '\0'; // Omit the trailing space.
	name.SetEnd( end );

	io.Run( args, out, e );

	if( e->Test() )
	    e->Fmt( &out );

	// Mask-out anything that might be sensitive, like passwords.

	for( const auto& m : masks )
	{
	    std::string re;
	    // Capture the leading newline so it's part of the replacement.
	    re += "((^|\n)";
	    re += m;
	    re += ").*";
	    out = std::regex_replace( out.Text(),
	                              std::regex( re ), "$1MASKED" ).c_str();
	}

	output.SetVar( name, out );

	// Prevent the error from being attached to all output.
	e->Clear();
}


void SystemInfo::Collect( StrBufDict& output, Error* e )
{
	// Not all commands are available everywhere, and for simplicity of
	// implementation, we don't try to minimize output (read: there will
	// be duplication in places).

	output.Clear();

	StrNum pid( Pid().GetID() );

	// Unix is =-separated and Windows is whitepace.
	const std::vector< std::string > masks = { "P4PASSWD=", "P4PASSWD\\s+" };

# ifdef OS_LINUX
# define FOUND_PLATFORM

	const std::vector< std::vector< const char* > > cmds =
	    { { "hostnamectl" },
	      { "lsb_release", "-a" },
	      { "sh", "-c", "cat /etc/*elease" },
	      { "sh", "-c", "cat /proc/swaps" },
	      { "sh", "-c", "cat /proc/cpuinfo" },
	      { "sh", "-c", "cat /proc/meminfo" },
	      { "sh", "-c", "ls -1 /dev/disk/by-id/" },
	      { "sh", "-c", "xargs -0 -L1 -a /proc/self/environ" },
	      { "sh", "-c", "cat /proc/sys/kernel/core_pattern" },
	      { "grep", "docker\\|lxc", "/proc/1/cgroup" },
	      { "systemd-detect-virt" },
	      { "mount" },
	      { "lshw" },
	      { "lspci" },
	      { "lsusb" },
	      { "free", "-m" },
	      { "sysctl", "-a" },
	      { "sh", "-c", "ulimit -a" },
	      { "timedatectl" },
	      { "sh", "-c", "cat /etc/fstab" },
	      { "sh", "-c", "cat /sys/kernel/mm/redhat_transparent_hugepage/enabled" },
	      { "sh", "-c", "cat /sys/kernel/mm/redhat_transparent_hugepage/defrag" },
	      { "sh", "-c", "cat /sys/kernel/mm/redhat_transparent_hugepage/khugepaged/defrag" },
	      { "sh", "-c", "cat /sys/kernel/mm/transparent_hugepage/enabled" },
	      { "sh", "-c", "cat /sys/kernel/mm/transparent_hugepage/defrag" },
	      { "sh", "-c", "cat /sys/kernel/mm/transparent_hugepage/khugepaged/defrag" },
	      { "sh", "-c", "cat /sys/class/dmi/id/sys_vendor" },
	      { "sh", "-c", "cat /sys/class/dmi/id/bios_*" },
	      { "sh", "-c", "cat /sys/class/dmi/id/board_vendor /sys/class/dmi/id/board_name  /sys/class/dmi/id/board_version" },
	      { "p4", "set" },
	    };

# endif // OS_LINUX

# ifdef OS_NT
# define FOUND_PLATFORM
	
	const std::vector< std::vector< const char* > > cmds =
	    // https://docs.microsoft.com/en-us/powershell/scripting/samples/collecting-information-about-computers?view=powershell-7
	    { { "powershell", "-Command", "Get-ComputerInfo" }, // PS 5.1
	      { "powershell", "-Command", "Get-WMIObject Win32_OperatingSystem | Select Name, version, servicepackmajorversion, BuildNumber, CSName, OSArchitecture, OperatingSystemSKU, Caption, InstallDate, " },
	      { "powershell", "-Command", "Get-HotFix | Format-List" },
	      { "powershell", "-Command", "Get-TimeZone" },
	      { "powershell", "-Command", "Get-CimInstance -ClassName Win32_BIOS" },
	      { "powershell", "-Command", "Get-CimInstance -ClassName Win32_Processor | Format-List *" },
	      { "powershell", "-Command", "Get-CimInstance -ClassName Win32_Baseboard" },
	      { "powershell", "-Command", "Get-CimInstance -ClassName Win32_PhysicalMemory" },
	      { "powershell", "-Command", "Get-CimInstance -ClassName Win32_LogicalDisk" },
	      { "powershell", "-Command", "Get-WmiObject -Class Win32_TemperatureProbe" },
	      { "powershell", "-Command", "Get-WmiObject win32_LogicalDisk | Select Name,Caption,Compressed,BlockSize,Availability,DeviceID,MediaType,DriveType,FreeSpace,FileSystem,VolumeName,SystemName | format-list" },
	      { "powershell", "-Command", "Get-CimInstance -ClassName Win32_ComputerSystem | Format-List *" },
	      { "powershell", "-Command", "Get-Childitem -Path Env:* | Sort-Object" },
	      { "systeminfo" },
	      { "powershell", "-Command", "Get-Date | Format-List *" },
	      { "powershell", "-Command", "[TimeZoneInfo]::Local" },
	      { "p4", "set" },
	    };

# endif // OS_NT

# if defined( OS_DARWIN ) || defined( OS_MACOSX )
# define FOUND_PLATFORM
	const std::vector< std::vector< const char* > > cmds;
	output.SetVar( "error", "Function not available on Darwin." );
# endif // OS_DARWIN OS_MACOSX

# ifdef FOUND_PLATFORM
	for( const auto& cmd : cmds )
	    run( output, cmd, masks, e );
# endif // FOUND_PLATFORM
}

# else // HAS_CPP11

void SystemInfo::Collect( StrBufDict& output, Error* e )
{
}

# endif // HAS_CPP11
