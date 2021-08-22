#include "Utils/Io.hpp"
#include "Utils/ExportParser.hpp"

int main( ) {
	Io::InitConsole( );

	//TODO: download syscall list and parse for current winver

	ExportParser ntdll( reinterpret_cast<std::uintptr_t>( LoadLibrary( "ntdll.dll" ) ) );
	ntdll.EnumerateExports( []( std::string_view name, std::uintptr_t address ) -> void {
		if ( name.substr( 0, 2 ).find( "Nt" ) != std::string::npos ) {
			Io::Log( "name {}, address {:X}, index {:X}\n", name, address, GetSyscallIndex( address ) );
		}
	} );

	ExportParser win32u( reinterpret_cast<std::uintptr_t>( LoadLibrary( "win32u.dll" ) ) );
	win32u.EnumerateExports( []( std::string_view name, std::uintptr_t address ) -> void {
		if ( name.substr( 0, 2 ).find( "Nt" ) != std::string::npos ) {
			Io::Log( "name {}, address {:X}, index {:X}\n", name, address, GetSyscallIndex( address ) );
		}
	} );
}
