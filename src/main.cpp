#include "Utils/Io.hpp"
#include "Utils/ExportParser.hpp"

int main( ) {
	Io::InitConsole( );

	std::size_t syscall_count{ };

	ExportParser ntdll( reinterpret_cast<std::uintptr_t>( LoadLibrary( "ntdll.dll" ) ) );
	ntdll.EnumerateExports( [ &syscall_count ]( std::string_view name, std::uintptr_t address ) -> void {
		if ( name.substr( 0, 2 ).find( "Nt" ) != std::string::npos ) {
			Io::Log( "name {}, address {:X}, index {:X}\n", name, address, GetSyscallIndex( address ) );
			syscall_count++;
		}
	} );

	ExportParser win32u( reinterpret_cast<std::uintptr_t>( LoadLibrary( "win32u.dll" ) ) );
	win32u.EnumerateExports( []( std::string_view name, std::uintptr_t address ) -> void {
		if ( name.substr( 0, 2 ).find( "Nt" ) != std::string::npos ) {
			Io::Log( "name {}, address {:X}, index {:X}\n", name, address, GetSyscallIndex( address ) );
		}
	} );
}
