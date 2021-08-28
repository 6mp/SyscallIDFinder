#include "Utils/Io.hpp"
#include "Utils/ExportParser.hpp"

int main( ) {
	Io::InitConsole( );
	std::string module_name{ };
	std::string function_name{ };

	Io::Log( "enter syscall module, ex ntdll or ntdll.dll\n" );
	std::cin >> module_name;

	Io::Log( "enter syscall name, ex NtCreateThread\n" );
	std::cin >> function_name;

	//tolower fn name
	std::ranges::transform( function_name.begin( ), function_name.end( ), function_name.begin( ),
							[]( std::uint8_t c ) -> std::uint8_t { return std::tolower( c ); } );

	//fixup name if someone only typed name without extension
	if ( module_name.find( '.' ) == std::string::npos )
		module_name += ".dll";

	ExportParser module( reinterpret_cast<std::uintptr_t>( LoadLibraryA( module_name.c_str( ) ) ) );

	if ( !module.GetFunctions( ).contains( function_name ) ) {
		Io::Log<fmt::color::red>( "function {} was not found in module {}\n", function_name, module_name );
		return 0;
	}

	Io::Log<fmt::color::green>( "{} id is {:X}\n", function_name,
				    GetSyscallIndex( module.GetFunctions( )[ function_name ] ) );

	/* doing this method results in 6 invalid syscalls, I am looking for a better way to sort them
	ExportParser ntdll( reinterpret_cast<std::uintptr_t>( LoadLibrary( "ntdll.dll" ) ) );
	ntdll.EnumerateExports( []( std::string_view name, std::uintptr_t address ) -> void {
		if ( name.substr( 0, 2 ).find( "Nt" ) != std::string::npos ) {
			Io::Log( "name {}, address {:X}, index {:X}\n", name, address, GetSyscallIndex( address ) );
		}
	} );
	*/
}
