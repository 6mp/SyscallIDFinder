#include "Utils/Io.hpp"
#include "Utils/ExportParser.hpp"

int main( ) {
	Io::InitConsole( );
	std::string module_name{ };
	std::string function_name{ };
	std::string lower_function_name{ };

	Io::Log( "enter syscall module, ex ntdll.dll\n" );
	std::cin >> module_name;

	Io::Log( "enter syscall name, ex NtCreateThread\n" );
	std::cin >> function_name;

	// tolower fn name
	std::transform( function_name.cbegin( ), function_name.cend( ), std::back_inserter( lower_function_name ),
					[]( std::uint8_t c ) -> std::uint8_t { return std::tolower( c ); } );

	// fixup name if someone only typed name without extension
	if ( module_name.find( '.' ) == std::string::npos )
		module_name += ".dll";

	ExportParser module( reinterpret_cast<std::uintptr_t>( LoadLibraryA( module_name.c_str( ) ) ) );

	if ( !module.GetFunctions( ).contains( lower_function_name ) ) {
		Io::Log<fmt::color::red>( "function {} was not found in module {}\n", function_name, module_name );
		return 0;
	}

	Io::Log<fmt::color::green>( "{} id is {:X}\n", function_name,
								GetSyscallIndex( module.GetFunctions( )[ lower_function_name ] ) );
}
