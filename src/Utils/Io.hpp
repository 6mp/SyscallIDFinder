#pragma once
#include <Windows.h>

#include <string_view>
#include <filesystem>

#include <fmt/core.h>
#include <fmt/color.h>

namespace Io {
	__forceinline auto InitConsole( ) -> void {
		auto console_handle = GetConsoleWindow( );
		auto stream_handle = GetStdHandle( STD_OUTPUT_HANDLE );
		SetConsoleMode( stream_handle, 0x7 );
		SetLayeredWindowAttributes( console_handle, 0, 242, LWA_ALPHA );
		SetConsoleTitle( " " );
	}

	template<fmt::color Color = fmt::color::white, typename... Args>
	__forceinline constexpr auto Log( std::string_view message, Args... args ) -> void {

		try {
			fmt::print( fg( Color ), message, args... );
		}

		catch ( std::exception& e ) {
			fmt::print( fg( fmt::color::red ) | fmt::emphasis::bold, e.what( ) );
		}
	}
}// namespace Io
