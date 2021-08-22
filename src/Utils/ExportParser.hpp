#pragma once

#include <Windows.h>
#include <winternl.h>

#include <cstdint>
#include <functional>
#include <unordered_map>
#include <string_view>

class ExportParser {
	std::uintptr_t m_base{ };
	IMAGE_EXPORT_DIRECTORY* m_ied{ };
	std::unordered_map<std::string_view, std::uintptr_t> m_exported_fns{ };

	[[nodiscard]] auto GetSize( ) const noexcept -> std::uint32_t {
		return this->m_ied->NumberOfNames;
	}

	[[nodiscard]] auto GetName( std::uint32_t index ) const noexcept -> std::string_view {
		return reinterpret_cast<const char*>( m_base + reinterpret_cast<std::uint32_t*>( m_base + m_ied->AddressOfNames )[ index ] );
	}

	[[nodiscard]] auto GetAddress( std::uint32_t index ) const noexcept -> std::uintptr_t {
		const auto rva_table = reinterpret_cast<std::uint32_t*>( m_base + m_ied->AddressOfFunctions );
		const auto ord_table = reinterpret_cast<std::uint16_t*>( m_base + m_ied->AddressOfNameOrdinals );

		return m_base + rva_table[ ord_table[ index ] ];
	}

public:
	explicit ExportParser( std::uintptr_t base ) noexcept : m_base( base ) {
		auto nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>( base + reinterpret_cast<IMAGE_DOS_HEADER*>( base )->e_lfanew );

		const auto ied_data_dir = nt_headers->OptionalHeader.DataDirectory[ 0 ];
		this->m_ied = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>( base + ied_data_dir.VirtualAddress );

		for ( auto idx{ 0 }; idx < this->GetSize( ); idx++ )
			m_exported_fns[ this->GetName( idx ) ] = this->GetAddress( idx );
	}

	[[nodiscard]] auto GetFunctions() -> std::unordered_map<std::string_view, std::uintptr_t> {
		return this->m_exported_fns;
	}

	auto EnumerateExports( const std::function<void( std::string_view name, std::uintptr_t address )>& callback_fn ) const -> void {
		for ( const auto& [ fn_name, fn_address ] : m_exported_fns )
			callback_fn( fn_name, fn_address );
	}
};

// The syscall ID is 2 bytes in length and starts 4 bytes into the function
// https://www.ired.team/offensive-security/defense-evasion/retrieving-ntdll-syscall-stubs-at-run-time#reminder
template<typename Ty>
__forceinline auto GetSyscallIndex( Ty function_address ) -> std::uint16_t {
	return *reinterpret_cast<std::uint16_t*>( reinterpret_cast<std::uintptr_t>( function_address ) + 4 );
}