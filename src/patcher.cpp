#include <windows.h>
#include <cstdio>
#include <algorithm>
#include <fstream>
#include <cstdint>
#include <vector>
#include <filesystem>

uint8_t pat[] = { 0x48, 0x89, 0x5c, 0x24, 0x08, 0x55, 0x56, 0x57, 0x48, 0x8d, 0xac, 0x24, 0x70, 0xff, 0xff, 0xff };
uint8_t patch[] = { 0xC6, 0x01, 0x01, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3 };

int run_patcher(int argc, char* argv[]) {
	printf("[ ] PatchAllBack\n");
	if (argc < 2) {
		printf("[-] invalid argument count\n");
		printf("[ ] usage: %s path_to_StartAllBackX64.dll\n", argv[0]);
		return 1;
	}

	auto path = std::filesystem::path(argv[1]);
	auto backup_path = std::filesystem::path(path.string() + ".bak");

	if (!std::filesystem::exists(path)) {
		printf("[-] invalid file or does not exist\n");
		return 1;
	}

	if (std::filesystem::exists(backup_path)) {
		printf("[-] backup file already exists\n");
		return 1;
	}

	std::ifstream file(path, std::ios::binary);
	std::vector<uint8_t> buf((std::istreambuf_iterator<char>(file)),
		std::istreambuf_iterator<char>());
	file.close();

	auto scan = std::search(buf.begin(), buf.end(), std::begin(pat), std::end(pat));
	if (scan == buf.end()) {
		printf("[-] pattern scan failed\n");
		return 1;
	}

	printf("[+] pattern found at 0x%llx\n", uint64_t(scan._Ptr - buf.data()));
	std::filesystem::copy(path, backup_path);

	memcpy(scan._Ptr, patch, sizeof(patch));
	printf("[+] patch applied\n");

	std::ofstream out(path, std::ios::binary | std::ios::out);
	out.write((char*)buf.data(), buf.size());
	out.close();
	
	printf("[+] file written\n");

	printf("[>] verifying patch\n");
	const auto lib = LoadLibraryA(path.string().c_str());

	using verify_license_t = uint64_t(*)(void*);
	const auto verify_license_fn = reinterpret_cast<verify_license_t>(GetProcAddress(lib, (char*)102));

	uint64_t test = 0;
	const auto res = verify_license_fn(&test);

	if (res && test) {
		printf("[+] patch verified working\n");
		return 0;
	}
	else {
		printf("[-] something went wrong...\n");
		return 1;
	}

	return 0;
}

int main(int argc, char* argv[]) {
	const auto ret = run_patcher(argc, argv);
	getchar();

	return ret;
}