#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>

int __cdecl wmain(int argc, wchar_t *argv[])
{
	HCRYPTPROV hCryptProv;
	BYTE *bData = NULL;
	BOOL bRes = CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, 0);
	DWORD le = GetLastError();
	int i, j, len = 0, num = 0;
	
	if(argc < 3 || wcslen(argv[1]) < 2)
	{
		_putws(L"Usage CSPRNG { -b | -w | -d } n");
		return 0;
	}

	if(!bRes)
	{
		wprintf_s(L"CryptAcquireContext failed: 0x%.8X\n", le);
		return -1;
	}
	
	if(L'-' == argv[1][0]) argv[1][0] = L'/';
	argv[1][1] = towupper(argv[1][1]);
	
	if(wcscmp(argv[1], L"/B") == 0)
	{
		len = 1;
	}
	else if (wcscmp(argv[1], L"/W") == 0)
	{
		len = 2;
	}
	else if (wcscmp(argv[1], L"/D") == 0)
	{
		len = 4;
	}
	else
	{
		_putws(L"Invalid size specifier (b = byte; w = word; d = dword)");
		return 0;
	}

	num = max(_wtoi(argv[2]), 1);

	bData = (BYTE *) malloc(len);		
	
	for(j = 0; j < num; j++)
	{
		CryptGenRandom(hCryptProv, len, bData);
		wprintf_s(L"0x");
		for(i = 0; i < len; i++)
		{
			wprintf_s(L"%.2X", *(bData + i) & 0xFF);
		}
		putwchar('\n');
	}

	CryptReleaseContext(hCryptProv, 0);
	free(bData);
	bData = NULL;
	return 0;
}
