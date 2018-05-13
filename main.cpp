#define  _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <vector>
#include <windows.h>
#include <TlHelp32.h>  
#include <tchar.h>
#include <Iphlpapi.h>
#include <Mprapi.h>  
#include <fstream>
#pragma comment(lib,"Iphlpapi.lib")
#pragma comment(lib, "Mprapi.lib")  

//��ȡIP��ַ��Ϣ  


std::vector<std::pair<std::string, std::string>> g_AdapteNames;

void GetIpAddrsInfo()
{
	PIP_ADAPTER_INFO pIpAdapterInfo = new IP_ADAPTER_INFO();
	ULONG stSize = sizeof(IP_ADAPTER_INFO);
	int nRel = GetAdaptersInfo(pIpAdapterInfo, &stSize);    //������С  

	if (ERROR_BUFFER_OVERFLOW == nRel)                      //������������Ҫ�Ŀռ�  
	{
		delete pIpAdapterInfo;
		pIpAdapterInfo = (PIP_ADAPTER_INFO) new BYTE[stSize];
		nRel = GetAdaptersInfo(pIpAdapterInfo, &stSize);
	}


	if (ERROR_SUCCESS == nRel)                              //��ȡ��Ϣ�ɹ�  
	{
		while (pIpAdapterInfo)                          //��ȡ��������  
		{
			g_AdapteNames.push_back(std::make_pair(pIpAdapterInfo->AdapterName, pIpAdapterInfo->Description));
			pIpAdapterInfo = pIpAdapterInfo->Next;
		}
	}
}

DWORD traverseProcesses(std::wstring processName)
{
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(pe32);

	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE) {
		std::cout << "CreateToolhelp32Snapshot Error!" << std::endl;;
		return false;
	}

	BOOL bResult = Process32First(hProcessSnap, &pe32);

	int num(0);

	while (bResult)
	{
		std::wstring name = pe32.szExeFile;
		if (name.find(processName))
		{
			return pe32.th32ProcessID;
		}
		int id = pe32.th32ProcessID;
		bResult = Process32Next(hProcessSnap, &pe32);
	}

	CloseHandle(hProcessSnap);

	return 0;
}

BOOL PatchFile(std::string & filePath, const char * oldPatch, const char * newPatch)
{
	HANDLE file = ::CreateFileA(filePath.c_str(), GENERIC_ALL, FILE_SHARE_WRITE |
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (INVALID_HANDLE_VALUE == file){
		printf("open %s,error:%d.", filePath.c_str(), GetLastError());
		return FALSE;
	}
	IMAGE_DOS_HEADER DosHeader = { 0 };
	IMAGE_FILE_HEADER FileHeader = { 0 };
	IMAGE_SECTION_HEADER *pSecHeader = NULL;
	DWORD dwReadLen = 0;
	DWORD NumOfSec;
	DWORD startAddress = 0;
	DWORD sectionSize = 0;
	//��ȡ����
	if (!ReadFile(file, &DosHeader, sizeof(DosHeader), &dwReadLen, NULL))
	{
		MessageBoxA(NULL,("�޷���ȡ�ļ�������ʧ�ܣ�"),"",0);
		return FALSE;
	}
	SetFilePointer(file, DosHeader.e_lfanew + sizeof(IMAGE_NT_SIGNATURE), NULL, FILE_BEGIN);
	ReadFile(file, &FileHeader, sizeof(FileHeader), &dwReadLen, NULL);
	NumOfSec = FileHeader.NumberOfSections;
	DWORD SectionSize = NumOfSec * IMAGE_SIZEOF_SECTION_HEADER;
	char *pSecBuff = new char[SectionSize + 1];

	SetFilePointer(file, FileHeader.SizeOfOptionalHeader, NULL, FILE_CURRENT);
	ReadFile(file, pSecBuff, SectionSize, &dwReadLen, NULL);
	char szSecName[IMAGE_SIZEOF_SHORT_NAME] = { 0 };
	pSecHeader = (PIMAGE_SECTION_HEADER)pSecBuff;
	for (int i = 0; i < NumOfSec; i++)
	{
		memcpy(szSecName, pSecHeader->Name, 8);
		//printf("%s\n", szSecName);

		//��ʾVirtualAddress��VirtualSize
		//printf(("%08X\n"), pSecHeader->VirtualAddress);
		//printf(("%08X\n"), pSecHeader->Misc.VirtualSize);
		if (!strcmp(szSecName, ".text"))
		{
			startAddress = pSecHeader->VirtualAddress;
			SectionSize = pSecHeader->Misc.VirtualSize;
			break;
		}
	}
	SetFilePointer(file, startAddress, NULL, FILE_BEGIN);
	const int maxReadByte = 1;
	char ReadBuff[maxReadByte];
	DWORD dwBytesRead = 0;
	int count = 0;
	int totalNUn = 0;
	bool isPushFlag = false;
	DWORD dwWriteByte = 0;
	while (SectionSize--){
		memset(&ReadBuff, 0x0, maxReadByte);
		ReadFile(file, ReadBuff, maxReadByte, &dwBytesRead, NULL);
		if (!isPushFlag &&
			ReadBuff[0] == 0x68)
		{
			isPushFlag = true;
			continue;
		}
		if (isPushFlag)
		{
			if (ReadBuff[0] == oldPatch[0])
			{
				count++;
			}
			else
			{
				count = 0;
				isPushFlag = false;
				continue;
			}
			if (count == 4)
			{
				//printf("find");
				//auto address = SetFilePointer(file, 0, NULL, FILE_CURRENT);
				//printf("%02x\n", address);
				count = 0;
				totalNUn++;
				isPushFlag = false;
				SetFilePointer(file, -4, NULL, FILE_CURRENT);
				if (!WriteFile(file, newPatch, 1, &dwBytesRead, NULL))
				{
					return FALSE;
				}

			}
		}
		
		if (!dwBytesRead)
			break;
	}
	//printf("%d\n", totalNUn);
	return TRUE;
}
void SelectNetCard(int & index)
{
	auto iter = g_AdapteNames.begin();
	int i = 1;
	for (; iter != g_AdapteNames.end(); ++iter)
	{
		std::cout << i << "." << iter->second.c_str() << std::endl;
		++i;
	}
	std::cout << "ѡ�����޸ĵ�mac������:";
	std::cin >> index;
}

char* ConvertLPWSTRToLPSTR(LPWSTR lpwszStrIn)
{
	LPSTR pszOut = NULL;
	if (lpwszStrIn != NULL)
	{
		int nInputStrLen = wcslen(lpwszStrIn);
		// Double NULL Termination
		int nOutputStrLen = WideCharToMultiByte(CP_ACP, 0, lpwszStrIn, nInputStrLen, NULL, 0, 0, 0) + 2;
		pszOut = new char[nOutputStrLen];
		if (pszOut)
		{
			memset(pszOut, 0x00, nOutputStrLen);
			WideCharToMultiByte(CP_ACP, 0, lpwszStrIn, nInputStrLen, pszOut, nOutputStrLen, 0, 0);
		}
	}
	return pszOut;
}

void GetConnectNames()
{
	/*******************************************
	*ͨ��mprapi���ȡ��������
	*��ͨ��index��������Ϣ���������������
	********************************************/
	HANDLE   hMprConfig;                    //������Ϣ�ľ��  
	DWORD   dwRet = 0;                        //����ֵ  
	PIP_INTERFACE_INFO   plfTable = NULL;   //�ӿ���Ϣ��  
	DWORD   dwBufferSize = 0;                 //�ӿ���Ϣ��ռ��С  


	dwRet = MprConfigServerConnect(NULL, &hMprConfig);  //��þ��  
	dwRet = GetInterfaceInfo(NULL, &dwBufferSize);      //��ýӿ���Ϣ���С  

	if (dwRet == ERROR_INSUFFICIENT_BUFFER)              //��ýӿ���Ϣ  
	{
		plfTable = (PIP_INTERFACE_INFO)HeapAlloc(GetProcessHeap(),
			HEAP_ZERO_MEMORY, dwBufferSize);
		GetInterfaceInfo(plfTable, &dwBufferSize);
	}


	TCHAR   szFriendName[256];                   //�ӿ�����  
	DWORD   tchSize = sizeof(TCHAR)* 256;
	ZeroMemory(&szFriendName, tchSize);

	for (UINT i = 0; i < plfTable->NumAdapters; i++)
	{
		IP_ADAPTER_INDEX_MAP   AdaptMap;         //�ӿ���Ϣ  
		AdaptMap = plfTable->Adapter[i];
	    auto adapteId = plfTable->Adapter->Name;
		char * assicAdapteId = ConvertLPWSTRToLPSTR(adapteId);
		std::string AdapteIdStr(assicAdapteId);
		delete[] assicAdapteId;
		

		dwRet = MprConfigGetFriendlyName(hMprConfig, AdaptMap.Name,
			(PWCHAR)szFriendName, tchSize);      //�����������unicode   
		char * assicName = ConvertLPWSTRToLPSTR(szFriendName);
		std::string FriendName(assicName);
		//std::cout << FriendName.c_str() << std::endl;
		delete[] assicName;
		auto iter = g_AdapteNames.begin();
		for (; iter != g_AdapteNames.end(); ++iter)
		{
			if (AdapteIdStr.find(iter->first)!= std::string::npos)
			{
				iter->first = FriendName;
				return;
			}
		}

	}
	HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, plfTable);
}


bool ChangeNetCardOfMacAddress(const int & index,std::string & macAddress)
{

	HKEY hKey, hSubKey, hNdiIntKey;
	if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
		"System\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}",
		0,
		KEY_ALL_ACCESS,
		&hKey) != ERROR_SUCCESS)
		return FALSE;

	DWORD dwIndex = 0;
	DWORD dwBufSize = 256;
	DWORD dwDataType;
	char szSubKey[256];
	 unsigned char szData[256];
	std::string findDescStr = g_AdapteNames[index-1].second;
	std::string findFirendStr = g_AdapteNames[index - 1].first;
	while (RegEnumKeyExA(hKey, dwIndex++, szSubKey, &dwBufSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
	{
		if (RegOpenKeyExA(hKey, szSubKey, 0, KEY_ALL_ACCESS, &hSubKey) == ERROR_SUCCESS)
		{
			if (RegOpenKeyExA(hSubKey, "Ndi\\Interfaces", 0, KEY_ALL_ACCESS, &hNdiIntKey) == ERROR_SUCCESS)
			{
				dwBufSize = 256;
				if (RegQueryValueExA(hNdiIntKey, "LowerRange", 0, &dwDataType, szData, &dwBufSize) == ERROR_SUCCESS)
				{
					if (strcmp((char*)szData, "ethernet") == 0)      //  �ж��ǲ�����̫����  
					{
						dwBufSize = 256;
						if (RegQueryValueExA(hSubKey, "DriverDesc", 0, &dwDataType, szData, &dwBufSize) == ERROR_SUCCESS)
						{
							
							if (!findDescStr.find((const char*)szData))
							{
								auto ret = RegSetValueExA(hSubKey, "NetworkAddress", 0, REG_SZ, (unsigned char*)macAddress.c_str(), macAddress.length());
								if (ret == ERROR_SUCCESS)
								{
									std::string disableStrCmd("netsh interface set interface \"");
									disableStrCmd += findFirendStr;
									disableStrCmd += "\" DISABLED";
									::system(disableStrCmd.c_str());
									std::string enableStrCmd("netsh interface set interface \"");
									enableStrCmd += findFirendStr;
									enableStrCmd += "\" enable";
									::system(enableStrCmd.c_str());
									return TRUE;
								}
								std::cout << "ʧ��:" << GetLastError() << ret << std::endl;
								
							}
							std::cout << szData << std::endl;
							// szData �б�����������ϸ����  
							dwBufSize = 256;
							if (RegQueryValueExA(hSubKey, "NetCfgInstanceID", 0, &dwDataType, szData, &dwBufSize) == ERROR_SUCCESS)
							{
								// szData �б�������������  
							}
							
						}
					}
				}
				RegCloseKey(hNdiIntKey);
			}
			RegCloseKey(hSubKey);
		}

		dwBufSize = 256;
	}   /* end of while */

	RegCloseKey(hKey);

	return 0;
}

bool  GetConfigData(std::string & data)
{
	std::fstream hFile("config.txt");
	if (!hFile.is_open())
	{
		std::fstream hFile("config.txt", std::ios::out);
		if (hFile)
			hFile.close();
		return false;
	}
	char fileBuf[MAX_PATH] = { 0 };
	hFile.getline(fileBuf, MAX_PATH - 1);
	data = fileBuf;
	hFile.close();
	return true;
}

bool GetRuijiePath(std::string & path)
{
	HKEY hKey, hSubKey, hNdiIntKey;

	DWORD dwIndex = 0;
	DWORD dwBufSize = 256;
	DWORD dwDataType;
	unsigned char szData[256];
	auto tet = GetLastError();
	if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
		"SOFTWARE\\�������\\Ruijie Supplicant",
		0,
		KEY_READ,
		&hKey) != ERROR_SUCCESS)
		return FALSE;
	if (RegQueryValueExA(hKey, "Path", 0, &dwDataType, szData, &dwBufSize) == ERROR_SUCCESS)
	{
		path = (char*)szData;
		path += "\\8021x.exe";
		//MessageBoxA(NULL, path.c_str(), "", 0);
		return true;
	}
	return false;
}

int main(int argc, char **argv)
{
	std::string macAdddress;
	std::string fileName;
	if (!GetConfigData(macAdddress) || macAdddress.empty())
	{
		MessageBoxA(NULL, "δ����mac,������ִ�б�����", "", 0);
		return 0;
	}
	if (!GetRuijiePath(fileName)||
		fileName.empty())
	{
		MessageBoxA(NULL, "���δ��װ", "", 0);
		return 0;
	}
	
	GetIpAddrsInfo();
	GetConnectNames();
	if (g_AdapteNames.empty())
	{
		MessageBoxA(NULL, "û�в��ҵ���Ҫ�޸ĵ�����", "", 0);
		return 0;
	}
	int selectIndex = 0;
	if (g_AdapteNames.size() == 1)
	{
		selectIndex = 1;
	}
	else
	{
		SelectNetCard(selectIndex);
	}
	
	if (selectIndex <= 0 || selectIndex > g_AdapteNames.size()){
		std::cout << "������Χ." << std::endl;
		return 0;
	}
	ChangeNetCardOfMacAddress(selectIndex, macAdddress);
	std::wstring findProcessName = _T("8021x.exe");
	int processId = traverseProcesses(findProcessName);
	if (processId)
	{
		MessageBoxA(NULL, "���ȹر���ݿͻ�����ִ�б�����", "��ʾ", 0);
		return processId;
	}
	const char old[] = { 1, 1, 1, 1 };
	const char newstr[] = { 2 };
	PatchFile(fileName, old, newstr);
	MessageBoxA(NULL, "�޸ĳɹ�", "", 0);
	return 0;

}