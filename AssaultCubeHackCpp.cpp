#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <tchar.h>
#include <vector>

using namespace std;

DWORD GetModuleBaseAddress(TCHAR* lpszModuleName, DWORD pID) {
    DWORD dwModuleBaseAddress = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pID); // make snapshot of all modules within process
    MODULEENTRY32 ModuleEntry32 = { 0 };
    ModuleEntry32.dwSize = sizeof(MODULEENTRY32);

    if (Module32First(hSnapshot, &ModuleEntry32)) //store first Module in ModuleEntry32
    {
        do {
            if (_tcscmp(ModuleEntry32.szModule, lpszModuleName) == 0) // if Found Module matches Module we look for -> done!
            {
                dwModuleBaseAddress = (DWORD)ModuleEntry32.modBaseAddr;
                break;
            }
        } while (Module32Next(hSnapshot, &ModuleEntry32)); // go through Module entries in Snapshot and store in ModuleEntry32


    }
    CloseHandle(hSnapshot);
    return dwModuleBaseAddress;
}

DWORD GetPointerAddress(HWND hwnd, DWORD gameBaseAddr, DWORD address, vector<DWORD> offsets)
{
    DWORD pID = NULL; // Game process ID
    GetWindowThreadProcessId(hwnd, &pID);
    HANDLE phandle = NULL;
    phandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pID);
    if (phandle == INVALID_HANDLE_VALUE || phandle == NULL);

    DWORD offset_null = NULL;
    ReadProcessMemory(phandle, (LPVOID*)(gameBaseAddr + address), &offset_null, sizeof(offset_null), 0);
    DWORD pointeraddress = offset_null; // the address we need
    for (int i = 0; i < offsets.size() - 1; i++) // we dont want to change the last offset value so we do -1
    {
        ReadProcessMemory(phandle, (LPVOID*)(pointeraddress + offsets.at(i)), &pointeraddress, sizeof(pointeraddress), 0);
    }
    return pointeraddress += offsets.at(offsets.size() - 1); // adding the last offset
}

int DrawText(

);

int main()
{
    HWND hwnd_AC = FindWindowA(NULL, "AssaultCube"); //getting handle 2 the window

    if (hwnd_AC != FALSE);
    DWORD pID = NULL;
    GetWindowThreadProcessId(hwnd_AC, &pID);
    HANDLE pHandle = NULL;                                                  //Process handle
    pHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pID);
    if (pHandle == INVALID_HANDLE_VALUE || pHandle == NULL);

    char gamemodule1[] = "ac_client.exe";
    DWORD gameBaseAddress1 = GetModuleBaseAddress(_T(gamemodule1), pID);    //getting module base address

    //Entity List
    DWORD EntityListAddr = 0x00187C10;
    vector<DWORD> EntityListOffsets{ 0xEC, 0xC };
    DWORD EntityListPtrAddr = GetPointerAddress(hwnd_AC, gameBaseAddress1, EntityListAddr, EntityListOffsets);

    //health
    DWORD healthAddr = 0x0017B0B8;
    vector<DWORD> healthOffsets{ 0xEC };
    DWORD healthPtrAddr = GetPointerAddress(hwnd_AC, gameBaseAddress1, healthAddr, healthOffsets);

    DWORD EntityAddr = 0x187C10;
    vector<DWORD> EntityOffsets{ 0xEC, 0x4 };
    DWORD EntityPtrAddr = GetPointerAddress(hwnd_AC, gameBaseAddress1, EntityAddr, EntityOffsets);
    
    DWORD playXAddr = 0x0017B0B8;
    vector<DWORD> PlayXOffsets{ 0x2C };
    DWORD playXPtrAddr = GetPointerAddress(hwnd_AC, gameBaseAddress1, playXAddr, PlayXOffsets);

    DWORD playYAddr = 0x0017B0B8;
    vector<DWORD> PlayYOffsets{ 0x30 };
    DWORD playYPtrAddr = GetPointerAddress(hwnd_AC, gameBaseAddress1, playYAddr, PlayYOffsets);

    DWORD playZAddr = 0x0017B0B8;
    vector<DWORD> PlayZOffsets{ 0x28 };
    DWORD playZPtrAddr = GetPointerAddress(hwnd_AC, gameBaseAddress1, playZAddr, PlayZOffsets);

    //Writing Memory
    while (true)
    {

        //Change
        int healthChng = 420;
        int enthealthChng = 0;

        //Results
        int healthResult;
        int healthResult2;
        int ammoResult;
        float entXpos;
        float entYpos;
        float entZpos;
        float playXpos;
        float playYpos;
        float playZpos;
        int Offset1;
        int EntOffset;
        int counter = 0;
        int selectedEnt;
        int entTP;
        bool entExists = false;
        char entTPName[12];

        char nameResult2[12];
        char nameTPResult[12];


        //Reading Memory
        ReadProcessMemory(pHandle, (LPVOID*)(healthPtrAddr), &healthResult, 4, 0);                      //Health
        ReadProcessMemory(pHandle, (LPVOID*)(playXPtrAddr), &playXpos, 4, 0);
        ReadProcessMemory(pHandle, (LPVOID*)(playYPtrAddr), &playYpos, 4, 0);
        ReadProcessMemory(pHandle, (LPVOID*)(playZPtrAddr), &playZpos, 4, 0);

        //Writing Memory
        WriteProcessMemory(pHandle, (LPVOID*)(healthPtrAddr), &healthChng, 4, 0);                       //Health


        ReadProcessMemory(pHandle, (LPVOID*)(0x400000 + EntityAddr), &Offset1, 4, NULL);

        for (int i = 4; i < 16; i+=4) {

            //Read
            ReadProcessMemory(pHandle, (LPVOID*)(Offset1 + i), &EntOffset, 4, NULL);
            ReadProcessMemory(pHandle, (LPVOID*)(EntOffset + 0xEC), &healthResult2, 4, 0);
            ReadProcessMemory(pHandle, (LPVOID*)(EntOffset + 0x140), &ammoResult, 4, 0);
            ReadProcessMemory(pHandle, (LPVOID*)(EntOffset + 0x2C), &entXpos, 4, 0);
            ReadProcessMemory(pHandle, (LPVOID*)(EntOffset + 0x30), &entYpos, 4, 0);
            ReadProcessMemory(pHandle, (LPVOID*)(EntOffset + 0x28), &entZpos, 4, 0);
            ReadProcessMemory(pHandle, (LPVOID*)(EntOffset + 0x205), &nameResult2, 20, 0);

            //WriteProcessMemory(pHandle, (LPVOID*)(Offset2 + 0x2C), &playXpos, 4, 0);
            //WriteProcessMemory(pHandle, (LPVOID*)(Offset2 + 0x30), &playYpos, 4, 0);
            //WriteProcessMemory(pHandle, (LPVOID*)(Offset2 + 0x28), &playZpos, 4, 0);


            counter++;
            
            if (EntOffset == 0) {
                entExists = false;
            }
            else if(EntOffset > 0) {
                entExists = true;
            }

            if (entExists == true) {
                std::cout << "Player: " << counter << " Name: " << nameResult2 << std::endl;
                std::cout << "health is " << healthResult2 << std::endl;
                std::cout << "ammo is " << ammoResult << std::endl;
                std::cout << "X Pos: " << entXpos << std::endl;
                std::cout << "Y Pos: " << entYpos << std::endl;
                std::cout << "Z Pos: " << entZpos << std::endl;
                std::cout << "-----------------------------" << std::endl;
            }
            else {
                std::cout << "Player does not exist" << std::endl;
            }

            EntOffset = 0;
        }

        std::cout << "Your heath is " << healthResult << std::endl;
        std::cout << "X " << playXpos << std::endl;
        std::cout << "Y " << playYpos << std::endl;
        std::cout << "Z " << playZpos << std::endl;

        cout << "Type Entity Num To TP To You: ";
        cin >> selectedEnt;
        entTP = selectedEnt * 4;
        

        ReadProcessMemory(pHandle, (LPVOID*)(Offset1 + entTP), &EntOffset, 4, NULL);
        WriteProcessMemory(pHandle, (LPVOID*)(EntOffset + 0x2C), &playXpos, 4, 0);
        WriteProcessMemory(pHandle, (LPVOID*)(EntOffset + 0x30), &playYpos, 4, 0);
        WriteProcessMemory(pHandle, (LPVOID*)(EntOffset + 0x28), &playZpos, 4, 0);
        ReadProcessMemory(pHandle, (LPVOID*)(EntOffset + 0x205), &nameTPResult, 20, 0);

        std::cout << "[+] Successfully Teleported Entity : " << nameTPResult << " to your location" << std::endl;


        system("pause");
    }
}

