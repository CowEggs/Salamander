// coweggs suspender.cpp

#include <windows.h>
#include <iostream>
#include <string>
#include <unordered_map>
#include <iomanip>
#include <sstream>

typedef NTSTATUS(WINAPI* NtSuspendProcess)(HANDLE hProcess);
typedef NTSTATUS(WINAPI* NtResumeProcess)(HANDLE hProcess);

std::string VirtualKeyCodeToString(UINT keyCode) {
    static std::unordered_map<UINT, std::string> keyMap = {
        { 0x01, "Left Mouse Button" },
        { 0x02, "Right Mouse Button" },
        { 0x04, "Middle Mouse Button" },
        { 0x05, "X1 Mouse Button" },
        { 0x06, "X2 Mouse Button" },
        { 0x08, "Backspace" },
        { 0x09, "Tab" },
        { 0x0D, "Enter" },
        { 0x10, "Shift" },
        { 0x11, "Control" },
        { 0x12, "Alt" },
        { 0x13, "Pause" },
        { 0x14, "Caps Lock" },
        { 0x1B, "Escape" },
        { 0x20, "Spacebar" },
        { 0x21, "Page Up" },
        { 0x22, "Page Down" },
        { 0x23, "End" },
        { 0x24, "Home" },
        { 0x25, "Left Arrow" },
        { 0x26, "Up Arrow" },
        { 0x27, "Right Arrow" },
        { 0x28, "Down Arrow" },
        { 0x2C, "Print Screen" },
        { 0x2D, "Insert" },
        { 0x2E, "Delete" },
        { 0x5B, "Left Windows" },
        { 0x5C, "Right Windows" },
        { 0x5D, "Applications" },
        { 0x60, "Numpad 0" },
        { 0x61, "Numpad 1" },
        { 0x62, "Numpad 2" },
        { 0x63, "Numpad 3" },
        { 0x64, "Numpad 4" },
        { 0x65, "Numpad 5" },
        { 0x66, "Numpad 6" },
        { 0x67, "Numpad 7" },
        { 0x68, "Numpad 8" },
        { 0x69, "Numpad 9" },
        { 0x70, "F1" },
        { 0x71, "F2" },
        { 0x72, "F3" },
        { 0x73, "F4" },
        { 0x74, "F5" },
        { 0x75, "F6" },
        { 0x76, "F7" },
        { 0x77, "F8" },
        { 0x78, "F9" },
        { 0x79, "F10" },
        { 0x7A, "F11" },
        { 0x7B, "F12" }
        // Add more key codes as needed
    };
    // numbers
    if (keyCode >= 0x30 && keyCode <= 0x39) {
        return std::string(1, static_cast<char>(keyCode));
    }
    // letters
    else if (keyCode >= 0x41 && keyCode <= 0x5A) {
        return std::string(1, static_cast<char>(keyCode));
    }
    // match to table
    auto it = keyMap.find(keyCode);
    if (it != keyMap.end()) {
        return it->second;
    } else {
        return "Unknown Key";
    }
}

std::string UINTToHex(unsigned int num) {
    std::ostringstream stream;
    stream << "0x" << std::setw(2) << std::setfill('0') << std::hex << num;
    return stream.str();
}

UINT WaitForKeybind(HWND ConsoleProcess)
{
    while (true) {
        // only detect keypresses when console focused
        if (ConsoleProcess == GetForegroundWindow())
        {
            // keyboard
            for (UINT keyCode = 0x01; keyCode <= 0xFE; ++keyCode) {
                if (GetAsyncKeyState(keyCode) & 0x8000) {
                    return keyCode;
                }
            }
        }

        // no crash
        Sleep(10);
    }
}

DWORD GetProcessIdFromHandle(HWND window) {
    DWORD pid;
    GetWindowThreadProcessId(window, &pid);
    return pid;
}

// spencers code
void SuspendOrResumeProcess(NtSuspendProcess pfnSuspend, NtResumeProcess pfnResume, HANDLE hProcess, bool suspend)
{
	if (suspend) {
		pfnSuspend(hProcess);
	} else {
		pfnResume(hProcess);
	}
}

std::wstring GetProcessTitle(HWND hProcess)
{
    std::wstring title(GetWindowTextLength(hProcess) + 1, L'\0');
    GetWindowTextW(hProcess, &title[0], title.size());
    return title;
}

int main() {
    bool suspend = false;
    bool held = false;
    HWND LastActiveProcess;
    HWND ConsoleProcess = GetForegroundWindow();

    // SETUP

    SetConsoleTitleA("Salamander");
    std::cout << "Press any key or mouse button to set as your keybind:\n";   
    UINT keybind = WaitForKeybind(ConsoleProcess);
    // message
    std::cout << "Keybind set to: " << VirtualKeyCodeToString(keybind) << " \"" << UINTToHex(keybind) << "\"" << std::endl;
    std::cout << "\033[38;2;249;3;140m" << R"(
  _________      .__                                    .___            
 /   _____/____  |  | _____    _____ _____    ____    __| _/___________ 
 \_____  \\__  \ |  | \__  \  /     \\__  \  /    \  / __ |/ __ \_  __ \
 /        \/ __ \|  |__/ __ \|  Y Y  \/ __ \|   |  \/ /_/ \  ___/|  | \/
/_______  (____  /____(____  /__|_|  (____  /___|  /\____ |\___  >__|   
        \/     \/          \/      \/     \/     \/      \/    \/
)" << "\033[0m" << "\n";
    std::cout << "\033[38;2;249;3;140m" << "Press " << VirtualKeyCodeToString(keybind) << " to toggle the suspension!.\033[0m\n\n";
    
    // suspend black magic
	const HMODULE hNtdll = GetModuleHandleA("ntdll");
	NtSuspendProcess pfnSuspend = reinterpret_cast<NtSuspendProcess>(GetProcAddress(hNtdll, "NtSuspendProcess"));
	NtResumeProcess pfnResume = reinterpret_cast<NtResumeProcess>(GetProcAddress(hNtdll, "NtResumeProcess"));

    // MAIN LOOP

    while (true) {
        HWND ActiveProcess = GetForegroundWindow();

        // cancel suspension conditions
        if (held)
        {
            if (LastActiveProcess != ActiveProcess)
            {
                held = false;
                std::cout << "Suspension disabled, lost focus.\n";
                suspend = false;
                SuspendOrResumeProcess(pfnSuspend, pfnResume, ActiveProcess, suspend);
            }
        }

        // side button 1 (XButton1) pressed?
        if (GetAsyncKeyState(keybind) & 0x8000) {
            if (!held)
            {
                // just pressed
                held = true;
                if (!suspend)
                {
                    if (ActiveProcess == ConsoleProcess)
                    {
                        std::cout << "Can't suspend self.\n";
                        suspend = false;
                        SuspendOrResumeProcess(pfnSuspend, pfnResume, ActiveProcess, suspend);
                    }
                    else
                    {
                        suspend = true;
                        
                        HANDLE hProcess = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, GetProcessIdFromHandle(ActiveProcess));

                        std::wcout << L"Suspension Enabled for: " + GetProcessTitle(ActiveProcess) + L"\n";
                        SuspendOrResumeProcess(pfnSuspend, pfnResume, hProcess, suspend);

                        CloseHandle(hProcess);
                    }
                }
            }
        }
        else
        { // not pressed
            suspend = false;
            if (held)
            { // just released
                held = false;
                std::cout << "Suspension Disabled\n";

                HANDLE hProcess = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, GetProcessIdFromHandle(ActiveProcess));
                SuspendOrResumeProcess(pfnSuspend, pfnResume, hProcess, suspend);

                CloseHandle(hProcess);
            }
        }

        LastActiveProcess = ActiveProcess;

        // no crash
	    Sleep(10);
    }

    return 0;
}
