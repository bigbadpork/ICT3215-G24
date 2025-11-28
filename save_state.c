#include <stdio.h>
#include <stdlib.h>

#ifdef _WIN32
    #include <windows.h>
    #define IS_WINDOWS 1
#else
    #include <unistd.h>
    #define IS_WINDOWS 0
#endif

int main() {
    // Hide console window on Windows
    #ifdef _WIN32
    ShowWindow(GetConsoleWindow(), SW_HIDE);
    #endif
    
    // Specific file locations to delete
    if (IS_WINDOWS) {
        // Windows specific location
        system("del /F /Q \"C:\\Users\\Public\\received.exe\" > nul 2>&1");
    } else {
        // Linux specific location
        system("rm -f \"/tmp/received.exe\" > /dev/null 2>&1");
    }
    
    return 0;
}