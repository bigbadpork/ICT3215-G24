#include <windows.h>

// Simple payload that displays a message box
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, 
                   LPSTR lpCmdLine, int nCmdShow) {
    
    MessageBoxA(NULL, 
                "This is a demonstration payload for educational purposes.\n\n"
                "Process Hollowing Technique Detected!\n\n"
                "In a real forensics scenario, this would be malicious code.",
                "Digital Forensics - Process Hollowing Demo",
                MB_OK | MB_ICONINFORMATION);
    
    return 0;
}

// Alternative: Console version
/*
int main() {
    MessageBoxA(NULL, 
                "Process Hollowing Demo - Educational Payload",
                "Digital Forensics Project",
                MB_OK | MB_ICONINFORMATION);
    return 0;
}
*/