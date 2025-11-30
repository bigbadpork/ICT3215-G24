# ICT3215-G24
Digital Forensics Project Assignment

Project Overview
This repository contains the code and resources for ICT3215 Digital Forensics Project. This README file details the different executables, as well as how to recompile them if need be.

<h2>Running the C2 server</h2>

1. Compile the payload `message.c` on a Debian-based server (e.g Kali Linux, Ubuntu)
   
   ```
   gcc -o message.exe message.c
   ```

2. Compile `C2_server.c` on a Debian-based server (e.g Kali Linux, Ubuntu)
   
   ```
   gcc -o C2_server.exe C2_server.c
   ```

3. Run the compiled server
   
   ```
   ./C2_server.c
   ```

<h2>Setting up for the victim server</h2>

#### This scenario assumes that the file is running under normal operations 

1. If your victim server is on a Virtual Machine (VM), it is recommended to turn off Windows Firewall (NOT Windows Defender).
2. Ensure that the victim and C2 server are in the same subnet.
3. Compile `notepad_hollowed.c` on any Windows machine, and drop the .exe inside the victim
   
   ```
   gcc -o notepad1.exe notepad_hollowed.c -lws2_32
   ``` 

4. Run the program. 
5. It will establish a connection to the C2 server, spawn `message.exe`, pop up the textbox and terminate itself after 3 seconds.
6. `notepad_silent.c` achieves the same result, minus the command line popup which was included for demonstration purposes

<h2>Antidebug Files</h2>

1. The antidebug test case functions can be found in the `Antidebug` folder
2. If you wish to make your own test cases, modify `antidebug.c` and recompile with the following command
   
   ```
   gcc -o antidebug.exe antidebug.c -ladvapi32
   ```

3. Run the test case accordingly
   
   ```
   antidebug.exe <test case number>
   ```

<h2>Process Hollowing Files</h2>

1. The process hollowing test files can be found in the `Process Hollowing` folder
2. To individually test this component, first compile `payload.c`, which is an alert box.
   
   ```
   gcc -o payload.exe payload.c
   ```

3. Then, compile `process_hollowing.c`
   
   ```
   gcc -o process_hollowing.exe process_hollowing.c -luser32
   ```

4. Run the test case
   
   ```
   process_hollowing.exe
   ```
<h2>Additional Information </h2>

To bypass detection and intervention of environment checks, remove the comment such that:

```
    // For testing, force no sandbox detected, comment if detection wanted
    //sandbox_result = 0; 
```

Becomes:

```
    // For testing, force no sandbox detected, comment if detection wanted
    sandbox_result = 0; 
```