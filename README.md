# ICT3215-G24
Digital Forensics Project Assignment

Project Overview

This repository contains the code and resources for the Digital Forensics Project. The project focuses on a security scenario involving attacker and victim systems, demonstrating various forensic techniques and security concepts.

Converting Files in Windows Environment:

    1. Navigate to the project directory containing Victim code (Note: Attacker will always be run in linux):
       cd path\to\project\folder

    3. Compile the C source files using GCC with Winsock library:
       gcc -o filename.exe filename.c -lws2_32

    3. Run the compiled executable:
       .\filename.exe

Converting Files in Linux Environment:

    1. Transfer the source files to your Linux system

    2. Navigate to the directory containing the source files:
       cd /destination/path

    3. Compile the C source files using GCC:
       gcc filename.c -o filename

Running the Attack:

    Step 1: Prepare Attacker Machine (Linux):
        Make sure that C2_server.c and message.c have been compiled on your Linux device:
            gcc C2_server.c -o C2_server
            gcc message.c -o message

        Run the Command & Control server:
            ./C2_server

    Step 2: Deploy Payload on Victim Machine (Windows)
        Ensure either notepad_silent.exe (without CLI messages) or notepad_embeded.exe (with CLI messages) is on your Windows device

        Run the payload on the victim machine:
            .\notepad_silent.exe
            or
            .\notepad_embeded.exe