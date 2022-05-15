# Password-Manager-Program

Project from COMPX518 Cyber Security where we were to create a Java program which generates and stores passwords on a user’s machine and allows them to access them through storing in and reading from an encrypted file.

## Setup Instructions

1. Compile: "javac PasswordManager.java PasswordGenerator.java PasswordRetriever.java PasswordStorage.java"

2. Run the program: "java PasswordManager"

3. To use the program:

User command options will be displayed as such:

"ADD : For storing a new password for a given application name"
"GET : For retrieving a saved password for a given application name"
"DEL : For removing a saved password for a given application name"
"QUIT : For exiting the Password Manager"

To pick an option, input the corresponding command and press the enter key.

Code reads in user input and changes all letters to upper case
so ADD, Add and add will all be accepted.


During first use, the user input for

"Enter Master Password for Performing <OperationName> Operation:"

will be used to setup the initial file system and will give the following message

"masterLogin.PassStore or appPasswords.PassStore does not exist"
"Creating new setup files with given Master Password"
