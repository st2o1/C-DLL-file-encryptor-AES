#include <iostream>
#include <limits>
#include <string>

#include <dlfcn.h>  // use this for Linux/macOS
// #include <windows.h> // << IMPORTANT . use this for Windows 


/* .. JUST SOME TESTS IGNORE IF YOU DONT 
// helpers =-=-=-=-=-=-=-=-=-=-=-=-= helpers //
bool _readBool() {
    int input;
    while (true) {
        std::cout << "Enter 0 for decrypt or 1 for encrypt: ";
        std::cin >> input;
        if (std::cin.fail()) {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::cout << "Invalid input. Please enter 0 or 1." << std::endl;
            continue;
        }
        if (input == 0 || input == 1) {
            return static_cast<bool>(input); // return true for 1, false for 0
        } else {
            std::cout << "Invalid input. Please enter 0 or 1." << std::endl;
        }
    }
}

// basic code to read the input line in C++

const char* readLine() {
    static std::string line;
    std::getline(std::cin, line);
    return line.c_str();
}*/

int main() {
    #ifdef _WIN32
    HINSTANCE hDLL = LoadLibrary("filecrypt.dll");
    #else
    void* hDLL = dlopen("./filecrypt.dll", RTLD_LAZY);
    #endif

    if (!hDLL) {
        std::cerr << "Err loading DLL\n";
        return 1;
    }

    typedef int (*EncryptFunc)(const char*, const char*);
    typedef int (*DecryptFunc)(const char*, const char*);

    #ifdef _WIN32
    EncryptFunc Encrypt = (EncryptFunc)GetProcAddress(hDLL, "Encrypt");
    DecryptFunc Decrypt = (DecryptFunc)GetProcAddress(hDLL, "Decrypt");
    #else
    EncryptFunc Encrypt = (EncryptFunc)dlsym(hDLL, "Encrypt");
    DecryptFunc Decrypt = (DecryptFunc)dlsym(hDLL, "Decrypt");
    #endif

    if (!Encrypt || !Decrypt) {
        std::cerr << "Err finding func in DLL\n";
        #ifdef _WIN32
        FreeLibrary(hDLL);
        #else
        dlclose(hDLL);
        #endif
        return 1;
    }

/* THIS CODE DOES NOT WORK, DOESN'T MATTER
 // just asking (qu)estion to encrypt(1) or decrypt(0) a file
    bool qu = _readBool();
    std::cout << "Type file name:" << std::endl;
    const char* file_path = readLine();

    std::cout << "Type password:" << std::endl;
    const char* password = readLine();
*/
    bool qu = true; // true to encrypt. false to decrypt
    const char* file_path = "testfile";
    const char* password = "hello";
    if (qu) {
        if (Encrypt(file_path, password) == 0) {
            std::cout << "File encrypted successfully.\n";
        }
        else {
            std::cerr << "Encryption failed.\n";
        }
    }
    else {
        if (Decrypt(file_path, password) == 0) {
            std::cout << "File decrypted successfully.\n";
        } else {
            std::cerr << "Decryption failed.\n";
        }
    }

    #ifdef _WIN32
    FreeLibrary(hDLL);
    #else
    dlclose(hDLL);
    #endif

    return 0;
}


