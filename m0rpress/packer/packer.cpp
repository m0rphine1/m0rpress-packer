// WindowsProject1.cpp : Uygulamanın giriş noktasını tanımlar.
//

#include "framework.h"
#include "packer.h"
#include <Commctrl.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <commdlg.h>
#include <random>
#include "binary.h"
#include <iomanip>

using namespace GuiItems;
using namespace std;

#define MAX_LOADSTRING 100

const char g_szClassName[] = "loginClass";
HINSTANCE g_hInstance;

int GetCenterX(int sizeX);
void SetButtonFontSize(int fontSize);
const char* GenerateRandomString();
BOOL CALLBACK SetChildFont(HWND hwndChild, LPARAM lParam);

unsigned char* ReadFile(const std::string& filePath, std::streampos& fileSize);
void WriteFile(const char* filePath, unsigned char* content, std::size_t size);
void appendToFile(const char* fileName, unsigned char* data, std::size_t dataSize);
void WriteToHexOffset(const char* dosyaAdi, std::streampos offset, const char* hexVeri);

char M0rCryptByte(char plainByte, const char* inputKey, std::size_t size);
unsigned char* M0rCryptData(unsigned char* plainData, std::size_t size, const char* inputKey, std::size_t keySize);
char De_M0rCryptByte(char plainByte, const char* inputKey, std::size_t size);
unsigned char* De_M0rCryptData(unsigned char* plainData, std::size_t size, const char* inputKey, std::size_t keySize);


LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    static HBRUSH hbrush = NULL;
    switch (msg)
    {
    case WM_CREATE:
    {
        hTitle_LB = CreateWindow("STATIC", "m0rpress packer | by execnone",
            WS_CHILD | WS_VISIBLE, GetCenterX(205 / 2) - 5, 20, 205, 20,
            hwnd, NULL, g_hInstance, NULL);

        hInputFile_LB = CreateWindow("STATIC", "input file",
            WS_CHILD | WS_VISIBLE, 40, 73, 55, 20,
            hwnd, NULL, g_hInstance, NULL);

        hInputFile_TB = CreateWindow("EDIT", NULL,
            WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | WS_BORDER,
            GetCenterX(77), 70, 150, 22,
            hwnd, NULL, g_hInstance, NULL);

        hInputFile_BT = CreateWindow("BUTTON", ". . .",
            WS_CHILD | WS_VISIBLE,
            280, 70, 55, 20,
            hwnd, (HMENU)idInputFile_BT, g_hInstance, NULL);

        hEncryptKey_LB = CreateWindow("STATIC", "enc. key",
            WS_CHILD | WS_VISIBLE, 40, 123, 55, 20,
            hwnd, NULL, g_hInstance, NULL);

        hEncryptKey_TB = CreateWindow("EDIT", NULL,
            WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | WS_BORDER,
            GetCenterX(77), 120, 150, 22,
            hwnd, NULL, g_hInstance, NULL);

        hRandomKey_BT = CreateWindow("BUTTON", "Random",
            WS_CHILD | WS_VISIBLE,
            280, 120, 55, 20,
            hwnd, (HMENU)idRandom_BT, g_hInstance, NULL);

        hPack_BT = CreateWindow("BUTTON", "PACK",
            WS_CHILD | WS_VISIBLE,
            GetCenterX(50) - 2, 180, 100, 30,
            hwnd, (HMENU)idPack_BT, g_hInstance, NULL);

        HWND hVersion_LB = CreateWindow("STATIC", g_Version,
            WS_CHILD | WS_VISIBLE, 270, 187, 80, 20,
            hwnd, NULL, g_hInstance, NULL);

        hTargetArch_CMB = CreateWindow(WC_COMBOBOX, TEXT(""),
            CBS_DROPDOWNLIST | WS_CHILD | WS_VISIBLE,
            25, 185, 100, 100, hwnd, (HMENU)idCMB1, g_hInstance, NULL);

        TCHAR items[][16] = { TEXT("Win32"), TEXT("Console32")};
        for (int i = 0; i < sizeof(items) / sizeof(items[0]); i++)
        {
            SendMessage(hTargetArch_CMB, CB_ADDSTRING, 0, (LPARAM)items[i]);
        }
        SendMessage(hTargetArch_CMB, CB_SETCURSEL, (WPARAM)0, (LPARAM)0);

        LOGFONT lf;
        ZeroMemory(&lf, sizeof(LOGFONT));
        lf.lfHeight = 17;
        lf.lfWeight = FW_NORMAL;
        lstrcpy(lf.lfFaceName, "Arial");
        HFONT hFont = CreateFontIndirect(&lf);

        EnumChildWindows(hwnd, SetChildFont, (LPARAM)hFont);
        SetButtonFontSize(12);

        break;
    }
    case WM_COMMAND:
    {
        switch (LOWORD(wParam))
        {
        case idPack_BT:
        {
            char inputFile[MAX_PATH];
            GetWindowText(hInputFile_TB, inputFile, sizeof(inputFile));
            char key[MAX_LOADSTRING];
            GetWindowText(hEncryptKey_TB, key, sizeof(key));
            char outputFile[MAX_PATH] = "output.exe";

            OPENFILENAME ofn;

            ZeroMemory(&ofn, sizeof(ofn));
            ofn.lStructSize = sizeof(ofn);
            ofn.hwndOwner = NULL;
            ofn.lpstrFilter = "Executable Files (*.exe)\0*.exe\0";  // Filtre, tüm dosya tiplerini destekler
            ofn.lpstrFile = outputFile;
            ofn.nMaxFile = MAX_PATH;
            ofn.Flags = OFN_EXPLORER;

            if (!GetOpenFileName(&ofn))
            {
                break;
            }
                        
            if (strlen(key) >= 100)
            {
                MessageBox(NULL, "encryption key must be less than 100 characters", "error", MB_ICONWARNING | MB_OK);
                break;
            }

            ifstream f(inputFile);
            if (f.good()) {

                streampos size;
                unsigned char* buffer = ReadFile(inputFile, size);
                unsigned char* encryptedBuffer = M0rCryptData(buffer, size, key, strlen(key));

                WriteFile(outputFile, baseFile, sizeof(baseFile));
                appendToFile(outputFile, encryptedBuffer, size);

                std::ofstream dosya(outputFile, std::ios::binary | std::ios::in | std::ios::out);
                dosya.seekp(0x4C28);

                if (strcmp(key, "") != 0)
                    dosya.write(key, strlen(key));
                else
                    dosya.put(0x00);

                dosya.seekp(0x4C26);
                if (cmb1_index == 0)
                {
                    dosya.put(0x30);
                }
                else if (cmb1_index == 1)
                {
                    dosya.put(0x31);
                }

                dosya.close();

                char message[256];
                sprintf_s(message, "Successfully packed file to: %s", outputFile);
                MessageBox(NULL, message, "Success", MB_ICONINFORMATION | MB_OK);
            }
            else
            {
                MessageBox(NULL, "file open error", "wqe", MB_OK);
            }
            f.close();
            break;
        }
        case idInputFile_BT:
        {
            OPENFILENAME ofn;
            char fileName[MAX_PATH] = "";

            ZeroMemory(&ofn, sizeof(ofn));
            ofn.lStructSize = sizeof(ofn);
            ofn.hwndOwner = NULL;
            ofn.lpstrFilter = "Executable Files (*.exe)\0*.exe\0"; // Tüm dosya tiplerini destekleyen bir filtre
            ofn.lpstrFile = (LPSTR)fileName;
            ofn.nMaxFile = MAX_PATH;
            ofn.Flags = OFN_EXPLORER;

            if (!GetOpenFileName(&ofn)) {
                break;
            }

            SendMessage(hInputFile_TB, WM_SETTEXT, 0, (LPARAM)fileName);

            break;
        }
        case idConsole_CB:
        {
            int checkboxState = SendMessage((HWND)lParam, BM_GETCHECK, 0, 0);
            cb1_isChecked = !cb1_isChecked;
            SendMessage(hConsole_CB, BM_SETCHECK, cb1_isChecked, 0);
            break;
        }
        case idRandom_BT:
        {
            SendMessage(hEncryptKey_TB, WM_SETTEXT, 0, (LPARAM)GenerateRandomString());
            break;
        }
        case idCMB1:
        {
            if (HIWORD(wParam) == CBN_SELCHANGE)
            {
                cmb1_index = SendMessage((HWND)lParam, (UINT)CB_GETCURSEL,
                    (WPARAM)0, (LPARAM)0);
                /*
                TCHAR  ListItem[256];
                (TCHAR)SendMessage((HWND)lParam, (UINT)CB_GETLBTEXT,
                    (WPARAM)cmb1_index, (LPARAM)ListItem);
                    */
            }
            break;
        }
        }
        break;
    }
    case WM_CTLCOLORSTATIC:
    {

        HDC hdcStatic = (HDC)wParam;
        if (true) //lParam == (LPARAM)hUsername_LB || hPassword_LB
        {
            SetTextColor(hdcStatic, RGB(0, 0, 0));
            SetBkColor(hdcStatic, RGB(255, 255, 255));
            if (!hbrush)
                hbrush = CreateSolidBrush(RGB(255, 255, 255));
            return (LRESULT)hbrush;
        }
        break;
    }
    case WM_CLOSE:
        DestroyWindow(hwnd);
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    return 0;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
    LPSTR lpCmdLine, int nCmdShow)
{
    g_hInstance = hInstance;
    WNDCLASSEX wc;
    MSG Msg;

    //Step 1: Registering the Window Class
    wc.cbSize = sizeof(WNDCLASSEX);
    wc.style = 0;
    wc.lpfnWndProc = WndProc;
    wc.cbClsExtra = 0;
    wc.cbWndExtra = 0;
    wc.hInstance = hInstance;
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszMenuName = NULL;
    wc.lpszClassName = g_szClassName;
    wc.hIconSm = LoadIcon(NULL, IDI_APPLICATION);

    if (!RegisterClassEx(&wc))
    {
        MessageBox(NULL, "Window Registration Failed!", "Error!",
            MB_ICONEXCLAMATION | MB_OK);
        return 0;
    }

    int posX = (GetSystemMetrics(SM_CXSCREEN) - winX) / 2;
    int posY = (GetSystemMetrics(SM_CYSCREEN) - winY) / 2;

    hWindow = CreateWindowEx(
        WS_EX_CLIENTEDGE,
        g_szClassName,
        g_szWindowName,
        WS_OVERLAPPEDWINDOW & ~WS_MAXIMIZEBOX & ~WS_THICKFRAME,
        posX, posY, winX, winY,
        NULL, NULL, hInstance, NULL);

    if (hWindow == NULL)
    {
        MessageBox(NULL, "Window Creation Failed!", "Error!",
            MB_ICONEXCLAMATION | MB_OK);
        return 0;
    }

    HWND hwndStatus = CreateWindowEx(
        0,
        STATUSCLASSNAME,
        NULL,
        SBARS_SIZEGRIP | WS_CHILD | WS_VISIBLE,
        0, 0, 0, 0,
        hWindow,
        (HMENU)2,
        GetModuleHandle(NULL),
        NULL
    );

    LOGFONT lf;
    ZeroMemory(&lf, sizeof(LOGFONT));
    lf.lfHeight = 20; // Yükseklik
    lf.lfWeight = FW_NORMAL; // Kalınlık
    lstrcpy(lf.lfFaceName, "Arial"); // Yazı tipi adı

    HFONT hFont = CreateFontIndirect(&lf);
    SendMessage(hWindow, WM_SETFONT, (WPARAM)hFont, TRUE);

    ShowWindow(hWindow, nCmdShow);
    UpdateWindow(hWindow);

    // Step 3: The Message Loop
    while (GetMessage(&Msg, NULL, 0, 0) > 0)
    {
        TranslateMessage(&Msg);
        DispatchMessage(&Msg);
    }
    return Msg.wParam;
}

int GetCenterX(int sizeX)
{
    return ((GuiItems::winX / 2) - sizeX) - 7;
}

char M0rCryptByte(char plainByte, const char* inputKey, std::size_t size)
{
    for (std::size_t i = 0; i < size; i++)
    {
        if (i % 2 == 0)
        {
            plainByte += static_cast<int>(inputKey[i]);
        }
        else
        {
            plainByte -= static_cast<int>(inputKey[i]);
        }
    }

    return plainByte;
}

unsigned char* M0rCryptData(unsigned char* plainData, std::size_t size, const char* inputKey, std::size_t keySize)
{
    unsigned char* encryptedData = new unsigned char[size];
    std::memcpy(encryptedData, plainData, size);

    for (std::size_t i = 0; i < size; i++)
    {
        encryptedData[i] = M0rCryptByte(encryptedData[i], inputKey, keySize);
    }

    return encryptedData;
}

char De_M0rCryptByte(char plainByte, const char* inputKey, std::size_t size)
{
    for (std::size_t i = 0; i < size; i++)
    {
        if (i % 2 == 0)
        {
            plainByte -= static_cast<int>(inputKey[i]);
        }
        else
        {
            plainByte += static_cast<int>(inputKey[i]);
        }
    }

    return plainByte;
}

unsigned char* De_M0rCryptData(unsigned char* encryptedData, std::size_t size, const char* inputKey, std::size_t keySize)
{
    unsigned char* decryptedData = new unsigned char[size];
    std::memcpy(decryptedData, encryptedData, size);

    for (std::size_t i = 0; i < size; i++)
    {
        decryptedData[i] = De_M0rCryptByte(decryptedData[i], inputKey, keySize);
    }

    return decryptedData;
}

unsigned char* ReadFile(const std::string& filePath, std::streampos& fileSize)
{
    std::ifstream file(filePath, std::ios::binary | std::ios::ate);

    if (!file)
    {
        return nullptr;
    }

    fileSize = file.tellg(); // Dosya boyutunu al

    unsigned char* fileContent = new unsigned char[fileSize]; // Dosya boyutu kadar bellek tahsis et

    file.seekg(0, std::ios::beg); // Dosyanın başına git
    file.read(reinterpret_cast<char*>(fileContent), fileSize); // Dosya içeriğini oku

    return fileContent;
}

void WriteFile(const char* filePath, unsigned char* content, std::size_t size)
{
    std::ofstream file(filePath, std::ios::binary);

    if (!file)
    {
        return;
    }

    file.write(reinterpret_cast<const char*>(content), size);
}

void appendToFile(const char* fileName, unsigned char* data, std::size_t dataSize)
{
    std::ifstream ifs(fileName, std::ios::binary); // Dosyayı binary modunda okuma

    if (!ifs) {
        std::cout << "Dosyayı açarken bir hata oluştu." << std::endl;
        return;
    }

    // Dosyanın mevcut verilerini belleğe oku
    std::vector<unsigned char> fileData(std::istreambuf_iterator<char>(ifs), {});

    ifs.close(); // Dosyayı kapat

    std::ofstream ofs(fileName, std::ios::binary | std::ios::trunc); // Dosyayı binary modunda aç ve içeriğini temizle

    if (!ofs) {
        std::cout << "Dosyayı açarken bir hata oluştu." << std::endl;
        return;
    }

    // Belleğe alınmış verileri dosyanın başından yaz
    ofs.write(reinterpret_cast<const char*>(fileData.data()), fileData.size());

    // Yeni veriyi dosyanın sonuna ekle
    ofs.write(reinterpret_cast<const char*>(data), dataSize);

    ofs.close(); // Dosyayı kapat
    std::cout << "Dosyaya yazma tamamlandı." << std::endl;
}

void SetButtonFontSize(int fontSize)
{
    HFONT hFont = (HFONT)SendMessage(hRandomKey_BT, WM_GETFONT, 0, 0);

    LOGFONT lf;
    GetObject(hFont, sizeof(LOGFONT), &lf);

    lf.lfHeight = -fontSize;

    HFONT newFont = CreateFontIndirect(&lf);
    SendMessage(hRandomKey_BT, WM_SETFONT, (WPARAM)newFont, MAKELPARAM(TRUE, 0));
}

const char* GenerateRandomString()
{
    static const char characters[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    static const int length = sizeof(characters) - 1;
    static std::mt19937 generator(time(0));
    static std::uniform_int_distribution<> distribution(0, length - 1);

    static char result[17];
    for (int i = 0; i < 16; i++) {
        result[i] = characters[distribution(generator)];
    }
    result[16] = '\0';

    return result;
}

void WriteToHexOffset(const char* dosyaAdi, std::streampos offset, const char* hexVeri)
{
    
}

BOOL CALLBACK SetChildFont(HWND hwndChild, LPARAM lParam)
{
    HFONT hFont = (HFONT)lParam;
    SendMessage(hwndChild, WM_SETFONT, (WPARAM)hFont, TRUE);
    return TRUE;
}
