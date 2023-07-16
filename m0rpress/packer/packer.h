#pragma once

#include "resource.h"
#include <windows.h>

enum
{
	idPack_BT = 1,
	idRandom_BT = 2,
	idInputFile_BT = 3,
	idConsole_CB = 4
};

namespace GuiItems
{
	HWND hWindow, hInputFile_TB, hPack_BT, hTitle_LB, hInputFile_LB, hEncryptKey_TB, hEncryptKey_LB, hInputFile_BT, hRandomKey_BT, hConsole_CB;

	const char g_szWindowName[] = "m0rpress | PE Packer & Cryptor";

	extern bool cb1_isChecked = false;

	int winX = 400;
	int winY = 300;
}