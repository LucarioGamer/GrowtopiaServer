/**********************************************************************************
	First Growtopia Private Server made with ENet.
	Copyright (C) 2018  Growtopia Noobs
	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU Affero General Public License as published
	by the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.
	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU Affero General Public License for more details.
	You should have received a copy of the GNU Affero General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
**********************************************************************************/

#pragma region Includes
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <cstdint>
#include <cstring>
#include <vector>
#include <stdint.h>
#include <string>
#include <fstream>
#include <utility>
#include <sstream>
#include <limits.h>
#pragma warning(disable:4996)
#ifndef _UNISTD_H
#define _UNISTD_H    1
#include <stdlib.h>
#include <io.h>
#include <process.h>
#include <direct.h>
#define srandom srand
#define random rand
#define R_OK    4    
#define W_OK    2  
#define F_OK    0 
#define access _access
#define dup2 _dup2
#define execve _execve
#define ftruncate _chsize
#define unlink _unlink
#define fileno _fileno
#define getcwd _getcwd
#define chdir _chdir
#define isatty _isatty
#define lseek _lseek
#ifdef _WIN64
#define ssize_t __int64
#else
#define ssize_t long
#endif
#define STDIN_FILENO 0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2
typedef __int16           int16_t;
typedef __int32           int32_t;
typedef __int64           int64_t;
typedef unsigned __int8   uint8_t;
typedef unsigned __int16  uint16_t;
typedef unsigned __int32  uint32_t;
typedef unsigned __int64  uint64_t;

#endif _UNISTD_H


using namespace std;

#pragma endregion
/*
=* Growtopia Dialog Stuff *=
=* For examples, check https://github.com/GrowtopiaNoobs/GrowtopiaServer *=
*/

enum LabelStyles {
	LABEL_BIG,
	LABEL_SMALL
};

enum SpacerTypes
{
	SPACER_BIG,
	SPACER_SMALL
};

enum CheckboxTypes
{
	CHECKBOX_SELECTED,
	CHECKBOX_NOT_SELECTED
};
#pragma region Dialog stuff
/*
	Dialog api starts.
*/


class GTDialog
{
public:
	string dialogstr = "";
	void addSpacer(SpacerTypes type);
	void addLabelWithIcon(string text, int tileid, LabelStyles type);
	void addButton(string buttonname, string buttontext);
	void addCheckbox(string checkboxname, string string, CheckboxTypes type);
	void addTextBox(string str);
	void addSmallText(string str);
	void addInputBox(string name, string text, string cont, int size);
	void addQuickExit();
	void endDialog(string name, string accept, string nvm);
	void addCustom(string name);
	string finishDialog();
	
	operator string() { 
		return this->dialogstr; 
	}
};


void GTDialog::addSpacer(SpacerTypes type) {
	switch (type)
	{
	case SPACER_BIG:
		this->dialogstr.append("add_spacer|big|\n");
		break;
	case SPACER_SMALL:
		this->dialogstr.append("add_spacer|small|\n");
		break;
	default:
		break;
	}
}

void GTDialog::addLabelWithIcon(string text, int tileid, LabelStyles type) {
	switch (type)
	{
	case LABEL_BIG:
		this->dialogstr.append("add_label_with_icon|big|" + text + "|left|" + to_string(tileid) + "|\n");
		break;
	case LABEL_SMALL:
		this->dialogstr.append("add_label_with_icon|small|" + text + "|left|" + to_string(tileid) + "|\n");
		break;
	default:
		break;
	}
}

void GTDialog::addButton(string buttonname, string buttontext) {
	this->dialogstr.append("add_button|" + buttonname + "|" + buttontext + "|noflags|0|0|\n");
}

void GTDialog::addCheckbox(string checkboxname, string string, CheckboxTypes type) {
	switch (type)
	{
	case CHECKBOX_SELECTED:
		this->dialogstr.append("add_checkbox|" + checkboxname + "|" + string + "|1|\n");
		break;
	case CHECKBOX_NOT_SELECTED:
		this->dialogstr.append("add_checkbox|" + checkboxname + "|" + string + "|0|\n");
		break;
	default:
		break;
	}
}

void GTDialog::addTextBox(string str) {
	this->dialogstr.append("add_textbox|" + str + "|left|\n");
}

void GTDialog::addSmallText(string str) {
	this->dialogstr.append("add_smalltext|" + str + "|\n");
}

void GTDialog::addInputBox(string name, string text, string cont, int size) {
	this->dialogstr.append("add_text_input|" + name + "|" + text + "|" + cont + "|" + to_string(size) + "|\n");
}

void GTDialog::addQuickExit() {
	this->dialogstr.append("add_quick_exit|\n");
}

void GTDialog::endDialog(string name, string accept, string nvm) {
	this->dialogstr.append("end_dialog|" + name + "|" + nvm + "|" + accept + "|\n");
}

void GTDialog::addCustom(string name) {
	this->dialogstr.append(name + "\n");
}

string GTDialog::finishDialog() {
	return this->dialogstr;
}
#pragma endregion

#pragma region Items.Dat

/*
	Taken from Gamedeveloper magazine's InnerProduct (Sean Barrett 2005-03-15)

	Created by Seth Robinson on 3/6/09.
	(c) RTSoft. All rights reserved.
*/

/*
	Get the file size. It's for binary.
*/
std::ifstream::pos_type filesize(string filename)
{
	std::ifstream in(filename, std::ifstream::ate | std::ifstream::binary);
	return in.tellg();
}

/*
	Hash the file.
*/
uint32_t HashString(unsigned char* str, int len)
{
	if (!str) return 0;

	unsigned char* n = (unsigned char*)str;
	uint32_t acc = 0x55555555;

	if (len == 0)
	{
		while (*n)
			acc = (acc >> 27) + (acc << 5) + *n++;
	}
	else
	{
		for (int i = 0; i < len; i++)
		{
			acc = (acc >> 27) + (acc << 5) + *n++;
		}
	}
	return acc;

}

/*
	GetHash from ProtonSDK.
*/
unsigned char* getA(string fileName, int* pSizeOut, bool bAddBasePath, bool bAutoDecompress)
{
	unsigned char* pData = NULL;
	FILE* fp = fopen(fileName.c_str(), "rb");
	if (!fp)
	{
		cout << "File not found" << endl;
		if (!fp) return NULL;
	}

	fseek(fp, 0, SEEK_END);
	*pSizeOut = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	pData = (unsigned char*)new unsigned char[((*pSizeOut) + 1)];
	if (!pData)
	{
		printf("Out of memory opening %s?", fileName.c_str());
		return 0;
	}
	pData[*pSizeOut] = 0;
	fread(pData, *pSizeOut, 1, fp);
	fclose(fp);

	return pData;
}

int GetHashOf(string path) {
	uint8_t* pData;
	int size = 0;
	size = filesize(path);
	pData = getA((string)path, &size, false, false);
	return HashString((unsigned char*)pData, size);
}
#pragma endregion
