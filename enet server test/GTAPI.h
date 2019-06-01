#include <string>
#include <iostream>
using namespace std;
/*
=* Growtopia Dialog Stuff *=
=* For examples, check https://github.com/GrowtopiaNoobs/GrowtopiaServer *=
*/
#pragma region Dialog stuff

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

struct GTDialog
{
	string dialogstr = "set_default_color|`o";
};

void addSpacer(GTDialog* dialog, SpacerTypes type) {
	switch (type)
	{
	case SPACER_BIG:
		((GTDialog*)(dialog))->dialogstr.append("\nadd_spacer|big|");
		break;
	case SPACER_SMALL:
		((GTDialog*)(dialog))->dialogstr.append("\nadd_spacer|small|");
		break;
	default:
		break;
	}
}

void addLabelWithIcon(GTDialog* dialog, string text, int tileid, LabelStyles type) {
	switch (type)
	{
	case LABEL_BIG:
		((GTDialog*)(dialog))->dialogstr.append("\nadd_label_with_icon|big|" + text + "|left|" + to_string(tileid) + "|");
		break;
	case LABEL_SMALL:
		((GTDialog*)(dialog))->dialogstr.append("\nadd_label_with_icon|small|" + text + "|left|" + to_string(tileid) + "|");
		break;
	default:
		break;
	}
}

void addButton(GTDialog* dialog, string buttonname, string buttontext) {
	((GTDialog*)(dialog))->dialogstr.append("\nadd_button|" + buttonname + "|" + buttontext + "|noflags|0|0|");
}

void addCheckbox(GTDialog* dialog, string checkboxname, string string, CheckboxTypes type) {
	switch (type)
	{
	case CHECKBOX_SELECTED:
		((GTDialog*)(dialog))->dialogstr.append("\nadd_checkbox|" + checkboxname + "|" + string + "|1|");
		break;
	case CHECKBOX_NOT_SELECTED:
		((GTDialog*)(dialog))->dialogstr.append("\nadd_checkbox|" + checkboxname + "|" + string + "|0|");
		break;
	default:
		break;
	}
}

void addLabel(GTDialog* dialog, string str) {
	((GTDialog*)(dialog))->dialogstr.append("\nadd_textbox|" + str + "|left|");
}

void addSmallText(GTDialog* dialog, string str) {
	((GTDialog*)(dialog))->dialogstr.append("\nadd_smalltext|" + str + "|");
}

void addInputBox(GTDialog* dialog, string name, string text, string cont, int size) {
	((GTDialog*)(dialog))->dialogstr.append("\nadd_text_input|" + name + "|" + text + "|" + cont + "|" + to_string(size) + "|");
}

void addQuickExit(GTDialog* dialog) {
	((GTDialog*)(dialog))->dialogstr.append("\nadd_quick_exit|");
}

void endDialog(GTDialog* dialog, string name, string accept, string nvm) {
	((GTDialog*)(dialog))->dialogstr.append("\nend_dialog|" + name + "|" + nvm + "|" + accept + "|");
}

void addCustom(GTDialog* dialog, string name) {
	((GTDialog*)(dialog))->dialogstr.append("\n" + name);
}

string finishDialog(GTDialog* dialog) {
	return ((GTDialog*)(dialog))->dialogstr;
}
#pragma endregion
