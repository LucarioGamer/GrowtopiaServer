# Setup HTTP Server

Dependencies are:
- VPS or Your Machine
- XAMPP or nginx - this tutorial is for XAMPP (Apache)

Download XAMPP here: [Click here to download XAMPP](https://www.apachefriends.org/xampp-files/7.4.6/xampp-windows-x64-7.4.6-0-VC15-installer.exe)

**NOTE**: You can also use Linux to host web server.

## Steps:
1. Locate path `C:\xampp\htdocs\`

2. Create new folder called `Growtopia`

3. Make file called `server_data.php` on `Growtopia` folder

4. Copy + paste this inside `server_data.php` file

```
server|<your gameserver (not webserver unless they are the same) IP or 127.0.0.1 if you use local>
port|17091
type|1
#maint|<your maintenance text, remove the # to block all connections>
beta_server|127.0.0.1
beta_port|17091
beta_type|1
meta|localhost
RTENDMARKERBS1001
```
**NOTE**: Your game server IP (that's the `server|` part) doesn't need to be the same as the webserver's IP, but, in most cases, they are. You replace `<your gameserver (not webserver unless they are the same) IP or 127.0.0.1 if you use local>` with your game/webserver IP. Also replace `<your maintenance text, remove the # to block all connections>` with your maintenance text.

5. Open XAMPP control panel.

6. Start Apache Module

**Notice if you are using VPS (Virtual Private Server) you have to disable firewall to make the connection work**

# Setting up the Game Server

Dependencies
- Visual Studio 2015 or newer.
- Basic knowledge of using Visual Studio
- GrowtopiaServer files.

## Additional file
- `config.json`
Example for the `config.json`:
```
{
	"port": 17091,
	"cdn": "0098/CDNContent64/cache/"
}
```
- `news.txt`
Example for the `news.txt`:
```
set_default_color|`o

add_label_with_icon|big|`wThe Growtopia Gazette``|left|5016|
add_spacer|small|
add_image_button|banner|interface/large/news_banner.rttex|noflags|||
add_spacer|small|
add_textbox|`oThis is my very own `wGrowtopia Private Server``, welcome! Enjoy playing here!``|left|
end_dialog|gazette||OK|
```

## Steps:
1. Download or clone GrowtopiaServer Repository (https://github.com/ipr0gr4mipas2/GrowtopiaServer)

2. Download Visual Studio 2015 or Newer (you can skip this step if you already have it

3. Open "enet server test.sln" file (solution)

4. Press `CTRL + SHIFT + B` to build the project, or `F5` to debug.

5. After it's built, press `WINDOWS + R` and type `%localappdata%\Growtopia\cache` and copy `items.dat` to your desktop

6. Then put `enet server test.exe` from the debug folder and `items.dat` from desktop to the same folder

7. After that put the `config.json` and `news.txt` into the server folder

8. If youre using VPS (Virtual Private Server) download / copy the files into your VPS. If you're making local/development server you can skip this step.

9. Run the "enet server test.exe" and your server should work. If you get errors, install the Visual Studio 2015/2017/2019 C++ Redistributable (check the domain to be `microsoft.com` first!) and the application should start.

# How to enter your server

## Android:
1. Create Hosts file on your computer or VPS

2. Type this to the file:

```html
<your ip> growtopia1.com
<your ip> growtopia2.com
```
3. Download the file on your phone

4. Install Virtual hosts

5. Select the host file

6. Enable Virtual Hosts

7. Connect to Growtopia

## Windows:
1. Press `WINDOWS + R`

2. Open Notepad/Notepad++/ as administrator

3. Locate path: `C:\Windows\System32\drivers\etc`

4. Open hosts file

5. type this inside the hosts file:

```html
<your ip> growtopia1.com
<your ip> growtopia2.com
```

6. Save the file.

7. Connect to Growtopia.

## MacOS:
1. Open launchpad

2. Open the folder which contains Terminal/Bootcamp

3. Open terminal

4. Type this: `sudo nano /etc/hosts`. This command allows you to edit the hosts file. It can also apply to linux.

5. Find an empty space

6. Type in the file:
```
(serverip) growtopia1.com
(serverip) growtopia2.com
```

7. CTRL+X to Save and Exit

8. Type y if you want to save

9. Connect to GT.

10. Open Growtopia to start playing!
