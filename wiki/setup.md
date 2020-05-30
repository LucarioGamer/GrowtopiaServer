# Setup HTTP Server

- Depencies are
- VPS or Your Machine
- XAMPP or nginx but this tutorial is for XAMPP (Apache)

Download XAMPP here: [Click here to download XAMPP](https://www.apachefriends.org/xampp-files/7.4.6/xampp-windows-x64-7.4.6-0-VC15-installer.exe)

## Steps:
1. locate path `C:\xampp\htdocs\`

2. create new folder called `Growtopia`

3. make file called `server_data.php` on `Growtopia` folder

4. copy + paste this inside `server_data.php` file

```html
server|<your server IP or 127.0.0.1 if you use local>
port|17091
type|1
#maint|Unused for now
beta_server|127.0.0.1
beta_port|17091
beta_type|1
meta|localhost
RTENDMARKERBS1001
```
5. if you're using vps (Virtual Private Server) you need to change `server|127.0.0.1` to `server| your vps ip here` and if your're localhost then you dont need do anything.

6. open Xampp control panel.

7. Start Apache Module

**Notice if you are using VPS (Virtual Private Server) you have to disable firewall to make the connection work**

# Setup Server

- Depencies
- Visual Studio 2015 or newer.
- Basic knowledge of using Visual Studio
- GrowtopiaServer files.

## Steps:
1. Download or clone GrowtopiaServer Repository (https://github.com/ipr0gr4mipas2/GrowtopiaServer)

2. Download Visual Studio 2015 or Newer (you can skip this step if you already have it

3. Open "enet server test.sln" file (solution)

4. Press `CTRL + SHIFT + B` to build the project, or `F5` to debug.

5. After it's built, press `WINDOWS + R` and type `%localappdata%\Growtopia\cache` and copy `items.dat` to your desktop

6. Then put `enet server test.exe` from the debug folder and `items.dat` from desktop to the same folder

7. If youre using VPS (Virtual Private Server) download / copy the files into your VPS. If you're making local/development server you can skip this step.

8. Run the "enet server test.exe" and your server should work. If you get errors, install the Visual Studio 2015/2017/2019 C++ Redistributable (check the domain to be `microsoft.com` first!) and the application should start.

# How to Join into your server.

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
