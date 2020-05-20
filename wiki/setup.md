# Setup HTTP Server

- Depencies are
- VPS or Your Machine
- Xampp or nginx but this tutorial is for Xampp (Apache)

Download Xampp here : [Click here to download Xampp](https://www.apachefriends.org/xampp-files/7.4.6/xampp-windows-x64-7.4.6-0-VC15-installer.exe)

## Steps:
1. locate path `C:\xampp\htdocs\`

2. create new folder called `Growtopia`

3. make file called `server_data.php` on `Growtopia` folder

4. copy + paste this inside `server_data.php` file

```html
server|127.0.0.1
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

**Notice if you are using vps (Virtual Private Server) you have to disable firewall to make the connection work**

# Setup Server

- Depencies
- Visual Studio 2015 or Newer.
- Basic knowledge of using Visual Studio
- GrowtopiaServer files.

## Steps:
1. Download or clone GrowtopiaServer Repository (https://github.com/GrowtopiaNoobs/GrowtopiaServer.git)

2. Download Visual Studio 2015 or Newer (you can skip this step if you already have it
3. Open "enet server test" project.

4. Press `CTRL + SHIFT + B` to build the project.

5. After its built press `WINDOWS + R` and type `%localappdata%\Growtopia\cache` and copy `items.dat` to your desktop

6. Then put `enet server test.exe` from the debug folder and `items.dat` from desktop to the same folder

7. If youre using vps (Virtual Private Server) Download / Copy the files into your vps if youre making localhost server you can skip this step.

8. Run the "enet server test.exe" and your server should work if you get error install the visual studio version c++ redistributable and the application should start.

# How to Join into your server.

## Android:
1. Create Hosts file on your computer or vps

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

2. Open notepad as administrator

3. Locate path: `C:\Windows\System32\drivers\etc`

4. Open hosts file

5. type this inside the hosts file:

```html
<your ip> growtopia1.com
<your ip> growtopia2.com
```

6. Save the file.

7. Connect to Growtopia
