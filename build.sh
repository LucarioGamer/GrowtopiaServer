sudo apt-get install build-essential
cd "enet server test"
cd "enet2"
sudo apt install cmake
cmake CMakeLists.txt
make
cp libenet.a ../libenet.a
cd ..
g++ -o "enet server test" "enet server test.cpp" -std=c++11 -L. -lenet -iquote.
echo Creating directories...
mkdir -m 777 -p "worlds"
mkdir -m 777 -p "players"
