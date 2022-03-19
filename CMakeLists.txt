cmake_minimum_required(VERSION 3.14)
project(fsd
        VERSION 3.99.1
        LANGUAGES CXX)

add_executable(fsd
        src/authenticate.cpp
        src/certificate.cpp
        src/client.cpp
        src/clinterface.cpp
        src/cluser.cpp
        src/config.cpp
        src/fsd.cpp
        src/interface.cpp
        src/main.cpp
        src/manage.cpp
        src/mm.cpp
        src/process.cpp
        src/server.cpp
        src/servinterface.cpp
        src/servuser.cpp
        src/support.cpp
        src/sysinterface.cpp
        src/sysuser.cpp
        src/user.cpp
        src/wprofile.cpp)

find_package(SQLite3 REQUIRED)
target_link_libraries(fsd sqlite3)

set_property(TARGET fsd PROPERTY CMAKE_CXX_STANDARD 17)
set_property(TARGET fsd PROPERTY CMAKE_CXX_STANDARD_REQUIRED ON)
set_property(TARGET fsd PROPERTY VS_PACKAGE_REFERENCES "SQLite_3.13.0")
