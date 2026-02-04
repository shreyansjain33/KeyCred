cmake_minimum_required(VERSION 3.16)
project(TitanKeyCredentialProvider VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Windows-specific settings
if(WIN32)
    add_definitions(-DUNICODE -D_UNICODE -DWIN32_LEAN_AND_MEAN)
    set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS OFF)
    
    # Use static runtime to avoid VCRUNTIME DLL dependency
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

# Source files
set(SOURCES
    src/dll.cpp
    src/TitanKeyCredentialProvider.cpp
    src/TitanKeyCredential.cpp
    src/WebAuthnHelper.cpp
    src/Ctap2Helper.cpp
    src/CredentialStorage.cpp
    src/TpmCrypto.cpp
)

set(HEADERS
    src/guid.h
    src/TitanKeyCredentialProvider.h
    src/TitanKeyCredential.h
    src/WebAuthnHelper.h
    src/Ctap2Helper.h
    src/CredentialStorage.h
    src/TpmCrypto.h
    src/resource.h
    include/common.h
)

# Create the DLL
add_library(TitanKeyCP SHARED
    ${SOURCES}
    ${HEADERS}
    res/TitanKeyCP.rc
    TitanKeyCP.def
)

# Include directories
target_include_directories(TitanKeyCP PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Link libraries (including ncrypt for TPM, hid/setupapi for CTAP2)
target_link_libraries(TitanKeyCP PRIVATE
    advapi32
    crypt32
    secur32
    ole32
    oleaut32
    uuid
    credui
    webauthn
    bcrypt
    ncrypt
    user32
    hid
    setupapi
)

# Set DLL properties
set_target_properties(TitanKeyCP PROPERTIES
    OUTPUT_NAME "TitanKeyCP"
    PREFIX ""
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

# Test executable
add_executable(TestTitanKeyCP
    src/TestTitanKeyCP.cpp
    src/CredentialStorage.cpp
    src/WebAuthnHelper.cpp
    src/Ctap2Helper.cpp
    src/TpmCrypto.cpp
)

target_include_directories(TestTitanKeyCP PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(TestTitanKeyCP PRIVATE
    advapi32
    crypt32
    ole32
    user32
    webauthn
    bcrypt
    ncrypt
    hid
    setupapi
)

set_target_properties(TestTitanKeyCP PROPERTIES
    OUTPUT_NAME "TestTitanKeyCP"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

# Install rules
install(TARGETS TitanKeyCP TestTitanKeyCP
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
)
