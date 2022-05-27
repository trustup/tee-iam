cmake_minimum_required(VERSION 3.13)
project(xmargin)

set(CMAKE_CXX_STANDARD 17)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)

# **************************************SGX**************************************
find_package(SGX REQUIRED)

set(SGX_MODE HW CACHE STRING "Run SGX on hardware: HW for intel sgx hardware, SIM for simulation.")

if(${SGX_MODE} STREQUAL "HW")
    set(SGX_HW ON CACHE BOOL "Run SGX on hardware, ON for simulation." FORCE)
elseif(${SGX_MODE} STREQUAL "SIM")
    set(SGX_HW OFF CACHE BOOL "Run SGX on hardware, OFF for simulation." FORCE)
else()  
    message(FATAL_ERROR "Incorrect sgx build mode! ({HW,SIM})")
endif()

set(SGX_ARCH x64)
# **************************************WOLFSSL**************************************
# For some reason the final executable is linked to the wolfssl library
find_package(WolfSSL REQUIRED)

if(EXISTS $ENV{WOLFSSL_ROOT})
    set(WOLFSSL_ROOT $ENV{WOLFSSL_ROOT})
    # message("FOUND ENV VARIABLE WOLFSSL_ROOT! ${WOLFSSL_ROOT}")
elseif(EXISTS ${WOLFSSL_ROOT})
    # message("FOUND CACHE VARIABLE WOLFSSL_ROOT! ${WOLFSSL_ROOT}")
    set(WOLFSSL_ROOT ${WOLFSSL_ROOT})
else()
    message(FATAL_ERROR "Could NOT find WOLFSSL_ROOT enviroment variable!")
endif()

get_filename_component(SGX_WOLFSSL_LIB_DIR ${WOLFSSL_ROOT} ABSOLUTE)
set(SGX_WOLFSSL_LIB_DIR ${SGX_WOLFSSL_LIB_DIR}/IDE/LINUX-SGX)

if(NOT EXISTS ${SGX_WOLFSSL_LIB_DIR}/libwolfssl.sgx.static.lib.a)
    message(FATAL_ERROR "Could NOT find SGX Wolfssl static library libwolfssl.sgx.static.lib.a at ${SGX_WOLFSSL_LIB_DIR}!. Follow the instructions from https://github.com/wolfSSL/wolfssl-examples/tree/master/SGX_Linux")
endif(NOT EXISTS ${SGX_WOLFSSL_LIB_DIR}/libwolfssl.sgx.static.lib.a)


# *********FLAGS***********
set(WOLFSSL_C_INCLUDE_DIRS ${WOLFSSL_ROOT} ${WOLFSSL_ROOT}/wolfcrypt)
set(WOLFSSL_C_EXTRA_FLAGS "-DWOLFSSL_SGX")

if(HAVE_WOLFSSL_TEST EQUAL 1)
    list(APPEND WOLFSSL_C_INCLUDE_DIRS ${WOLFSSL_ROOT}/wolfcrypt/test)
    set(WOLFSSL_C_EXTRA_FLAGS "${WOLFSSL_C_EXTRA_FLAGS} -DHAVE_WOLFSSL_TEST")
endif()    
if(HAVE_WOLFSSL_BENCHMARK EQUAL 1)
    list(APPEND WOLFSSL_C_INCLUDE_DIRS ${WOLFSSL_ROOT}/wolfcrypt/benchmark)
    set(WOLFSSL_C_EXTRA_FLAGS "${WOLFSSL_C_EXTRA_FLAGS} -DHAVE_WOLFSSL_BENCHMARK")
endif()  
if(HAVE_WOLFSSL_SP EQUAL 1)
    set(WOLFSSL_C_EXTRA_FLAGS "${WOLFSSL_C_EXTRA_FLAGS} -DWOLFSSL_HAVE_SP_RSA -DWOLFSSL_HAVE_SP_DH -DWOLFSSL_HAVE_SP_ECC")
endif()  
set(WOLFSSL_C_EXTRA_FLAGS "${WOLFSSL_C_EXTRA_FLAGS} -DWOLFSSL_STATIC_RSA -DHAVE_SUPPORTED_CURVES  -DHAVE_SNI -DHAVE_TLS_EXTENSIONS")

# message("WOLFSSL_C_INCLUDE_DIRS: ${WOLFSSL_C_INCLUDE_DIRS}")
set(WOLFSSL_ENCLAVE_EXTRA_FLAGS "${WOLFSSL_C_EXTRA_FLAGS} -DSGX_ENCLAVE")
# message("WOLFSSL_ENCLAVE_EXTRA_FLAGS: ${WOLFSSL_ENCLAVE_EXTRA_FLAGS}")



# # **************************************OPENSSL **************************************
# if(EXISTS $ENV{SGX_OPENSSL_PATH})
#     set(SGX_OPENSSL_PATH $ENV{SGX_OPENSSL_PATH})
# elseif(EXISTS /opt/intel/sgxssl)
#     set(SGX_OPENSSL_PATH /opt/intel/sgxssl)
# else()
#     message(FATAL_ERROR "Could NOT find Intel SGX OPENSSL path!")
# endif()

# if(EXISTS "${SGX_OPENSSL_PATH}/include" AND EXISTS "${SGX_OPENSSL_PATH}/lib64")
#     set(SGX_OPENSSL_INCLUDE_DIR ${SGX_OPENSSL_PATH}/include)
#     set(SGX_OPENSSL_LIB_DIR ${SGX_OPENSSL_PATH}/lib64)
# else()
#     message(FATAL_ERROR "Could NOT find Intel SGX OPENSSL directories!")        
# endif()

# get_filename_component(SGX_OPENSSL_INCLUDE_DIR ${SGX_OPENSSL_INCLUDE_DIR} ABSOLUTE)
# get_filename_component(SGX_OPENSSL_LIB_DIR ${SGX_OPENSSL_LIB_DIR} ABSOLUTE)

set(LDS Enclave/Enclave.lds)

# message("SGX_WOLFSSL_LIB_DIR: ${SGX_WOLFSSL_LIB_DIR}")
# message("SGX_OPENSSL_INCLUDE_DIR: ${SGX_OPENSSL_INCLUDE_DIR}")
# message("SGX_OPENSSL_LIB_DIR: ${SGX_OPENSSL_LIB_DIR}")
# message("WOLFSSL_ROOT: ${WOLFSSL_ROOT}")

# ************************************** SPDLOG **************************************
find_package(spdlog REQUIRED)

# ************************************** Boost **************************************
find_package(Boost REQUIRED COMPONENTS program_options filesystem)

# if(Boost_FOUND)
#     message("Boost FOUND with version: ${Boost_VERSION_STRING}")
#     message("Boost_INCLUDE_DIRS: ${Boost_INCLUDE_DIRS}")
#     message("Boost_LIBRARY_DIRS: ${Boost_LIBRARY_DIRS}")
#     message("Boost_LIBRARIES: ${Boost_LIBRARIES}")
# endif()


# **************************************APPLICATION**************************************

# ************CONFIGURATION**********************
set(CONFIG_DIR "config")
if(EXISTS ${CMAKE_SOURCE_DIR}/${CONFIG_DIR}/app.cfg)
    file(MAKE_DIRECTORY ${CONFIG_DIR})
    file(COPY ${CMAKE_SOURCE_DIR}/${CONFIG_DIR}/app.cfg DESTINATION ${CMAKE_BINARY_DIR}/${CONFIG_DIR})
endif(EXISTS ${CMAKE_SOURCE_DIR}/${CONFIG_DIR}/app.cfg)

#
# **************************************TRUSTED**************************************
set(EDL_SEARCH_PATHS ${CMAKE_SOURCE_DIR}/Enclave)

set(T_INCLUDE_DIRS Enclave 
    ${SGX_OPENSSL_INCLUDE_DIR}
    ${WOLFSSL_C_INCLUDE_DIRS}
    third_party/rapidjson/include
    Enclave/Crypto
    Common
    Enclave/HTTPS_Handlers
    Enclave/Agg
    Enclave/KeyStorageHandlers
    Enclave/ProofLib
    Enclave/DataUtils)


file(GLOB T_SRCS Enclave/*.c*)

file(GLOB T_SRCS_Crypto Enclave/Crypto/*.c*)
file(GLOB T_SRCS_HTTPS_Handlers Enclave/HTTPS_Handlers/*.c*)
file(GLOB T_SRCS_DataUtils Enclave/DataUtils/*.c*)
file(GLOB T_SRCS_Agg Enclave/Agg/*.c*)
file(GLOB T_SRCS_PROOF Enclave/ProofLib/*.c*)


# TODO remove after merge with master and bitfinex enters to the Agg folder
file(GLOB T_SRCS_Exchanges Enclave/Exchanges/Bitfinex/*.c*)


add_enclave_library(enclave
                    SRCS ${T_SRCS} ${T_SRCS_Crypto} ${T_SRCS_PROOF} ${T_SRCS_HTTPS_Handlers} ${T_SRCS_DataUtils} ${T_SRCS_Agg} ${T_SRCS_Exchanges}
                    EDL Enclave/Enclave.edl
                    EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS}
                    USE_PREFIX
                    LDSCRIPT ${LDS}
                    OPENSSL_LIBRARY_PATH ${SGX_OPENSSL_LIB_DIR}
                    WOLFSSL_LIBRARY_PATH ${SGX_WOLFSSL_LIB_DIR}
                    EXTRA_INCLUDE_DIRS ${T_INCLUDE_DIRS}
                    EXTRA_OPTIONS_FLAGS ${WOLFSSL_ENCLAVE_EXTRA_FLAGS})

                                   
enclave_sign(enclave KEY Enclave/Enclave_private.pem CONFIG Enclave/Enclave.config.xml)

# **************************************UNTRUSTED**************************************

set(DISPATCHER OFF CACHE BOOL "Run DISPATCHER main: ON for run Dispatcher.cpp, OFF for run App.cpp (Default).")

file(GLOB U_SRCS App/*.c*)

file(GLOB U_SRCS_Exchanges App/Exchanges/*.c*)

set(U_INCLUDE_DIRS 
    ${WOLFSSL_C_INCLUDE_DIRS}
    third_party/rapidjson/include
    ${SPDLOG_INCLUDE_DIR}
    App
    Common
    App/kdb
    App/xmkx/include
    App/xmkx/external/kdb/include
)

if(ENABLE_PROMETEUS)
    set(PROMETEUS_LIBRARY_DIRS 
        /usr/local/lib
    )
    message("PROMETEUS_LIBRARY_DIRS: ${PROMETEUS_LIBRARY_DIRS}")
    list(APPEND PROMETEUS_LIBRARIES prometheus-cpp-core prometheus-cpp-push prometheus-cpp-pull)
else()
    list(REMOVE_ITEM U_SRCS ${CMAKE_SOURCE_DIR}/App/Prometheus.cpp)
    message("U_SRCS: ${U_SRCS}")
endif(ENABLE_PROMETEUS)

set(WOLFSSL_APP_EXTRA_FLAGS "${WOLFSSL_C_EXTRA_FLAGS} -DWOLFSSL_SHA512 -DOPENSSL_EXTRA -DOPENSSL_ALL  -DLWS_HAVE_SSL_CTX_load_verify_file \
    -DLWS_WITH_SOCKS5 -DLWS_WITH_DETAILED_LATENCY  -DLWS_WITH_SPAWN  -DLWS_WITH_RANGES -DLWS_WITH_ACCESS_LOG -DCPPHTTPLIB_OPENSSL_SUPPORT -DHAVE_SUPPORTED_CURVES")

message("using App.cpp as entry point")
list(REMOVE_ITEM U_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/App/Dispatcher.cpp)
add_untrusted_executable(kmsapp SRCS ${U_SRCS} ${U_SRCS_Exchanges} 
                    EDL Enclave/Enclave.edl 
                    EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS}
                    OPENSSL_LIBRARY_PATH ${SGX_OPENSSL_LIB_DIR}
                    EXTRA_INCLUDE_DIRS ${U_INCLUDE_DIRS}
                    EXTRA_LIB_DIRS ${PROMETEUS_LIBRARY_DIRS} ${ZLIB_LIBRARIES_DIR}
                    EXTRA_OPTIONS_FLAGS ${WOLFSSL_APP_EXTRA_FLAGS}
                    EXTRA_LIBS spdlog::spdlog Boost::program_options Boost::filesystem
                    ${PROMETEUS_LIBRARIES} ${ZLIB_LIBRARIES} -lsgx_uprotected_fs  -lstdc++fs
)
add_dependencies(kmsapp enclave-sign)



enable_testing()
include_directories(App)
include_directories(Enclave)
# add_subdirectory(test)
