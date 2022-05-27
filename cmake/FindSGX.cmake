# FindPackage cmake file for Intel SGX SDK

cmake_minimum_required(VERSION 2.8.11) # target_include_directories
include(CMakeParseArguments)

set(SGX_FOUND "NO")

if(EXISTS SGX_DIR)
    set(SGX_PATH ${SGX_DIR})
elseif(EXISTS SGX_ROOT)
    set(SGX_PATH ${SGX_ROOT})
elseif(EXISTS $ENV{SGX_SDK})
    set(SGX_PATH $ENV{SGX_SDK})
elseif(EXISTS $ENV{SGX_DIR})
    set(SGX_PATH $ENV{SGX_DIR})
elseif(EXISTS $ENV{SGX_ROOT})
    set(SGX_PATH $ENV{SGX_ROOT})
else()
    set(SGX_PATH "/opt/intel/sgxsdk")
endif()

if(CMAKE_SIZEOF_VOID_P EQUAL 4)
    set(SGX_COMMON_CFLAGS -m32)
    set(SGX_LIBRARY_PATH ${SGX_PATH}/lib32)
    set(SGX_ENCLAVE_SIGNER ${SGX_PATH}/bin/x86/sgx_sign)
    set(SGX_EDGER8R ${SGX_PATH}/bin/x86/sgx_edger8r)
else()
    set(SGX_COMMON_CFLAGS -m64)
    set(SGX_LIBRARY_PATH ${SGX_PATH}/lib64)
    set(SGX_ENCLAVE_SIGNER ${SGX_PATH}/bin/x64/sgx_sign)
    set(SGX_EDGER8R ${SGX_PATH}/bin/x64/sgx_edger8r)
endif()

find_path(SGX_INCLUDE_DIR sgx.h "${SGX_PATH}/include" NO_DEFAULT_PATH)
find_path(SGX_LIBRARY_DIR libsgx_urts.so "${SGX_LIBRARY_PATH}" NO_DEFAULT_PATH)

if(SGX_INCLUDE_DIR AND SGX_LIBRARY_DIR)
    set(SGX_FOUND "YES")
    set(SGX_INCLUDE_DIR "${SGX_PATH}/include" CACHE PATH "Intel SGX include directory" FORCE)
    set(SGX_TLIBC_INCLUDE_DIR "${SGX_INCLUDE_DIR}/tlibc" CACHE PATH "Intel SGX tlibc include directory" FORCE)
    set(SGX_LIBCXX_INCLUDE_DIR "${SGX_INCLUDE_DIR}/libcxx" CACHE PATH "Intel SGX libcxx include directory" FORCE)
    set(SGX_INCLUDE_DIRS ${SGX_INCLUDE_DIR} ${SGX_TLIBC_INCLUDE_DIR} ${SGX_LIBCXX_INCLUDE_DIR})
    mark_as_advanced(SGX_INCLUDE_DIR SGX_TLIBC_INCLUDE_DIR SGX_LIBCXX_INCLUDE_DIR SGX_LIBRARY_DIR)
    message(STATUS "Found Intel SGX SDK.")
endif()

if(SGX_FOUND)
    set(SGX_HW OFF CACHE BOOL "Run SGX on hardware, OFF for simulation.")
    set(SGX_BUILD_TYPE Debug CACHE STRING "SGX build mode: Debug; PreRelease; Release.")

    if(SGX_HW)
        set(SGX_URTS_LIB sgx_urts)
        set(SGX_USVC_LIB sgx_uae_service)
        set(SGX_TRTS_LIB sgx_trts)
        set(SGX_TSVC_LIB sgx_tservice)
    else()
        set(SGX_URTS_LIB sgx_urts_sim)
        set(SGX_USVC_LIB sgx_uae_service_sim)
        set(SGX_TRTS_LIB sgx_trts_sim)
        set(SGX_TSVC_LIB sgx_tservice_sim)
    endif()

    if(SGX_BUILD_TYPE STREQUAL "Debug")
        set(SGX_COMMON_CFLAGS "${SGX_COMMON_CFLAGS} -O0 -g -DSGX_DEBUG -DDEBUG -UNDEBUG -UEDEBUG")
    elseif(SGX_BUILD_TYPE STREQUAL "PreRelease")
        set(SGX_COMMON_CFLAGS "${SGX_COMMON_CFLAGS} -O2 -UDEBUG -DNDEBUG -DEDEBUG")
    elseif(SGX_BUILD_TYPE STREQUAL "Release")
        set(SGX_COMMON_CFLAGS "${SGX_COMMON_CFLAGS} -O2 -UDEBUG -DNDEBUG -UEDEBUG")
    else()
        message(FATAL_ERROR "SGX_BUILD_TYPE ${SGX_BUILD_TYPE} is not Debug, PreRelease or Release.")
    endif()

    set(ENCLAVE_INC_DIRS "${SGX_INCLUDE_DIR}" "${SGX_TLIBC_INCLUDE_DIR}" "${SGX_LIBCXX_INCLUDE_DIR}")
    set(ENCLAVE_C_FLAGS "${SGX_COMMON_CFLAGS} -nostdinc -fvisibility=hidden -fpie -fstack-protector-strong")
    set(ENCLAVE_CXX_FLAGS "${ENCLAVE_C_FLAGS} -nostdinc++")

    set(APP_INC_DIRS "${SGX_PATH}/include")
    set(APP_C_FLAGS "${SGX_COMMON_CFLAGS} -fPIC -Wno-attributes ")
    set(APP_CXX_FLAGS "${APP_C_FLAGS}")

    function(_build_edl_obj edl edl_search_paths use_prefix)
        set(oneValueArgs EXTRA_FLAGS)
        set(multiValueArgs EXTRA_INCLUDE_DIRS)
        cmake_parse_arguments(OBJ "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN} )
        get_filename_component(EDL_NAME ${edl} NAME_WE)
        get_filename_component(EDL_ABSPATH ${edl} ABSOLUTE)
        set(EDL_T_C "${CMAKE_CURRENT_BINARY_DIR}/${EDL_NAME}_t.c")
        set(SEARCH_PATHS "")
        foreach(path ${edl_search_paths})
            get_filename_component(ABSPATH ${path} ABSOLUTE)
            list(APPEND SEARCH_PATHS "${ABSPATH}")
        endforeach()
        list(APPEND SEARCH_PATHS "${SGX_PATH}/include")
        string(REPLACE ";" ":" SEARCH_PATHS "${SEARCH_PATHS}")
        if(${use_prefix})
            set(USE_PREFIX "--use-prefix")
        endif()
        if(NOT "${OBJ_EXTRA_INCLUDE_DIRS}" STREQUAL "")
            # message("OBJ_EXTRA_INCLUDE_DIRS: ${OBJ_EXTRA_INCLUDE_DIRS}")
        endif()        
        add_custom_command(OUTPUT ${EDL_T_C}
                           COMMAND ${SGX_EDGER8R} ${USE_PREFIX} --trusted ${EDL_ABSPATH} --search-path ${SEARCH_PATHS}
                           MAIN_DEPENDENCY ${EDL_ABSPATH}
                           WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
        set( LIB_ENCLAVE_C_FLAGS "-std=c11 ${ENCLAVE_C_FLAGS} ${OBJ_EXTRA_FLAGS}")
        add_library(${target}-edlobj OBJECT ${EDL_T_C})
        set_target_properties(${target}-edlobj PROPERTIES COMPILE_FLAGS ${LIB_ENCLAVE_C_FLAGS})
        target_include_directories(${target}-edlobj PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${ENCLAVE_INC_DIRS}  ${OBJ_EXTRA_INCLUDE_DIRS})

        set_property(DIRECTORY APPEND PROPERTY ADDITIONAL_MAKE_CLEAN_FILES "${CMAKE_CURRENT_BINARY_DIR}/${EDL_NAME}_t.h")
    endfunction()

    # build trusted static library to be linked into enclave library
    # function(add_trusted_library target)
    #     set(optionArgs USE_PREFIX)
    #     set(oneValueArgs EDL LDSCRIPT)
    #     set(multiValueArgs SRCS EDL_SEARCH_PATHS EXTRA_OPTIONS_FLAGS EXTRA_INCLUDE_DIRS)
    #     cmake_parse_arguments("SGX" "${optionArgs}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})
    #     if(NOT "${SGX_LDSCRIPT}" STREQUAL "")
    #         get_filename_component(LDS_ABSPATH ${SGX_LDSCRIPT} ABSOLUTE)
    #         set(LDSCRIPT_FLAG "-Wl,--version-script=${LDS_ABSPATH}")
    #     endif()
    #     if(NOT "${SGX_EXTRA_OPTIONS_FLAGS}" STREQUAL "")
    #         message("SGX_EXTRA_OPTIONS_FLAGS: ${SGX_EXTRA_OPTIONS_FLAGS}")
    #     endif()        
    #     if(NOT "${SGX_EXTRA_INCLUDE_DIRS}" STREQUAL "")
    #         message("SGX_EXTRA_INCLUDE_DIRS: ${SGX_EXTRA_INCLUDE_DIRS}")
    #     endif()

    #     if("${SGX_EDL}" STREQUAL "")
    #         message("${target}: SGX enclave edl file is not provided; skipping edger8r")
    #         add_library(${target} STATIC ${SGX_SRCS})
    #     else()
    #         if("${SGX_EDL_SEARCH_PATHS}" STREQUAL "")
    #             message("${target}: SGX enclave edl file search paths are not provided!")
    #         endif()
    #         _build_edl_obj(${SGX_EDL} "${SGX_EDL_SEARCH_PATHS}" ${SGX_USE_PREFIX}  EXTRA_INCLUDE_DIRS ${SGX_EXTRA_INCLUDE_DIRS} EXTRA_FLAGS ${SGX_EXTRA_OPTIONS_FLAGS})
    #         add_library(${target} STATIC ${SGX_SRCS} $<TARGET_OBJECTS:${target}-edlobj>)
    #     endif()
        
    #     set_target_properties(${target} PROPERTIES COMPILE_FLAGS ${ENCLAVE_CXX_FLAGS})
    #     target_include_directories(${target} PUBLIC ${CMAKE_CURRENT_BINARY_DIR} ${ENCLAVE_INC_DIRS} 
    #                                 ${SGX_EXTRA_INCLUDE_DIRS})

    #     set(SGX_COMPILER_OPTIONS "${SGX_COMMON_CFLAGS} -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L${SGX_LIBRARY_PATH} \
    #     -Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_tkey_exchange -lsgx_tcrypto -l${SGX_TSVC_LIB} -Wl,--end-group \
    #     -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
    #     -Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
    #     ${LDSCRIPT_FLAG} ${SGX_EXTRA_OPTIONS_FLAGS} \
    #     -Wl,--defsym,__ImageBase=0")
        
    #     message("add_trusted_library SGX_COMPILER_OPTIONS: ${SGX_COMPILER_OPTIONS}")

    #     target_link_libraries(${target} "${SGX_COMPILER_OPTIONS}")
    # endfunction()

    # build enclave shared library
    function(add_enclave_library target)
        set(optionArgs USE_PREFIX)
        set(oneValueArgs EDL LDSCRIPT OPENSSL_LIBRARY_PATH WOLFSSL_LIBRARY_PATH)
        set(multiValueArgs SRCS TRUSTED_LIBS EDL_SEARCH_PATHS EXTRA_INCLUDE_DIRS EXTRA_OPTIONS_FLAGS)
        cmake_parse_arguments("SGX" "${optionArgs}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})
        if("${SGX_EDL}" STREQUAL "")
            message(FATAL_ERROR "${target}: SGX enclave edl file is not provided!")
        endif()
        # if(NOT "${SGX_EXTRA_INCLUDE_DIRS}" STREQUAL "")
        #     message("SGX_EXTRA_INCLUDE_DIRS: ${SGX_EXTRA_INCLUDE_DIRS}")
        # endif()
        # if(NOT "${SGX_EXTRA_OPTIONS_FLAGS}" STREQUAL "")
        #     # message("SGX_EXTRA_OPTIONS_FLAGS: ${SGX_EXTRA_OPTIONS_FLAGS}")
        # endif()                   
        # if("${SGX_EDL_SEARCH_PATHS}" STREQUAL "")
        #     message("${target}: SGX enclave edl file search paths are not provided!")
        # endif()
        if(NOT "${SGX_LDSCRIPT}" STREQUAL "")
            # message("SGX_LDSCRIPT provided ${SGX_LDSCRIPT}")
            get_filename_component(LDS_ABSPATH ${SGX_LDSCRIPT} ABSOLUTE)
            set(LDSCRIPT_FLAG "-Wl,--version-script=${LDS_ABSPATH}")
        endif()
        if(NOT "${SGX_OPENSSL_LIBRARY_PATH}" STREQUAL "")
            # message("SGX_OPENSSL_LIBRARY_PATH provided ${SGX_OPENSSL_LIBRARY_PATH}")
            if(SGX_BUILD_TYPE STREQUAL "Debug")
                set(OPENSSL_SGX_SSL_LIBRARY_NAME "sgx_tsgxssld")
                set(OPENSSL_SGX_CRYPTO_LIBRARY_NAME "sgx_tsgxssl_cryptod")
            else()
                set(OPENSSL_SGX_SSL_LIBRARY_NAME "sgx_tsgxssl")
                set(OPENSSL_SGX_CRYPTO_LIBRARY_NAME "sgx_tsgxssl_crypto")
            endif()
            set(OPENSSL_FLAGS "-L${SGX_OPENSSL_LIBRARY_PATH} -Wl,--whole-archive -l${OPENSSL_SGX_SSL_LIBRARY_NAME} -Wl,--no-whole-archive -l${OPENSSL_SGX_CRYPTO_LIBRARY_NAME}")
        endif()          

        if(NOT "${SGX_WOLFSSL_LIBRARY_PATH}" STREQUAL "")
            # message("SGX_WOLFSSL_LIBRARY_PATH provided ${SGX_WOLFSSL_LIBRARY_PATH}")
            set(WOLFSSL_SGX_LIBRARY_NAME "wolfssl.sgx.static.lib")
            set(WOLFSSL_FLAGS "-L${SGX_WOLFSSL_LIBRARY_PATH} -l${WOLFSSL_SGX_LIBRARY_NAME}")
            # message("WOLFSSL_FLAGS provided ${WOLFSSL_FLAGS}")
        endif()          
        _build_edl_obj(${SGX_EDL} "${SGX_EDL_SEARCH_PATHS}" ${SGX_USE_PREFIX} EXTRA_INCLUDE_DIRS ${SGX_EXTRA_INCLUDE_DIRS} EXTRA_FLAGS ${SGX_EXTRA_OPTIONS_FLAGS})
        set( LIB_ENCLAVE_CPP_FLAGS "-std=c++11 ${ENCLAVE_CXX_FLAGS} ${SGX_EXTRA_OPTIONS_FLAGS}")
        add_library(${target} SHARED ${SGX_SRCS} $<TARGET_OBJECTS:${target}-edlobj>)
        set_target_properties(${target} PROPERTIES COMPILE_FLAGS ${LIB_ENCLAVE_CPP_FLAGS})
        target_include_directories(${target} PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${ENCLAVE_INC_DIRS} ${SGX_EXTRA_INCLUDE_DIRS})

        set(TLIB_LIST "")
        foreach(TLIB ${SGX_TRUSTED_LIBS})
            string(APPEND TLIB_LIST "$<TARGET_FILE:${TLIB}> ")
            add_dependencies(${target} ${TLIB})
        endforeach()
        set(SGX_COMPILER_OPTIONS "${SGX_COMMON_CFLAGS} -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles \
        ${OPENSSL_FLAGS}  ${WOLFSSL_FLAGS} \
        -L${SGX_LIBRARY_PATH} -Wl,--whole-archive -l${SGX_TRTS_LIB} -Wl,--no-whole-archive \
        -Wl,--start-group ${TLIB_LIST} -lsgx_tstdc -lsgx_tcxx -lsgx_pthread -lsgx_tkey_exchange -lsgx_tcrypto -lsgx_tprotected_fs -l${SGX_TSVC_LIB} -Wl,--end-group \
        -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
        -Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
        ${LDSCRIPT_FLAG} -Wl,--defsym,__ImageBase=0")

        # message("add_enclave_library SGX_COMPILER_OPTIONS: ${SGX_COMPILER_OPTIONS}")
        target_link_libraries(${target} ${SGX_COMPILER_OPTIONS})
    endfunction()

    # sign the enclave, according to configurations one-step or two-step signing will be performed.
    # default one-step signing output enclave name is target.signed.so, change it with OUTPUT option.
    function(enclave_sign target)
        set(optionArgs IGNORE_INIT IGNORE_REL)
        set(oneValueArgs KEY CONFIG OUTPUT)
        cmake_parse_arguments("SGX" "${optionArgs}" "${oneValueArgs}" "" ${ARGN})
        if("${SGX_CONFIG}" STREQUAL "")
            message("${target}: SGX enclave config is not provided!")
        else()
            get_filename_component(CONFIG_ABSPATH ${SGX_CONFIG} ABSOLUTE)
        endif()
        if("${SGX_KEY}" STREQUAL "")
            if (NOT SGX_HW OR NOT SGX_BUILD_TYPE STREQUAL "Release")
                message(FATAL_ERROR "${target}: Private key used to sign enclave is not provided!")
            endif()
        else()
            get_filename_component(KEY_ABSPATH ${SGX_KEY} ABSOLUTE)
        endif()
        if("${SGX_OUTPUT}" STREQUAL "")
            set(OUTPUT_NAME "${target}.signed.so")
        else()
            set(OUTPUT_NAME ${SGX_OUTPUT})
        endif()
	if(${SGX_IGNORE_INIT})
	    set(IGN_INIT "-ignore-init-sec-error")
	endif()
	if(${SGX_IGNORE_REL})
	    set(IGN_REL "-ignore-rel-error")
	endif()

        if(SGX_HW AND SGX_BUILD_TYPE STREQUAL "Release")
            add_custom_target(${target}-sign ALL
                              COMMAND ${SGX_ENCLAVE_SIGNER} gendata
                                      $<$<NOT:$<STREQUAL:${SGX_CONFIG},>>:-config> $<$<NOT:$<STREQUAL:${SGX_CONFIG},>>:${CONFIG_ABSPATH}>
                                      -enclave $<TARGET_FILE:${target}> -out $<TARGET_FILE_DIR:${target}>/${target}_hash.hex ${IGN_INIT} ${IGN_REL}
                              COMMAND ${CMAKE_COMMAND} -E cmake_echo_color
                                  --cyan "SGX production enclave first step signing finished, \
    use ${CMAKE_CURRENT_BINARY_DIR}/${target}_hash.hex for second step"
                              WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
        else()
            add_custom_target(${target}-sign ALL ${SGX_ENCLAVE_SIGNER} sign -key ${KEY_ABSPATH}
                              $<$<NOT:$<STREQUAL:${SGX_CONFIG},>>:-config> $<$<NOT:$<STREQUAL:${SGX_CONFIG},>>:${CONFIG_ABSPATH}>
                              -enclave $<TARGET_FILE:${target}>
                              -out $<TARGET_FILE_DIR:${target}>/${OUTPUT_NAME}
			      ${IGN_INIT} ${IGN_REL}
                              WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
        endif()

        set(CLEAN_FILES "$<TARGET_FILE_DIR:${target}>/${OUTPUT_NAME};$<TARGET_FILE_DIR:${target}>/${target}_hash.hex")
        set_property(DIRECTORY APPEND PROPERTY ADDITIONAL_MAKE_CLEAN_FILES "${CLEAN_FILES}")
    endfunction()

    # function(add_untrusted_library target mode)
    #     set(optionArgs USE_PREFIX)
    #     set(multiValueArgs SRCS EDL EDL_SEARCH_PATHS)
    #     cmake_parse_arguments("SGX" "${optionArgs}" "" "${multiValueArgs}" ${ARGN})
    #     if("${SGX_EDL}" STREQUAL "")
    #         message(FATAL_ERROR "${target}: SGX enclave edl file is not provided!")
    #     endif()
    #     if("${SGX_EDL_SEARCH_PATHS}" STREQUAL "")
    #         message("${target}: SGX enclave edl file search paths are not provided!")
    #     endif()
    #     set(EDL_U_SRCS "")
    #     foreach(EDL ${SGX_EDL})
    #         get_filename_component(EDL_NAME ${EDL} NAME_WE)
    #         get_filename_component(EDL_ABSPATH ${EDL} ABSOLUTE)
    #         set(EDL_U_C "${CMAKE_CURRENT_BINARY_DIR}/${EDL_NAME}_u.c")
    #         set(SEARCH_PATHS "")
    #         foreach(path ${SGX_EDL_SEARCH_PATHS})
    #             get_filename_component(ABSPATH ${path} ABSOLUTE)
    #             list(APPEND SEARCH_PATHS "${ABSPATH}")
    #         endforeach()
    #         list(APPEND SEARCH_PATHS "${SGX_PATH}/include")
    #         string(REPLACE ";" ":" SEARCH_PATHS "${SEARCH_PATHS}")
    #         if(${SGX_USE_PREFIX})
    #             set(USE_PREFIX "--use-prefix")
    #         endif()
    #         add_custom_command(OUTPUT ${EDL_U_C}
    #                            COMMAND ${SGX_EDGER8R} ${USE_PREFIX} --untrusted ${EDL_ABSPATH} --search-path ${SEARCH_PATHS}
    #                            MAIN_DEPENDENCY ${EDL_ABSPATH}
    #                            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

    #         list(APPEND EDL_U_SRCS ${EDL_U_C})
    #     endforeach()

    #     add_library(${target} ${mode} ${SGX_SRCS} ${EDL_U_SRCS})
    #     set_target_properties(${target} PROPERTIES COMPILE_FLAGS ${APP_CXX_FLAGS})
    #     target_include_directories(${target} PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${APP_INC_DIRS})
    #     target_link_libraries(${target} "${SGX_COMMON_CFLAGS} \
    #                                      -L${SGX_LIBRARY_PATH} \
    #                                      -l${SGX_URTS_LIB} \
    #                                      -l${SGX_USVC_LIB} \
    #                                      -lsgx_ukey_exchange \
    #                                      -lpthread")

    #     set_property(DIRECTORY APPEND PROPERTY ADDITIONAL_MAKE_CLEAN_FILES "${CMAKE_CURRENT_BINARY_DIR}/${EDL_NAME}_u.h")
    # endfunction()

    function(add_untrusted_executable target)
        set(optionArgs USE_PREFIX)
        set(oneValueArgs OPENSSL_LIBRARY_PATH)
        set(multiValueArgs SRCS EDL EDL_SEARCH_PATHS EXTRA_INCLUDE_DIRS EXTRA_LIB_DIRS EXTRA_OPTIONS_FLAGS EXTRA_LIBS)
        cmake_parse_arguments("SGX" "${optionArgs}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})
        if("${SGX_EDL}" STREQUAL "")
            message(FATAL_ERROR "${target}: SGX enclave edl file is not provided!")
        endif()
        # if("${SGX_EDL_SEARCH_PATHS}" STREQUAL "")
        #     message("${target}: SGX enclave edl file search paths are not provided!")
        # endif()
        if(NOT "${SGX_OPENSSL_LIBRARY_PATH}" STREQUAL "")
            # message("SGX_OPENSSL_LIBRARY_PATH provided ${SGX_OPENSSL_LIBRARY_PATH}")
            if(SGX_BUILD_TYPE STREQUAL "Debug")
                set(OPENSSL_SGX_SSL_LIBRARY_NAME "sgx_usgxssld")
            else()
                set(OPENSSL_SGX_SSL_LIBRARY_NAME "sgx_usgxssl")
            endif()
            set(OPENSSL_FLAGS "-L${SGX_OPENSSL_LIBRARY_PATH} -l${OPENSSL_SGX_SSL_LIBRARY_NAME} ")
            message("OPENSSL_FLAGS provided ${OPENSSL_FLAGS}")
        endif()
        if(NOT "${SGX_EXTRA_LIB_DIRS}" STREQUAL "")
            message("SGX_EXTRA_LIB_DIRS: ${SGX_EXTRA_LIB_DIRS}")
        endif()
        if(NOT "${SGX_EXTRA_INCLUDE_DIRS}" STREQUAL "")
            message("SGX_EXTRA_INCLUDE_DIRS: ${SGX_EXTRA_INCLUDE_DIRS}")
        endif()
        # if(NOT "${SGX_EXTRA_INCLUDE_DIRS}" STREQUAL "")
        #     message("SGX_EXTRA_INCLUDE_DIRS: ${SGX_EXTRA_INCLUDE_DIRS}")
        # endif()
        # if(NOT "${SGX_EXTRA_OPTIONS_FLAGS}" STREQUAL "")
        #     message("SGX_EXTRA_OPTIONS_FLAGS: ${SGX_EXTRA_OPTIONS_FLAGS}")
        # endif()             
        # if(NOT "${SGX_EXTRA_LIBS}" STREQUAL "")
        #     message("SGX_EXTRA_LIBS: ${SGX_EXTRA_LIBS}")
        # endif()             
        set(EDL_U_SRCS "")
        foreach(EDL ${SGX_EDL})
            get_filename_component(EDL_NAME ${EDL} NAME_WE)
            get_filename_component(EDL_ABSPATH ${EDL} ABSOLUTE)
            set(EDL_U_C "${CMAKE_CURRENT_BINARY_DIR}/${EDL_NAME}_u.c")
            set(EDL_U_H "${CMAKE_CURRENT_BINARY_DIR}/${EDL_NAME}_u.h")
            set(SEARCH_PATHS "")
            foreach(path ${SGX_EDL_SEARCH_PATHS})
                get_filename_component(ABSPATH ${path} ABSOLUTE)
                list(APPEND SEARCH_PATHS "${ABSPATH}")
            endforeach()
            list(APPEND SEARCH_PATHS "${SGX_PATH}/include")
            string(REPLACE ";" ":" SEARCH_PATHS "${SEARCH_PATHS}")
            if(${SGX_USE_PREFIX})
                set(USE_PREFIX "--use-prefix")
            endif()
            add_custom_command(OUTPUT ${EDL_U_C}
                               COMMAND ${SGX_EDGER8R} ${USE_PREFIX} --untrusted ${EDL_ABSPATH} --search-path ${SEARCH_PATHS}
                               MAIN_DEPENDENCY ${EDL_ABSPATH}
                               WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

            list(APPEND EDL_U_SRCS ${EDL_U_C})
            list(APPEND EDL_U_HDRS ${EDL_U_H})
        endforeach()
        set(EXTRA_BUILD_OBJECTS "")
        foreach(EBOBJ ${SGX_EXTRA_BUILD_OBJECTS})
            get_filename_component(EBOBJ_NAME ${EBOBJ} NAME_WE)
            get_filename_component(EBOBJ_ABSPATH ${EBOBJ} ABSOLUTE)
            set(EBOBJ_NAME "${EBOBJ_NAME}-${target}-ext-obj")
            add_library(${EBOBJ_NAME} OBJECT IMPORTED GLOBAL)
            set_target_properties(${EBOBJ_NAME} PROPERTIES IMPORTED_OBJECTS ${EBOBJ_ABSPATH})
            list(APPEND EXTRA_BUILD_OBJECTS ${EBOBJ_NAME})
        endforeach()

        # message("EXTRA_BUILD_OBJECTS   ======    ${EXTRA_BUILD_OBJECTS}")

        add_executable(${target} ${SGX_SRCS} ${EDL_U_SRCS})
        set( U_EXEC_CPP_FLAGS "-std=c++17 ${APP_CXX_FLAGS} ${SGX_EXTRA_OPTIONS_FLAGS} ")
        # message("U_EXEC_CPP_FLAGS : ${U_EXEC_CPP_FLAGS}")
        set_target_properties(${target} PROPERTIES COMPILE_FLAGS ${U_EXEC_CPP_FLAGS})
        target_include_directories(${target} PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${SGX_EXTRA_INCLUDE_DIRS} ${APP_INC_DIRS})
        target_link_directories(${target} PUBLIC ${SGX_EXTRA_LIB_DIRS})
        target_link_libraries(${target} "${SGX_COMMON_CFLAGS} \
                                         ${OPENSSL_FLAGS} \
                                         -L${SGX_LIBRARY_PATH} \
                                         -l${SGX_URTS_LIB} \
                                         -l${SGX_USVC_LIB} \
                                         -lcrypto -lwolfssl -lpthread"
                                         ${SGX_EXTRA_LIBS})
        set_property(DIRECTORY APPEND PROPERTY ADDITIONAL_MAKE_CLEAN_FILES ${EDL_U_HDRS})
    endfunction()

else(SGX_FOUND)
    message(WARNING "Intel SGX SDK not found!")
    if(SGX_FIND_REQUIRED)
        message(FATAL_ERROR "Could NOT find Intel SGX SDK!")
    endif()
endif(SGX_FOUND)
