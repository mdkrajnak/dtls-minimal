find_package(PkgConfig)
pkg_check_modules(PC_libcoap QUIET libcoap-2)

# Note use of NO_DEFAULT_PATH to avoid name collision with system libcoap.
find_path(libcoap_INCLUDE_DIR
  NAMES coap2/coap.h
  PATHS {PC_libcoap_INCLUDE_DIRS} 
)

# Note use of NO_DEFAULT_PATH to avoid name collision with system libcoap.
find_library(libcoap_LIBRARY
  NAMES libcoap-2-openssl.so
  PATHS ${PC_libcoap_LIBRARY_DIRS} 
)

set(libcoap_VERSION ${PC_libcoap_VERSION})
mark_as_advanced(libcoap_FOUND libcoap_INCLUDE_DIR libcoap_VERSION)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(libcoap
  FOUND_VAR libcoap_FOUND
  REQUIRED_VARS
    libcoap_LIBRARY
    libcoap_INCLUDE_DIR
  VERSION_VAR libcoap_VERSION
)

if(libcoap_FOUND AND NOT TARGET libcoap::libcoap)
    add_library(libcoap::libcoap INTERFACE IMPORTED)
    set_target_properties(libcoap::libcoap PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES "${libcoap_INCLUDE_DIR}"
        INTERFACE_LINK_LIBRARIES "${libcoap_LIBRARY}"
    )
endif()
