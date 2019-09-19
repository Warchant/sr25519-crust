#----------------------------------------------------------------
# Generated CMake target import file.
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "sr25519::sr25519" for configuration ""
set_property(TARGET sr25519::sr25519 APPEND PROPERTY IMPORTED_CONFIGURATIONS NOCONFIG)
set_target_properties(sr25519::sr25519 PROPERTIES
    IMPORTED_LINK_INTERFACE_LANGUAGES_NOCONFIG "C"
    IMPORTED_LOCATION_NOCONFIG "${_IMPORT_PREFIX}/lib/libsr25519crust.a"
    )

list(APPEND _IMPORT_CHECK_TARGETS sr25519::sr25519 )
list(APPEND _IMPORT_CHECK_FILES_FOR_sr25519::sr25519 "${_IMPORT_PREFIX}/lib/libsr25519crust.a" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
