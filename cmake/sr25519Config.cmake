
# find include


# find library
find_library(
    lib
    NAMES sr25519
    REQUIRED
)

find_path(
    include_path
    sr25519.h
    PATH_SUFFIXES sr25519/
    REQUIRED
)

add_library(sr25519 STATIC IMPORTED GLOBAL)

set_target_properties(sr25519 PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES ${include_path}
    IMPORTED_LOCATION ${lib}
    )
