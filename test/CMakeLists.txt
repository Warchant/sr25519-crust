# https://docs.hunter.sh/en/latest/packages/pkg/GTest.html
hunter_add_package(GTest)
find_package(GTest CONFIG REQUIRED)
find_package(GMock CONFIG REQUIRED)

addtest(sr25519_test
    ds.cpp
    derive.cpp
    keypair_from_seed.cpp
    )
target_link_libraries(sr25519_test
    sr25519
    )
