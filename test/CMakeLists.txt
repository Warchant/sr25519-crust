# https://docs.hunter.sh/en/latest/packages/pkg/GTest.html
hunter_add_package(GTest)
find_package(GTest CONFIG REQUIRED)
find_package(GMock CONFIG REQUIRED)

addtest(sr25519_test
        sr25519/ds.cpp
        sr25519/derive.cpp
        sr25519/keypair_from_seed.cpp
        sr25519/vrf.cpp
    )
target_link_libraries(sr25519_test
    sr25519
    )

addtest(ed25519_test)
target_link_libraries()