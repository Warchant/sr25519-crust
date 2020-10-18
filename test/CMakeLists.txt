# https://docs.hunter.sh/en/latest/packages/pkg/GTest.html
hunter_add_package(GTest)
find_package(GTest CONFIG REQUIRED)
find_package(GMock CONFIG REQUIRED)

if(TARGET schnorrkel_crust)
    message(INFO Found)
endif()

addtest(sr25519_test
        sr25519/ds.cpp
        sr25519/derive.cpp
        sr25519/keypair_from_seed.cpp
        sr25519/vrf.cpp
    )
target_link_libraries(sr25519_test
    schnorrkel_crust
    )

addtest(ed25519_test
        ed25519/test.cpp)
target_link_libraries(ed25519_test
    schnorrkel_crust
    )