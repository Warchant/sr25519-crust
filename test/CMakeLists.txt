addtest(sr25519_test
    ds.cpp
    derive.cpp
    keypair_from_seed.cpp
    )
target_link_libraries(sr25519_test
    sr25519
    )
