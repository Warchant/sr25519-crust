addtest(sign
    sign.cpp
    )
target_link_libraries(sign
    sr25519
    Boost::boost
    )
