addtest(sign
    sign.cpp
    )
target_link_libraries(sign
    Boost::boost
    sr25519
    ${RND}
    )
