find_package(GTest REQUIRED)

function(add_unit_test testname)
    add_executable(${testname} ${testname}.cpp)
    # target_include_directories(mpc_laplace_noise PUBLIC "${CMAKE_SOURCE_DIR}/include")
    target_link_libraries(${testname}
        mpc_laplace_noise
        # fmt::fmt
        GMP::GMP
        Boost::headers Boost::date_time Boost::regex Boost::system
        GTest::GTest
    )
    add_test(NAME ${testname}
        COMMAND ${testname}
    )
endfunction(add_unit_test testname)

add_unit_test(test_gmac)
add_unit_test(test_aes)
add_unit_test(test_hmac)
add_unit_test(test_binomial)
add_unit_test(test_laplace)