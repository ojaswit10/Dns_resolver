#pragma once

// Tiny test helpers so tests need no external framework.
//
//   CHECK(a == b);
//   CHECK_THROWS(decode(bad), ParseError);
//   return dns::test::report();   // at the end of main()

#include <iostream>

namespace dns::test {

inline int& failures() {
    static int count = 0;
    return count;
}

inline int report() {
    if (failures() == 0) {
        std::cout << "all checks passed\n";
        return 0;
    }
    std::cout << failures() << " check(s) failed\n";
    return 1;
}

}  // namespace dns::test

#define CHECK(condition)                                                                 \
    do {                                                                                 \
        if (!(condition)) {                                                              \
            std::cerr << __FILE__ << ':' << __LINE__ << ": CHECK failed: " #condition "\n"; \
            ++dns::test::failures();                                                     \
        }                                                                                \
    } while (0)

#define CHECK_THROWS(expression, exception_type)                                                     \
    do {                                                                                             \
        bool thrown = false;                                                                         \
        try {                                                                                        \
            (void)(expression);                                                                      \
        } catch (const exception_type&) {                                                            \
            thrown = true;                                                                           \
        }                                                                                            \
        if (!thrown) {                                                                               \
            std::cerr << __FILE__ << ':' << __LINE__ << ": expected " #exception_type " from " #expression "\n"; \
            ++dns::test::failures();                                                                 \
        }                                                                                            \
    } while (0)
