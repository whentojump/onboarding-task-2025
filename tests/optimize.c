// Example adapted from P24 of [1] (the original presentation uses -Ofast)
// [1] https://eascitech.eu.org/iwes/2020/documents/bagnara1/slides.pdf

#include <stdint.h>
#include <assert.h>
#include <stdio.h>

//----------------------------------------------------------------------------//
//                                                                            //
//                           Function under test                              //
//                                                                            //
//----------------------------------------------------------------------------//

uint64_t sum(uint32_t n)
__attribute__ ((optimize(0)));
                      // ^ force optimization level for this function alone
                      //   (only GCC recognizes this)

uint64_t sum(uint32_t n) {
    uint64_t total = 0;

    for (uint32_t i = 0; i < n; ++i)
        total += i & n;

    return total;
}

//----------------------------------------------------------------------------//
//                                                                            //
//                              "Test suite"                                  //
//                                                                            //
//----------------------------------------------------------------------------//

int main(void) {
    printf("Test (1/1): running\n");
    assert(
        sum(1) == 0
    );
    printf("Test (1/1): OK\n");
    return 0;
}
