#include "gtest/gtest.h"

int main(int argc, char **argv)
{
    testing::InitGoogleTest(&argc, argv);
	const int ret = RUN_ALL_TESTS();
    return ret;
}
