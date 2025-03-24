int x;

int foo(int a) {
    // Only True
    if (a < 0xffff)
        x+=0xaaaa;
    // True and False
    if (a > 0xfff)
        x+=0xaaa;
    // Only False
    if (a < 0xff)
        x+=0xaa;
}

int bar(int a) {
    // Neither
    if (a < 0xfffff)
        x+=0xaaaaa;
}

int main(void) {
    foo(0xfff-1);
    foo(0xfff+1);
    return x;
}
