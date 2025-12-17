Takes a jammed noun from stdin and prints it to stdout. 

Zero dependencies, zero includes. Works on macos, linux and windows.

Compiles with `clang main.c`, `gcc main.c` or `cl.exe main.c`.

`clang main.c -o cue`

`cat your-jamfile | ./cue`

Be ready to wait a while if you decide to print a noun with heavy structural sharing...
