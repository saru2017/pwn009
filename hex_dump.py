import sys

if len(sys.argv) != 2:
    print("usage: %s [filename]" % (sys.argv[0]))
    sys.exit()


f = open(sys.argv[1])



#c = sys.stdin.buffer.read(1)
c = f.buffer.read(1)
print(c)
while len(c) != 0:
    val = c[0]
    print("\\x%02x" % (val), end="")
    c = f.buffer.read(1)

f.close()

