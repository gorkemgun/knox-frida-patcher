import sys
import argparse
import rand
import elfcheck
import time

parser = argparse.ArgumentParser()
parser.add_argument('-b', '--binarypath', type=str, nargs='?', help='location of frida binary to patch (server or gadget)')
parser.add_argument('-o', '--output', type=str, nargs='?', help='output location for new binary')

args = parser.parse_args()
exclusions = []

if args.binarypath:
    frida_bin = args.binarypath
else:
    sys.exit(parser.print_help())

with open(frida_bin, 'rb') as f:
    data = bytearray(f.read())

original_size = len(data)

try:
    exclusions.append(data.index(b'/System/Library/Caches/') + len('/System'))
except Exception:
    pass


def find_and_replace(replacer, replacee="", startpos=0, endpos=0):
    match = replacer.encode('utf8')
    length = len(match)
    if replacee == '':
        val = rand.gen_random_name(length).encode('utf8')[startpos:]
    else:
        val = replacee.encode('utf8')[startpos:]
        if len(val) > length:
            raise Exception('[-] input length is higher than required')
        else:
            val += int.to_bytes(0, length - len(val), 'big')
    if endpos > 0:
        val = val[:-endpos]
    cur_index = 0

    while True:
        try:
            index = data.index(match, cur_index)
            cur_index = index + 1
            if index in exclusions:
                continue
        except Exception:
            break
        data[index + startpos: index + length - endpos] = val
        print("[*] patching: " + replacer + " at: " + str(hex(index)) + " with: " + val.decode("utf8"))


frida_string_to_patch = [
    "linjector",
    "gmain",
    "gum-js-loop",
    "re.frida.server",
    "frida-helper",
    "gdbus",
    "frida-agent",
    "pipe-",
    "GADGET",
    "gadget.so",
    "FRIDA",
    "AGENT",
    "frida-",
    "frida-agent-32.so",
    "frida-server",
    "frida-agent-64.so",
]

for value in frida_string_to_patch:
    find_and_replace(value)
    time.sleep(0.5)

find_and_replace('"frida"', startpos=1, endpos=1)

bin_name = args.output if args.output else '%s-modified' % frida_bin

with open(bin_name, 'wb') as f:
    f.write(data)

# Verify output size matches input (same-length replacements must not change size)
if len(data) != original_size:
    raise Exception("Size mismatch: input=%d output=%d" % (original_size, len(data)))
print("[*] size check: %d bytes OK" % len(data))

# Verify ELF structure of the patched binary
elfcheck.validate_binary(bin_name)
