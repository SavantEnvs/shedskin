# Known-answer program for the shedskin oracle: translated to C++ by shedskin at build time, compiled
# against the runtime, and checked line by line by test.sh.
import re
import struct
import heapq
import bisect
import binascii
import base64
import datetime
import csv
import configparser
import io


def main():
    s = 'Hello, World'
    print('str.center', s.center(20, '*'))
    print('str.ljust', s.ljust(15, '-') + '|')
    print('str.rjust', s.rjust(15, '.'))
    print('str.count', s.count('o'), s.count(''), 'aaaa'.count('aa'))
    print('str.find', s.find('o'), s.rfind('o'), s.find('o', -4), s.find('zz'))
    print('str.replace', s.replace('l', 'L', 2))
    print('str.split', s.split(', '), 'a,b,,c'.split(','), ' a  b '.split())
    print('str.join', '-'.join(['x', 'y', 'z']))
    print('str.misc', s.upper(), s.lower(), s.swapcase(), s[::-1], s[2:7])
    print('bytes', b'abcabc'.count(b'bc'), b'abc'.center(7, b'.'), b'xyz'.hex())
    print('format', '%5d|%-5d|%05.1f|%s|%x|%r' % (42, 42, 3.14159, 'abc', 255, 'q'))
    print('format2', '{} {:>6} {:<6}| {:08.3f}'.format(1, 'ab', 'cd', 2.5))

    print('re.search', re.search(r'(\d+)-(\d+)', 'tel 555-1234 x').groups())
    print('re.sub', re.sub(r'\s+', '_', 'a b   c\td'))
    print('re.subn', re.subn(r'a', 'X', 'banana'))
    print('re.findall', re.findall(r'[a-z]+', 'ab1cd22ef'))
    print('re.split', re.split(r'[,;]', 'a,b;c'))

    print('struct.pack', binascii.hexlify(struct.pack('<hIq', -2, 7, 1 << 40)).decode())
    u1, u2, u3 = struct.unpack('>HBb', b'\x01\x02\x03\xff')
    print('struct.unpack', u1, u2, u3)
    print('struct.calcsize', struct.calcsize('<hIq'))

    h = [5, 1, 4, 2, 3]
    heapq.heapify(h)
    out = []
    while h:
        out.append(heapq.heappop(h))
    print('heapq', out)
    print('nlargest', heapq.nlargest(2, [3, 9, 1, 7]))
    a = [1, 3, 5, 7]
    print('bisect', bisect.bisect_left(a, 5), bisect.bisect_right(a, 5), bisect.bisect(a, 0))

    print('base64', base64.b64encode(b'shedskin'), base64.b64decode('c2hlZHNraW4='))
    print('binascii', binascii.crc32(b'hello'), binascii.hexlify(b'\x00\xff'))

    d = datetime.datetime(2024, 2, 29, 13, 5, 9)
    print('datetime', d.isoformat(), (d + datetime.timedelta(days=1, hours=12)).isoformat())
    print('fromiso', datetime.datetime.fromisoformat('2021-03-04T05:06:07.250').microsecond)
    print('date', datetime.date(2000, 1, 1).weekday(), str(datetime.timedelta(seconds=3725)))

    rows = list(csv.reader(['a,"b,c",d', '1,2,3']))
    print('csv', rows)
    cp = configparser.ConfigParser()
    cp.read_string('[sec]\nk = v\nn = 42\nf = %(k)s-x\n')
    print('configparser', cp.get('sec', 'k'), cp.getint('sec', 'n'), cp.get('sec', 'f'))

    lst = [1, 2, 3]
    lst.extend(lst)
    print('list', lst, sorted([3, 1, 2], reverse=True), lst.index(3))
    dd = {'a': 1, 'b': 2}
    print('dict', sorted(dd.items()), len(dd))
    f = io.StringIO()
    f.write('xyz')
    print('io', f.getvalue())


main()
