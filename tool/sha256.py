#!/usr/bin/env python

import hashlib
import sys

if len(sys.argv) != 2:
    print 'usage: ', sys.argv[0], '<string-to-hash>'
    sys.exit()

h = hashlib.new('sha256')
h.update(sys.argv[1])
print h.hexdigest()
