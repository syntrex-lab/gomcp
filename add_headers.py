import os
import glob

HEADER = """// Copyright 2026 Syntrex Lab. All rights reserved.
// Use of this source code is governed by an Apache-2.0 license
// that can be found in the LICENSE file.

"""

def run():
    for filepath in glob.glob("**/*.go", recursive=True):
        if os.path.isfile(filepath):
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Skip if already has header
            if "Copyright 2026 Syntrex Lab" not in content:
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(HEADER + content)

if __name__ == '__main__':
    run()
