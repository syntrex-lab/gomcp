import os
import glob

def run():
    for ext in ["**/*.go", "Makefile"]:
        for filepath in glob.glob(ext, recursive=True):
            if os.path.isfile(filepath):
                with open(filepath, 'r', encoding='utf-8') as file:
                    content = file.read()
                if "github.com/syntrex/gomcp" in content:
                    content = content.replace("github.com/syntrex/gomcp", "github.com/syntrex-lab/gomcp")
                    with open(filepath, 'w', encoding='utf-8') as file:
                        file.write(content)
                    print(f"Updated {filepath}")

if __name__ == '__main__':
    run()
