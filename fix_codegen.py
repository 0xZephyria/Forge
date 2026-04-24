import re

with open("src/codegen.zig", "r") as f:
    content = f.read()

# 1. Fix the pointless discard
content = content.replace("        _ = self;\n        // Allocate space for 8 saved regs + max spills", "        // Allocate space for 8 saved regs + max spills")

with open("src/codegen.zig", "w") as f:
    f.write(content)
