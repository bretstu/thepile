"""Structural guard for the two-theme stylesheet.

Written because of a real bug: the dark block got inserted INSIDE :root,
orphaning --mono, --disp and --bw so they existed only in dark mode. The
page fell back to serif and the blocks lost their sizing. Every check
below corresponds to a way that can happen.
"""
import io, re, sys

PATH = sys.argv[1] if len(sys.argv) > 1 else "dashboard/index.html"
s = io.open(PATH, encoding="utf-8").read()
print(f"\nchecking {PATH}")
css = s[s.index("<style>"):s.index("</style>")]
fails = []


def check(label, ok, detail=""):
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}" + (f"  {detail}" if not ok else ""))
    if not ok:
        fails.append(label)


print("\nSTRUCTURE")
# :root must close BEFORE the dark block opens. If the dark selector appears
# inside the braces of :root, the file is broken in exactly last time's way.
root_start = css.index(":root{")
dark_start = css.index('html[data-theme="dark"]{')
depth, root_end = 0, None
for i in range(root_start, len(css)):
    if css[i] == "{":
        depth += 1
    elif css[i] == "}":
        depth -= 1
        if depth == 0:
            root_end = i
            break
check(":root closes before the dark block opens", root_end < dark_start,
      f"root ends at {root_end}, dark starts at {dark_start}")

depth, dark_end = 0, None
for i in range(dark_start, len(css)):
    if css[i] == "{":
        depth += 1
    elif css[i] == "}":
        depth -= 1
        if depth == 0:
            dark_end = i
            break
check("dark block is balanced", dark_end is not None)

root = css[root_start:root_end]
dark = css[dark_start:dark_end]

print("\nDEFINITIONS")
root_vars = set(re.findall(r"(--[a-z0-9-]+)\s*:", root))
dark_vars = set(re.findall(r"(--[a-z0-9-]+)\s*:", dark))
used = set(re.findall(r"var\((--[a-z0-9-]+)", s))
LOCAL = {"--c", "--d", "--tb", "--tintbg"}   # set per-component on .block

missing = sorted((used - LOCAL) - root_vars)
check("every var() used is defined in :root", not missing, str(missing))

# The three that broke last time, named explicitly so the failure is obvious.
for v in ("--mono", "--disp", "--bw"):
    check(f"{v} is in :root (not orphaned into dark)", v in root_vars)

orphaned = sorted(dark_vars - root_vars)
check("dark defines nothing that :root does not", not orphaned, str(orphaned))

print("\nTHEME COVERAGE")
# Anything theme-dependent must be a token. Literals in RULES are the leak.
rules = css[css.index("*{box-sizing"):]
lits = sorted(set(re.findall(r"#[0-9A-Fa-f]{6}", rules))
              | set(re.findall(r"rgba\([0-9]+,[0-9]+,[0-9]+", rules)))
# These sit against --void, which is dark in BOTH themes, so they are
# legitimately theme-independent.
ALLOWED = {"rgba(79,179,191", "rgba(232,227,213"}
leaks = [l for l in lits if l not in ALLOWED]
check("no theme-dependent literals left in rules", not leaks, str(leaks))

print("\nTOGGLE")
check("pre-paint script present", "thepile-theme" in s and s.index("thepile-theme") < s.index("<style>"))
check("toggle button in markup", 'id="themetoggle"' in s)
check("chart re-themes on toggle", "themeChart()" in s and "getComputedStyle" in s)
# Every chart must be hoisted to a module-level variable and re-themed on
# toggle. echarts bakes colours in at render time, so a chart that is not
# re-themed keeps the previous theme's ink — silently, and only for readers
# who use the toggle.
inits = re.findall(r"(\w+)\s*=\s*echarts\.init", s)
check("every echarts.init is hoisted to a variable",
      len(inits) == s.count("echarts.init"),
      f"{s.count('echarts.init')} inits, {len(inits)} assigned")
for name in set(inits):
    check(f"{name} is declared at module level", f"let {name} = null" in s)
    check(f"{name} is re-themed on toggle",
          s.count(f"{name}.setOption") >= 2,
          "rendered but never re-themed")

print("\n" + "=" * 46)
print(f"  {'ALL PASS' if not fails else str(len(fails)) + ' FAILED: ' + ', '.join(fails)}")
print("=" * 46 + "\n")
sys.exit(1 if fails else 0)
