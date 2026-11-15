"""Each README command block holds one lab step, so one paste cannot run the next.

Pasting a copied multi-line block into PowerShell runs all of its commands:
PSReadLine's Paste (Ctrl+V) puts the whole block into one input, and a console
right-click paste runs each line as its newline arrives
(about_PSReadLine_Functions, Paste). A block that holds a -WhatIf preview and
its real command therefore runs the real command before anyone has read the
preview, and a block that deploys the rules disabled and then reruns the
deployer with -EnableRules enables them before anyone has reviewed the queries.
These tests read README.md only; nothing runs.
"""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"

# A fence is three or more backticks or tildes (a backtick fence's info string
# has no backtick). It closes on a line of the same character, at least as long,
# with nothing after it; an unclosed block runs to the end of the file.
FENCE = re.compile(r"^\s*(`{3,}|~{3,})(.*)$")
# Words, with quoted text kept whole, and the separators that end a command.
TOKEN = re.compile(r"""(?:"[^"]*"|'[^']*'|[^\s"';&|]|&(?!&)|\|(?!\|))+|;|&&|\|\|""")
SEPARATORS = {";", "&&", "||"}
WHATIF_SWITCHES = {"-whatif", "-wi"}
ENABLE_SWITCHES = {"-enablerules", "-enablesentinelrules"}
# The scripts whose runs reach Azure, Entra or Microsoft Graph. Each run, a
# -WhatIf preview included, is one step and needs a block of its own.
STEP_SCRIPTS = {"deploy-lab.ps1", "test-sessionhijack.ps1"}

# The Quick Start block as README.md carried it at commit 1f4c3e7. One paste
# deployed the rules, enabled them, ran the helper, previewed the cleanup and
# then ran it.
COMBINED_QUICK_START = """\
git clone https://github.com/j-dahl7/session-hijack-detection-sentinel.git
cd session-hijack-detection-sentinel

# Creates the workbook and the five rules, disabled (safe default)
./scripts/Deploy-Lab.ps1 -ResourceGroup "rg-sentinel-lab" -WorkspaceName "law-sentinel-lab"

# After reviewing and tuning the queries, enable the rules explicitly
./scripts/Deploy-Lab.ps1 -ResourceGroup "rg-sentinel-lab" -WorkspaceName "law-sentinel-lab" -EnableRules
./scripts/Test-SessionHijack.ps1 -TenantId "<tenant-id>" -BurstCount 30

./scripts/Deploy-Lab.ps1 -ResourceGroup "rg-sentinel-lab" -WorkspaceName "law-sentinel-lab" -Destroy -WhatIf
./scripts/Deploy-Lab.ps1 -ResourceGroup "rg-sentinel-lab" -WorkspaceName "law-sentinel-lab" -Destroy
"""


def fenced_blocks(markdown):
    """Return (opening fence line number, body lines) for each fenced code block."""
    blocks, fence, start, body = [], None, 0, []
    for number, line in enumerate(markdown.splitlines(), 1):
        match = FENCE.match(line)
        if fence is None:
            if match and not (match.group(1)[0] == "`" and "`" in match.group(2)):
                fence, start, body = match.group(1), number, []
        elif (match and match.group(1)[0] == fence[0] and len(match.group(1)) >= len(fence)
              and not match.group(2).strip()):
            blocks.append((start, body))
            fence = None
        else:
            body.append(line)
    if fence is not None:
        blocks.append((start, body))
    return blocks


def drop_comment(line):
    """Cut a comment: a # that begins a word outside quotes."""
    quote = None
    for index, char in enumerate(line):
        if quote:
            if char == quote:
                quote = None
        elif char in "\"'":
            quote = char
        elif char == "#" and (index == 0 or line[index - 1].isspace()):
            return line[:index]
    return line


def is_switch(word, names):
    """True for -Name and -Name:$true; -Name:$false turns the switch off."""
    name, _, value = word.lower().partition(":")
    return name in names and value.strip("\"'") != "$false"


class Command:
    """One command from a block, reduced to what decides whether it may share it."""

    def __init__(self, words):
        if len(words) > 1 and words[0] in ("&", "."):
            words = words[1:]  # the call and dot-source operators
        self.text = " ".join(words)
        self.name = words[0].strip("\"'").replace("\\", "/").rsplit("/", 1)[-1].lower()
        self.preview = any(is_switch(word, WHATIF_SWITCHES) for word in words[1:])
        self.enables = any(is_switch(word, ENABLE_SWITCHES) for word in words[1:])
        # The same command without -WhatIf, compared without regard to case or quotes.
        self.real = (self.name,) + tuple(
            word.strip("\"'").lower() for word in words[1:]
            if word.lower().partition(":")[0] not in WHATIF_SWITCHES
        )


def commands(body):
    """Join lines continued with ` or \\, drop comments and return each command in a block."""
    lines, pending = [], ""
    for line in body:
        line = drop_comment(line).rstrip()
        if line.endswith(("`", "\\")):
            pending += line[:-1] + " "
        else:
            lines.append(pending + line)
            pending = ""
    lines.append(pending)
    found = []
    for line in lines:
        words = []
        for token in TOKEN.findall(line) + [";"]:
            if token in SEPARATORS:
                if words:
                    found.append(Command(words))
                words = []
            else:
                words.append(token)
    return found


def block_problems(found):
    """Return each reason the commands of one block must not share it."""
    problems = []
    for preview in (command for command in found if command.preview):
        if any(not command.preview and command.real == preview.real for command in found):
            problems.append(f"a -WhatIf preview and its real command: {preview.text}")
    if {command.enables for command in found if command.name == "deploy-lab.ps1"} == {True, False}:
        problems.append("Deploy-Lab.ps1 both without and with -EnableRules")
    steps = [command.text for command in found if command.name in STEP_SCRIPTS]
    if len(steps) > 1:
        problems.append(f"{len(steps)} lab steps: " + " | ".join(steps))
    return problems


class ReadmeCommandBlockTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.blocks = fenced_blocks(README.read_text(encoding="utf-8"))

    def test_each_readme_block_holds_at_most_one_lab_step(self):
        self.assertTrue(self.blocks, "README.md has no fenced code block")
        for start, body in self.blocks:
            with self.subTest(block=f"README.md line {start}"):
                self.assertEqual(block_problems(commands(body)), [])

    def test_previews_and_rule_enablement_follow_in_later_blocks(self):
        located = [(index, command) for index, (_, body) in enumerate(self.blocks)
                   for command in commands(body)]
        previews = [(index, command) for index, command in located if command.preview]
        self.assertTrue(previews, "the README shows no -WhatIf preview")
        for index, preview in previews:
            with self.subTest(preview=preview.text):
                real = [later for later, command in located
                        if not command.preview and command.real == preview.real]
                self.assertTrue(real, "the README never shows the command this previews")
                self.assertGreater(min(real), index, "the real command must come after its preview")

        deploys = [(index, command) for index, command in located
                   if command.name == "deploy-lab.ps1" and not command.preview]
        disabled = [index for index, command in deploys
                    if not command.enables and "-destroy" not in command.real]
        enabled = [index for index, command in deploys if command.enables]
        self.assertTrue(disabled and enabled, "the Quick Start deploys disabled and then enables")
        self.assertGreater(min(enabled), min(disabled),
                           "the rules are enabled only after a disabled deployment")

    def test_the_check_flags_the_combined_quick_start_block(self):
        # Keeps the check honest: it must reject the block that README.md
        # carried at 1f4c3e7, for each of the three reasons.
        problems = block_problems(commands(COMBINED_QUICK_START.splitlines()))
        self.assertEqual(len(problems), 3, problems)
        self.assertIn("a -WhatIf preview and its real command: ./scripts/Deploy-Lab.ps1", problems[0])
        self.assertTrue(problems[0].endswith("-Destroy -WhatIf"), problems[0])
        self.assertEqual(problems[1], "Deploy-Lab.ps1 both without and with -EnableRules")
        self.assertTrue(problems[2].startswith("5 lab steps: "), problems[2])

    def test_the_check_reads_commands_the_way_powershell_parses_them(self):
        # A backtick continues a line, # starts a comment, ; ends a command and
        # -WhatIf:$false is a real run. Case, quotes and \ or / in the script
        # path do not change which command it is.
        continued = commands([
            "./scripts/Deploy-Lab.ps1 -ResourceGroup 'rg-sentinel-lab' `",
            "  -WorkspaceName 'law-sentinel-lab' -Destroy -WhatIf  # preview only",
            ".\\scripts\\Deploy-Lab.ps1 -resourcegroup rg-sentinel-lab -workspacename law-sentinel-lab -destroy",
        ])
        self.assertEqual(len(continued), 2)
        self.assertIn("a -WhatIf preview and its real command", block_problems(continued)[0])
        self.assertEqual(len(commands(["./scripts/Deploy-Lab.ps1 -WhatIf; ./scripts/Deploy-Lab.ps1"])), 2)
        self.assertEqual(commands(["# ./scripts/Deploy-Lab.ps1 -Destroy"]), [])
        self.assertFalse(commands(["./scripts/Deploy-Lab.ps1 -WhatIf:$false"])[0].preview)
        self.assertTrue(commands(["./scripts/Deploy-Lab.ps1 -EnableSentinelRules"])[0].enables)
        self.assertEqual(block_problems(commands([COMBINED_QUICK_START.splitlines()[-1]])), [])


if __name__ == "__main__":
    unittest.main()
