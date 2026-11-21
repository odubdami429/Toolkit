"""Slack-style emphasis rewritten into the Markdown Hermes's Slack adapter converts back to Slack bold."""

from __future__ import annotations

import importlib.util
from pathlib import Path

PATH = Path(__file__).resolve().parents[1] / "plugins" / "jarvis_guard" / "slack_format.py"
_spec = importlib.util.spec_from_file_location("slack_format_under_test", PATH)
sf = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sf)
fmt = sf.slack_to_markdown


def test_labels_become_markdown_bold():
    assert fmt("*Verdict:* Needs review — 88% confidence") == "**Verdict:** Needs review — 88% confidence"
    assert fmt("*Why:*\n• one\n• two") == "**Why:**\n• one\n• two"
    assert fmt("*Specialists used:* Insider risk") == "**Specialists used:** Insider risk"


def test_italics_bullets_and_markdown_bold_unchanged():
    for s in ("_Searched: all states, 90 days._", "• a\n• b", "**Already bold**", "- item\n* item", "———"):
        assert fmt(s) == s


def test_idempotent():
    s = "*Verdict:* Escalate\n_Searched:_ x\n*Why:*\n• `abc*def*`"
    assert fmt(fmt(s)) == fmt(s)


def test_arithmetic_globs_and_lone_asterisks_unchanged():
    for s in ("a*b*c", "2 * 3 * 4", "files *.dmg and *.pkg", "rated 5* by", "*", "** x **"):
        assert fmt(s) == s


def test_code_and_links_protected():
    assert fmt("run `*x*` now") == "run `*x*` now"
    assert fmt("```\n*not bold*\n```") == "```\n*not bold*\n```"
    url = "<https://console.irm.example.com/app/#/alerts/review-alerts/x_1_0|View in console>"
    assert fmt(url) == url
    assert fmt("<@U00000000A1> *Verdict:* x") == "<@U00000000A1> **Verdict:** x"
    assert fmt("<!subteam^S00000000G1> 1 of 1 needs an analyst") == "<!subteam^S00000000G1> 1 of 1 needs an analyst"
    assert fmt("[*a*](https://x/*y*)") == "[*a*](https://x/*y*)"


def test_slack_link_in_backticks_is_unwrapped():
    s = "went to `<mailto:someone@personal-mail.net|someone@personal-mail.net>`, signed in"
    assert fmt(s) == "went to <mailto:someone@personal-mail.net|someone@personal-mail.net>, signed in"
    assert fmt("`<https://x.example/a|label>`") == "<https://x.example/a|label>"
    assert fmt("`someone@example.com`") == "`someone@example.com`"


def test_bold_italic_and_inline_label():
    assert fmt("*_Personal account:_* text") == "**_Personal account:_** text"
    assert fmt("• *Not approved:* not in any group") == "• **Not approved:** not in any group"


def test_real_alert_reply_shape():
    reply = ("<!subteam^S00000000G1> 1 of 1 alerts needs an analyst.\n\n"
             "*Verdict:* Needs review — 88% confidence\n*Summary:* About 1 KB pasted into a personal AI-tool account.\n"
             "*Why:*\n• *Personal account:* `<mailto:p@personal-mail.net|p@personal-mail.net>`, classified `PERSONAL`\n"
             "*Next step:* Review the 5 open sessions.\n_Searched: all states, 90 days._\n\n"
             "*Specialists used:* Insider risk")
    out = fmt(reply)
    assert "*Verdict:*" not in out.replace("**Verdict:**", "")
    assert out.count("**") == 12
    assert "`<mailto:" not in out and "<mailto:p@personal-mail.net|p@personal-mail.net>" in out
    assert "`PERSONAL`" in out and "_Searched: all states, 90 days._" in out


def test_empty_and_plain():
    assert fmt("") == ""
    assert fmt("no emphasis here") == "no emphasis here"
