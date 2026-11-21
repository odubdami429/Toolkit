"""Anthropic server-side web tools for specialists.

These run on Anthropic's side, inside the specialist's Messages API call: jarvis-tools never fetches a page, and
web_fetch only fetches URLs already present in the conversation, so the model can't build a URL that carries data
out. What does leave is the search query text, so every prompt that gets these tools says to search only for
public indicators. `max_uses` is per model request, a backstop under the prompt's own per-run caps.
"""

WEB_SEARCH = {"type": "web_search_20260209", "name": "web_search", "max_uses": 5}
WEB_FETCH = {"type": "web_fetch_20260209", "name": "web_fetch", "max_uses": 3, "max_content_tokens": 20000}
WEB_TOOLS = [WEB_SEARCH, WEB_FETCH]
