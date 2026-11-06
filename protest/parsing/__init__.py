"""HTML understanding.

dom.py   A minimal DOM tree built on the standard library's html.parser. It behaves like the
         "html.parser" builder of BeautifulSoup, which matters for XSS checks: a payload only
         counts if it ends up as a real tag/attribute in a place where a browser would run it.
page.py  High-level helpers on top of the DOM: links, extra resources, meta/JavaScript
         redirections and HTML forms turned into ready-to-send Request objects.

Named "parsing" rather than "html" so it does not shadow Python's own ``html`` module.
"""
