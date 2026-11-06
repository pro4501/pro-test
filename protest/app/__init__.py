"""User interfaces.

cli.py   Command-line front end. Parses options (argparse), applies the scan profile, builds the
         HTTP client, then runs the whole pipeline: crawl -> passive checks -> active attacks -> report.
         Its run() function is the best place to start reading the code: it calls every layer in order.

menu.py  Interactive menu (URL -> attacks + settings -> weaknesses found -> "What next?"). It builds
         the same options the command line would and calls cli.run(), then reads the findings back
         from the SQLite session to display them.
"""
