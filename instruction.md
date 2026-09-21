The summariser in /app is wrong. It runs, but the report it writes does not match what
downstream expects.

Rebuild /app/out/report.json for the files under /app/data. The report is a JSON object with
a "files" array — one entry per .txt file, each with its "name" and its "words" count — ordered
by name, plus a "total_words" holding the sum of every word counted. It is indented by two
spaces and ends with a trailing newline.

Keep it driveable the way CI drives it: the program stays at /app/src/summarize.py and is run as
`python3 /app/src/summarize.py --data <dir> --out <file>`. CI points it at directories other
than the one shipped here.
