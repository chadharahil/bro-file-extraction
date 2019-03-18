# bro-file-extraction
Extract Files using Bro's Powerful Scripting Engine
This script can be used both against a pcap or in real-time (configuration needed)

Extracting files against a pcap:

__bro -r example.pcap bro-file-extraction.bro__

Extracting files in real-time:
1. Add the bro-file-extraction.bro script to a new directory under __/opt/bro/share/bro/policy/bro-file-extraction__
2. Add a file called \_\_load\_\_.bro to the same directory with the following content
__@load ./bro-file-extraction.bro__

3. Reference the bro-file-extraction.bro in __/opt/bro/share/bro/site/local.bro__ so that it will load the new scripts in
/opt/bro/share/bro/policy/custom-scripts, by adding __@load bro-file-extraction__ at the end of the file
4. Restart Bro
