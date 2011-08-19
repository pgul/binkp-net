
all:	nodelist/nodelist.db

nodelist/nodelist.db:	/ftp/pub/nodelist/[Nn][Oo][Dd][Ee][Ll][Ii][Ss][Tt].[Zz][0-9][0-9] nodelist_compile Makefile
	unzip -q -p $< | ./nodelist_compile $@

