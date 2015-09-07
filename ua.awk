##
#	Web server log file analysis & filtering - anonymised user-agent data
#
#	v1.0; Sep 2015
#	Ben Carpenter
#	https://github.com/lapsedtheorist/awk-for-apache-nginx-logs
#
#	This awk script processes lines from a log format that matches the
#	'combined' log often used by the Apache and Nginx web servers. If your log
#	file format is different, amend accordingly, but for reference this is the
#	combined format this script expects by default:
#
#		%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-agent}i"
#
#		%h		Remote host
#		%l		Remote logname (ignored)
#		%u		Remote user (ignored)
#		%t		Date and time of the request
#		%r		First line of the request, typically "GET /something HTTP/1.1"
#		%>s		Status
#		%b		Size of response in bytes
#
#	It tries to be efficient on resources, so there's minimal progress messages
#	and no system commands in the main loop other than writing to a file based
#	on the status code. The output files are written in a simplified
#	tab-separated format, error corrected for some strange things like spaces
#	in URLs and double quotes for the userid. This revised format is easier to
#	pass reliably through other awk scripts when filtering for specific data,
#	etc. The file format is:
#
#		Date/Time, Method, Status, User Agent
#
#	You should be able to send a large (>1GB) amount of log data through this
#	script quite comfortably. This works well for me, but usual clauses apply
#	(use it at your own risk, etc.). Bug reports and suggestions for
#	improvements are very welcome
##
BEGIN {
	FS="( \"|\" )"
	intro="Processing..."
	printf "%s", intro
}

{
	split($1, a, " ")
	ip=a[1]
	# It seems some browsers/bots set the 'user' part to the blank string,
	# double quoted, which is therefore something that can foul our detection
	# for the status code, unless we explicitly look for it
	if($2!="") {
		datetime=a[4]" "a[5]
		request=$2
		referer=$4
		useragent=$5
		split($3, c, " ")
		code=c[1]
		size=c[2]
	} else {
		split($3, b, " ")
		datetime=b[2]" "b[3]
		request=$4
		referer=$6
		useragent=$7
		split($5, c, " ")
		code=c[1]
		size=c[2]
	}
	total=NR
	if(match(code, /^[0-9]+$/)==0) {
		# This status code, whatever it is, isn't a number so let's set it to
		# UNKNOWN so it's obvious in the analysis that this is a dud
		code="UNKNOWN"
	}

	# Analyse the request
	n=split(request, detail, " ")
	method=detail[1]
	if(match(method, /^[A-Z]+$/)==0) {
		# This request method, whatever it is, doesn't 'look like' a request
		# method, so let's set it to UNKNOWN so it's obvious in the analysis
		# that this is a dud
		method="UNKNOWN"
	}

	# Create a condensed file format containing UA data with a few extra
	# helpful, but still non-identifying, pieces of info
	file="http-anonymous-ua-full.log"
	printf "%s\t%s\t%d\t%s\n", \
		datetime, method, code, useragent > file

}

END {
	for(l=0; l<length(intro); l++) {
		printf "\b"
	}
	printf "%d requests filtered\n", \
		total

	# Close and compress the file
	file="http-anonymous-ua-full.log"
	close(file)
	system("gzip -f "file)
	system("du -sh "file".gz")
	
	printf "\n"
}
