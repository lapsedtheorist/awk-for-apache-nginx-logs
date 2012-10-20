Web server log file analysis & filtering
========================================

v1.2; Oct 2012
Ben Carpenter
http://www.bencarpenter.co.uk/awk-for-apache-nginx-logs

This awk script processes lines from a log format that matches the
'combined' log often used by the Apache and Nginx web servers. If your log
file format is different, amend accordingly, but for reference this is the
combined format this script expects by default:

	%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-agent}i"

	%h		Remote host
	%l		Remote logname (ignored)
	%u		Remote user (ignored)
	%t		Date and time of the request 
	%r		First line of the request, typically "GET /something HTTP/1.1"
	%>s		Status
	%b		Size of response in bytes

It tries to be efficient on resources, so there's minimal progress messages
and no system commands in the main loop other than writing to a file based
on the status code. The output files are written in a simplified
tab-separated format, error corrected for some strange things like spaces
in URLs and double quotes for the userid. This revised format is easier to
pass reliably through other awk scripts when filtering for specific data,
etc. The file format is:

	IP, Date/Time, Method, URL, Status, Size, Referer, User Agent

You should be able to send a large (>1GB) amount of log data through this
script quite comfortably. This works well for me, but usual clauses apply
(use it at your own risk, etc.). Bug reports and suggestions for
improvements are very welcome
