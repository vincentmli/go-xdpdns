#! /bin/sh
### BEGIN INIT INFO
# Provides:          dns-rrl 
# Required-Start:    $network $remote_fs $syslog
# Required-Stop:     $network $remote_fs $syslog
# Default-Start:     5
# Default-Stop:      0 1 6
# Description: Starts dns response rate limiting configuration
# short-description: dns response rate limit configuration
### END INIT INFO

PATH=/bin:/usr/bin:/sbin:/usr/sbin
NAME=dns-rrl
DESC="DNS response rate limit"
SCRIPTNAME=/etc/init.d/$NAME
DEVICE=eno1
OBJ=/etc/init.d/xdp_rrl_per_ip.o
THRESHOLD=10


# load the VERBOSE setting and other rcS variables
. /lib/init/vars.sh

# include lsb functions
. /lib/lsb/init-functions

do_start () {

#	ip l set dev $DEVICE xdpgeneric obj $OBJ sec xdp > /dev/null 2>&1 || return 1
	/usr/local/bin/go-xdpdns --interface=$DEVICE --threshold=$THRESHOLD
}

# systemctl stop dns-rrl not working, run it ip l set dev <interface> xdp off at command line
# manually as workaround: Vincent 04-22-2023

# since using ebpf-go library go-xdpdns to pin the program, systemctl stop dns-rrl works by removing
# the pinned file forcefully, note there are few seconds "freezing" if ssh session on the same interface
# Vincent 05-03-2023

do_stop () {
	#ip l set dev $DEVICE xdp off > /dev/null 2>&1 || return 1
	/usr/bin/rm -rf /sys/fs/bpf/xdp-dnsrrl
}

COMMAND="$1"
[ "$COMMAND" ] && shift

case "$COMMAND" in
	start)
		[ "$VERBOSE" != no ] && log_daemon_msg "Starting $DESC" "$NAME"
		do_start 
		case "$?" in
			0) [ "$VERBOSE" != no ] && log_end_msg 0 ;;
			1) [ "$VERBOSE" != no ] && log_end_msg 1 ;;
			4) [ "$VERBOSE" != no ] && { log_progress_msg "disabled, see /etc/default/firehol" ; log_end_msg 255 ; } ;;
		esac
	;;

	stop)
		[ "$VERBOSE" != no ] && log_daemon_msg "Stopping $DESC" "$NAME"
		do_stop
		case "$?" in
			0) [ "$VERBOSE" != no ] && log_end_msg 0 ;;
			1) [ "$VERBOSE" != no ] && log_end_msg 1 ;;
		esac
	;;

	*)
	echo "Usage: $SCRIPTNAME {start|stop} [<args>]" >&2
	exit 3
	;;
esac

:

