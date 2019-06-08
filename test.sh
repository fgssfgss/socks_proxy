HOST=127.0.0.1
PORT=1080
GETIP="https://2ip.ru"
PID=0
SERVER_NAME="proxy"
OUTLOG=log.txt
PASSED=0

start_server(){
	echo "Starting server"
	"./${SERVER_NAME}" &>$OUTLOG &disown;
	PID=$!
}

stop_server() {
	echo "Stopping server"
	kill -9 $PID
}

send_request_using_proxy() {
	VAL_PROXY=$(curl -s -x socks5h://$HOST:$PORT $1)
}

send_request_without_proxy() {
	VAL_WPROXY=$(curl -s $1)
}

check_ip_test() {
	echo "Check ip test"
	send_request_using_proxy $GETIP
	send_request_without_proxy $GETIP
	if [ "$VAL_PROXY" == "$VAL_WPROXY" ]; then
		PASSED=0
	else
		PASSED=1
	fi
}

stability_test() {
	echo "Stability test"
	for i in {1..10};
	do send_request_using_proxy $GETIP && echo "Success";
	done;
}

rm $OUTLOG
start_server
stability_test
check_ip_test
stop_server

echo "Server log:"
cat $OUTLOG
