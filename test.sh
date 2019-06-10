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

fail() {
	stop_server
	exit 1
}

send_request_using_proxy4() {
        VAL_PROXY4=$(curl -s -x socks4h://$HOST:$PORT $1)
}

send_request_using_proxy4a() {
        VAL_PROXY4A=$(curl -s -x socks4ah://$HOST:$PORT $1)
}

send_request_using_proxy5() {
	VAL_PROXY5=$(curl -s -x socks5h://$HOST:$PORT $1)
}

send_request_without_proxy() {
	VAL_WPROXY=$(curl -s $1)
}

check_ip_test4() {
	echo "4: Check ip test"
	send_request_using_proxy4 $GETIP
	send_request_without_proxy $GETIP
	if [ "$VAL_PROXY4" != "$VAL_WPROXY" ]; then
		fail
	fi
}

check_ip_test4a() {
        echo "4a: Check ip test"
        send_request_using_proxy4a $GETIP
        send_request_without_proxy $GETIP
        if [ "$VAL_PROXY4A" != "$VAL_WPROXY" ]; then
                fail
        fi
}

check_ip_test5() {
        echo "5: Check ip test"
        send_request_using_proxy5 $GETIP
        send_request_without_proxy $GETIP
        if [ "$VAL_PROXY5" != "$VAL_WPROXY" ]; then
                fail
        fi
}

stability_test4() {
	echo "4: Stability test"
	for i in {1..10};
	do send_request_using_proxy4 $GETIP && echo "Success";
	done;
}

stability_test4a() {
        echo "4a: Stability test"
        for i in {1..10};
        do send_request_using_proxy4a $GETIP && echo "Success";
        done;
}

stability_test5() {
        echo "5: Stability test"
        for i in {1..10};
        do send_request_using_proxy4a $GETIP && echo "Success";
        done;
}


rm $OUTLOG
start_server
stability_test4
stability_test4a
stability_test5
#check_ip_test4
#check_ip_test4a
#check_ip_test5
stop_server

echo "Server log:"
cat $OUTLOG
