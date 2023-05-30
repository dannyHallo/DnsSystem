case "$1" in
    1)
        ./DNSClient.out
        ;;
    2)
        ./LocalDNSServer.out
        ;;
    3)
        ./DNSServer.out rr3.txt 127.0.0.3
        ;;
    4)
        ./DNSServer.out rr4.txt 127.0.0.4
        ;;
    5)
        ./DNSServer.out rr5.txt 127.0.0.5
        ;;
    6)
        ./DNSServer.out rr6.txt 127.0.0.6
        ;;
    7)
        ./DNSServer.out rr7.txt 127.0.0.7
        ;;
    8)
        ./DNSServer.out rr8.txt 127.0.0.8
        ;;
    else)
        echo "Usage: $0 {1|2|3|4|5|6|7|8}"
        ;;
esac
