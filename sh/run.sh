case "$1" in
    1)
        ./DNSClient.out
        ;;
    2)
        ./LocalDNSServer.out
        ;;
    3)
        ./DNSServer.out
        ;;
    *)
        echo "Usage: $0 {1|2|3}"
        exit 1
        ;;
esac
