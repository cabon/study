CC= gcc
TARGET= pcap

$(TARGET): pcap.c
	$(CC) -o  $(TARGET) pcap.c -lpcap

clean:
	rm -rf $(TARGET)
