
all: dell-xps13.cab lenovo-x1-carbon.cab

dell-xps13.bin: dell-xps13.ini intel-csme.ini intel-ucode.ini
	uswid --verbose --load $^ --save $@

lenovo-x1-carbon.bin: lenovo-x1-carbon.ini intel-csme.ini intel-ucode.ini
	uswid --verbose --load $^ --save $@

dell-xps13.cab: dell-xps13.bin dell-xps13.metainfo.xml
	gcab -c $@ $^

lenovo-x1-carbon.cab: lenovo-x1-carbon.bin lenovo-x1-carbon.metainfo.xml
	gcab -c $@ $^

clean:
	rm -f *.cab dell-xps13.bin lenovo-x1-carbon.bin
