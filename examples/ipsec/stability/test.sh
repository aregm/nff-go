# instruction for crypt library in DPDK: https://doc.dpdk.org/guides/cryptodevs/aesni_mb.html
# instruction for ipsec application: https://doc.dpdk.org/guides/sample_app_ug/ipsec_secgw.html
./build/ipsec-secgw -l 4,5 -n 4 --socket-mem 0,1024 --vdev "crypto_aesni_mb" -- -p 0xf -P -u 0x2 --config="(0,0,4),(1,0,5)" -f test.conf
