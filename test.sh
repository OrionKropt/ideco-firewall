
echo "Test 1 Console input"

echo "10.0.1.11 1.1.1.1 132 33 7
 10.0.1.12 1.1.1.1 14640 5000 6 
 1.1.1.1 1.12.1.2 5000 14640 6
 10.0.1.11 1.1.1.1 3000 14640 6
 10.0.2.12 1.1.1.1 1111 1566 6
 10.0.2.12 8.8.8.8 5000 14640 6
 10.0.3.13 1.2.2.3 1234 4321 17
 10.0.2.12 1.2.3.4 3311 4312 17
 12.0.4.128/16  1.2.3.4 12 13 6
 1.1.1.128  10.0.9.1 999 1209 6
 10.0.5.0/24 10.0.11.1 1 10 17" | ./out

echo 
echo "Test 2 file input"

./out file
 
echo
echo "Test 3 Console input (FTP, NTP)"

echo "128.2.2.1 64.64.64.64 121 144 21
      128.2.1.2 41.0.0.0 1024 2048 27
      128.1.1.1 1.64.64.64 1 2 27" | ./out
