# go-xdpdns

# Compile
  $make clean;  make

# Run
# attach to interface with DNS response rate limit per IP threshold by ratelimit/numcpus, you can also use systemctl with init.d script to start/stop the ratelimit program

  $sudo go-xdpdns --interface=interface-name --ratelimit=ratelimit-value --numcpus=nummber-of-cpus 

# Youtube Demo

[![XDP DNS Response Rate Limit](http://img.youtube.com/vi/LA8adgQACoI/0.jpg)](https://www.youtube.com/watch?v=LA8adgQACoI "XDP DNS Response Rate Limit")
