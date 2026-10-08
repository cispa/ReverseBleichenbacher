FROM erlang:20.1.6 
# Vulnerable to CVE-2017-1000255
WORKDIR /server
CMD ["sh", "-c", "erl -compile my_simple_server; erl -noshell -s my_simple_server start > /dev/null 2>&1"]
