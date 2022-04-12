table_add MyIngress.forwarding forward 10.0.0.1 => 0
table_add MyIngress.forwarding forward 10.0.0.2 => 1
table_add MyIngress.forwarding forward 10.0.0.3 => 2
table_add MyIngress.filter_tcp_flags drop 0x02 =>