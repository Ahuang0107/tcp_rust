# readme

## TUN/TAP(https://www.kernel.org/doc/Documentation/networking/tuntap.txt)

用空间户应用程序可以通过TUN/TAP直接从网络层或者数据链路层获取IP数据包或者以太帧

```text
3.2 Frame format:
  If flag IFF_NO_PI is not set each frame format is: 
     Flags [2 bytes]
     Proto [2 bytes]
     Raw protocol(IP, IPv6, etc) frame.
```

## 用到的命令

### ip

具体可以查看 https://access.redhat.com/sites/default/files/attachments/rh_ip_command_cheatsheet_1214_jcs_print.pdf

```shell
ip addr
```

### For Now

1. 授权程序 net 权限 `sudo setcap cap_net_admin=eip $CARGO_TARGET_DIR/release/tcp_rust`(
   不过因为我是root登录的所以不需要)
2. 运行程序
3. 给开启的 tun0 分配 ip 地址
4. 开始 tun0
5. 此时程序就能读取到一个 package 的数据

