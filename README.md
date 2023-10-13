# readme

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

