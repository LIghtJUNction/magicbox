# magicbox-dns-wire

该库编解码 DNS A 和 AAAA 报文。它只依赖 core 与 alloc，可在有分配器的 no_std 环境使用。调用方负责选择解析器、发送报文、验证传输身份和控制超时时间。

~~~rust
use magicbox_dns_wire::{answers, query, Error, RecordType};
use core::net::IpAddr;

let request = query("example.org", RecordType::A, 42).unwrap();
assert_eq!(&request[..2], &42u16.to_be_bytes());

fn decode_reply(received: &[u8]) -> Result<Vec<IpAddr>, Error> {
    answers(received, "example.org", RecordType::A, 42)
}
~~~

query 接受 ASCII 名称与可选末尾点，在分配报文前校验标签长度和总长度。answers 校验事务 ID、问题名称、记录类型和类别，支持压缩名称与 CNAME 链，返回最多 16 个属于目标的地址。每条回复上限为 16 KiB，最多处理 256 条回答记录。非法报文返回 Error，另一个名称的地址会被忽略。

在当前目录执行 cargo test --locked --offline 即可运行测试。主程序通过 Cargo 路径依赖调用同一实现。
