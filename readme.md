# VLP-16 数据格式

## PCAP 整体文件格式

VLP-16保存的文件是`.pcap` 格式，这是一种通用的格式，一般用于保存网络流数据。

一个`pcap` 文件主要包含两个部分，第一部分是24字节的头部，主要定义了文件的类型等信息，之后则是数据部分。每个`pcap`文件只有一个头部。之后的数据部分则是由 `帧头部`+`帧数据`构成。其中的帧头部是16字节，包括内容为：

- 4字节时间戳（精确到秒）

- 4字节时间戳（精确到微秒）

- 4字节理论长度（理论上之后的帧数据的长度）

- 4字节实际长度（实际上后面的帧数据长度）

整体的形式如下所示。

| `pcap`头部(24 Byte) | 帧头部-1(16 Byte) | 帧数据-1(N Byte) | 帧头部-2 | 帧数据-2 | 帧头部-3 | 帧数据-3 |
| ------------------- | ----------------- | ---------------- | -------- | -------- | -------- | -------- |

## 帧数据格式

每一帧数据实际上就是在网络上传输的一帧的所有数据。VLP雷达就是依靠UDP协议传输数据的，因此雷达的点云数据就保存在UDP数据里。根据网络模型可以知道，每一个帧数据中包含了：

- 14字节以太网头数据
- 至少20字节 IP头数据
- 8字节 UDP头数据
- N字节 UDP实际数据

## VLP 数据格式

根据以上可知，雷达每次扫描的结果就在这 N字节的UDP实际数据中。但并不是所有的N字节都是实际的扫描结果，之后以 "单回波模式"为例进行说明。其他模式的方法可以参考用户手册。

VLP雷达的一个基本数据单元称为 `Data block`, 每个 `Data block` 是100字节，每个UDP帧数据包含12个`Data block`，共1200字节。

此外，每个UDP帧数据还包含4字节的时间戳和2字节的 `Factory Bytes`。时间戳是第一个 `Data block` 中的第一个点发射的时间，记录的是当前这个小时已经过去了多少微秒。除以1000000可以得到秒。

`Fatcory Bytes` 则是用来确定雷达工作模式以及雷达型号的，因为不同的型号的雷达在计算扫描点的时候需要不同程度的矫正，根据这个型号就能确定应该用哪个矫正参数。对于VLP-16雷达来说，这个位置的数字为 `0x22`，HDL-32E雷达是 `0x21`,不同型号数字不同。同一型号的不同机器则是相同的ID。

然后再加上42字节的头数据，一共为1248字节 = 14 + 20 + 8 + 1200 + 4 + 2.整体的模式如下所示

| 以太网头 (14 Bytes) | IP头 (20 Bytes) | UDP头 (8 Bytes) | 12个 Data block (1200 Bytes) | 时间戳 (4 Bytes) | Mode (1 Byte) | ID (1 Byte) |
| ------------------- | --------------- | --------------- | ---------------------------- | ---------------- | ------------- | :---------: |

每个`Data block` 包含的内容如下

- 2字节的标志位 flag(固定为 `0xFFEE`)
- 2字节的旋转角度 $\alpha$ , 单位是 $0.01 ^ \circ$
- 32个点数据，每个点数据3字节。每个点数据包含2字节的距离，1字节的反射率。距离的单位是$2mm$，因此 $34987 = 69.974m$


