//nat64自动填充proxyip，无需且不支持proxyip设置
import { connect } from "cloudflare:sockets";
const WS_READY_STATE_OPEN = 1;
let userID = "86c50e3a-5b87-49dd-bd20-03c7f2735e40";
const cn_hostnames = [''];
let CDNIP = '\u0077\u0077\u0077\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d\u002e\u0073\u0067'
// http_ip
let IP1 = '\u0077\u0077\u0077\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d'
let IP2 = '\u0063\u0069\u0073\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d'
let IP3 = '\u0061\u0066\u0072\u0069\u0063\u0061\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d'
let IP4 = '\u0077\u0077\u0077\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d\u002e\u0073\u0067'
let IP5 = '\u0077\u0077\u0077\u002e\u0076\u0069\u0073\u0061\u0065\u0075\u0072\u006f\u0070\u0065\u002e\u0061\u0074'
let IP6 = '\u0077\u0077\u0077\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d\u002e\u006d\u0074'
let IP7 = '\u0071\u0061\u002e\u0076\u0069\u0073\u0061\u006d\u0069\u0064\u0064\u006c\u0065\u0065\u0061\u0073\u0074\u002e\u0063\u006f\u006d'

// https_ip
let IP8 = '\u0075\u0073\u0061\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d'
let IP9 = '\u006d\u0079\u0061\u006e\u006d\u0061\u0072\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d'
let IP10 = '\u0077\u0077\u0077\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d\u002e\u0074\u0077'
let IP11 = '\u0077\u0077\u0077\u002e\u0076\u0069\u0073\u0061\u0065\u0075\u0072\u006f\u0070\u0065\u002e\u0063\u0068'
let IP12 = '\u0077\u0077\u0077\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d\u002e\u0062\u0072'
let IP13 = '\u0077\u0077\u0077\u002e\u0076\u0069\u0073\u0061\u0073\u006f\u0075\u0074\u0068\u0065\u0061\u0073\u0074\u0065\u0075\u0072\u006f\u0070\u0065\u002e\u0063\u006f\u006d'

// http_port
let PT1 = '80'
let PT2 = '8080'
let PT3 = '8880'
let PT4 = '2052'
let PT5 = '2082'
let PT6 = '2086'
let PT7 = '2095'

// https_port
let PT8 = '443'
let PT9 = '8443'
let PT10 = '2053'
let PT11 = '2083'
let PT12 = '2087'
let PT13 = '2096'

export default {
    /**
     * @param {any} request
     * @param {{uuid: string, proxyip: string, cdnip: string, ip1: string, ip2: string, ip3: string, ip4: string, ip5: string, ip6: string, ip7: string, ip8: string, ip9: string, ip10: string, ip11: string, ip12: string, ip13: string, pt1: string, pt2: string, pt3: string, pt4: string, pt5: string, pt6: string, pt7: string, pt8: string, pt9: string, pt10: string, pt11: string, pt12: string, pt13: string}} env
     * @param {any} ctx
     * @returns {Promise<Response>}
     */
    async fetch(request, env, ctx) {
        try {
            userID = env.uuid || userID;
            CDNIP = env.cdnip || CDNIP;
            IP1 = env.ip1 || IP1;
            IP2 = env.ip2 || IP2;
            IP3 = env.ip3 || IP3;
            IP4 = env.ip4 || IP4;
            IP5 = env.ip5 || IP5;
            IP6 = env.ip6 || IP6;
            IP7 = env.ip7 || IP7;
            IP8 = env.ip8 || IP8;
            IP9 = env.ip9 || IP9;
            IP10 = env.ip10 || IP10;
            IP11 = env.ip11 || IP11;
            IP12 = env.ip12 || IP12;
            IP13 = env.ip13 || IP13;
            PT1 = env.pt1 || PT1;
            PT2 = env.pt2 || PT2;
            PT3 = env.pt3 || PT3;
            PT4 = env.pt4 || PT4;
            PT5 = env.pt5 || PT5;
            PT6 = env.pt6 || PT6;
            PT7 = env.pt7 || PT7;
            PT8 = env.pt8 || PT8;
            PT9 = env.pt9 || PT9;
            PT10 = env.pt10 || PT10;
            PT11 = env.pt11 || PT11;
            PT12 = env.pt12 || PT12;
            PT13 = env.pt13 || PT13;
            const upgradeHeader = request.headers.get("Upgrade");
            const url = new URL(request.url);
            if (!upgradeHeader || upgradeHeader !== "websocket") {
                const url = new URL(request.url);
                switch (url.pathname) {
                    case `/${userID}`: {
                        const vlessConfig = get\u0076\u006c\u0065\u0073\u0073Config(userID, request.headers.get("Host"));
                        return new Response(vlessConfig, {
                            status: 200,
                            headers: {
                                "Content-Type": "text/html;charset=utf-8",
                            },
                        });
                    }
                    case `/${userID}/ty`: {
                        const tyConfig = gettyConfig(userID, request.headers.get('Host'));
                        return new Response(`${tyConfig}`, {
                            status: 200,
                            headers: {
                                "Content-Type": "text/plain;charset=utf-8",
                            }
                        });
                    }
                    case `/${userID}/cl`: {
                        const clConfig = getclConfig(userID, request.headers.get('Host'));
                        return new Response(`${clConfig}`, {
                            status: 200,
                            headers: {
                                "Content-Type": "text/plain;charset=utf-8",
                            }
                        });
                    }
                    case `/${userID}/sb`: {
                        const sbConfig = getsbConfig(userID, request.headers.get('Host'));
                        return new Response(`${sbConfig}`, {
                            status: 200,
                            headers: {
                                "Content-Type": "application/json;charset=utf-8",
                            }
                        });
                    }
                    case `/${userID}/pty`: {
                        const ptyConfig = getptyConfig(userID, request.headers.get('Host'));
                        return new Response(`${ptyConfig}`, {
                            status: 200,
                            headers: {
                                "Content-Type": "text/plain;charset=utf-8",
                            }
                        });
                    }
                    case `/${userID}/pcl`: {
                        const pclConfig = getpclConfig(userID, request.headers.get('Host'));
                        return new Response(`${pclConfig}`, {
                            status: 200,
                            headers: {
                                "Content-Type": "text/plain;charset=utf-8",
                            }
                        });
                    }
                    case `/${userID}/psb`: {
                        const psbConfig = getpsbConfig(userID, request.headers.get('Host'));
                        return new Response(`${psbConfig}`, {
                            status: 200,
                            headers: {
                                "Content-Type": "application/json;charset=utf-8",
                            }
                        });
                    }
                    default:
                        if (cn_hostnames.includes('')) {
                            return new Response(JSON.stringify(request.cf, null, 4), {
                                status: 200,
                                headers: {
                                    "Content-Type": "application/json;charset=utf-8",
                                },
                            });
                        }
                        const randomHostname = cn_hostnames[Math.floor(Math.random() * cn_hostnames.length)];
                        const newHeaders = new Headers(request.headers);
                        newHeaders.set("cf-connecting-ip", "1.2.3.4");
                        newHeaders.set("x-forwarded-for", "1.2.3.4");
                        newHeaders.set("x-real-ip", "1.2.3.4");
                        newHeaders.set("referer", "https://www.google.com/search?q=edtunnel");
                        const proxyUrl = "https://" + randomHostname + url.pathname + url.search;
                        let modifiedRequest = new Request(proxyUrl, {
                            method: request.method,
                            headers: newHeaders,
                            body: request.body,
                            redirect: "manual",
                        });
                        const proxyResponse = await fetch(modifiedRequest, {
                            redirect: "manual"
                        });
                        if ([301, 302].includes(proxyResponse.status)) {
                            return new Response(`Redirects to ${randomHostname} are not allowed.`, {
                                status: 403,
                                statusText: "Forbidden",
                            });
                        }
                        return proxyResponse;
                }
            }
            return await handle\u0076\u006c\u0065\u0073\u0073WebSocket(request);
        } catch (err) {
            /** @type {Error} */
            let e = err;
            return new Response(e.toString());
        }
    },
};

async function handle\u0076\u006c\u0065\u0073\u0073WebSocket(request) {
    const wsPair = new WebSocketPair();
    const [clientWS, serverWS] = Object.values(wsPair);

    serverWS.accept();

    const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
    const wsReadable = createWebSocketReadableStream(serverWS, earlyDataHeader);
    let remoteSocket = null;

    let udpStreamWrite = null;
    let isDns = false;

    wsReadable.pipeTo(new WritableStream({
        async write(chunk) {

            if (isDns && udpStreamWrite) {
                return udpStreamWrite(chunk);
            }

            if (remoteSocket) {
                const writer = remoteSocket.writable.getWriter();
                await writer.write(chunk);
                writer.releaseLock();
                return;
            }

            const result = parse\u0076\u006c\u0065\u0073\u0073Header(chunk, userID);
            if (result.hasError) {
                throw new Error(result.message);
            }

            const vlessRespHeader = new Uint8Array([result.vlessVersion[0], 0]);
            const rawClientData = chunk.slice(result.rawDataIndex);

            if (result.isUDP) {
                if (result.portRemote === 53) {
                    isDns = true;
                    const {
                        write
                    } = await handleUDPOutBound(serverWS, vlessRespHeader);
                    udpStreamWrite = write;
                    udpStreamWrite(rawClientData);
                    return;
                } else {
                    throw new Error('UDP代理仅支持DNS(端口53)');
                }
            }

            async function connectAndWrite(address, port) {
                const tcpSocket = await connect({
                    hostname: address,
                    port: port
                });
                remoteSocket = tcpSocket;
                const writer = tcpSocket.writable.getWriter();
                await writer.write(rawClientData);
                writer.releaseLock();
                return tcpSocket;
            }

            function convertToNAT64IPv6(ipv4Address) {
                const parts = ipv4Address.split('.');
                if (parts.length !== 4) {
                    throw new Error('无效的IPv4地址');
                }

                const hex = parts.map(part => {
                    const num = parseInt(part, 10);
                    if (num < 0 || num > 255) {
                        throw new Error('无效的IPv4地址段');
                    }
                    return num.toString(16).padStart(2, '0');
                });
                const prefixes = ['2001:67c:2960:6464::'];
                const chosenPrefix = prefixes[Math.floor(Math.random() * prefixes.length)];
                return `[${chosenPrefix}${hex[0]}${hex[1]}:${hex[2]}${hex[3]}]`;
            }

            async function getIPv6ProxyAddress(domain) {
                try {
                    const dnsQuery = await fetch(`https://1.1.1.1/dns-query?name=${domain}&type=A`, {
                        headers: {
                            'Accept': 'application/dns-json'
                        }
                    });

                    const dnsResult = await dnsQuery.json();
                    if (dnsResult.Answer && dnsResult.Answer.length > 0) {
                        const aRecord = dnsResult.Answer.find(record => record.type === 1);
                        if (aRecord) {
                            const ipv4Address = aRecord.data;
                            return convertToNAT64IPv6(ipv4Address);
                        }
                    }
                    throw new Error('无法解析域名的IPv4地址');
                } catch (err) {
                    throw new Error(`DNS解析失败: ${err.message}`);
                }
            }

            async function retry() {
                try {
                    const proxyIP = await getIPv6ProxyAddress(result.addressRemote);
                    console.log(`尝试通过NAT64 IPv6地址 ${proxyIP} 连接...`);
                    const tcpSocket = await connect({
                        hostname: proxyIP,
                        port: result.portRemote
                    });
                    remoteSocket = tcpSocket;
                    const writer = tcpSocket.writable.getWriter();
                    await writer.write(rawClientData);
                    writer.releaseLock();

                    tcpSocket.closed.catch(error => {
                        console.error('NAT64 IPv6连接关闭错误:', error);
                    }).finally(() => {
                        if (serverWS.readyState === WS_READY_STATE_OPEN) {
                            serverWS.close(1000, '连接已关闭');
                        }
                    });

                    pipeRemoteToWebSocket(tcpSocket, serverWS, vlessRespHeader, null);
                } catch (err) {
                    console.error('NAT64 IPv6连接失败:', err);
                    serverWS.close(1011, 'NAT64 IPv6连接失败: ' + err.message);
                }
            }

            try {
                const tcpSocket = await connectAndWrite(result.addressRemote, result.portRemote);
                pipeRemoteToWebSocket(tcpSocket, serverWS, vlessRespHeader, retry);
            } catch (err) {
                console.error('连接失败:', err);
                serverWS.close(1011, '连接失败');
            }
        },
        close() {
            if (remoteSocket) {
                closeSocket(remoteSocket);
            }
        }
    })).catch(err => {
        console.error('WebSocket 错误:', err);
        closeSocket(remoteSocket);
        serverWS.close(1011, '内部错误');
    });

    return new Response(null, {
        status: 101,
        webSocket: clientWS,
    });
}

function createWebSocketReadableStream(ws, earlyDataHeader) {
    return new ReadableStream({
        start(controller) {
            ws.addEventListener('message', event => {
                controller.enqueue(event.data);
            });

            ws.addEventListener('close', () => {
                controller.close();
            });

            ws.addEventListener('error', err => {
                controller.error(err);
            });

            if (earlyDataHeader) {
                try {
                    const decoded = atob(earlyDataHeader.replace(/-/g, '+').replace(/_/g, '/'));
                    const data = Uint8Array.from(decoded, c => c.charCodeAt(0));
                    controller.enqueue(data.buffer);
                } catch (e) {}
            }
        }
    });
}

function parse\u0076\u006c\u0065\u0073\u0073Header(buffer, userID) {
    if (buffer.byteLength < 24) {
        return {
            hasError: true,
            message: '无效的头部长度'
        };
    }

    const view = new DataView(buffer);
    const version = new Uint8Array(buffer.slice(0, 1));

    const uuid = formatUUID(new Uint8Array(buffer.slice(1, 17)));
    if (uuid !== userID) {
        return {
            hasError: true,
            message: '无效的用户'
        };
    }

    const optionsLength = view.getUint8(17);
    const command = view.getUint8(18 + optionsLength);

    let isUDP = false;
    if (command === 1) {

    } else if (command === 2) {

        isUDP = true;
    } else {
        return {
            hasError: true,
            message: '不支持的命令，仅支持TCP(01)和UDP(02)'
        };
    }

    let offset = 19 + optionsLength;
    const port = view.getUint16(offset);
    offset += 2;

    const addressType = view.getUint8(offset++);
    let address = '';

    switch (addressType) {
        case 1: // IPv4
            address = Array.from(new Uint8Array(buffer.slice(offset, offset + 4))).join('.');
            offset += 4;
            break;

        case 2: // 域名
            const domainLength = view.getUint8(offset++);
            address = new TextDecoder().decode(buffer.slice(offset, offset + domainLength));
            offset += domainLength;
            break;

        case 3: // IPv6
            const ipv6 = [];
            for (let i = 0; i < 8; i++) {
                ipv6.push(view.getUint16(offset).toString(16).padStart(4, '0'));
                offset += 2;
            }
            address = ipv6.join(':').replace(/(^|:)0+(\w)/g, '$1$2');
            break;

        default:
            return {
                hasError: true,
                message: '不支持的地址类型'
            };
    }

    return {
        hasError: false,
        addressRemote: address,
        portRemote: port,
        rawDataIndex: offset,
        vlessVersion: version,
        isUDP
    };
}

function pipeRemoteToWebSocket(remoteSocket, ws, vlessHeader, retry = null) {
    let headerSent = false;
    let hasIncomingData = false;

    remoteSocket.readable.pipeTo(new WritableStream({
        write(chunk) {
            hasIncomingData = true;
            if (ws.readyState === WS_READY_STATE_OPEN) {
                if (!headerSent) {
                    const combined = new Uint8Array(vlessHeader.byteLength + chunk.byteLength);
                    combined.set(new Uint8Array(vlessHeader), 0);
                    combined.set(new Uint8Array(chunk), vlessHeader.byteLength);
                    ws.send(combined.buffer);
                    headerSent = true;
                } else {
                    ws.send(chunk);
                }
            }
        },
        close() {
            if (!hasIncomingData && retry) {
                retry();
                return;
            }
            if (ws.readyState === WS_READY_STATE_OPEN) {
                ws.close(1000, '正常关闭');
            }
        },
        abort() {
            closeSocket(remoteSocket);
        }
    })).catch(err => {
        console.error('数据转发错误:', err);
        closeSocket(remoteSocket);
        if (ws.readyState === WS_READY_STATE_OPEN) {
            ws.close(1011, '数据传输错误');
        }
    });
}

function closeSocket(socket) {
    if (socket) {
        try {
            socket.close();
        } catch (e) {}
    }
}

function formatUUID(bytes) {
    const hex = Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
    return `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`;
}

async function handleUDPOutBound(webSocket, vlessResponseHeader) {
    let isVlessHeaderSent = false;
    const transformStream = new TransformStream({
        start(controller) {},
        transform(chunk, controller) {
            for (let index = 0; index < chunk.byteLength;) {
                const lengthBuffer = chunk.slice(index, index + 2);
                const udpPacketLength = new DataView(lengthBuffer).getUint16(0);
                const udpData = new Uint8Array(
                    chunk.slice(index + 2, index + 2 + udpPacketLength)
                );
                index = index + 2 + udpPacketLength;
                controller.enqueue(udpData);
            }
        },
        flush(controller) {}
    });

    transformStream.readable.pipeTo(new WritableStream({
        async write(chunk) {
            const resp = await fetch('https://1.1.1.1/dns-query', {
                method: 'POST',
                headers: {
                    'content-type': 'application/dns-message',
                },
                body: chunk,
            })
            const dnsQueryResult = await resp.arrayBuffer();
            const udpSize = dnsQueryResult.byteLength;
            const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);

            if (webSocket.readyState === WS_READY_STATE_OPEN) {
                console.log(`DNS查询成功，DNS消息长度为 ${udpSize}`);
                if (isVlessHeaderSent) {
                    webSocket.send(await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer());
                } else {
                    webSocket.send(await new Blob([vlessResponseHeader, udpSizeBuffer, dnsQueryResult]).arrayBuffer());
                    isVlessHeaderSent = true;
                }
            }
        }
    })).catch((error) => {
        console.error('DNS UDP处理错误:', error);
    });

    const writer = transformStream.writable.getWriter();

    return {
        write(chunk) {
            writer.write(chunk);
        }
    };
}

/**
 * @param {string} userID
 * @param {string | null} hostName
 * @returns {string}
 */
function get\u0076\u006c\u0065\u0073\u0073Config(userID, hostName) {
    // VLESS
    const vlessWs = `vless://${userID}@${CDNIP}:8880?encryption=none&security=none&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#${hostName}`;
    const vlessWsTls = `vless://${userID}@${CDNIP}:8443?encryption=none&security=tls&type=ws&host=${hostName}&sni=${hostName}&fp=random&path=%2F%3Fed%3D2560#${hostName}`;

    // Subscription Links
    const note = `甬哥博客地址：https://ygkkk.blogspot.com\\n甬哥YouTube频道：https://www.youtube.com/@ygkkk\n甬哥TG电报群组：https://t.me/ygkkktg\n甬哥TG电报频道：https://t.me/ygkkktgpd\n\nProxyIP使用nat64自动生成，无需设置`;
    const ty = `https://${hostName}/${userID}/ty`;
    const cl = `https://${hostName}/${userID}/cl`;
    const sb = `https://${hostName}/${userID}/sb`;
    const pty = `https://${hostName}/${userID}/pty`;
    const pcl = `https://${hostName}/${userID}/pcl`;
    const psb = `https://${hostName}/${userID}/psb`;

    // Base64 encoded share links
    const wkShare = btoa(`vless://${userID}@${IP1}:${PT1}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V1_${IP1}_${PT1}\nvless://${userID}@${IP2}:${PT2}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V2_${IP2}_${PT2}\nvless://${userID}@${IP3}:${PT3}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V3_${IP3}_${PT3}\nvless://${userID}@${IP4}:${PT4}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V4_${IP4}_${PT4}\nvless://${userID}@${IP5}:${PT5}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V5_${IP5}_${PT5}\nvless://${userID}@${IP6}:${PT6}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V6_${IP6}_${PT6}\nvless://${userID}@${IP7}:${PT7}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V7_${IP7}_${PT7}\nvless://${userID}@${IP8}:${PT8}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V8_${IP8}_${PT8}\nvless://${userID}@${IP9}:${PT9}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V9_${IP9}_${PT9}\nvless://${userID}@${IP10}:${PT10}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V10_${IP10}_${PT10}\nvless://${userID}@${IP11}:${PT11}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V11_${IP11}_${PT11}\nvless://${userID}@${IP12}:${PT12}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V12_${IP12}_${PT12}\nvless://${userID}@${IP13}:${PT13}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V13_${IP13}_${PT13}`);
    const pgShare = btoa(`vless://${userID}@${IP8}:${PT8}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V8_${IP8}_${PT8}\nvless://${userID}@${IP9}:${PT9}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V9_${IP9}_${PT9}\nvless://${userID}@${IP10}:${PT10}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V10_${IP10}_${PT10}\nvless://${userID}@${IP11}:${PT11}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V11_${IP11}_${PT11}\nvless://${userID}@${IP12}:${PT12}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V12_${IP12}_${PT12}\nvless://${userID}@${IP13}:${PT13}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V13_${IP13}_${PT13}`);

    const isWorkersDev = hostName.includes("workers.dev");

    const htmlContent = `
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>VLESS Configuration</title>
        <style>
            :root {
                --primary-color: #FFA500; /* Orange */
                --background-color: #121212;
                --card-background: #1E1E1E;
                --text-color: #E0E0E0;
                --header-color: #FFFFFF;
                --border-color: #333333;
                --button-text-color: #000000;
            }
            body {
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                background-color: var(--background-color);
                color: var(--text-color);
                margin: 0;
                padding: 20px;
                display: flex;
                flex-direction: column;
                align-items: center;
            }
            .container {
                max-width: 800px;
                width: 100%;
            }
            header {
                text-align: center;
                margin-bottom: 40px;
            }
            header h1 {
                color: var(--primary-color);
                font-size: 2.5rem;
                margin: 0;
            }
            header p {
                font-size: 1.1rem;
                color: var(--text-color);
            }
            .card {
                background-color: var(--card-background);
                border: 1px solid var(--border-color);
                border-radius: 8px;
                padding: 25px;
                margin-bottom: 30px;
                box-shadow: 0 4px 15px rgba(0,0,0,0.2);
            }
            .card h2 {
                color: var(--primary-color);
                border-bottom: 2px solid var(--primary-color);
                padding-bottom: 10px;
                margin-top: 0;
            }
            .card p {
                line-height: 1.6;
            }
            .config-item {
                display: flex;
                align-items: center;
                justify-content: space-between;
                background: var(--background-color);
                padding: 10px 15px;
                border-radius: 5px;
                margin-bottom: 15px;
                word-break: break-all;
            }
            .config-item code {
                color: #4CAF50; /* Green for code */
                font-size: 0.9rem;
            }
             .config-item button, .copy-button {
                background-color: var(--primary-color);
                color: var(--button-text-color);
                border: none;
                padding: 8px 12px;
                border-radius: 5px;
                cursor: pointer;
                font-weight: bold;
                transition: transform 0.2s, opacity 0.2s;
                margin-left: 15px;
                white-space: nowrap;
            }
            .config-item button:hover, .copy-button:hover {
                transform: scale(1.05);
                opacity: 0.9;
            }
            ul {
                list-style: none;
                padding: 0;
            }
            ul li {
                background-color: rgba(255, 165, 0, 0.1);
                padding: 12px;
                border-left: 4px solid var(--primary-color);
                margin-bottom: 10px;
                border-radius: 4px;
            }
            .grid-container {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 20px;
            }
            footer {
                text-align: center;
                margin-top: 40px;
                color: #777;
            }
            .tooltip {
                position: relative;
                display: inline-block;
            }

            .tooltip .tooltiptext {
                visibility: hidden;
                width: 140px;
                background-color: var(--primary-color);
                color: var(--button-text-color);
                text-align: center;
                border-radius: 6px;
                padding: 5px;
                position: absolute;
                z-index: 1;
                bottom: 150%;
                left: 50%;
                margin-left: -70px;
                opacity: 0;
                transition: opacity 0.3s;
            }

            .tooltip .tooltiptext::after {
                content: "";
                position: absolute;
                top: 100%;
                left: 50%;
                margin-left: -5px;
                border-width: 5px;
                border-style: solid;
                border-color: var(--primary-color) transparent transparent transparent;
            }

            .tooltip.show .tooltiptext {
                visibility: visible;
                opacity: 1;
            }

        </style>
    </head>
    <body>
        <div class="container">
            <header>
                <h1>VLESS Config Hub</h1>
                <p>Cloudflare-workers/pages-vless代理脚本 V25.5.27</p>
            </header>

            <main>
                ${isWorkersDev ? `
                <div class="card">
                    <h2>WS (无TLS) 节点</h2>
                    <p>此节点关闭TLS加密，推荐在网络环境较差或需要极致速度时使用。</p>
                    <div class="config-item">
                        <code>${vlessWs}</code>
                        <div class="tooltip">
                            <button onclick="copyToClipboard(this, '${vlessWs}')">复制链接</button>
                            <span class="tooltiptext">已复制!</span>
                        </div>
                    </div>
                </div>` : ''}
                
                <div class="card">
                    <h2>WS + TLS 节点</h2>
                    <p>此节点启用TLS加密，提供更强的安全性。推荐在大多数情况下使用。</p>
                    <div class="config-item">
                        <code>${vlessWsTls}</code>
                        <div class="tooltip">
                            <button onclick="copyToClipboard(this, '${vlessWsTls}')">复制链接</button>
                            <span class="tooltiptext">已复制!</span>
                        </div>
                    </div>
                </div>

                <div class="card">
                    <h2>订阅链接</h2>
                    <p>请根据您的客户端类型选择合适的订阅链接。workers.dev域名需要通过代理更新订阅。</p>
                    <div class="grid-container">
                        ${isWorkersDev ? `
                        <div class="sub-card">
                            <h3>通用订阅</h3>
                            <div class="config-item">
                                <code>${ty}</code>
                                <div class="tooltip"><button onclick="copyToClipboard(this, '${ty}')">复制</button><span class="tooltiptext">已复制!</span></div>
                            </div>
                        </div>
                        <div class="sub-card">
                            <h3>Clash-meta</h3>
                            <div class="config-item">
                                <code>${cl}</code>
                                <div class="tooltip"><button onclick="copyToClipboard(this, '${cl}')">复制</button><span class="tooltiptext">已复制!</span></div>
                            </div>
                        </div>
                        <div class="sub-card">
                            <h3>Sing-box</h3>
                            <div class="config-item">
                                <code>${sb}</code>
                                <div class="tooltip"><button onclick="copyToClipboard(this, '${sb}')">复制</button><span class="tooltiptext">已复制!</span></div>
                            </div>
                        </div>
                        ` : `
                        <div class="sub-card">
                            <h3>通用订阅 (TLS)</h3>
                            <div class="config-item">
                                <code>${pty}</code>
                                <div class="tooltip"><button onclick="copyToClipboard(this, '${pty}')">复制</button><span class="tooltiptext">已复制!</span></div>
                            </div>
                        </div>
                        <div class="sub-card">
                            <h3>Clash-meta (TLS)</h3>
                            <div class="config-item">
                                <code>${pcl}</code>
                                <div class="tooltip"><button onclick="copyToClipboard(this, '${pcl}')">复制</button><span class="tooltiptext">已复制!</span></div>
                            </div>
                        </div>
                        <div class="sub-card">
                            <h3>Sing-box (TLS)</h3>
                            <div class="config-item">
                                <code>${psb}</code>
                                <div class="tooltip"><button onclick="copyToClipboard(this, '${psb}')">复制</button><span class="tooltiptext">已复制!</span></div>
                            </div>
                        </div>
                        `}
                    </div>
                </div>

                 <div class="card">
                    <h2>聚合分享链接</h2>
                    <p>此链接包含多个节点配置，可直接导入到支持的客户端中。</p>
                    <div class="tooltip">
                        <button class="copy-button" onclick="copyToClipboard(this, '${isWorkersDev ? wkShare : pgShare}')">一键复制所有节点</button>
                        <span class="tooltiptext">已复制!</span>
                    </div>
                </div>
                
                <div class="card">
                    <h2>客户端参数</h2>
                    <ul>
                        <li><b>用户ID(uuid):</b> ${userID}</li>
                        <li><b>伪装域名(host):</b> ${hostName}</li>
                        <li><b>路径(path):</b> /?ed=2560</li>
                        <li><b>端口(port):</b> 非TLS (80, 8080等), TLS (443, 8443等)</li>
                    </ul>
                </div>
            </main>

            <footer>
                <p>${note.replace(/\\n/g, '<br>')}</p>
            </footer>
        </div>

        <script>
            function copyToClipboard(button, text) {
                navigator.clipboard.writeText(text).then(function() {
                    const tooltip = button.parentElement;
                    tooltip.classList.add('show');
                    setTimeout(function() {
                        tooltip.classList.remove('show');
                    }, 1500);
                }, function(err) {
                    alert('复制失败!');
                });
            }
        </script>
    </body>
    </html>
    `;

    return htmlContent;
}


function gettyConfig(userID, hostName) {
    const vlessshare = btoa(`vless://${userID}@${IP1}:${PT1}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V1_${IP1}_${PT1}\nvless://${userID}@${IP2}:${PT2}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V2_${IP2}_${PT2}\nvless://${userID}@${IP3}:${PT3}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V3_${IP3}_${PT3}\nvless://${userID}@${IP4}:${PT4}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V4_${IP4}_${PT4}\nvless://${userID}@${IP5}:${PT5}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V5_${IP5}_${PT5}\nvless://${userID}@${IP6}:${PT6}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V6_${IP6}_${PT6}\nvless://${userID}@${IP7}:${PT7}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V7_${IP7}_${PT7}\nvless://${userID}@${IP8}:${PT8}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V8_${IP8}_${PT8}\nvless://${userID}@${IP9}:${PT9}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V9_${IP9}_${PT9}\nvless://${userID}@${IP10}:${PT10}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V10_${IP10}_${PT10}\nvless://${userID}@${IP11}:${PT11}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V11_${IP11}_${PT11}\nvless://${userID}@${IP12}:${PT12}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V12_${IP12}_${PT12}\nvless://${userID}@${IP13}:${PT13}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V13_${IP13}_${PT13}`);
    return `${vlessshare}`
}

function getclConfig(userID, hostName) {
    return `
port: 7890
allow-lan: true
mode: rule
log-level: info
unified-delay: true
global-client-fingerprint: chrome
dns:
  enable: false
  listen: :53
  ipv6: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  default-nameserver: 
    - 223.5.5.5
    - 114.114.114.114
    - 8.8.8.8
  nameserver:
    - https://dns.alidns.com/dns-query
    - https://doh.pub/dns-query
  fallback:
    - https://1.0.0.1/dns-query
    - tls://dns.google
  fallback-filter:
    geoip: true
    geoip-code: CN
    ipcidr:
      - 240.0.0.0/4

proxies:
- name: CF_V1_${IP1}_${PT1}
  type: vless
  server: ${IP1.replace(/[\[\]]/g, '')}
  port: ${PT1}
  uuid: ${userID}
  udp: false
  tls: false
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V2_${IP2}_${PT2}
  type: vless
  server: ${IP2.replace(/[\[\]]/g, '')}
  port: ${PT2}
  uuid: ${userID}
  udp: false
  tls: false
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V3_${IP3}_${PT3}
  type: vless
  server: ${IP3.replace(/[\[\]]/g, '')}
  port: ${PT3}
  uuid: ${userID}
  udp: false
  tls: false
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V4_${IP4}_${PT4}
  type: vless
  server: ${IP4.replace(/[\[\]]/g, '')}
  port: ${PT4}
  uuid: ${userID}
  udp: false
  tls: false
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V5_${IP5}_${PT5}
  type: vless
  server: ${IP5.replace(/[\[\]]/g, '')}
  port: ${PT5}
  uuid: ${userID}
  udp: false
  tls: false
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V6_${IP6}_${PT6}
  type: vless
  server: ${IP6.replace(/[\[\]]/g, '')}
  port: ${PT6}
  uuid: ${userID}
  udp: false
  tls: false
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V7_${IP7}_${PT7}
  type: vless
  server: ${IP7.replace(/[\[\]]/g, '')}
  port: ${PT7}
  uuid: ${userID}
  udp: false
  tls: false
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V8_${IP8}_${PT8}
  type: vless
  server: ${IP8.replace(/[\[\]]/g, '')}
  port: ${PT8}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V9_${IP9}_${PT9}
  type: vless
  server: ${IP9.replace(/[\[\]]/g, '')}
  port: ${PT9}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V10_${IP10}_${PT10}
  type: vless
  server: ${IP10.replace(/[\[\]]/g, '')}
  port: ${PT10}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V11_${IP11}_${PT11}
  type: vless
  server: ${IP11.replace(/[\[\]]/g, '')}
  port: ${PT11}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V12_${IP12}_${PT12}
  type: vless
  server: ${IP12.replace(/[\[\]]/g, '')}
  port: ${PT12}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V13_${IP13}_${PT13}
  type: vless
  server: ${IP13.replace(/[\[\]]/g, '')}
  port: ${PT13}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

proxy-groups:
- name: 负载均衡
  type: load-balance
  url: http://www.gstatic.com/generate_204
  interval: 300
  proxies:
    - CF_V1_${IP1}_${PT1}
    - CF_V2_${IP2}_${PT2}
    - CF_V3_${IP3}_${PT3}
    - CF_V4_${IP4}_${PT4}
    - CF_V5_${IP5}_${PT5}
    - CF_V6_${IP6}_${PT6}
    - CF_V7_${IP7}_${PT7}
    - CF_V8_${IP8}_${PT8}
    - CF_V9_${IP9}_${PT9}
    - CF_V10_${IP10}_${PT10}
    - CF_V11_${IP11}_${PT11}
    - CF_V12_${IP12}_${PT12}
    - CF_V13_${IP13}_${PT13}

- name: 自动选择
  type: url-test
  url: http://www.gstatic.com/generate_204
  interval: 300
  tolerance: 50
  proxies:
    - CF_V1_${IP1}_${PT1}
    - CF_V2_${IP2}_${PT2}
    - CF_V3_${IP3}_${PT3}
    - CF_V4_${IP4}_${PT4}
    - CF_V5_${IP5}_${PT5}
    - CF_V6_${IP6}_${PT6}
    - CF_V7_${IP7}_${PT7}
    - CF_V8_${IP8}_${PT8}
    - CF_V9_${IP9}_${PT9}
    - CF_V10_${IP10}_${PT10}
    - CF_V11_${IP11}_${PT11}
    - CF_V12_${IP12}_${PT12}
    - CF_V13_${IP13}_${PT13}

- name: 🌍选择代理
  type: select
  proxies:
    - 负载均衡
    - 自动选择
    - DIRECT
    - CF_V1_${IP1}_${PT1}
    - CF_V2_${IP2}_${PT2}
    - CF_V3_${IP3}_${PT3}
    - CF_V4_${IP4}_${PT4}
    - CF_V5_${IP5}_${PT5}
    - CF_V6_${IP6}_${PT6}
    - CF_V7_${IP7}_${PT7}
    - CF_V8_${IP8}_${PT8}
    - CF_V9_${IP9}_${PT9}
    - CF_V10_${IP10}_${PT10}
    - CF_V11_${IP11}_${PT11}
    - CF_V12_${IP12}_${PT12}
    - CF_V13_${IP13}_${PT13}

rules:
  - GEOIP,LAN,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,🌍选择代理`
}

function getsbConfig(userID, hostName) {
    return `{
      "log": {
        "disabled": false,
        "level": "info",
        "timestamp": true
      },
      "experimental": {
        "clash_api": {
          "external_controller": "127.0.0.1:9090",
          "external_ui": "ui",
          "external_ui_download_url": "",
          "external_ui_download_detour": "",
          "secret": "",
          "default_mode": "Rule"
        },
        "cache_file": {
          "enabled": true,
          "path": "cache.db",
          "store_fakeip": true
        }
      },
      "dns": {
        "servers": [
          {
            "tag": "proxydns",
            "address": "tls://8.8.8.8/dns-query",
            "detour": "select"
          },
          {
            "tag": "localdns",
            "address": "h3://223.5.5.5/dns-query",
            "detour": "direct"
          },
          {
            "tag": "dns_fakeip",
            "address": "fakeip"
          }
        ],
        "rules": [
          {
            "outbound": "any",
            "server": "localdns",
            "disable_cache": true
          },
          {
            "clash_mode": "Global",
            "server": "proxydns"
          },
          {
            "clash_mode": "Direct",
            "server": "localdns"
          },
          {
            "rule_set": "geosite-cn",
            "server": "localdns"
          },
          {
            "rule_set": "geosite-geolocation-!cn",
            "server": "proxydns"
          },
          {
            "rule_set": "geosite-geolocation-!cn",
            "query_type": [
              "A",
              "AAAA"
            ],
            "server": "dns_fakeip"
          }
        ],
        "fakeip": {
          "enabled": true,
          "inet4_range": "198.18.0.0/15",
          "inet6_range": "fc00::/18"
        },
        "independent_cache": true,
        "final": "proxydns"
      },
      "inbounds": [
        {
          "type": "tun",
                          "tag": "tun-in",
          "address": [
                          "172.19.0.1/30",
            "fd00::1/126"
      ],
          "auto_route": true,
          "strict_route": true,
          "sniff": true,
          "sniff_override_destination": true,
          "domain_strategy": "prefer_ipv4"
        }
      ],
      "outbounds": [
        {
          "tag": "select",
          "type": "selector",
          "default": "auto",
          "outbounds": [
            "auto",
            "CF_V1_${IP1}_${PT1}",
            "CF_V2_${IP2}_${PT2}",
            "CF_V3_${IP3}_${PT3}",
            "CF_V4_${IP4}_${PT4}",
            "CF_V5_${IP5}_${PT5}",
            "CF_V6_${IP6}_${PT6}",
            "CF_V7_${IP7}_${PT7}",
            "CF_V8_${IP8}_${PT8}",
            "CF_V9_${IP9}_${PT9}",
            "CF_V10_${IP10}_${PT10}",
            "CF_V11_${IP11}_${PT11}",
            "CF_V12_${IP12}_${PT12}",
            "CF_V13_${IP13}_${PT13}"
          ]
        },
        {
          "server": "${IP1}",
          "server_port": ${PT1},
          "tag": "CF_V1_${IP1}_${PT1}",
          "packet_encoding": "packetaddr",
          "transport": {
            "headers": {
              "Host": [
                "${hostName}"
              ]
            },
            "path": "/?ed=2560",
            "type": "ws"
          },
          "type": "vless",
          "uuid": "${userID}"
        },
        {
          "server": "${IP2}",
          "server_port": ${PT2},
          "tag": "CF_V2_${IP2}_${PT2}",
          "packet_encoding": "packetaddr",
          "transport": {
            "headers": {
              "Host": [
                "${hostName}"
              ]
            },
            "path": "/?ed=2560",
            "type": "ws"
          },
          "type": "vless",
          "uuid": "${userID}"
        },
        {
          "server": "${IP3}",
          "server_port": ${PT3},
          "tag": "CF_V3_${IP3}_${PT3}",
          "packet_encoding": "packetaddr",
          "transport": {
            "headers": {
              "Host": [
                "${hostName}"
              ]
            },
            "path": "/?ed=2560",
            "type": "ws"
          },
          "type": "vless",
          "uuid": "${userID}"
        },
        {
          "server": "${IP4}",
          "server_port": ${PT4},
          "tag": "CF_V4_${IP4}_${PT4}",
          "packet_encoding": "packetaddr",
          "transport": {
            "headers": {
              "Host": [
                "${hostName}"
              ]
            },
            "path": "/?ed=2560",
            "type": "ws"
          },
          "type": "vless",
          "uuid": "${userID}"
        },
        {
          "server": "${IP5}",
          "server_port": ${PT5},
          "tag": "CF_V5_${IP5}_${PT5}",
          "packet_encoding": "packetaddr",
          "transport": {
            "headers": {
              "Host": [
                "${hostName}"
              ]
            },
            "path": "/?ed=2560",
            "type": "ws"
          },
          "type": "vless",
          "uuid": "${userID}"
        },
        {
          "server": "${IP6}",
          "server_port": ${PT6},
          "tag": "CF_V6_${IP6}_${PT6}",
          "packet_encoding": "packetaddr",
          "transport": {
            "headers": {
              "Host": [
                "${hostName}"
              ]
            },
            "path": "/?ed=2560",
            "type": "ws"
          },
          "type": "vless",
          "uuid": "${userID}"
        },
        {
          "server": "${IP7}",
          "server_port": ${PT7},
          "tag": "CF_V7_${IP7}_${PT7}",
          "packet_encoding": "packetaddr",
          "transport": {
            "headers": {
              "Host": [
                "${hostName}"
              ]
            },
            "path": "/?ed=2560",
            "type": "ws"
          },
          "type": "vless",
          "uuid": "${userID}"
        },
        {      
          "server": "${IP8}",
          "server_port": ${PT8},
          "tag": "CF_V8_${IP8}_${PT8}",
          "tls": {
            "enabled": true,
            "server_name": "${hostName}",
            "insecure": false,
            "utls": {
              "enabled": true,
              "fingerprint": "chrome"
            }
          },
          "packet_encoding": "packetaddr",
          "transport": {
            "headers": {
              "Host": [
                "${hostName}"
              ]
            },
            "path": "/?ed=2560",
            "type": "ws"
          },
          "type": "vless",
          "uuid": "${userID}"
        },
        {
          "server": "${IP9}",
          "server_port": ${PT9},
          "tag": "CF_V9_${IP9}_${PT9}",
          "tls": {
            "enabled": true,
            "server_name": "${hostName}",
            "insecure": false,
            "utls": {
              "enabled": true,
              "fingerprint": "chrome"
            }
          },
          "packet_encoding": "packetaddr",
          "transport": {
            "headers": {
              "Host": [
                "${hostName}"
              ]
            },
            "path": "/?ed=2560",
            "type": "ws"
          },
          "type": "vless",
          "uuid": "${userID}"
        },
        {
          "server": "${IP10}",
          "server_port": ${PT10},
          "tag": "CF_V10_${IP10}_${PT10}",
          "tls": {
            "enabled": true,
            "server_name": "${hostName}",
            "insecure": false,
            "utls": {
              "enabled": true,
              "fingerprint": "chrome"
            }
          },
          "packet_encoding": "packetaddr",
          "transport": {
            "headers": {
              "Host": [
                "${hostName}"
              ]
            },
            "path": "/?ed=2560",
            "type": "ws"
          },
          "type": "vless",
          "uuid": "${userID}"
        },
        {
          "server": "${IP11}",
          "server_port": ${PT11},
          "tag": "CF_V11_${IP11}_${PT11}",
          "tls": {
            "enabled": true,
            "server_name": "${hostName}",
            "insecure": false,
            "utls": {
              "enabled": true,
              "fingerprint": "chrome"
            }
          },
          "packet_encoding": "packetaddr",
          "transport": {
            "headers": {
              "Host": [
                "${hostName}"
              ]
            },
            "path": "/?ed=2560",
            "type": "ws"
          },
          "type": "vless",
          "uuid": "${userID}"
        },
        {
          "server": "${IP12}",
          "server_port": ${PT12},
          "tag": "CF_V12_${IP12}_${PT12}",
          "tls": {
            "enabled": true,
            "server_name": "${hostName}",
            "insecure": false,
            "utls": {
              "enabled": true,
              "fingerprint": "chrome"
            }
          },
          "packet_encoding": "packetaddr",
          "transport": {
            "headers": {
              "Host": [
                "${hostName}"
              ]
            },
            "path": "/?ed=2560",
            "type": "ws"
          },
          "type": "vless",
          "uuid": "${userID}"
        },
        {
          "server": "${IP13}",
          "server_port": ${PT13},
          "tag": "CF_V13_${IP13}_${PT13}",
          "tls": {
            "enabled": true,
            "server_name": "${hostName}",
            "insecure": false,
            "utls": {
              "enabled": true,
              "fingerprint": "chrome"
            }
          },
          "packet_encoding": "packetaddr",
          "transport": {
            "headers": {
              "Host": [
                "${hostName}"
              ]
            },
            "path": "/?ed=2560",
            "type": "ws"
          },
          "type": "vless",
          "uuid": "${userID}"
        },
        {
          "tag": "direct",
          "type": "direct"
        },
        {
          "tag": "auto",
          "type": "urltest",
          "outbounds": [
            "CF_V1_${IP1}_${PT1}",
            "CF_V2_${IP2}_${PT2}",
            "CF_V3_${IP3}_${PT3}",
            "CF_V4_${IP4}_${PT4}",
            "CF_V5_${IP5}_${PT5}",
            "CF_V6_${IP6}_${PT6}",
            "CF_V7_${IP7}_${PT7}",
            "CF_V8_${IP8}_${PT8}",
            "CF_V9_${IP9}_${PT9}",
            "CF_V10_${IP10}_${PT10}",
            "CF_V11_${IP11}_${PT11}",
            "CF_V12_${IP12}_${PT12}",
            "CF_V13_${IP13}_${PT13}"
          ],
          "url": "https://www.gstatic.com/generate_204",
          "interval": "1m",
          "tolerance": 50,
          "interrupt_exist_connections": false
        }
      ],
      "route": {
        "rule_set": [
          {
            "tag": "geosite-geolocation-!cn",
            "type": "remote",
            "format": "binary",
            "url": "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/geolocation-!cn.srs",
            "download_detour": "select",
            "update_interval": "1d"
          },
          {
            "tag": "geosite-cn",
            "type": "remote",
            "format": "binary",
            "url": "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/geolocation-cn.srs",
            "download_detour": "select",
            "update_interval": "1d"
          },
          {
            "tag": "geoip-cn",
            "type": "remote",
            "format": "binary",
            "url": "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geoip/cn.srs",
            "download_detour": "select",
            "update_interval": "1d"
          }
        ],
        "auto_detect_interface": true,
        "final": "select",
        "rules": [
                              {
                            "inbound": "tun-in",
                            "action": "sniff"
                              },
                               {
                            "protocol": "dns",
                                "action": "hijack-dns"
                              },
                              {
                                "port": 443,
                                "network": "udp",
                                "action": "reject"
                              },
          {
            "clash_mode": "Direct",
            "outbound": "direct"
          },
          {
            "clash_mode": "Global",
            "outbound": "select"
          },
          {
            "rule_set": "geoip-cn",
            "outbound": "direct"
          },
          {
            "rule_set": "geosite-cn",
            "outbound": "direct"
          },
          {
            "ip_is_private": true,
            "outbound": "direct"
          },
          {
            "rule_set": "geosite-geolocation-!cn",
            "outbound": "select"
          }
        ]
      },
      "ntp": {
        "enabled": true,
        "server": "time.apple.com",
        "server_port": 123,
        "interval": "30m",
        "detour": "direct"
      }
    }`
}

function getptyConfig(userID, hostName) {
    const vlessshare = btoa(`vless://${userID}@${IP8}:${PT8}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V8_${IP8}_${PT8}\nvless://${userID}@${IP9}:${PT9}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V9_${IP9}_${PT9}\nvless://${userID}@${IP10}:${PT10}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V10_${IP10}_${PT10}\nvless://${userID}@${IP11}:${PT11}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V11_${IP11}_${PT11}\nvless://${userID}@${IP12}:${PT12}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V12_${IP12}_${PT12}\nvless://${userID}@${IP13}:${PT13}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V13_${IP13}_${PT13}`);
    return `${vlessshare}`
}

function getpclConfig(userID, hostName) {
    return `
port: 7890
allow-lan: true
mode: rule
log-level: info
unified-delay: true
global-client-fingerprint: chrome
dns:
  enable: false
  listen: :53
  ipv6: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  default-nameserver: 
    - 223.5.5.5
    - 114.114.114.114
    - 8.8.8.8
  nameserver:
    - https://dns.alidns.com/dns-query
    - https://doh.pub/dns-query
  fallback:
    - https://1.0.0.1/dns-query
    - tls://dns.google
  fallback-filter:
    geoip: true
    geoip-code: CN
    ipcidr:
      - 240.0.0.0/4

proxies:
- name: CF_V8_${IP8}_${PT8}
  type: vless
  server: ${IP8.replace(/[\[\]]/g, '')}
  port: ${PT8}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V9_${IP9}_${PT9}
  type: vless
  server: ${IP9.replace(/[\[\]]/g, '')}
  port: ${PT9}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V10_${IP10}_${PT10}
  type: vless
  server: ${IP10.replace(/[\[\]]/g, '')}
  port: ${PT10}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V11_${IP11}_${PT11}
  type: vless
  server: ${IP11.replace(/[\[\]]/g, '')}
  port: ${PT11}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V12_${IP12}_${PT12}
  type: vless
  server: ${IP12.replace(/[\[\]]/g, '')}
  port: ${PT12}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V13_${IP13}_${PT13}
  type: vless
  server: ${IP13.replace(/[\[\]]/g, '')}
  port: ${PT13}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

proxy-groups:
- name: 负载均衡
  type: load-balance
  url: http://www.gstatic.com/generate_204
  interval: 300
  proxies:
    - CF_V8_${IP8}_${PT8}
    - CF_V9_${IP9}_${PT9}
    - CF_V10_${IP10}_${PT10}
    - CF_V11_${IP11}_${PT11}
    - CF_V12_${IP12}_${PT12}
    - CF_V13_${IP13}_${PT13}

- name: 自动选择
  type: url-test
  url: http://www.gstatic.com/generate_204
  interval: 300
  tolerance: 50
  proxies:
    - CF_V8_${IP8}_${PT8}
    - CF_V9_${IP9}_${PT9}
    - CF_V10_${IP10}_${PT10}
    - CF_V11_${IP11}_${PT11}
    - CF_V12_${IP12}_${PT12}
    - CF_V13_${IP13}_${PT13}

- name: 🌍选择代理
  type: select
  proxies:
    - 负载均衡
    - 自动选择
    - DIRECT
    - CF_V8_${IP8}_${PT8}
    - CF_V9_${IP9}_${PT9}
    - CF_V10_${IP10}_${PT10}
    - CF_V11_${IP11}_${PT11}
    - CF_V12_${IP12}_${PT12}
    - CF_V13_${IP13}_${PT13}

rules:
  - GEOIP,LAN,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,🌍选择代理`
}

function getpsbConfig(userID, hostName) {
    return `{
          "log": {
            "disabled": false,
            "level": "info",
            "timestamp": true
          },
          "experimental": {
            "clash_api": {
              "external_controller": "127.0.0.1:9090",
              "external_ui": "ui",
              "external_ui_download_url": "",
              "external_ui_download_detour": "",
              "secret": "",
              "default_mode": "Rule"
            },
            "cache_file": {
              "enabled": true,
              "path": "cache.db",
              "store_fakeip": true
            }
          },
          "dns": {
            "servers": [
              {
                "tag": "proxydns",
                "address": "tls://8.8.8.8/dns-query",
                "detour": "select"
              },
              {
                "tag": "localdns",
                "address": "h3://223.5.5.5/dns-query",
                "detour": "direct"
              },
              {
                "tag": "dns_fakeip",
                "address": "fakeip"
              }
            ],
            "rules": [
              {
                "outbound": "any",
                "server": "localdns",
                "disable_cache": true
              },
              {
                "clash_mode": "Global",
                "server": "proxydns"
              },
              {
                "clash_mode": "Direct",
                "server": "localdns"
              },
              {
                "rule_set": "geosite-cn",
                "server": "localdns"
              },
              {
                "rule_set": "geosite-geolocation-!cn",
                "server": "proxydns"
              },
              {
                "rule_set": "geosite-geolocation-!cn",
                "query_type": [
                  "A",
                  "AAAA"
                ],
                "server": "dns_fakeip"
              }
            ],
            "fakeip": {
              "enabled": true,
              "inet4_range": "198.18.0.0/15",
              "inet6_range": "fc00::/18"
            },
            "independent_cache": true,
            "final": "proxydns"
          },
          "inbounds": [
            {
              "type": "tun",
                                "tag": "tun-in",
          "address": [
                                "172.19.0.1/30",
            "fd00::1/126"
      ],
              "auto_route": true,
              "strict_route": true,
              "sniff": true,
              "sniff_override_destination": true,
              "domain_strategy": "prefer_ipv4"
            }
          ],
          "outbounds": [
            {
              "tag": "select",
              "type": "selector",
              "default": "auto",
              "outbounds": [
                "auto",
                "CF_V8_${IP8}_${PT8}",
                "CF_V9_${IP9}_${PT9}",
                "CF_V10_${IP10}_${PT10}",
                "CF_V11_${IP11}_${PT11}",
                "CF_V12_${IP12}_${PT12}",
                "CF_V13_${IP13}_${PT13}"
              ]
            },
            {
              "server": "${IP8}",
              "server_port": ${PT8},
              "tag": "CF_V8_${IP8}_${PT8}",
              "tls": {
                "enabled": true,
                "server_name": "${hostName}",
                "insecure": false,
                "utls": {
                  "enabled": true,
                  "fingerprint": "chrome"
                }
              },
              "packet_encoding": "packetaddr",
              "transport": {
                "headers": {
                  "Host": [
                    "${hostName}"
                  ]
                },
                "path": "/?ed=2560",
                "type": "ws"
              },
              "type": "vless",
              "uuid": "${userID}"
            },
            {
              "server": "${IP9}",
              "server_port": ${PT9},
              "tag": "CF_V9_${IP9}_${PT9}",
              "tls": {
                "enabled": true,
                "server_name": "${hostName}",
                "insecure": false,
                "utls": {
                  "enabled": true,
                  "fingerprint": "chrome"
                }
              },
              "packet_encoding": "packetaddr",
              "transport": {
                "headers": {
                  "Host": [
                    "${hostName}"
                  ]
                },
                "path": "/?ed=2560",
                "type": "ws"
              },
              "type": "vless",
              "uuid": "${userID}"
            },
            {
              "server": "${IP10}",
              "server_port": ${PT10},
              "tag": "CF_V10_${IP10}_${PT10}",
              "tls": {
                "enabled": true,
                "server_name": "${hostName}",
                "insecure": false,
                "utls": {
                  "enabled": true,
                  "fingerprint": "chrome"
                }
              },
              "packet_encoding": "packetaddr",
              "transport": {
                "headers": {
                  "Host": [
                    "${hostName}"
                  ]
                },
                "path": "/?ed=2560",
                "type": "ws"
              },
              "type": "vless",
              "uuid": "${userID}"
            },
            {
              "server": "${IP11}",
              "server_port": ${PT11},
              "tag": "CF_V11_${IP11}_${PT11}",
              "tls": {
                "enabled": true,
                "server_name": "${hostName}",
                "insecure": false,
                "utls": {
                  "enabled": true,
                  "fingerprint": "chrome"
                }
              },
              "packet_encoding": "packetaddr",
              "transport": {
                "headers": {
                  "Host": [
                    "${hostName}"
                  ]
                },
                "path": "/?ed=2560",
                "type": "ws"
              },
              "type": "vless",
              "uuid": "${userID}"
            },
            {
              "server": "${IP12}",
              "server_port": ${PT12},
              "tag": "CF_V12_${IP12}_${PT12}",
              "tls": {
                "enabled": true,
                "server_name": "${hostName}",
                "insecure": false,
                "utls": {
                  "enabled": true,
                  "fingerprint": "chrome"
                }
              },
              "packet_encoding": "packetaddr",
              "transport": {
                "headers": {
                  "Host": [
                    "${hostName}"
                  ]
                },
                "path": "/?ed=2560",
                "type": "ws"
              },
              "type": "vless",
              "uuid": "${userID}"
            },
            {
              "server": "${IP13}",
              "server_port": ${PT13},
              "tag": "CF_V13_${IP13}_${PT13}",
              "tls": {
                "enabled": true,
                "server_name": "${hostName}",
                "insecure": false,
                "utls": {
                  "enabled": true,
                  "fingerprint": "chrome"
                }
              },
              "packet_encoding": "packetaddr",
              "transport": {
                "headers": {
                  "Host": [
                    "${hostName}"
                  ]
                },
                "path": "/?ed=2560",
                "type": "ws"
              },
              "type": "vless",
              "uuid": "${userID}"
            },
            {
              "tag": "direct",
              "type": "direct"
            },
            {
              "tag": "auto",
              "type": "urltest",
              "outbounds": [
                "CF_V8_${IP8}_${PT8}",
                "CF_V9_${IP9}_${PT9}",
                "CF_V10_${IP10}_${PT10}",
                "CF_V11_${IP11}_${PT11}",
                "CF_V12_${IP12}_${PT12}",
                "CF_V13_${IP13}_${PT13}"
              ],
              "url": "https://www.gstatic.com/generate_204",
              "interval": "1m",
              "tolerance": 50,
              "interrupt_exist_connections": false
            }
          ],
          "route": {
            "rule_set": [
              {
                "tag": "geosite-geolocation-!cn",
                "type": "remote",
                "format": "binary",
                "url": "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/geolocation-!cn.srs",
                "download_detour": "select",
                "update_interval": "1d"
              },
              {
                "tag": "geosite-cn",
                "type": "remote",
                "format": "binary",
                "url": "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/geolocation-cn.srs",
                "download_detour": "select",
                "update_interval": "1d"
              },
              {
                "tag": "geoip-cn",
                "type": "remote",
                "format": "binary",
                "url": "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geoip/cn.srs",
                "download_detour": "select",
                "update_interval": "1d"
              }
            ],
            "auto_detect_interface": true,
            "final": "select",
            "rules": [
                                {
                                "inbound": "tun-in",
                                "action": "sniff"
                                },
                                {
                                "protocol": "dns",
                                "action": "hijack-dns"
                                  },
                                {
                                  "port": 443,
                                "network": "udp",
                                "action": "reject"
                                },
              {
                "clash_mode": "Direct",
                "outbound": "direct"
              },
              {
                "clash_mode": "Global",
                "outbound": "select"
              },
              {
                "rule_set": "geoip-cn",
                "outbound": "direct"
              },
              {
                "rule_set": "geosite-cn",
                "outbound": "direct"
              },
              {
                "ip_is_private": true,
                "outbound": "direct"
              },
              {
                "rule_set": "geosite-geolocation-!cn",
                "outbound": "select"
              }
            ]
          },
          "ntp": {
            "enabled": true,
            "server": "time.apple.com",
            "server_port": 123,
            "interval": "30m",
            "detour": "direct"
          }
        }`;
}
