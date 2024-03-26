# Sock5ws Socks5 Proxy Over HTTP/Websocket

## Introduction

It is a simple Socks5 Proxy implementation over HTTP/Websocket. It is based on our previous work called stcp2ws which is at https://github.com/bingotang1981/stcp2ws/. By using it, we can make a socks5 proxy over http/websocket which can enhance the security as socks5 proxy itself does not support the encryption (if you are using https).

Main features:

1. Socks5 proxy with only connect command supported.
2. Enable the sniff flag to adjust the host to counter the dns pollution. This feature is grabbed from *ray sniffing feature.

## Command

We will need to deploy the application on both the client and server side.

For server side: `./socks5ws server tcp2wsPort yourCustomizedBearerToken`

For client side: `./socks5ws client http://tcp2wsUrl localPort yourCustomizedBearerToken [s]`

Given this solution is compatible with our previous work stcp2ws (which is at https://github.com/bingotang1981/stcp2ws/), if you have already set up the stcp2ws server, you do not need to set up one more and you can make your client connect to that server directly.

## Scenarios

(1) Suppose you want to set up a client without the host sniffing feature. You may use the following command. We suppose your server is at https://aa.yourdomain.com, and your socks5 proxy listens at port 1080.

`./socks5ws client https://aa.yourdomain.com 1080 yourCustomizedBearerToken`

(2) Suppose you want to set up a client with the host sniffing feature. You may use the following command. We suppose your server is at https://aa.yourdomain.com, and your socks5 proxy listens at port 1080.

`./socks5ws client https://aa.yourdomain.com 1080 yourCustomizedBearerToken s`

You may find the last parameter is s.
