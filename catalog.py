"""Capabilities verified against upstream YPtun README, 2026-11-15."""
PROTOCOLS = [
    dict(id='wdtt',name='VK-TURN / qWDTT',core='qWDTT 1.4.3',mode='managed',description='TURN-туннель · пользователи · подписки'),
    dict(id='vless', name='VLESS', core='Xray', mode='native', description='8 транспортов Xray · TLS / Reality · self-SNI'),
    dict(id='vmess', name='VMess', core='Xray', mode='native', description='TCP, WebSocket, gRPC · TLS'),
    dict(id='trojan', name='Trojan', core='Xray', mode='native', description='TCP, WebSocket, gRPC · TLS'),
    dict(id='webproxy', name='Telegram · WebProxy', core='tgwebproxy', mode='native', description='HTTPS / WebSocket для Telegram · ссылка tg://webproxy · без подписки'),
    dict(id='shadowsocks', name='Shadowsocks', core='Xray', mode='native', description='ChaCha20-IETF-Poly1305'),
    dict(id='hysteria2', name='Hysteria2', core='sing-box', mode='native', description='QUIC · TLS · Salamander'),
    *[dict(id=i, name=n, core=c, mode='custom', description=d) for i,n,c,d in [
      ('wireguard','WireGuard','WireGuard','Свой конфиг и образ сервера'),
      ('amneziawg','AmneziaWG','AmneziaWG','wg-quick, параметры обфускации'),
      ('olcrtc','olcRTC','olcRTC','Транспорт через видеосвязь'),
      ('vkturn','VK-TURN / Free TURN','free-turn','Туннель через звонки VK'),
      ('masterdns','MasterDNS','MasterDnsVPN','DNS-туннель'),
      ('openflux','OpenFlux','OpenFlux','Транспорт через Яндекс / MAX'),
      ('trusttunnel','Trust Tunnel','TrustTunnel','Свой конфиг TrustTunnel'),
      ('snolc','snolc','snolc','Rust-движок'),
      ('warp','WARP / Telegram','WireGuard / AmneziaWG','Клиентский туннель и SOCKS5'),
      ('raw','Xray / sing-box JSON','Свой движок','Полная конфигурация Xray / sing-box'),
    ]]
]
BY_ID = {p['id']:p for p in PROTOCOLS}
