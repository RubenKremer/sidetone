// Help and About, written per language (not machine-swapped like the rest of the UI).

import { EXTRA } from "./i18n.js";

const REPO = "https://github.com/igtoth/sidetone";

const H = {
  en: {
    title: "Help",
    intro: "Sidetone is a SIP softphone built for troubleshooting: every call is captured, traced and explained.",
    sections: [
      ["Getting started", [
        "Open Settings and add an account: user, password and the domain or registrar (host or host:port). Save, and the dot next to the account turns green when it is registered.",
        "No registrar? Leave the domain empty and turn Register off: Sidetone becomes an anonymous client that dials SIP URIs directly (sip:600@10.0.0.5:5060).",
        "In the browser version the account needs a WebSocket URL (wss://...): your PBX or SBC must accept SIP over WebSocket.",
        "Provision loads account fields from a URL (Settings, Provision on the account): a sidetone-provision XML, or on the desktop the Yealink .cfg or Polycom XML your PBX serves to desk phones and saves them. A SIP NOTIFY with Event check-sync or resync re-downloads that URL; if you are on a call, Sidetone waits until it ends before applying the new file.",
      ]],
      ["Making and taking calls", [
        "Type a number, user@host or a SIP URI and press Enter or Call. The keypad sends DTMF once a call is up.",
        "Dial string shortcuts: 600?Subject=test adds headers to the INVITE; 600,,1234# sends the digits after the call is answered (each comma waits one second).",
        "The options button next to the number adds headers or overrides account settings (codecs, DTMF mode...) for the next call only.",
        "Incoming calls ring on the speaker and appear in Lines with Answer and Reject. Several lines at once: answering or resuming one puts the others on hold.",
      ]],
      ["Hold, transfer, record", [
        "Hold sends a re-INVITE with sendonly; Resume sends sendrecv. Mute only stops your microphone.",
        "Transfer, Blind: REFER to the target and the call leaves you. Transfer, Consult first: your call goes on hold, Sidetone calls the target, and Complete transfer joins both sides (REFER with Replaces).",
        "Record keeps a stereo WAV of the call: left is what you sent, right is what you received. Download it from the Calls page.",
      ]],
      ["TCP, TLS, SRTP, BLF, presence and conference", [
        "Account, Network: Transport chooses UDP, TCP or TLS. TLS uses port 5061 by default; turn Check the server's TLS certificate off for a PBX with a self-signed certificate.",
        "Account, Media: SRTP Optional offers encryption and falls back to RTP; Required rejects or ends calls without it. SRTP keys: SDES (a=crypto, use with TLS) or DTLS-SRTP (handshake on the media path, certificate checked against a=fingerprint). The Current call card shows the suite and whether the fingerprint matched.",
        "Account, BLF: one extension per line. Each appears under the keypad as Free, Ringing or Busy (SUBSCRIBE to the dialog event); click one to call it.",
        "Presence: when the server offers it, each lamp also shows Away, Do not disturb or Offline and the note (SUBSCRIBE to presence, PIDF). The selector under the account publishes your own presence with PUBLISH; Asterisk does not accept PUBLISH from phones and answers 489.",
        "Conference: with two calls up, select one and press Conference to join the other. Sidetone mixes the audio locally; holding or hanging up either call ends the conference.",
        "Voicemail: when the server reports messages (SUBSCRIBE message-summary or unsolicited NOTIFY), a lamp under the account shows how many are new; pressing it dials the voicemail number set in the account.",
        "Forwarding: Settings, Call handling forwards every call, calls while busy or in DND, or calls not answered in time, with 302 Moved Temporarily. A ringing call can also be forwarded by hand: type the number in the dial field and press Forward.",
        "Messages: the options under the dial field send a SIP MESSAGE (RFC 3428) to the number typed; received messages and the delivery result show in Phone events.",
      ]],
      ["Troubleshooting a call", [
        "SIP trace shows every message live. Click one to read it in full, filter by number or Call-ID, and save the session as pcapng for Wireshark.",
        "Analyze (on the phone, in the history or in the trace) opens the capture in Analysis: ladder diagram, findings in plain words, RTP loss, jitter and MOS.",
        "Ask AI sends the findings and the relevant messages to the AI provider you choose, masked by default. Show what will be sent prints the exact prompt first.",
        "Export gives an annotated pcapng (findings as Wireshark comments) or a redacted one that masks numbers, names, credentials and public IPs for vendor tickets.",
        "Filters work like Wireshark display filters, in the SIP trace and in Analysis: ip.addr == 10.0.0.5, sip.method == INVITE, sip.status >= 400, sip.from contains \"2001\", sdp.codec == PCMA, combined with && || ! and parentheses. A plain word searches the whole message.",
        "Click an RTP arrow in the ladder, or the play button in Media, to listen to that stream and see its waveform (in the browser G.711 and Opus; the desktop app plays every codec). Silence in the middle is a gap: loss, hold or silence suppression. Save WAV keeps the audio.",
        "Media also draws jitter, loss and MOS per second for each stream, with the SIP events marked, and shows what the other side measured from its RTCP reports: loss, jitter and round trip. A stream that flows but carries only silence is flagged (mute, a bad transcoder or a broken media path).",
        "Legs of the same call on both sides of an SBC or B2BUA are linked when they share X-CID, Session-ID or similar headers; the chain link in the dialog list selects them together in one ladder.",
        "The jitter buffer table shows the MOS a phone with a fixed 50 ms, a fixed 200 ms or an adaptive buffer would get: packets arriving after their playout time are dropped there, so jitter turns into loss.",
        "SRTP calls are analyzed and played decrypted; SIP trace saves the capture as it went on the wire, and Save with SRTP decrypted gives the readable version, each decrypted packet commented.",
        "HEP: captures from Homer agents (Kamailio, OpenSIPS, FreeSWITCH, heplify) are unwrapped automatically. Settings, Capture and recording can send a HEPv3 copy of every SIP message to your Homer; sidetone hep on the command line acts as a collector.",
        "The Explanations button hides the Explanation tab, the SDP line by line and the header help for those who only want the raw data.",
        "Calls now shows each call live (number, duration, codec, transport, RTP counters), each account's registration, and the result of the last action: when hold, transfer or DTMF fails, it says whether the PBX does not support it, refused it or did not answer.",
      ]],
      ["Diagnostics", [
        "Server reachability sends OPTIONS: any answer, even 404 or 405, proves the server is reachable. Silence points at the address, port, firewall or network interface.",
        "DNS shows how a domain resolves (NAPTR, SRV, A/AAAA) and which address Sidetone uses.",
        "NAT asks STUN servers which public address they see; different ports for different servers mean a symmetric NAT, the classic cause of one-way audio.",
        "Audio lets you pick the microphone and speaker and play the microphone back to check levels.",
        "Capture on an interface records other hosts' traffic (a PBX, an SBC, a phone on a mirrored port) with a BPF filter, shows SIP as it passes, and opens the result in Analysis. It needs Npcap on Windows and capture rights on Linux and macOS; the message says what to change.",
        "Phone provisioning fetches what a desk phone with a given MAC would get from a TFTP or HTTP server (tftp://10.0.0.5/SEP{MAC}.cnf.xml) and shows the error or the account the file describes; Ask DHCP shows the server the network hands to phones (options 66, 150, 160). A capture of a phone booting shows the same in Analysis.",
      ]],
      ["Common problems", [
        "Registration failed 401/403: check user, authentication user and password. 404: the user does not exist on that domain.",
        "Server not answering: wrong address or port, a firewall dropping UDP, or the wrong network interface (see Local IP in the account's Network tab).",
        "Call drops after 32 seconds: an ACK is lost, usually NAT or a wrong Contact; the finding no ACK in Analysis confirms it.",
        "One-way or no audio: private address in SDP, symmetric NAT or a firewall on the RTP ports; look at Media in Analysis and run the NAT test.",
      ]],
    ],
    keys: "Keyboard: Enter calls or answers, Esc hangs up, F2 transfer, F3 hold, F4 mute, digits send DTMF during a call.",
    about: "About",
    aboutText: "Open source SIP softphone and call analyzer for troubleshooting. Made by Ighor Toth.",
    version: "Version",
    engine: "Mode",
    license: "License",
    source: "Source code",
    issues: "Report a problem",
    releases: "Downloads",
    web: "Browser version",
    credits: "Built with Rust, Tauri, cpal, hickory-dns, WebRTC and the IBM Plex typefaces.",
    language: "Language",
  },
  pt: {
    title: "Ajuda",
    intro: "O Sidetone é um softphone SIP feito para troubleshooting: toda chamada é capturada, rastreada e explicada.",
    sections: [
      ["Primeiros passos", [
        "Abra Configurações e adicione uma conta: usuário, senha e o domínio ou registrar (host ou host:porta). Salve; a bolinha ao lado da conta fica verde quando ela registra.",
        "Sem registrar? Deixe o domínio vazio e desligue Registrar: o Sidetone vira um cliente anônimo que disca SIP URIs direto (sip:600@10.0.0.5:5060).",
        "Na versão do navegador a conta precisa de uma URL WebSocket (wss://...): seu PABX ou SBC tem de aceitar SIP sobre WebSocket.",
        "Provisionar carrega os campos da conta a partir de uma URL (Configurações, Provisionar na conta): um XML sidetone-provision ou, no desktop, o .cfg Yealink ou o XML Polycom que o seu PABX já serve aos telefones e os salva. Um NOTIFY SIP com Event check-sync ou resync baixa de novo essa URL; se houver chamada, o Sidetone espera ela terminar antes de aplicar o arquivo.",
      ]],
      ["Fazendo e recebendo chamadas", [
        "Digite um número, usuario@host ou um SIP URI e aperte Enter ou Ligar. Com a chamada ativa, o teclado envia DTMF.",
        "Atalhos na discagem: 600?Subject=teste adiciona headers ao INVITE; 600,,1234# manda os dígitos depois que atenderem (cada vírgula espera um segundo).",
        "O botão de opções ao lado do número adiciona headers ou muda ajustes da conta (codecs, modo de DTMF...) só para a próxima chamada.",
        "Chamadas recebidas tocam no alto-falante e aparecem em Linhas com Atender e Rejeitar. Várias linhas ao mesmo tempo: atender ou retomar uma coloca as outras em espera.",
      ]],
      ["Espera, transferência, gravação", [
        "Espera manda um re-INVITE com sendonly; Retomar manda sendrecv. Mudo só desliga o seu microfone.",
        "Transferir, Direta: REFER para o destino e a chamada sai de você. Transferir, Consultar antes: sua chamada fica em espera, o Sidetone liga para o destino e Concluir transferência junta os dois lados (REFER com Replaces).",
        "Gravar guarda um WAV estéreo da chamada: esquerda é o que você enviou, direita o que recebeu. Baixe na página Chamadas.",
      ]],
      ["TCP, TLS, SRTP, BLF, presença e conferência", [
        "Conta, Rede: Transporte escolhe UDP, TCP ou TLS. TLS usa a porta 5061 por padrão; desligue Verificar o certificado TLS do servidor para um PABX com certificado autoassinado.",
        "Conta, Mídia: SRTP Opcional oferece criptografia e cai para RTP; Obrigatória rejeita ou encerra chamadas sem ela. Chaves SRTP: SDES (a=crypto, use com TLS) ou DTLS-SRTP (handshake no caminho de mídia, certificado conferido com o a=fingerprint). O cartão Chamada atual mostra a suíte e se o fingerprint conferiu.",
        "Conta, BLF: um ramal por linha. Cada um aparece abaixo do teclado como Livre, Tocando ou Ocupado (SUBSCRIBE ao evento dialog); clique para ligar.",
        "Presença: quando o servidor oferece, cada lâmpada também mostra Ausente, Não perturbe ou Offline e a nota (SUBSCRIBE a presence, PIDF). O seletor abaixo da conta publica a sua presença com PUBLISH; o Asterisk não aceita PUBLISH de telefones e responde 489.",
        "Conferência: com duas chamadas ativas, selecione uma e clique Conferência para juntar a outra. O Sidetone mixa o áudio localmente; colocar em espera ou desligar qualquer uma encerra a conferência.",
        "Correio de voz: quando o servidor informa mensagens (SUBSCRIBE message-summary ou NOTIFY não solicitado), uma lâmpada abaixo da conta mostra quantas são novas; clicar disca o número de correio de voz definido na conta.",
        "Desvio: Configurações, Tratamento de chamadas desvia todas as chamadas, as que chegam com ocupado ou em Não perturbe, ou as não atendidas a tempo, com 302 Moved Temporarily. Uma chamada tocando também pode ser desviada na hora: digite o número no campo de discagem e aperte Desviar.",
        "Mensagens: as opções abaixo do campo de discagem enviam um SIP MESSAGE (RFC 3428) para o número digitado; mensagens recebidas e o resultado da entrega aparecem em Eventos do telefone.",
      ]],
      ["Investigando uma chamada", [
        "O Trace SIP mostra cada mensagem ao vivo. Clique para ler inteira, filtre por número ou Call-ID e salve a sessão em pcapng para o Wireshark.",
        "Analisar (no telefone, no histórico ou no trace) abre a captura em Análise: diagrama ladder, achados explicados, perda, jitter e MOS do RTP.",
        "Perguntar à IA envia os achados e as mensagens relevantes ao provedor de IA que você escolher, mascarados por padrão. Mostrar o que será enviado exibe o prompt exato antes.",
        "Exportar gera um pcapng anotado (achados como comentários do Wireshark) ou um anonimizado que mascara números, nomes, credenciais e IPs públicos para chamados com fornecedores.",
        "Os filtros funcionam como os display filters do Wireshark, no trace SIP e na Análise: ip.addr == 10.0.0.5, sip.method == INVITE, sip.status >= 400, sip.from contains \"2001\", sdp.codec == PCMA, combinados com && || ! e parênteses. Uma palavra solta busca na mensagem inteira.",
        "Clique numa seta RTP do ladder, ou no botão play em Mídia, para ouvir aquele stream e ver a forma de onda (no navegador G.711 e Opus; o app desktop toca todos os codecs). Silêncio no meio é uma lacuna: perda, espera ou supressão de silêncio. Salvar WAV guarda o áudio.",
        "Mídia também desenha jitter, perda e MOS por segundo de cada stream, com os eventos SIP marcados, e mostra o que o outro lado mediu nos relatórios RTCP: perda, jitter e tempo de ida e volta. Um stream que flui mas só leva silêncio é sinalizado (mudo, transcodificador com defeito ou caminho de mídia quebrado).",
        "Pernas da mesma chamada dos dois lados de um SBC ou B2BUA são ligadas quando compartilham X-CID, Session-ID ou cabeçalhos parecidos; o ícone de corrente na lista de diálogos seleciona todas juntas num só ladder.",
        "A tabela de jitter buffer mostra o MOS que um telefone com buffer fixo de 50 ms, fixo de 200 ms ou adaptativo teria: pacotes que chegam depois da hora de tocar são descartados, então jitter vira perda.",
        "Chamadas SRTP são analisadas e tocadas decifradas; o SIP trace salva a captura como passou na rede, e Salvar com SRTP decifrado gera a versão legível, com cada pacote decifrado comentado.",
        "HEP: capturas de agentes Homer (Kamailio, OpenSIPS, FreeSWITCH, heplify) são desembrulhadas automaticamente. Configurações, Captura e gravação pode enviar uma cópia HEPv3 de cada mensagem SIP ao seu Homer; sidetone hep na linha de comando funciona como coletor.",
        "O botão Explicações esconde a aba Explicação, o SDP linha a linha e a ajuda dos cabeçalhos para quem só quer os dados crus.",
        "Chamadas agora mostra cada chamada ao vivo (número, duração, codec, transporte, contadores RTP), o registro de cada conta e o resultado da última ação: quando espera, transferência ou DTMF falha, diz se o PBX não suporta, recusou ou não respondeu.",
      ]],
      ["Diagnóstico", [
        "Alcance do servidor envia OPTIONS: qualquer resposta, até 404 ou 405, prova que o servidor está alcançável. Silêncio aponta para endereço, porta, firewall ou interface de rede.",
        "Provisionamento de telefones busca o que um telefone de mesa com um MAC receberia de um servidor TFTP ou HTTP (tftp://10.0.0.5/SEP{MAC}.cnf.xml) e mostra o erro ou a conta que o arquivo descreve; Perguntar ao DHCP mostra o servidor que a rede entrega aos telefones (opções 66, 150, 160). Uma captura de um telefone iniciando mostra o mesmo em Análise.",
        "DNS mostra como um domínio é resolvido (NAPTR, SRV, A/AAAA) e qual endereço o Sidetone usa.",
        "NAT pergunta a servidores STUN qual endereço público eles veem; portas diferentes para servidores diferentes indicam NAT simétrico, a causa clássica de áudio de um lado só.",
        "Áudio permite escolher microfone e alto-falante e ouvir o próprio microfone para conferir os níveis.",
        "Captura numa interface grava o tráfego de outros equipamentos (um PABX, um SBC, um telefone numa porta espelhada) com filtro BPF, mostra o SIP enquanto passa e abre o resultado na Análise. Precisa do Npcap no Windows e de permissão de captura no Linux e no macOS; a mensagem diz o que mudar.",
      ]],
      ["Problemas comuns", [
        "Falha no registro 401/403: confira usuário, usuário de autenticação e senha. 404: o usuário não existe nesse domínio.",
        "Servidor não responde: endereço ou porta errados, firewall bloqueando UDP ou a interface de rede errada (veja IP local na aba Rede da conta).",
        "Chamada cai depois de 32 segundos: um ACK se perdeu, geralmente NAT ou Contact errado; o achado de ACK ausente na Análise confirma.",
        "Áudio de um lado só ou sem áudio: endereço privado no SDP, NAT simétrico ou firewall nas portas RTP; veja Mídia na Análise e rode o teste de NAT.",
      ]],
    ],
    keys: "Teclado: Enter liga ou atende, Esc desliga, F2 transfere, F3 espera, F4 mudo, dígitos mandam DTMF durante a chamada.",
    about: "Sobre",
    aboutText: "Softphone SIP e analisador de chamadas open source para troubleshooting. Feito por Ighor Toth.",
    version: "Versão",
    engine: "Modo",
    license: "Licença",
    source: "Código-fonte",
    issues: "Relatar um problema",
    releases: "Downloads",
    web: "Versão no navegador",
    credits: "Feito com Rust, Tauri, cpal, hickory-dns, WebRTC e as fontes IBM Plex.",
    language: "Idioma",
  },
  es: {
    title: "Ayuda",
    intro: "Sidetone es un softphone SIP pensado para diagnosticar: cada llamada se captura, se traza y se explica.",
    sections: [
      ["Primeros pasos", [
        "Abre Configuración y añade una cuenta: usuario, contraseña y el dominio o registrar (host o host:puerto). Guarda; el punto junto a la cuenta se pone verde cuando se registra.",
        "¿Sin registrar? Deja el dominio vacío y desactiva Registrar: Sidetone se convierte en un cliente anónimo que marca SIP URI directamente (sip:600@10.0.0.5:5060).",
        "En la versión del navegador la cuenta necesita una URL WebSocket (wss://...): tu centralita o SBC debe aceptar SIP sobre WebSocket.",
        "Provisionar carga los campos de la cuenta desde una URL (Configuración, Provisionar en la cuenta): un XML sidetone-provision o, en escritorio, el .cfg de Yealink o el XML de Polycom que tu centralita ya sirve a los teléfonos y los guarda. Un NOTIFY SIP con Event check-sync o resync vuelve a descargar esa URL; si hay una llamada, Sidetone espera a que termine antes de aplicar el archivo.",
      ]],
      ["Hacer y recibir llamadas", [
        "Escribe un número, usuario@host o un SIP URI y pulsa Enter o Llamar. Con la llamada activa, el teclado envía DTMF.",
        "Atajos al marcar: 600?Subject=prueba añade cabeceras al INVITE; 600,,1234# envía los dígitos al contestar (cada coma espera un segundo).",
        "El botón de opciones junto al número añade cabeceras o cambia ajustes de la cuenta (códecs, modo DTMF...) solo para la próxima llamada.",
        "Las llamadas entrantes suenan en el altavoz y aparecen en Líneas con Contestar y Rechazar. Varias líneas a la vez: contestar o reanudar una pone las demás en espera.",
      ]],
      ["Espera, transferencia, grabación", [
        "Espera envía un re-INVITE con sendonly; Reanudar envía sendrecv. Silencio solo corta tu micrófono.",
        "Transferir, Directa: REFER al destino y la llamada sale de ti. Transferir, Consultar antes: tu llamada queda en espera, Sidetone llama al destino y Completar transferencia une ambos lados (REFER con Replaces).",
        "Grabar guarda un WAV estéreo de la llamada: izquierda lo que enviaste, derecha lo que recibiste. Descárgalo en la página Llamadas.",
      ]],
      ["TCP, TLS, SRTP, BLF, presencia y conferencia", [
        "Cuenta, Red: Transporte elige UDP, TCP o TLS. TLS usa el puerto 5061 por defecto; desactiva Verificar el certificado TLS del servidor para una PBX con certificado autofirmado.",
        "Cuenta, Medios: SRTP Opcional ofrece cifrado y vuelve a RTP; Obligatorio rechaza o termina las llamadas sin él. Claves SRTP: SDES (a=crypto, úsalo con TLS) o DTLS-SRTP (handshake en la ruta de medios, certificado comprobado con a=fingerprint). La tarjeta Llamada actual muestra la suite y si el fingerprint coincidió.",
        "Cuenta, BLF: una extensión por línea. Cada una aparece bajo el teclado como Libre, Sonando u Ocupado (SUBSCRIBE al evento dialog); haz clic para llamar.",
        "Presencia: cuando el servidor la ofrece, cada lámpara muestra también Ausente, No molestar o Desconectado y la nota (SUBSCRIBE a presence, PIDF). El selector bajo la cuenta publica tu presencia con PUBLISH; Asterisk no acepta PUBLISH de teléfonos y responde 489.",
        "Conferencia: con dos llamadas activas, selecciona una y pulsa Conferencia para unir la otra. Sidetone mezcla el audio localmente; poner en espera o colgar cualquiera termina la conferencia.",
        "Buzón de voz: cuando el servidor informa mensajes (SUBSCRIBE message-summary o NOTIFY no solicitado), una lámpara bajo la cuenta muestra cuántos son nuevos; al pulsarla se marca el número de buzón definido en la cuenta.",
        "Desvío: Ajustes, Gestión de llamadas desvía todas las llamadas, las que llegan ocupado o en No molestar, o las no contestadas a tiempo, con 302 Moved Temporarily. Una llamada que suena también se puede desviar a mano: escribe el número en el campo de marcación y pulsa Desviar.",
        "Mensajes: las opciones bajo el campo de marcación envían un SIP MESSAGE (RFC 3428) al número escrito; los mensajes recibidos y el resultado de la entrega aparecen en Eventos del teléfono.",
      ]],
      ["Diagnosticar una llamada", [
        "La traza SIP muestra cada mensaje en vivo. Haz clic para leerlo completo, filtra por número o Call-ID y guarda la sesión como pcapng para Wireshark.",
        "Analizar (en el teléfono, el historial o la traza) abre la captura en Análisis: diagrama de escalera, hallazgos explicados, pérdida, jitter y MOS del RTP.",
        "Preguntar a la IA envía los hallazgos y los mensajes relevantes al proveedor que elijas, ocultos por defecto. Mostrar lo que se enviará enseña antes el prompt exacto.",
        "Exportar genera un pcapng anotado (hallazgos como comentarios de Wireshark) o uno anonimizado que oculta números, nombres, credenciales e IP públicas para tickets con proveedores.",
        "Los filtros funcionan como los display filters de Wireshark, en la traza SIP y en Análisis: ip.addr == 10.0.0.5, sip.method == INVITE, sip.status >= 400, sip.from contains \"2001\", sdp.codec == PCMA, combinados con && || ! y paréntesis. Una palabra suelta busca en todo el mensaje.",
        "Haz clic en una flecha RTP del ladder, o en el botón play en Medios, para escuchar ese stream y ver su forma de onda (en el navegador G.711 y Opus; la app de escritorio reproduce todos los códecs). El silencio en medio es un hueco: pérdida, espera o supresión de silencio. Guardar WAV conserva el audio.",
        "Medios también dibuja jitter, pérdida y MOS por segundo de cada stream, con los eventos SIP marcados, y muestra lo que midió el otro lado en sus informes RTCP: pérdida, jitter y tiempo de ida y vuelta. Un stream que fluye pero solo lleva silencio se señala (mute, un transcodificador defectuoso o un camino de medios roto).",
        "Las patas de la misma llamada a ambos lados de un SBC o B2BUA se enlazan cuando comparten X-CID, Session-ID o cabeceras similares; el icono de cadena en la lista de diálogos las selecciona juntas en un solo ladder.",
        "La tabla de jitter buffer muestra el MOS que tendría un teléfono con un buffer fijo de 50 ms, fijo de 200 ms o adaptativo: los paquetes que llegan tarde se descartan, así el jitter se convierte en pérdida.",
        "Las llamadas SRTP se analizan y reproducen descifradas; el SIP trace guarda la captura tal como pasó por la red, y Guardar con SRTP descifrado da la versión legible, con cada paquete descifrado comentado.",
        "HEP: las capturas de agentes Homer (Kamailio, OpenSIPS, FreeSWITCH, heplify) se desenvuelven automáticamente. Ajustes, Captura y grabación puede enviar una copia HEPv3 de cada mensaje SIP a tu Homer; sidetone hep en la línea de comandos actúa como colector.",
        "El botón Explicaciones oculta la pestaña Explicación, el SDP línea por línea y la ayuda de cabeceras para quien solo quiere los datos.",
        "Llamadas ahora muestra cada llamada en vivo (número, duración, códec, transporte, contadores RTP), el registro de cada cuenta y el resultado de la última acción: si la espera, la transferencia o el DTMF fallan, dice si la PBX no lo soporta, lo rechazó o no respondió.",
      ]],
      ["Diagnóstico", [
        "Alcance del servidor envía OPTIONS: cualquier respuesta, incluso 404 o 405, prueba que el servidor es alcanzable. El silencio apunta a dirección, puerto, firewall o interfaz de red.",
        "Aprovisionamiento de teléfonos descarga lo que recibiría un teléfono de sobremesa con una MAC desde un servidor TFTP o HTTP (tftp://10.0.0.5/SEP{MAC}.cnf.xml) y muestra el error o la cuenta que describe el archivo; Preguntar al DHCP muestra el servidor que la red da a los teléfonos (opciones 66, 150, 160). Una captura de un teléfono arrancando muestra lo mismo en Análisis.",
        "DNS muestra cómo se resuelve un dominio (NAPTR, SRV, A/AAAA) y qué dirección usa Sidetone.",
        "NAT pregunta a servidores STUN qué dirección pública ven; puertos distintos para servidores distintos indican NAT simétrico, la causa clásica del audio en un solo sentido.",
        "Audio permite elegir micrófono y altavoz y escuchar tu micrófono para comprobar niveles.",
        "Captura en una interfaz graba el tráfico de otros equipos (una centralita, un SBC, un teléfono en un puerto espejo) con un filtro BPF, muestra el SIP mientras pasa y abre el resultado en Análisis. Necesita Npcap en Windows y permisos de captura en Linux y macOS; el mensaje indica qué cambiar.",
      ]],
      ["Problemas frecuentes", [
        "Registro fallido 401/403: revisa usuario, usuario de autenticación y contraseña. 404: el usuario no existe en ese dominio.",
        "El servidor no responde: dirección o puerto incorrectos, un firewall que bloquea UDP o la interfaz de red equivocada (mira IP local en la pestaña Red de la cuenta).",
        "La llamada se corta a los 32 segundos: se pierde un ACK, normalmente por NAT o un Contact incorrecto; el hallazgo de ACK ausente en Análisis lo confirma.",
        "Audio en un solo sentido o sin audio: dirección privada en el SDP, NAT simétrico o firewall en los puertos RTP; mira Medios en Análisis y ejecuta la prueba de NAT.",
      ]],
    ],
    keys: "Teclado: Enter llama o contesta, Esc cuelga, F2 transfiere, F3 espera, F4 silencio, los dígitos envían DTMF durante la llamada.",
    about: "Acerca de",
    aboutText: "Softphone SIP y analizador de llamadas de código abierto para diagnóstico. Hecho por Ighor Toth.",
    version: "Versión",
    engine: "Modo",
    license: "Licencia",
    source: "Código fuente",
    issues: "Informar de un problema",
    releases: "Descargas",
    web: "Versión en el navegador",
    credits: "Hecho con Rust, Tauri, cpal, hickory-dns, WebRTC y las tipografías IBM Plex.",
    language: "Idioma",
  },
  de: {
    title: "Hilfe",
    intro: "Sidetone ist ein SIP-Softphone für die Fehlersuche: Jeder Anruf wird mitgeschnitten, protokolliert und erklärt.",
    sections: [
      ["Erste Schritte", [
        "Einstellungen öffnen und ein Konto anlegen: Benutzer, Passwort und Domain oder Registrar (Host oder Host:Port). Speichern; der Punkt neben dem Konto wird grün, sobald es registriert ist.",
        "Kein Registrar? Domain leer lassen und Registrieren ausschalten: Sidetone wird zum anonymen Client, der SIP-URIs direkt wählt (sip:600@10.0.0.5:5060).",
        "In der Browser-Version braucht das Konto eine WebSocket-URL (wss://...): Ihre TK-Anlage oder Ihr SBC muss SIP über WebSocket annehmen.",
        "Provisionieren lädt Kontofelder von einer URL (Einstellungen, Provisionieren am Konto): ein sidetone-provision-XML oder in der Desktop-App die Yealink-.cfg oder das Polycom-XML, das Ihre TK-Anlage den Tischtelefonen liefert und speichert sie. Ein SIP-NOTIFY mit Event check-sync oder resync lädt diese URL erneut; bei einem Gespräch wartet Sidetone, bis es endet, bevor die Datei angewendet wird.",
      ]],
      ["Anrufen und Anrufe annehmen", [
        "Nummer, benutzer@host oder SIP-URI eingeben und Enter oder Anrufen drücken. Im Gespräch sendet die Tastatur DTMF.",
        "Wählkürzel: 600?Subject=test fügt Header zum INVITE hinzu; 600,,1234# sendet die Ziffern nach dem Annehmen (jedes Komma wartet eine Sekunde).",
        "Die Optionstaste neben der Nummer fügt Header hinzu oder ändert Kontoeinstellungen (Codecs, DTMF-Modus...) nur für den nächsten Anruf.",
        "Eingehende Anrufe klingeln im Lautsprecher und erscheinen unter Leitungen mit Annehmen und Ablehnen. Mehrere Leitungen: Annehmen oder Fortsetzen hält die anderen.",
      ]],
      ["Halten, Weiterleiten, Aufnehmen", [
        "Halten sendet ein re-INVITE mit sendonly; Fortsetzen sendet sendrecv. Stumm schaltet nur Ihr Mikrofon ab.",
        "Weiterleiten, Blind: REFER an das Ziel, der Anruf verlässt Sie. Weiterleiten, Erst rückfragen: Ihr Anruf wird gehalten, Sidetone ruft das Ziel an, und Weiterleitung abschließen verbindet beide Seiten (REFER mit Replaces).",
        "Aufnehmen speichert ein Stereo-WAV: links das Gesendete, rechts das Empfangene. Download auf der Seite Anrufe.",
      ]],
      ["TCP, TLS, SRTP, BLF, Presence und Konferenz", [
        "Konto, Netzwerk: Transport wählt UDP, TCP oder TLS. TLS nutzt standardmäßig Port 5061; schalte TLS-Zertifikat des Servers prüfen bei einer TK-Anlage mit selbstsigniertem Zertifikat aus.",
        "Konto, Medien: SRTP Optional bietet Verschlüsselung an und fällt auf RTP zurück; Erforderlich lehnt Anrufe ohne sie ab oder beendet sie. SRTP-Schlüssel: SDES (a=crypto, mit TLS verwenden) oder DTLS-SRTP (Handshake auf dem Medienpfad, Zertifikat gegen a=fingerprint geprüft). Die Karte Aktueller Anruf zeigt die Suite und ob der Fingerprint passte.",
        "Konto, BLF: eine Nebenstelle pro Zeile. Jede erscheint unter der Wähltastatur als Frei, Klingelt oder Besetzt (SUBSCRIBE auf das Dialog-Event); Klick ruft sie an.",
        "Presence: wenn der Server sie anbietet, zeigt jede Lampe auch Abwesend, Nicht stören oder Offline und die Notiz (SUBSCRIBE auf presence, PIDF). Die Auswahl unter dem Konto veröffentlicht die eigene Presence per PUBLISH; Asterisk nimmt PUBLISH von Telefonen nicht an und antwortet 489.",
        "Konferenz: bei zwei aktiven Anrufen einen auswählen und Konferenz drücken, um den anderen dazuzuholen. Sidetone mischt das Audio lokal; Halten oder Auflegen eines Anrufs beendet die Konferenz.",
        "Mailbox: wenn der Server Nachrichten meldet (SUBSCRIBE message-summary oder unaufgefordertes NOTIFY), zeigt eine Lampe unter dem Konto, wie viele neu sind; ein Klick wählt die im Konto hinterlegte Mailbox-Nummer.",
        "Umleitung: Einstellungen, Anrufbehandlung leitet alle Anrufe, Anrufe bei besetzt oder Nicht stören oder unbeantwortete Anrufe mit 302 Moved Temporarily um. Ein klingelnder Anruf lässt sich auch von Hand umleiten: Nummer ins Wählfeld eingeben und Umleiten drücken.",
        "Nachrichten: die Optionen unter dem Wählfeld senden eine SIP MESSAGE (RFC 3428) an die eingegebene Nummer; empfangene Nachrichten und das Zustellergebnis erscheinen in Telefonereignisse.",
      ]],
      ["Einen Anruf untersuchen", [
        "Der SIP-Trace zeigt jede Nachricht live. Anklicken zum Lesen, nach Nummer oder Call-ID filtern und die Sitzung als pcapng für Wireshark speichern.",
        "Analysieren (am Telefon, im Verlauf oder im Trace) öffnet den Mitschnitt in der Analyse: Leiterdiagramm, verständliche Befunde, RTP-Verlust, Jitter und MOS.",
        "KI fragen sendet Befunde und relevante Nachrichten an den gewählten KI-Anbieter, standardmäßig maskiert. Zeigen, was gesendet wird, zeigt vorher den genauen Prompt.",
        "Export liefert ein kommentiertes pcapng (Befunde als Wireshark-Kommentare) oder ein anonymisiertes, das Nummern, Namen, Zugangsdaten und öffentliche IPs für Herstellertickets maskiert.",
        "Filter funktionieren wie Wireshark-Anzeigefilter, im SIP-Trace und in der Analyse: ip.addr == 10.0.0.5, sip.method == INVITE, sip.status >= 400, sip.from contains \"2001\", sdp.codec == PCMA, kombiniert mit && || ! und Klammern. Ein einzelnes Wort durchsucht die ganze Nachricht.",
        "Auf einen RTP-Pfeil im Ladder oder den Play-Knopf unter Medien klicken, um den Stream anzuhören und seine Wellenform zu sehen (im Browser G.711 und Opus; die Desktop-App spielt alle Codecs). Stille in der Mitte ist eine Lücke: Verlust, Halten oder Stillenunterdrückung. WAV speichern behält das Audio.",
        "Medien zeichnet außerdem Jitter, Verlust und MOS pro Sekunde für jeden Stream mit markierten SIP-Ereignissen und zeigt, was die Gegenseite in ihren RTCP-Berichten gemessen hat: Verlust, Jitter und Umlaufzeit. Ein Stream, der fließt, aber nur Stille trägt, wird markiert (stumm, defekter Transcoder oder kaputter Medienpfad).",
        "Abschnitte desselben Anrufs auf beiden Seiten eines SBC oder B2BUA werden verknüpft, wenn sie X-CID, Session-ID oder ähnliche Header teilen; das Kettensymbol in der Dialogliste wählt sie zusammen in einem Leiterdiagramm aus.",
        "Die Jitter-Buffer-Tabelle zeigt den MOS, den ein Telefon mit festem 50-ms-, festem 200-ms- oder adaptivem Buffer hätte: zu spät ankommende Pakete werden verworfen, so wird Jitter zu Verlust.",
        "SRTP-Anrufe werden entschlüsselt analysiert und abgespielt; der SIP-Trace speichert den Mitschnitt wie im Netz, und Mit entschlüsseltem SRTP speichern liefert die lesbare Version, jedes entschlüsselte Paket kommentiert.",
        "HEP: Mitschnitte von Homer-Agenten (Kamailio, OpenSIPS, FreeSWITCH, heplify) werden automatisch entpackt. Einstellungen, Mitschnitt und Aufnahme kann eine HEPv3-Kopie jeder SIP-Nachricht an Ihren Homer senden; sidetone hep auf der Kommandozeile arbeitet als Collector.",
        "Der Knopf Erklärungen blendet den Erklärungs-Tab, das SDP Zeile für Zeile und die Header-Hilfe aus, für alle, die nur die Rohdaten wollen.",
        "Anrufe zeigt jeden Anruf live (Nummer, Dauer, Codec, Transport, RTP-Zähler), die Registrierung jedes Kontos und das Ergebnis der letzten Aktion: Schlägt Halten, Weiterleiten oder DTMF fehl, steht dort, ob die TK-Anlage es nicht unterstützt, abgelehnt oder nicht geantwortet hat.",
      ]],
      ["Diagnose", [
        "Erreichbarkeit sendet OPTIONS: jede Antwort, auch 404 oder 405, beweist die Erreichbarkeit. Stille deutet auf Adresse, Port, Firewall oder Netzwerkschnittstelle.",
        "Telefon-Provisionierung holt, was ein Tischtelefon mit einer bestimmten MAC von einem TFTP- oder HTTP-Server bekäme (tftp://10.0.0.5/SEP{MAC}.cnf.xml), und zeigt den Fehler oder das beschriebene Konto; DHCP fragen zeigt den Server, den das Netz den Telefonen gibt (Optionen 66, 150, 160). Ein Mitschnitt eines startenden Telefons zeigt dasselbe in der Analyse.",
        "DNS zeigt, wie eine Domain aufgelöst wird (NAPTR, SRV, A/AAAA) und welche Adresse Sidetone nutzt.",
        "NAT fragt STUN-Server nach der öffentlichen Adresse; unterschiedliche Ports je Server bedeuten symmetrisches NAT, die klassische Ursache für einseitiges Audio.",
        "Audio wählt Mikrofon und Lautsprecher und spielt das Mikrofon zur Pegelkontrolle ab.",
        "Mitschnitt auf einer Schnittstelle zeichnet den Verkehr anderer Geräte auf (TK-Anlage, SBC, ein Telefon an einem gespiegelten Port), mit BPF-Filter, zeigt SIP live und öffnet das Ergebnis in der Analyse. Braucht Npcap unter Windows und Mitschnittrechte unter Linux und macOS; die Meldung sagt, was zu ändern ist.",
      ]],
      ["Häufige Probleme", [
        "Registrierung fehlgeschlagen 401/403: Benutzer, Authentifizierungsbenutzer und Passwort prüfen. 404: den Benutzer gibt es in dieser Domain nicht.",
        "Server antwortet nicht: falsche Adresse oder falscher Port, eine Firewall blockiert UDP oder die falsche Netzwerkschnittstelle (Lokale IP im Reiter Netzwerk des Kontos).",
        "Anruf bricht nach 32 Sekunden ab: ein ACK geht verloren, meist NAT oder ein falscher Contact; der Befund fehlendes ACK in der Analyse bestätigt es.",
        "Einseitiges oder kein Audio: private Adresse im SDP, symmetrisches NAT oder Firewall auf den RTP-Ports; Medien in der Analyse ansehen und den NAT-Test starten.",
      ]],
    ],
    keys: "Tastatur: Enter ruft an oder nimmt an, Esc legt auf, F2 Weiterleiten, F3 Halten, F4 Stumm, Ziffern senden im Gespräch DTMF.",
    about: "Über Sidetone",
    aboutText: "Open-Source-SIP-Softphone und Anrufanalyse für die Fehlersuche. Von Ighor Toth.",
    version: "Version",
    engine: "Modus",
    license: "Lizenz",
    source: "Quellcode",
    issues: "Problem melden",
    releases: "Downloads",
    web: "Browser-Version",
    credits: "Gebaut mit Rust, Tauri, cpal, hickory-dns, WebRTC und den Schriften IBM Plex.",
    language: "Sprache",
  },
};

const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

export function renderHelp(el, { lang, version, mode, langs, onLang }) {
  const h = H[lang] || (EXTRA[lang] && EXTRA[lang].H) || H.en;
  el.innerHTML = `
    <div class="help help-raw">
      <div class="page-head"><h1>${esc(h.title)}</h1>
        <label class="lang-pick">${esc(h.language)} <select id="help-lang">${langs.map(([c, n]) => `<option value="${c}" ${c === lang ? "selected" : ""}>${esc(n)}</option>`).join("")}</select></label>
      </div>
      <p class="lead">${esc(h.intro)}</p>
      <nav class="help-toc">${h.sections.map(([t], i) => `<a href="#help-${i}">${esc(t)}</a>`).join("")}<a href="#help-about">${esc(h.about)}</a></nav>
      <div class="help-grid">
        ${h.sections.map(([t, items], i) => `<section class="card" id="help-${i}"><h2>${esc(t)}</h2><ul>${items.map((x) => `<li>${esc(x)}</li>`).join("")}</ul></section>`).join("")}
      </div>
      <p class="help-keys">${esc(h.keys)}</p>
      <section class="card about" id="help-about">
        <div class="about-head">
          <svg viewBox="0 0 32 32" width="48" height="48" aria-hidden="true" class="st-ladder"><rect width="32" height="32" rx="7" class="brand-bg"/><path d="M9 7v18M23 7v18M9 12h14M23 19H9" class="brand-ink" stroke-width="2.4" fill="none" stroke-linecap="round"/></svg>
          <div><h2>Sidetone</h2><p>${esc(h.aboutText)}</p></div>
        </div>
        <dl class="kv">
          <dt>${esc(h.version)}</dt><dd>${esc(version || "dev")}</dd>
          <dt>${esc(h.engine)}</dt><dd>${esc(mode)}</dd>
          <dt>${esc(h.license)}</dt><dd><a href="${REPO}/blob/main/LICENSE" target="_blank" rel="noopener">MIT</a></dd>
          <dt>${esc(h.source)}</dt><dd><a href="${REPO}" target="_blank" rel="noopener">github.com/igtoth/sidetone</a></dd>
          <dt>${esc(h.releases)}</dt><dd><a href="${REPO}/releases/latest" target="_blank" rel="noopener">${REPO.replace("https://", "")}/releases</a></dd>
          <dt>${esc(h.web)}</dt><dd><a href="https://igtoth.github.io/sidetone/" target="_blank" rel="noopener">igtoth.github.io/sidetone</a></dd>
          <dt>${esc(h.issues)}</dt><dd><a href="${REPO}/issues/new" target="_blank" rel="noopener">${REPO.replace("https://", "")}/issues</a></dd>
        </dl>
        <p class="hint">${esc(h.credits)}</p>
      </section>
    </div>`;
  el.querySelector("#help-lang").addEventListener("change", (e) => onLang(e.target.value));
}
