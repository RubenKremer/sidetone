// Plain-language explanations for troubleshooting: what a call used, where it
// came from, what the SDP asked for and what the media really did. Written for
// people who do not remember every SIP header and SDP attribute by heart.
// Texts in English, Portuguese (Brazil), Spanish, German, French, Simplified
// Chinese and Hindi.

import { currentLang } from "./i18n.js";
import { trFinding } from "./findings-i18n.js";

const LI = { en: 0, pt: 1, es: 2, de: 3, fr: 4, zh: 5, hi: 6 };
/// Picks the text for the current language (English when one is missing).
const L = (...v) => v[LI[currentLang()] ?? 0] ?? v[0];
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const mono = (s) => `<span class="mono">${esc(s)}</span>`;

// ---------------------------------------------------------------------------
// Addresses

export function isPrivate(ip) {
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|169\.254\.|fc|fd|fe80:)/i.test(ip || "");
}
export function isLoopback(ip) {
  return /^(127\.|::1$)/.test(ip || "");
}
const host = (a) => (a || "").replace(/^\[/, "").replace(/\](:\d+)?$/, "").replace(/:\d+$/, "");
const port = (a) => +((a || "").match(/:(\d+)$/) || [])[1] || null;
function ipKind(ip) {
  if (!ip) return "";
  if (ip === "0.0.0.0") return L("placeholder address: media on hold (RFC 2543 style)", "endereço de espera: mídia em hold (estilo RFC 2543)", "dirección comodín: medios en espera (estilo RFC 2543)", "Platzhalteradresse: Medien gehalten (Stil RFC 2543)", "adresse fictive : média en attente (style RFC 2543)", "占位地址：媒体处于保持状态（RFC 2543 方式）", "placeholder address: media hold पर है (RFC 2543 शैली)");
  if (isLoopback(ip)) return L("loopback: only this machine", "loopback: só esta máquina", "loopback: solo esta máquina", "Loopback: nur dieser Rechner", "loopback : uniquement cette machine", "环回地址：仅限本机", "loopback: केवल यही मशीन");
  if (isPrivate(ip)) return L("private address: not reachable from the internet", "endereço privado: não é alcançável pela internet", "dirección privada: no alcanzable desde internet", "private Adresse: aus dem Internet nicht erreichbar", "adresse privée : injoignable depuis Internet", "私有地址：无法从互联网访问", "private address: internet से पहुँच योग्य नहीं");
  return L("public address", "endereço público", "dirección pública", "öffentliche Adresse", "adresse publique", "公网地址", "public address");
}

// ---------------------------------------------------------------------------
// SIP headers: [en, pt, es, de, fr, zh, hi]

const HEADERS = {
  via: [
    "Path of the request: every proxy adds a Via on top. Responses travel back along these. received= and rport= show the address the next hop really saw (NAT).",
    "Caminho da requisição: cada proxy adiciona um Via em cima. As respostas voltam por esses Via. received= e rport= mostram o endereço que o próximo salto realmente viu (NAT).",
    "Camino de la petición: cada proxy añade un Via encima. Las respuestas vuelven por esos Via. received= y rport= muestran la dirección que el siguiente salto vio realmente (NAT).",
    "Weg der Anfrage: Jeder Proxy setzt einen Via oben drauf. Antworten laufen diesen Weg zurück. received= und rport= zeigen die Adresse, die der nächste Hop wirklich gesehen hat (NAT).",
    "Chemin de la requête : chaque proxy ajoute un Via au-dessus. Les réponses reviennent par ces Via. received= et rport= indiquent l'adresse que le saut suivant a réellement vue (NAT).",
    "请求的路径：每个代理都会在最上面添加一个 Via。响应沿这些 Via 原路返回。received= 和 rport= 显示下一跳实际看到的地址（NAT）。",
    "Request का रास्ता: हर proxy सबसे ऊपर एक Via जोड़ता है। Responses इन्हीं Via के रास्ते वापस आते हैं। received= और rport= वह address दिखाते हैं जो अगले hop ने वास्तव में देखा (NAT)।",
  ],
  from: [
    "Who starts this dialog (the caller for an INVITE). The tag identifies this side of the dialog.",
    "Quem inicia o diálogo (quem liga, num INVITE). O tag identifica este lado do diálogo.",
    "Quién inicia el diálogo (quien llama, en un INVITE). El tag identifica este lado del diálogo.",
    "Wer den Dialog beginnt (bei einem INVITE der Anrufer). Der Tag kennzeichnet diese Seite des Dialogs.",
    "Qui initie ce dialogue (l'appelant pour un INVITE). Le tag identifie ce côté du dialogue.",
    "发起此对话的一方（对 INVITE 而言即主叫）。tag 标识对话的这一端。",
    "यह dialog कौन शुरू करता है (INVITE में कॉल करने वाला)। tag dialog के इस पक्ष की पहचान करता है।",
  ],
  to: [
    "Who is being called, as dialed. The far end adds its tag when it answers.",
    "Para quem é a chamada, como foi discado. O outro lado adiciona o tag ao responder.",
    "A quién se llama, tal como se marcó. El otro lado añade su tag al responder.",
    "Wer angerufen wird, wie gewählt. Die Gegenseite fügt beim Antworten ihren Tag hinzu.",
    "Qui est appelé, tel que composé. L'extrémité distante ajoute son tag en répondant.",
    "被叫方，即所拨号码。对端应答时会添加自己的 tag。",
    "किसे कॉल किया जा रहा है, जैसा डायल किया गया। दूसरा पक्ष जवाब देते समय अपना tag जोड़ता है।",
  ],
  "call-id": [
    "Unique name of the call. Every message of the same dialog shares it.",
    "Nome único da chamada. Todas as mensagens do mesmo diálogo têm o mesmo.",
    "Nombre único de la llamada. Todos los mensajes del mismo diálogo lo comparten.",
    "Eindeutiger Name des Anrufs. Alle Nachrichten desselben Dialogs tragen ihn.",
    "Nom unique de l'appel. Tous les messages d'un même dialogue le partagent.",
    "呼叫的唯一名称。同一对话中的所有消息都使用它。",
    "कॉल का अद्वितीय नाम। एक ही dialog के सभी messages में यही होता है।",
  ],
  cseq: [
    "Sequence number and method: pairs each response with its request.",
    "Número de sequência e método: liga cada resposta à sua requisição.",
    "Número de secuencia y método: empareja cada respuesta con su petición.",
    "Folgenummer und Methode: ordnet jede Antwort ihrer Anfrage zu.",
    "Numéro de séquence et méthode : associe chaque réponse à sa requête.",
    "序列号和方法：把每个响应与其请求对应起来。",
    "Sequence number और method: हर response को उसके request से जोड़ता है।",
  ],
  contact: [
    "Where this side wants to receive the next requests of the dialog (ACK, BYE, re-INVITE). A private address here behind NAT is a classic cause of missing ACK and calls dropping at 32 s.",
    "Onde este lado quer receber as próximas requisições do diálogo (ACK, BYE, re-INVITE). Um endereço privado aqui atrás de NAT é causa clássica de ACK perdido e queda aos 32 s.",
    "Dónde quiere recibir este lado las siguientes peticiones del diálogo (ACK, BYE, re-INVITE). Una dirección privada aquí detrás de NAT es causa clásica de ACK perdido y cortes a los 32 s.",
    "Wo diese Seite die nächsten Anfragen des Dialogs empfangen will (ACK, BYE, re-INVITE). Eine private Adresse hier hinter NAT ist eine klassische Ursache für fehlendes ACK und Abbrüche nach 32 s.",
    "Où ce côté veut recevoir les requêtes suivantes du dialogue (ACK, BYE, re-INVITE). Une adresse privée ici derrière un NAT est une cause classique d'ACK manquant et d'appels coupés à 32 s.",
    "本端希望接收该对话后续请求（ACK、BYE、re-INVITE）的地址。在 NAT 后面此处出现私有地址，是 ACK 丢失、呼叫在 32 秒时断开的典型原因。",
    "यह पक्ष dialog के अगले requests (ACK, BYE, re-INVITE) कहाँ पाना चाहता है। NAT के पीछे यहाँ private address होना ACK न मिलने और 32 s पर कॉल कटने का आम कारण है।",
  ],
  "record-route": [
    "A proxy asks to stay in the path for the rest of the dialog.",
    "Um proxy pede para continuar no caminho pelo resto do diálogo.",
    "Un proxy pide seguir en el camino durante el resto del diálogo.",
    "Ein Proxy bittet, für den Rest des Dialogs im Weg zu bleiben.",
    "Un proxy demande à rester sur le chemin pour le reste du dialogue.",
    "代理要求在对话的剩余过程中留在路径上。",
    "एक proxy बाकी dialog के लिए रास्ते में बने रहने को कहता है।",
  ],
  route: [
    "The proxies this request must go through, taken from Record-Route.",
    "Os proxies por onde esta requisição tem de passar, tirados do Record-Route.",
    "Los proxies por los que debe pasar esta petición, tomados de Record-Route.",
    "Die Proxys, über die diese Anfrage laufen muss, aus Record-Route übernommen.",
    "Les proxies par lesquels cette requête doit passer, repris du Record-Route.",
    "此请求必须经过的代理，取自 Record-Route。",
    "वे proxies जिनसे होकर यह request जाना चाहिए, Record-Route से लिए गए।",
  ],
  "max-forwards": [
    "Hop limit, lowered by each proxy. Near 0 means a routing loop.",
    "Limite de saltos, cada proxy diminui. Perto de 0 indica loop de roteamento.",
    "Límite de saltos, cada proxy lo reduce. Cerca de 0 indica un bucle de enrutamiento.",
    "Hop-Limit, jeder Proxy senkt ihn. Nahe 0 deutet auf eine Routing-Schleife hin.",
    "Limite de sauts, décrémentée par chaque proxy. Proche de 0 signifie une boucle de routage.",
    "跳数限制，每经过一个代理减一。接近 0 表示存在路由环路。",
    "Hop limit, हर proxy इसे घटाता है। 0 के करीब होना routing loop का संकेत है।",
  ],
  "user-agent": ["Software that sent the request.", "Software que enviou a requisição.", "Software que envió la petición.", "Software, die die Anfrage gesendet hat.", "Logiciel qui a envoyé la requête.", "发送该请求的软件。", "वह software जिसने request भेजा।"],
  server: ["Software that sent the response.", "Software que enviou a resposta.", "Software que envió la respuesta.", "Software, die die Antwort gesendet hat.", "Logiciel qui a envoyé la réponse.", "发送该响应的软件。", "वह software जिसने response भेजा।"],
  allow: ["Methods this side accepts.", "Métodos que este lado aceita.", "Métodos que acepta este lado.", "Methoden, die diese Seite annimmt.", "Méthodes acceptées par ce côté.", "本端接受的方法。", "वे methods जो यह पक्ष स्वीकार करता है।"],
  supported: [
    "SIP extensions this side can use (100rel = PRACK, timer = session timers, replaces = attended transfer).",
    "Extensões SIP que este lado sabe usar (100rel = PRACK, timer = session timers, replaces = transferência assistida).",
    "Extensiones SIP que este lado sabe usar (100rel = PRACK, timer = session timers, replaces = transferencia atendida).",
    "SIP-Erweiterungen, die diese Seite beherrscht (100rel = PRACK, timer = Session-Timer, replaces = Vermittlung mit Rückfrage).",
    "Extensions SIP que ce côté sait utiliser (100rel = PRACK, timer = session timers, replaces = transfert supervisé).",
    "本端可使用的 SIP 扩展（100rel = PRACK，timer = 会话定时器，replaces = 咨询转接）。",
    "SIP extensions जो यह पक्ष उपयोग कर सकता है (100rel = PRACK, timer = session timers, replaces = attended transfer)।",
  ],
  require: [
    "Extensions the other side must support, or reject with 420.",
    "Extensões que o outro lado tem de suportar, senão rejeita com 420.",
    "Extensiones que el otro lado debe soportar; si no, rechaza con 420.",
    "Erweiterungen, die die Gegenseite unterstützen muss, sonst lehnt sie mit 420 ab.",
    "Extensions que l'autre côté doit prendre en charge, sinon il refuse avec 420.",
    "对端必须支持的扩展，否则以 420 拒绝。",
    "वे extensions जिन्हें दूसरे पक्ष को support करना ही होगा, वरना वह 420 से reject करेगा।",
  ],
  "session-expires": [
    "Session timer: the call must be refreshed (re-INVITE or UPDATE) before this many seconds, or it is torn down.",
    "Session timer: a chamada tem de ser renovada (re-INVITE ou UPDATE) antes desse tempo, senão cai.",
    "Session timer: la llamada debe renovarse (re-INVITE o UPDATE) antes de estos segundos, o se corta.",
    "Session-Timer: Der Anruf muss vor Ablauf dieser Sekunden erneuert werden (re-INVITE oder UPDATE), sonst wird er beendet.",
    "Session timer : l'appel doit être rafraîchi (re-INVITE ou UPDATE) avant ce nombre de secondes, sinon il est libéré.",
    "会话定时器：必须在这么多秒内刷新呼叫（re-INVITE 或 UPDATE），否则呼叫会被拆除。",
    "Session timer: इतने सेकंड से पहले कॉल को refresh (re-INVITE या UPDATE) करना होगा, वरना कॉल खत्म कर दी जाएगी।",
  ],
  "min-se": ["Shortest session timer this side accepts.", "Menor session timer que este lado aceita.", "Session timer más corto que acepta este lado.", "Kürzester Session-Timer, den diese Seite annimmt.", "Session timer le plus court accepté par ce côté.", "本端接受的最短会话定时器。", "सबसे छोटा session timer जो यह पक्ष स्वीकार करता है।"],
  "content-type": [
    "Format of the body: application/sdp is the media offer or answer.",
    "Formato do corpo: application/sdp é a oferta ou resposta de mídia.",
    "Formato del cuerpo: application/sdp es la oferta o respuesta de medios.",
    "Format des Inhalts: application/sdp ist das Medienangebot oder die Medienantwort.",
    "Format du corps : application/sdp est l'offre ou la réponse média.",
    "消息体格式：application/sdp 表示媒体的提议（offer）或应答（answer）。",
    "Body का format: application/sdp media का offer या answer है।",
  ],
  "content-length": [
    "Body size in bytes. Mandatory over TCP and TLS.",
    "Tamanho do corpo em bytes. Obrigatório em TCP e TLS.",
    "Tamaño del cuerpo en bytes. Obligatorio en TCP y TLS.",
    "Größe des Inhalts in Bytes. Pflicht bei TCP und TLS.",
    "Taille du corps en octets. Obligatoire sur TCP et TLS.",
    "消息体大小（字节）。在 TCP 和 TLS 上为必填。",
    "Body का आकार bytes में। TCP और TLS पर अनिवार्य।",
  ],
  "p-asserted-identity": [
    "The caller identity a trusted network vouches for (used for caller ID and billing).",
    "A identidade do chamador garantida por uma rede confiável (usada para bina e tarifação).",
    "La identidad del llamante que garantiza una red de confianza (usada para el identificador de llamadas y la tarificación).",
    "Die Anruferidentität, für die ein vertrauenswürdiges Netz bürgt (für Rufnummernanzeige und Abrechnung).",
    "L'identité de l'appelant garantie par un réseau de confiance (utilisée pour la présentation du numéro et la facturation).",
    "由可信网络担保的主叫身份（用于来电显示和计费）。",
    "कॉल करने वाले की पहचान जिसकी गारंटी एक trusted network देता है (caller ID और billing के लिए)।",
  ],
  "p-preferred-identity": [
    "The identity the phone would like to present; the network decides.",
    "A identidade que o telefone gostaria de apresentar; a rede decide.",
    "La identidad que el teléfono querría presentar; decide la red.",
    "Die Identität, die das Telefon gern anzeigen würde; das Netz entscheidet.",
    "L'identité que le téléphone souhaiterait présenter ; le réseau décide.",
    "话机希望显示的身份；由网络决定。",
    "वह पहचान जो फ़ोन दिखाना चाहता है; फ़ैसला network करता है।",
  ],
  "remote-party-id": [
    "Older header for caller identity and privacy.",
    "Cabeçalho antigo de identidade do chamador e privacidade.",
    "Cabecera antigua de identidad del llamante y privacidad.",
    "Älterer Header für Anruferidentität und Datenschutz.",
    "Ancien en-tête pour l'identité de l'appelant et la confidentialité.",
    "用于主叫身份和隐私的旧头字段。",
    "कॉल करने वाले की पहचान और privacy के लिए पुराना header।",
  ],
  privacy: [
    "Hide the caller identity from the far end (id, header, user).",
    "Esconder a identidade do chamador do outro lado (id, header, user).",
    "Ocultar la identidad del llamante al otro lado (id, header, user).",
    "Anruferidentität vor der Gegenseite verbergen (id, header, user).",
    "Masquer l'identité de l'appelant à l'extrémité distante (id, header, user).",
    "向对端隐藏主叫身份（id、header、user）。",
    "दूसरे पक्ष से कॉल करने वाले की पहचान छिपाना (id, header, user)।",
  ],
  diversion: [
    "The call was forwarded: who forwarded it and why.",
    "A chamada foi desviada: quem desviou e por quê.",
    "La llamada fue desviada: quién la desvió y por qué.",
    "Der Anruf wurde umgeleitet: von wem und warum.",
    "L'appel a été renvoyé : par qui et pourquoi.",
    "呼叫已被前转：由谁前转以及原因。",
    "कॉल forward की गई थी: किसने और क्यों।",
  ],
  "history-info": [
    "Every retarget of the request (forwarding), in order.",
    "Cada redirecionamento da requisição (desvios), em ordem.",
    "Cada redirección de la petición (desvíos), en orden.",
    "Jede Umleitung der Anfrage, in Reihenfolge.",
    "Chaque redirection de la requête (renvois), dans l'ordre.",
    "请求的每一次重定向（前转），按顺序列出。",
    "Request का हर retarget (forwarding), क्रम से।",
  ],
  reason: [
    "Why the call ended or was cancelled; Q.850 cause numbers come from the telephone network.",
    "Por que a chamada terminou ou foi cancelada; os números Q.850 vêm da rede telefônica.",
    "Por qué terminó o se canceló la llamada; los números Q.850 vienen de la red telefónica.",
    "Warum der Anruf endete oder abgebrochen wurde; Q.850-Ursachen stammen aus dem Telefonnetz.",
    "Pourquoi l'appel s'est terminé ou a été annulé ; les numéros de cause Q.850 viennent du réseau téléphonique.",
    "呼叫结束或被取消的原因；Q.850 原因值来自电话网络。",
    "कॉल क्यों खत्म हुई या रद्द हुई; Q.850 cause numbers टेलीफ़ोन network से आते हैं।",
  ],
  warning: ["Extra text from the server explaining a failure.", "Texto extra do servidor explicando uma falha.", "Texto adicional del servidor que explica un fallo.", "Zusätzlicher Text des Servers zu einem Fehler.", "Texte supplémentaire du serveur expliquant un échec.", "服务器对失败原因的附加说明文字。", "Server का अतिरिक्त text जो किसी failure को समझाता है।"],
  expires: [
    "How long a registration or subscription is valid, in seconds.",
    "Quanto tempo um registro ou assinatura vale, em segundos.",
    "Cuánto vale un registro o una suscripción, en segundos.",
    "Wie lange eine Registrierung oder ein Abonnement gilt, in Sekunden.",
    "Durée de validité d'un enregistrement ou d'un abonnement, en secondes.",
    "注册或订阅的有效期，单位为秒。",
    "Registration या subscription कितने समय तक मान्य है, सेकंड में।",
  ],
  "www-authenticate": [
    "The server asks for credentials (401): realm and nonce for the digest.",
    "O servidor pede credenciais (401): realm e nonce para o digest.",
    "El servidor pide credenciales (401): realm y nonce para el digest.",
    "Der Server verlangt Zugangsdaten (401): Realm und Nonce für den Digest.",
    "Le serveur demande des identifiants (401) : realm et nonce pour le digest.",
    "服务器要求提供凭据（401）：用于 digest 的 realm 和 nonce。",
    "Server credentials माँगता है (401): digest के लिए realm और nonce।",
  ],
  "proxy-authenticate": ["A proxy asks for credentials (407).", "Um proxy pede credenciais (407).", "Un proxy pide credenciales (407).", "Ein Proxy verlangt Zugangsdaten (407).", "Un proxy demande des identifiants (407).", "代理要求提供凭据（407）。", "एक proxy credentials माँगता है (407)।"],
  authorization: [
    "Digest answer to a 401 challenge: proves the password without sending it.",
    "Resposta digest ao desafio 401: prova a senha sem enviá-la.",
    "Respuesta digest al desafío 401: demuestra la contraseña sin enviarla.",
    "Digest-Antwort auf eine 401-Abfrage: beweist das Passwort, ohne es zu senden.",
    "Réponse digest à un challenge 401 : prouve le mot de passe sans l'envoyer.",
    "对 401 质询的 digest 应答：无需发送密码即可证明知道密码。",
    "401 challenge का digest जवाब: password भेजे बिना उसे साबित करता है।",
  ],
  "proxy-authorization": ["Digest answer to a 407 challenge.", "Resposta digest ao desafio 407.", "Respuesta digest al desafío 407.", "Digest-Antwort auf eine 407-Abfrage.", "Réponse digest à un challenge 407.", "对 407 质询的 digest 应答。", "407 challenge का digest जवाब।"],
  "refer-to": [
    "Transfer target: who the other side should call.",
    "Destino da transferência: para quem o outro lado deve ligar.",
    "Destino de la transferencia: a quién debe llamar el otro lado.",
    "Ziel der Vermittlung: wen die Gegenseite anrufen soll.",
    "Cible du transfert : qui l'autre côté doit appeler.",
    "转接目标：对端应呼叫的对象。",
    "Transfer का लक्ष्य: दूसरे पक्ष को किसे कॉल करना है।",
  ],
  "referred-by": ["Who requested the transfer.", "Quem pediu a transferência.", "Quién pidió la transferencia.", "Wer die Vermittlung angefordert hat.", "Qui a demandé le transfert.", "请求转接的一方。", "Transfer किसने माँगा।"],
  replaces: [
    "This call replaces an existing dialog (attended transfer, call pickup).",
    "Esta chamada substitui um diálogo existente (transferência assistida, captura).",
    "Esta llamada sustituye un diálogo existente (transferencia atendida, captura).",
    "Dieser Anruf ersetzt einen bestehenden Dialog (Vermittlung mit Rückfrage, Heranholen).",
    "Cet appel remplace un dialogue existant (transfert supervisé, interception d'appel).",
    "此呼叫替换一个现有对话（咨询转接、代接）。",
    "यह कॉल एक मौजूदा dialog की जगह लेती है (attended transfer, call pickup)।",
  ],
  event: [
    "Event package of a SUBSCRIBE or NOTIFY (dialog = BLF, presence, refer = transfer progress, message-summary = voicemail).",
    "Pacote de evento de SUBSCRIBE ou NOTIFY (dialog = BLF, presence, refer = andamento de transferência, message-summary = correio de voz).",
    "Paquete de eventos de un SUBSCRIBE o NOTIFY (dialog = BLF, presence, refer = progreso de transferencia, message-summary = buzón de voz).",
    "Ereignispaket eines SUBSCRIBE oder NOTIFY (dialog = BLF, presence, refer = Vermittlungsfortschritt, message-summary = Mailbox).",
    "Paquetage d'événements d'un SUBSCRIBE ou NOTIFY (dialog = BLF, presence, refer = progression du transfert, message-summary = messagerie vocale).",
    "SUBSCRIBE 或 NOTIFY 的事件包（dialog = BLF，presence = 在线状态，refer = 转接进度，message-summary = 语音信箱）。",
    "SUBSCRIBE या NOTIFY का event package (dialog = BLF, presence, refer = transfer की प्रगति, message-summary = voicemail)।",
  ],
  "subscription-state": [
    "Whether the subscription is active, pending or terminated.",
    "Se a assinatura está ativa, pendente ou encerrada.",
    "Si la suscripción está activa, pendiente o terminada.",
    "Ob das Abonnement aktiv, ausstehend oder beendet ist.",
    "Indique si l'abonnement est actif, en attente ou terminé.",
    "订阅是活动、待定还是已终止。",
    "Subscription active है, pending है या terminated।",
  ],
  rseq: [
    "Sequence number of a reliable provisional response (PRACK).",
    "Número de sequência de resposta provisória confiável (PRACK).",
    "Número de secuencia de una respuesta provisional fiable (PRACK).",
    "Folgenummer einer zuverlässigen vorläufigen Antwort (PRACK).",
    "Numéro de séquence d'une réponse provisoire fiable (PRACK).",
    "可靠临时响应的序列号（PRACK）。",
    "Reliable provisional response का sequence number (PRACK)।",
  ],
  rack: ["Acknowledges a reliable provisional response.", "Confirma uma resposta provisória confiável.", "Confirma una respuesta provisional fiable.", "Bestätigt eine zuverlässige vorläufige Antwort.", "Acquitte une réponse provisoire fiable.", "确认一个可靠临时响应。", "एक reliable provisional response की पुष्टि करता है।"],
  "alert-info": [
    "Ring tone hint, or auto answer for intercom.",
    "Dica de toque, ou atendimento automático para interfone.",
    "Indicación de tono de llamada, o respuesta automática para intercomunicador.",
    "Hinweis auf den Klingelton oder automatische Annahme für Gegensprechen.",
    "Indication de sonnerie, ou réponse automatique pour l'interphonie.",
    "振铃音提示，或用于对讲的自动应答。",
    "Ring tone का संकेत, या intercom के लिए auto answer।",
  ],
  "call-info": [
    "Extra information about the call; answer-after asks for auto answer.",
    "Informação extra da chamada; answer-after pede atendimento automático.",
    "Información adicional de la llamada; answer-after pide respuesta automática.",
    "Zusatzinformation zum Anruf; answer-after verlangt automatische Annahme.",
    "Informations supplémentaires sur l'appel ; answer-after demande une réponse automatique.",
    "呼叫的附加信息；answer-after 表示要求自动应答。",
    "कॉल के बारे में अतिरिक्त जानकारी; answer-after auto answer माँगता है।",
  ],
  accept: ["Body formats this side understands.", "Formatos de corpo que este lado entende.", "Formatos de cuerpo que entiende este lado.", "Inhaltsformate, die diese Seite versteht.", "Formats de corps que ce côté comprend.", "本端能理解的消息体格式。", "Body formats जिन्हें यह पक्ष समझता है।"],
};
const COMPACT = { v: "via", f: "from", t: "to", i: "call-id", m: "contact", l: "content-length", c: "content-type", k: "supported", r: "refer-to", b: "referred-by", o: "event", x: "session-expires" };

export function headerHelp(name) {
  const n = name.trim().toLowerCase();
  const h = HEADERS[COMPACT[n] || n];
  return h ? L(...h) : "";
}

// ---------------------------------------------------------------------------
// Status codes: [en, pt, es, de, fr, zh, hi]

const STATUS = {
  100: ["The next hop got the request and is working on it.", "O próximo salto recebeu a requisição e está tratando.", "El siguiente salto recibió la petición y la está procesando.", "Der nächste Hop hat die Anfrage erhalten und bearbeitet sie.", "Le saut suivant a reçu la requête et la traite.", "下一跳已收到请求，正在处理。", "अगले hop को request मिल गया है और वह उस पर काम कर रहा है।"],
  180: ["The phone is ringing.", "O telefone está tocando.", "El teléfono está sonando.", "Das Telefon klingelt.", "Le téléphone sonne.", "电话正在振铃。", "फ़ोन बज रहा है।"],
  181: ["The call is being forwarded.", "A chamada está sendo desviada.", "La llamada se está desviando.", "Der Anruf wird umgeleitet.", "L'appel est en cours de renvoi.", "呼叫正在被前转。", "कॉल forward की जा रही है।"],
  182: ["The call is queued.", "A chamada está na fila.", "La llamada está en cola.", "Der Anruf ist in der Warteschlange.", "L'appel est en file d'attente.", "呼叫正在排队。", "कॉल queue में है।"],
  183: ["Session progress: early media (ringback, announcements) may flow before the answer.", "Progresso da sessão: mídia antecipada (tom de chamada, anúncios) pode passar antes do atendimento.", "Progreso de sesión: medios tempranos (tono de llamada, anuncios) pueden fluir antes de la respuesta.", "Sitzungsfortschritt: Early Media (Freiton, Ansagen) kann vor der Annahme fließen.", "Progression de session : un early media (retour d'appel, annonces) peut circuler avant la réponse.", "会话进展：应答前可能已有早期媒体（回铃音、通知音）在传输。", "Session progress: जवाब से पहले early media (ringback, announcements) चल सकता है।"],
  200: ["Success. For an INVITE: the call was answered.", "Sucesso. Num INVITE: a chamada foi atendida.", "Éxito. En un INVITE: la llamada fue contestada.", "Erfolg. Bei einem INVITE: Der Anruf wurde angenommen.", "Succès. Pour un INVITE : l'appel a été répondu.", "成功。对 INVITE 而言：呼叫已应答。", "सफल। INVITE के लिए: कॉल का जवाब दिया गया।"],
  202: ["Accepted, done later (a REFER transfer is under way).", "Aceito, será feito depois (uma transferência REFER está em andamento).", "Aceptado, se hará después (una transferencia REFER está en curso).", "Angenommen, wird später erledigt (eine REFER-Vermittlung läuft).", "Accepté, traité plus tard (un transfert REFER est en cours).", "已接受，稍后执行（REFER 转接正在进行中）。", "स्वीकार किया, बाद में पूरा होगा (एक REFER transfer चल रहा है)।"],
  301: ["The user moved permanently; Contact has the new address.", "O usuário mudou de vez; o Contact tem o novo endereço.", "El usuario se movió de forma permanente; Contact tiene la nueva dirección.", "Der Teilnehmer ist dauerhaft umgezogen; Contact enthält die neue Adresse.", "L'utilisateur a déménagé définitivement ; Contact contient la nouvelle adresse.", "用户已永久迁移；Contact 中有新地址。", "User स्थायी रूप से कहीं और चला गया; Contact में नया address है।"],
  302: ["Moved temporarily: try the address in Contact (call forwarding).", "Mudou temporariamente: tente o endereço do Contact (desvio).", "Movido temporalmente: pruebe la dirección de Contact (desvío).", "Vorübergehend umgezogen: Adresse in Contact versuchen (Rufumleitung).", "Déplacé temporairement : essayez l'adresse dans Contact (renvoi d'appel).", "临时迁移：请尝试 Contact 中的地址（呼叫前转）。", "अस्थायी रूप से moved: Contact वाला address आज़माएँ (call forwarding)।"],
  400: ["Bad request: the message is malformed.", "Requisição inválida: a mensagem está malformada.", "Petición incorrecta: el mensaje está mal formado.", "Fehlerhafte Anfrage: Die Nachricht ist nicht wohlgeformt.", "Requête incorrecte : le message est mal formé.", "错误请求：消息格式不正确。", "Bad request: message का format गलत है।"],
  401: ["Credentials needed: the phone repeats the request with a digest. Normal once; a second 401 means a wrong user or password.", "Credenciais necessárias: o telefone repete a requisição com digest. Normal uma vez; um segundo 401 indica usuário ou senha errados.", "Credenciales necesarias: el teléfono repite la petición con digest. Normal una vez; un segundo 401 indica usuario o contraseña incorrectos.", "Zugangsdaten nötig: Das Telefon wiederholt die Anfrage mit Digest. Einmal normal; ein zweites 401 heißt falscher Benutzer oder falsches Passwort.", "Identifiants requis : le téléphone répète la requête avec un digest. Normal une fois ; un second 401 signifie un utilisateur ou un mot de passe erroné.", "需要凭据：话机会带上 digest 重发请求。出现一次属正常；第二次 401 表示用户名或密码错误。", "Credentials चाहिए: फ़ोन digest के साथ request दोबारा भेजता है। एक बार होना सामान्य है; दूसरा 401 मतलब गलत user या password।"],
  403: ["Forbidden: the server knows who you are and refuses (no permission, blocked number, wrong realm).", "Proibido: o servidor sabe quem você é e recusa (sem permissão, número bloqueado, realm errado).", "Prohibido: el servidor sabe quién eres y lo rechaza (sin permiso, número bloqueado, realm incorrecto).", "Verboten: Der Server kennt dich und lehnt ab (keine Berechtigung, gesperrte Nummer, falscher Realm).", "Interdit : le serveur sait qui vous êtes et refuse (pas d'autorisation, numéro bloqué, mauvais realm).", "禁止：服务器知道你是谁，但拒绝请求（无权限、号码被封锁、realm 错误）。", "Forbidden: server जानता है कि आप कौन हैं और मना करता है (अनुमति नहीं, number blocked, गलत realm)।"],
  404: ["Not found: the number or user does not exist on that server.", "Não encontrado: o número ou usuário não existe naquele servidor.", "No encontrado: el número o usuario no existe en ese servidor.", "Nicht gefunden: Nummer oder Benutzer gibt es auf diesem Server nicht.", "Introuvable : le numéro ou l'utilisateur n'existe pas sur ce serveur.", "未找到：该服务器上不存在此号码或用户。", "Not found: वह number या user उस server पर मौजूद नहीं है।"],
  405: ["Method not allowed here.", "Método não permitido aqui.", "Método no permitido aquí.", "Methode hier nicht erlaubt.", "Méthode non autorisée ici.", "此处不允许该方法。", "यहाँ यह method अनुमत नहीं है।"],
  407: ["A proxy needs credentials: the request is repeated with Proxy-Authorization.", "Um proxy precisa de credenciais: a requisição é repetida com Proxy-Authorization.", "Un proxy necesita credenciales: la petición se repite con Proxy-Authorization.", "Ein Proxy braucht Zugangsdaten: Die Anfrage wird mit Proxy-Authorization wiederholt.", "Un proxy a besoin d'identifiants : la requête est répétée avec Proxy-Authorization.", "代理需要凭据：请求会带上 Proxy-Authorization 重发。", "Proxy को credentials चाहिए: request Proxy-Authorization के साथ दोबारा भेजा जाता है।"],
  408: ["Request timeout: nobody answered in time.", "Tempo esgotado: ninguém respondeu a tempo.", "Tiempo agotado: nadie respondió a tiempo.", "Zeitüberschreitung: Niemand hat rechtzeitig geantwortet.", "Délai dépassé : personne n'a répondu à temps.", "请求超时：无人及时响应。", "Request timeout: किसी ने समय पर जवाब नहीं दिया।"],
  410: ["Gone: the number existed but no longer does.", "Não existe mais: o número existiu mas foi desativado.", "Ya no existe: el número existió pero se dio de baja.", "Nicht mehr vorhanden: Die Nummer gab es, jetzt nicht mehr.", "Disparu : le numéro a existé mais n'existe plus.", "已不存在：该号码曾经存在，但现已停用。", "Gone: यह number पहले था, अब नहीं है।"],
  415: ["Unsupported body format.", "Formato de corpo não suportado.", "Formato de cuerpo no soportado.", "Nicht unterstütztes Inhaltsformat.", "Format de corps non pris en charge.", "不支持的消息体格式。", "Body format support नहीं है।"],
  420: ["The far end does not support an extension listed in Require.", "O outro lado não suporta uma extensão listada em Require.", "El otro lado no soporta una extensión indicada en Require.", "Die Gegenseite unterstützt eine in Require genannte Erweiterung nicht.", "L'extrémité distante ne prend pas en charge une extension indiquée dans Require.", "对端不支持 Require 中列出的某个扩展。", "दूसरा पक्ष Require में दी गई किसी extension को support नहीं करता।"],
  422: ["Session timer too short; see Min-SE.", "Session timer curto demais; veja Min-SE.", "Session timer demasiado corto; ver Min-SE.", "Session-Timer zu kurz; siehe Min-SE.", "Session timer trop court ; voir Min-SE.", "会话定时器过短；参见 Min-SE。", "Session timer बहुत छोटा है; Min-SE देखें।"],
  423: ["Registration interval too short; see Min-Expires.", "Intervalo de registro curto demais; veja Min-Expires.", "Intervalo de registro demasiado corto; ver Min-Expires.", "Registrierungsintervall zu kurz; siehe Min-Expires.", "Intervalle d'enregistrement trop court ; voir Min-Expires.", "注册间隔过短；参见 Min-Expires。", "Registration interval बहुत छोटा है; Min-Expires देखें।"],
  480: ["Temporarily unavailable: the user is not registered, in DND or not answering.", "Temporariamente indisponível: o usuário não está registrado, está em não perturbe ou não atende.", "No disponible temporalmente: el usuario no está registrado, está en no molestar o no contesta.", "Vorübergehend nicht erreichbar: Teilnehmer nicht registriert, auf Nicht stören oder antwortet nicht.", "Temporairement indisponible : l'utilisateur n'est pas enregistré, est en ne pas déranger ou ne répond pas.", "暂时不可用：用户未注册、处于免打扰状态或无人接听。", "अस्थायी रूप से उपलब्ध नहीं: user registered नहीं है, DND पर है या जवाब नहीं दे रहा।"],
  481: ["Call or transaction does not exist: a request for a dialog the far end does not know (lost state, wrong tags).", "Chamada ou transação inexistente: requisição para um diálogo que o outro lado não conhece (estado perdido, tags errados).", "La llamada o transacción no existe: petición para un diálogo que el otro lado no conoce (estado perdido, tags incorrectos).", "Anruf oder Transaktion existiert nicht: Anfrage für einen Dialog, den die Gegenseite nicht kennt (Zustand verloren, falsche Tags).", "L'appel ou la transaction n'existe pas : requête pour un dialogue que l'extrémité distante ne connaît pas (état perdu, mauvais tags).", "呼叫或事务不存在：请求针对的是对端不认识的对话（状态丢失、tag 错误）。", "Call या transaction मौजूद नहीं: ऐसे dialog के लिए request जिसे दूसरा पक्ष नहीं जानता (state खो गई, गलत tags)।"],
  482: ["Loop detected.", "Loop detectado.", "Bucle detectado.", "Schleife erkannt.", "Boucle détectée.", "检测到环路。", "Loop detected।"],
  483: ["Too many hops.", "Saltos demais.", "Demasiados saltos.", "Zu viele Hops.", "Trop de sauts.", "跳数过多。", "बहुत ज़्यादा hops।"],
  484: ["Address incomplete: more digits are needed.", "Endereço incompleto: faltam dígitos.", "Dirección incompleta: faltan dígitos.", "Adresse unvollständig: Es fehlen Ziffern.", "Adresse incomplète : il manque des chiffres.", "地址不完整：还需要更多位数字。", "Address अधूरा है: और अंक चाहिए।"],
  486: ["Busy here.", "Ocupado.", "Ocupado.", "Besetzt.", "Occupé.", "此处忙。", "व्यस्त।"],
  487: ["Request terminated: the caller cancelled before the answer.", "Requisição encerrada: quem ligou cancelou antes do atendimento.", "Petición terminada: quien llamaba canceló antes de la respuesta.", "Anfrage beendet: Der Anrufer hat vor der Annahme aufgelegt.", "Requête terminée : l'appelant a annulé avant la réponse.", "请求已终止：主叫在应答前取消了呼叫。", "Request terminated: कॉल करने वाले ने जवाब से पहले cancel कर दिया।"],
  488: ["Not acceptable here: no common codec, or the media security (SRTP) does not match.", "Não aceitável: nenhum codec em comum, ou a segurança da mídia (SRTP) não bate.", "No aceptable: ningún códec en común, o la seguridad de medios (SRTP) no coincide.", "Hier nicht annehmbar: kein gemeinsamer Codec, oder die Mediensicherheit (SRTP) passt nicht.", "Non acceptable ici : aucun codec commun, ou la sécurité du média (SRTP) ne correspond pas.", "此处不可接受：没有共同的编解码器，或媒体安全（SRTP）不匹配。", "Not acceptable here: कोई common codec नहीं, या media security (SRTP) मेल नहीं खाती।"],
  491: ["Request pending: both sides sent a re-INVITE at the same time (glare); retried after a random delay.", "Requisição pendente: os dois lados mandaram re-INVITE ao mesmo tempo (glare); repete depois de um tempo aleatório.", "Petición pendiente: ambos lados enviaron un re-INVITE a la vez (glare); se reintenta tras un retardo aleatorio.", "Anfrage ausstehend: Beide Seiten haben gleichzeitig ein re-INVITE gesendet (Glare); Wiederholung nach zufälliger Wartezeit.", "Requête en attente : les deux côtés ont envoyé un re-INVITE en même temps (glare) ; nouvel essai après un délai aléatoire.", "请求待定：双方同时发送了 re-INVITE（glare）；随机延时后重试。", "Request pending: दोनों पक्षों ने एक साथ re-INVITE भेजा (glare); random delay के बाद दोबारा कोशिश होती है।"],
  500: ["Server internal error.", "Erro interno do servidor.", "Error interno del servidor.", "Interner Serverfehler.", "Erreur interne du serveur.", "服务器内部错误。", "Server की internal error।"],
  501: ["Not implemented on the server.", "Não implementado no servidor.", "No implementado en el servidor.", "Auf dem Server nicht implementiert.", "Non implémenté sur le serveur.", "服务器未实现此功能。", "Server पर implement नहीं है।"],
  502: ["Bad gateway: the next network failed.", "Gateway inválido: a próxima rede falhou.", "Gateway incorrecto: falló la siguiente red.", "Fehlerhaftes Gateway: Das nächste Netz ist ausgefallen.", "Mauvaise passerelle : le réseau suivant a échoué.", "网关错误：下一个网络出现故障。", "Bad gateway: अगला network fail हो गया।"],
  503: ["Service unavailable: overloaded, no route or trunk down.", "Serviço indisponível: sobrecarga, sem rota ou tronco fora.", "Servicio no disponible: sobrecarga, sin ruta o troncal caída.", "Dienst nicht verfügbar: überlastet, keine Route oder Trunk ausgefallen.", "Service indisponible : surcharge, pas de route ou trunk hors service.", "服务不可用：过载、无路由或中继故障。", "Service unavailable: overload, कोई route नहीं या trunk down।"],
  504: ["The next server timed out.", "O próximo servidor não respondeu a tempo.", "El siguiente servidor no respondió a tiempo.", "Der nächste Server hat nicht rechtzeitig geantwortet.", "Le serveur suivant n'a pas répondu à temps.", "下一个服务器超时。", "अगले server का समय समाप्त हो गया (timeout)।"],
  600: ["Busy everywhere.", "Ocupado em todos os lugares.", "Ocupado en todas partes.", "Überall besetzt.", "Occupé partout.", "所有位置均忙。", "हर जगह व्यस्त।"],
  603: ["Declined: the user rejected the call.", "Recusada: o usuário rejeitou a chamada.", "Rechazada: el usuario rechazó la llamada.", "Abgelehnt: Der Teilnehmer hat den Anruf abgewiesen.", "Refusé : l'utilisateur a rejeté l'appel.", "已拒绝：用户拒接了呼叫。", "Declined: user ने कॉल reject कर दी।"],
  604: ["Does not exist anywhere.", "Não existe em lugar nenhum.", "No existe en ningún lugar.", "Existiert nirgends.", "N'existe nulle part.", "在任何地方都不存在。", "कहीं भी मौजूद नहीं है।"],
};
export function statusHelp(code) {
  const s = STATUS[code];
  if (s) return L(...s);
  if (code >= 100 && code < 200) return L("Provisional response: still working on it.", "Resposta provisória: ainda em andamento.", "Respuesta provisional: aún en curso.", "Vorläufige Antwort: wird noch bearbeitet.", "Réponse provisoire : traitement en cours.", "临时响应：仍在处理中。", "Provisional response: अभी भी काम चल रहा है।");
  if (code < 300) return L("Success.", "Sucesso.", "Éxito.", "Erfolg.", "Succès.", "成功。", "सफल।");
  if (code < 400) return L("Redirect: try another address.", "Redirecionamento: tente outro endereço.", "Redirección: pruebe otra dirección.", "Umleitung: andere Adresse versuchen.", "Redirection : essayez une autre adresse.", "重定向：请尝试其他地址。", "Redirect: कोई दूसरा address आज़माएँ।");
  if (code < 500) return L("The request was refused or cannot be completed by this destination.", "A requisição foi recusada ou não pode ser completada neste destino.", "La petición fue rechazada o este destino no puede completarla.", "Die Anfrage wurde abgelehnt oder kann von diesem Ziel nicht erfüllt werden.", "La requête a été refusée ou ne peut pas être traitée par cette destination.", "请求被拒绝，或此目的地无法完成该请求。", "Request reject कर दिया गया या यह destination उसे पूरा नहीं कर सकता।");
  if (code < 600) return L("A server failed.", "Um servidor falhou.", "Falló un servidor.", "Ein Server ist ausgefallen.", "Un serveur a échoué.", "某个服务器出现故障。", "एक server fail हो गया।");
  return L("Global failure.", "Falha global.", "Fallo global.", "Globaler Fehler.", "Échec global.", "全局失败。", "Global failure।");
}

// ---------------------------------------------------------------------------
// SDP line by line

const STATIC_PT = { 0: "PCMU (G.711 μ-law)", 3: "GSM", 4: "G.723", 8: "PCMA (G.711 A-law)", 9: "G.722", 13: "CN (comfort noise)", 18: "G.729" };

function codecMap(sdpText) {
  const m = {};
  for (const l of sdpText.split(/\r?\n/)) {
    const r = l.match(/^a=rtpmap:(\d+)\s+([^/\s]+)\/(\d+)/);
    if (r) m[r[1]] = `${r[2]}/${r[3]}`;
  }
  return m;
}

function explainLine(line, map) {
  const [k, v = ""] = [line.slice(0, 1), line.slice(2)];
  if (line[1] !== "=") return "";
  switch (k) {
    case "v": return L("SDP version (always 0).", "Versão do SDP (sempre 0).", "Versión de SDP (siempre 0).", "SDP-Version (immer 0).", "Version SDP (toujours 0).", "SDP 版本（始终为 0）。", "SDP version (हमेशा 0)।");
    case "o": {
      const p = v.split(/\s+/);
      return L(
        `Origin: user ${p[0]}, session id ${p[1]}, version ${p[2]} (goes up by one each time this side changes its media), created on ${p[5] || ""}. The address here is informational, not where media goes.`,
        `Origem: usuário ${p[0]}, id da sessão ${p[1]}, versão ${p[2]} (sobe um a cada mudança de mídia deste lado), criada em ${p[5] || ""}. O endereço aqui é só informativo, não é para onde vai a mídia.`,
        `Origen: usuario ${p[0]}, id de sesión ${p[1]}, versión ${p[2]} (sube uno cada vez que este lado cambia sus medios), creada en ${p[5] || ""}. La dirección aquí es informativa, no es adonde van los medios.`,
        `Ursprung: Benutzer ${p[0]}, Sitzungs-ID ${p[1]}, Version ${p[2]} (steigt um eins bei jeder Medienänderung dieser Seite), erstellt auf ${p[5] || ""}. Die Adresse hier ist nur informativ, nicht das Medienziel.`,
        `Origine : utilisateur ${p[0]}, id de session ${p[1]}, version ${p[2]} (augmente de un à chaque changement de média de ce côté), créée sur ${p[5] || ""}. L'adresse ici est informative, ce n'est pas là que va le média.`,
        `来源：用户 ${p[0]}，会话 ID ${p[1]}，版本 ${p[2]}（本端每次更改媒体时加一），创建于 ${p[5] || ""}。此处地址仅供参考，并非媒体的发送目标。`,
        `Origin: user ${p[0]}, session id ${p[1]}, version ${p[2]} (यह पक्ष जब भी अपना media बदलता है, एक बढ़ जाता है), ${p[5] || ""} पर बनाया गया। यहाँ का address केवल जानकारी के लिए है, media वहाँ नहीं जाता।`,
      );
    }
    case "s": return L("Session name (free text).", "Nome da sessão (texto livre).", "Nombre de la sesión (texto libre).", "Sitzungsname (freier Text).", "Nom de la session (texte libre).", "会话名称（自由文本）。", "Session का नाम (free text)।");
    case "c": {
      const ip = v.split(/\s+/).pop();
      return L(`Connection: send RTP to ${ip} (${ipKind(ip)}).`, `Conexão: mande o RTP para ${ip} (${ipKind(ip)}).`, `Conexión: enviar el RTP a ${ip} (${ipKind(ip)}).`, `Verbindung: RTP an ${ip} senden (${ipKind(ip)}).`, `Connexion : envoyer le RTP à ${ip} (${ipKind(ip)}).`, `连接：将 RTP 发送到 ${ip}（${ipKind(ip)}）。`, `Connection: RTP को ${ip} पर भेजें (${ipKind(ip)})।`);
    }
    case "t": return L("Timing: 0 0 means the session is not bounded in time.", "Tempo: 0 0 quer dizer sessão sem limite de tempo.", "Tiempo: 0 0 significa sesión sin límite de tiempo.", "Zeit: 0 0 heißt, die Sitzung ist zeitlich nicht begrenzt.", "Temps : 0 0 signifie que la session n'est pas limitée dans le temps.", "时间：0 0 表示会话没有时间限制。", "Timing: 0 0 का मतलब session की कोई समय सीमा नहीं है।");
    case "b": return L(`Bandwidth limit ${v}.`, `Limite de banda ${v}.`, `Límite de ancho de banda ${v}.`, `Bandbreitenlimit ${v}.`, `Limite de bande passante ${v}.`, `带宽限制 ${v}。`, `Bandwidth सीमा ${v}।`);
    case "m": {
      const p = v.split(/\s+/);
      const pts = p.slice(3).map((x) => `${x} = ${map[x] || STATIC_PT[x] || "?"}`).join(", ");
      const prof = {
        "RTP/AVP": L("plain RTP", "RTP sem criptografia", "RTP sin cifrar", "unverschlüsseltes RTP", "RTP non chiffré", "未加密的 RTP", "बिना encryption वाला RTP"),
        "RTP/SAVP": L("SRTP with keys in a=crypto (SDES)", "SRTP com chaves em a=crypto (SDES)", "SRTP con claves en a=crypto (SDES)", "SRTP mit Schlüsseln in a=crypto (SDES)", "SRTP avec clés dans a=crypto (SDES)", "SRTP，密钥在 a=crypto 中（SDES）", "SRTP, keys a=crypto में (SDES)"),
        "UDP/TLS/RTP/SAVP": L("SRTP with keys from DTLS (a=fingerprint)", "SRTP com chaves via DTLS (a=fingerprint)", "SRTP con claves por DTLS (a=fingerprint)", "SRTP mit Schlüsseln aus DTLS (a=fingerprint)", "SRTP avec clés issues de DTLS (a=fingerprint)", "SRTP，密钥来自 DTLS（a=fingerprint）", "SRTP, keys DTLS से (a=fingerprint)"),
        "UDP/TLS/RTP/SAVPF": L("WebRTC: DTLS-SRTP with RTCP feedback", "WebRTC: DTLS-SRTP com feedback RTCP", "WebRTC: DTLS-SRTP con feedback RTCP", "WebRTC: DTLS-SRTP mit RTCP-Feedback", "WebRTC : DTLS-SRTP avec feedback RTCP", "WebRTC：DTLS-SRTP，带 RTCP 反馈", "WebRTC: DTLS-SRTP, RTCP feedback के साथ"),
        "RTP/AVPF": L("RTP with RTCP feedback", "RTP com feedback RTCP", "RTP con feedback RTCP", "RTP mit RTCP-Feedback", "RTP avec feedback RTCP", "带 RTCP 反馈的 RTP", "RTCP feedback के साथ RTP"),
      }[p[2]] || p[2];
      const off = p[1] === "0";
      return L(
        `Media line: ${p[0]} on port ${p[1]}${off ? " (port 0 = this stream is rejected or disabled)" : ""}, ${prof}. Payload types in order of preference: ${pts}.`,
        `Linha de mídia: ${p[0]} na porta ${p[1]}${off ? " (porta 0 = fluxo recusado ou desativado)" : ""}, ${prof}. Payload types em ordem de preferência: ${pts}.`,
        `Línea de medios: ${p[0]} en el puerto ${p[1]}${off ? " (puerto 0 = flujo rechazado o desactivado)" : ""}, ${prof}. Payload types en orden de preferencia: ${pts}.`,
        `Medienzeile: ${p[0]} auf Port ${p[1]}${off ? " (Port 0 = Strom abgelehnt oder deaktiviert)" : ""}, ${prof}. Payload-Typen nach Vorliebe: ${pts}.`,
        `Ligne média : ${p[0]} sur le port ${p[1]}${off ? " (port 0 = ce flux est refusé ou désactivé)" : ""}, ${prof}. Payload types par ordre de préférence : ${pts}.`,
        `媒体行：${p[0]}，端口 ${p[1]}${off ? "（端口 0 = 此媒体流被拒绝或禁用）" : ""}，${prof}。按优先顺序排列的 payload type：${pts}。`,
        `Media line: ${p[0]}, port ${p[1]}${off ? " (port 0 = यह stream reject या disabled है)" : ""}, ${prof}। पसंद के क्रम में payload types: ${pts}।`,
      );
    }
    case "a": {
      const [name, val = ""] = v.split(/:(.*)/s);
      switch (name) {
        case "rtpmap": {
          const [pt, enc] = val.split(/\s+/);
          const ev = /telephone-event/i.test(enc);
          const st = /\/2$/.test(enc);
          return ev
            ? L(`Payload ${pt} carries DTMF digits as RFC 4733 events (${enc}).`, `Payload ${pt} leva os dígitos DTMF como eventos RFC 4733 (${enc}).`, `El payload ${pt} lleva los dígitos DTMF como eventos RFC 4733 (${enc}).`, `Payload ${pt} überträgt DTMF-Ziffern als RFC-4733-Ereignisse (${enc}).`, `Le payload ${pt} transporte les chiffres DTMF sous forme d'événements RFC 4733 (${enc}).`, `Payload ${pt} 以 RFC 4733 事件形式承载 DTMF 数字（${enc}）。`, `Payload ${pt} DTMF अंकों को RFC 4733 events के रूप में ले जाता है (${enc})।`)
            : L(`Payload ${pt} is ${enc} (codec/clock rate${st ? "/channels" : ""}).`, `Payload ${pt} é ${enc} (codec/taxa${st ? "/canais" : ""}).`, `El payload ${pt} es ${enc} (códec/frecuencia${st ? "/canales" : ""}).`, `Payload ${pt} ist ${enc} (Codec/Taktrate${st ? "/Kanäle" : ""}).`, `Le payload ${pt} est ${enc} (codec/fréquence d'horloge${st ? "/canaux" : ""}).`, `Payload ${pt} 为 ${enc}（编解码器/时钟频率${st ? "/声道数" : ""}）。`, `Payload ${pt} है ${enc} (codec/clock rate${st ? "/channels" : ""})।`);
        }
        case "fmtp": {
          const ev = val.split(/\s+/)[1];
          const pt = val.split(/\s+/)[0];
          return /0-1[56]/.test(val) ? L(`DTMF events supported: ${ev} (0-15 are the keys 0-9 * # A-D).`, `Eventos DTMF suportados: ${ev} (0-15 são as teclas 0-9 * # A-D).`, `Eventos DTMF soportados: ${ev} (0-15 son las teclas 0-9 * # A-D).`, `Unterstützte DTMF-Ereignisse: ${ev} (0-15 sind die Tasten 0-9 * # A-D).`, `Événements DTMF pris en charge : ${ev} (0-15 sont les touches 0-9 * # A-D).`, `支持的 DTMF 事件：${ev}（0-15 对应按键 0-9 * # A-D）。`, `Supported DTMF events: ${ev} (0-15 का मतलब keys 0-9 * # A-D)।`)
            : /useinbandfec/.test(val) ? L("Opus options: in-band FEC lets the receiver repair lost packets.", "Opções do Opus: FEC in-band permite ao receptor recuperar pacotes perdidos.", "Opciones de Opus: FEC in-band permite al receptor reparar paquetes perdidos.", "Opus-Optionen: In-Band-FEC erlaubt dem Empfänger, verlorene Pakete zu reparieren.", "Options Opus : la FEC in-band permet au récepteur de réparer les paquets perdus.", "Opus 选项：带内 FEC 让接收端能够修复丢失的数据包。", "Opus options: in-band FEC से receiver खोए हुए packets ठीक कर सकता है।")
            : /annexb=no/.test(val) ? L("G.729 without Annex B (no silence suppression).", "G.729 sem Anexo B (sem supressão de silêncio).", "G.729 sin Anexo B (sin supresión de silencio).", "G.729 ohne Annex B (keine Stillenunterdrückung).", "G.729 sans Annexe B (pas de suppression de silence).", "G.729 不带 Annex B（无静音抑制）。", "G.729 बिना Annex B के (silence suppression नहीं)।")
            : L(`Codec options for payload ${pt}.`, `Opções do codec para o payload ${pt}.`, `Opciones del códec para el payload ${pt}.`, `Codec-Optionen für Payload ${pt}.`, `Options du codec pour le payload ${pt}.`, `payload ${pt} 的编解码器选项。`, `Payload ${pt} के लिए codec options।`);
        }
        case "ptime": return L(`Packet time: ${val} ms of audio per RTP packet.`, `Packet time: ${val} ms de áudio por pacote RTP.`, `Packet time: ${val} ms de audio por paquete RTP.`, `Paketzeit: ${val} ms Audio pro RTP-Paket.`, `Packet time : ${val} ms d'audio par paquet RTP.`, `打包时长：每个 RTP 包 ${val} ms 音频。`, `Packet time: हर RTP packet में ${val} ms audio।`);
        case "maxptime": return L(`Longest packet time accepted: ${val} ms.`, `Maior packet time aceito: ${val} ms.`, `Mayor packet time aceptado: ${val} ms.`, `Längste akzeptierte Paketzeit: ${val} ms.`, `Packet time maximal accepté : ${val} ms.`, `可接受的最长打包时长：${val} ms。`, `स्वीकार्य सबसे लंबा packet time: ${val} ms।`);
        case "sendrecv": return L("Two-way audio.", "Áudio nos dois sentidos.", "Audio en ambos sentidos.", "Audio in beide Richtungen.", "Audio dans les deux sens.", "双向音频。", "दोनों दिशाओं में audio।");
        case "sendonly": return L("This side only sends: usually it is putting the call on hold (music on hold).", "Este lado só envia: normalmente está colocando a chamada em espera (música de espera).", "Este lado solo envía: normalmente está poniendo la llamada en espera (música en espera).", "Diese Seite sendet nur: meist hält sie den Anruf (Wartemusik).", "Ce côté ne fait qu'émettre : en général il met l'appel en attente (musique d'attente).", "本端只发送：通常表示它正在将呼叫置于保持状态（保持音乐）。", "यह पक्ष केवल भेजता है: आमतौर पर यह कॉल को hold पर रख रहा है (music on hold)।");
        case "recvonly": return L("This side only receives: the answer to a hold.", "Este lado só recebe: a resposta a uma espera.", "Este lado solo recibe: la respuesta a una espera.", "Diese Seite empfängt nur: die Antwort auf ein Halten.", "Ce côté ne fait que recevoir : la réponse à une mise en attente.", "本端只接收：这是对保持请求的应答。", "यह पक्ष केवल प्राप्त करता है: hold का जवाब।");
        case "inactive": return L("No audio either way: held from both sides.", "Sem áudio nos dois sentidos: espera dos dois lados.", "Sin audio en ningún sentido: espera desde ambos lados.", "Kein Audio in beide Richtungen: von beiden Seiten gehalten.", "Pas d'audio dans aucun sens : mis en attente des deux côtés.", "双向均无音频：双方都处于保持状态。", "किसी भी दिशा में audio नहीं: दोनों पक्षों से hold।");
        case "rtcp": {
          const p = val.split(/\s+/);
          return L(`RTCP (quality reports) goes to port ${p[0]}${p[3] ? ` at ${p[3]}` : ""}.`, `RTCP (relatórios de qualidade) vai para a porta ${p[0]}${p[3] ? ` em ${p[3]}` : ""}.`, `El RTCP (informes de calidad) va al puerto ${p[0]}${p[3] ? ` en ${p[3]}` : ""}.`, `RTCP (Qualitätsberichte) geht an Port ${p[0]}${p[3] ? ` auf ${p[3]}` : ""}.`, `Le RTCP (rapports de qualité) va au port ${p[0]}${p[3] ? ` à ${p[3]}` : ""}.`, `RTCP（质量报告）发往端口 ${p[0]}${p[3] ? `，地址 ${p[3]}` : ""}。`, `RTCP (quality reports) port ${p[0]} पर जाता है${p[3] ? `, address ${p[3]}` : ""}।`);
        }
        case "rtcp-mux": return L("RTCP shares the RTP port.", "O RTCP usa a mesma porta do RTP.", "El RTCP comparte el puerto del RTP.", "RTCP nutzt denselben Port wie RTP.", "Le RTCP partage le port du RTP.", "RTCP 与 RTP 共用同一端口。", "RTCP उसी port का उपयोग करता है जो RTP का है।");
        case "crypto": {
          const s = val.split(/\s+/)[1];
          return L(`SRTP key offered in the SDP (SDES) with suite ${s}. Anyone who can read this SDP can decrypt the audio, so use it with TLS.`, `Chave SRTP oferecida no próprio SDP (SDES) com a suíte ${s}. Quem ler este SDP consegue decifrar o áudio, por isso use com TLS.`, `Clave SRTP ofrecida en el propio SDP (SDES) con la suite ${s}. Quien lea este SDP puede descifrar el audio, así que úsalo con TLS.`, `SRTP-Schlüssel direkt im SDP angeboten (SDES), Suite ${s}. Wer dieses SDP lesen kann, kann das Audio entschlüsseln, daher nur mit TLS verwenden.`, `Clé SRTP proposée dans le SDP lui-même (SDES) avec la suite ${s}. Quiconque peut lire ce SDP peut déchiffrer l'audio, utilisez-le donc avec TLS.`, `SRTP 密钥直接在 SDP 中提供（SDES），套件为 ${s}。任何能读取此 SDP 的人都能解密音频，因此请配合 TLS 使用。`, `SRTP key सीधे SDP में दी गई है (SDES), suite ${s}। जो भी यह SDP पढ़ सकता है वह audio decrypt कर सकता है, इसलिए इसे TLS के साथ ही उपयोग करें।`);
        }
        case "fingerprint": {
          const h = val.split(/\s+/)[0];
          return L(`Hash of this side's DTLS certificate (${h}): the far end checks the certificate in the DTLS handshake against it.`, `Hash do certificado DTLS deste lado (${h}): o outro lado confere o certificado do handshake DTLS com ele.`, `Hash del certificado DTLS de este lado (${h}): el otro lado comprueba con él el certificado del handshake DTLS.`, `Hash des DTLS-Zertifikats dieser Seite (${h}): Die Gegenseite prüft damit das Zertifikat im DTLS-Handshake.`, `Empreinte du certificat DTLS de ce côté (${h}) : l'extrémité distante vérifie avec elle le certificat reçu lors du handshake DTLS.`, `本端 DTLS 证书的哈希（${h}）：对端用它校验 DTLS 握手中的证书。`, `इस पक्ष के DTLS certificate का hash (${h}): दूसरा पक्ष DTLS handshake में मिले certificate को इससे जाँचता है।`);
        }
        case "setup": return {
          actpass: L("DTLS role: either; the answerer chooses.", "Papel DTLS: qualquer um; quem responde escolhe.", "Rol DTLS: cualquiera; elige quien responde.", "DTLS-Rolle: beliebig; die antwortende Seite wählt.", "Rôle DTLS : l'un ou l'autre ; celui qui répond choisit.", "DTLS 角色：均可；由应答方选择。", "DTLS role: कोई भी; जवाब देने वाला पक्ष चुनता है।"),
          active: L("DTLS role: this side starts the handshake (client).", "Papel DTLS: este lado inicia o handshake (cliente).", "Rol DTLS: este lado inicia el handshake (cliente).", "DTLS-Rolle: Diese Seite startet den Handshake (Client).", "Rôle DTLS : ce côté démarre le handshake (client).", "DTLS 角色：本端发起握手（客户端）。", "DTLS role: यह पक्ष handshake शुरू करता है (client)।"),
          passive: L("DTLS role: this side waits for the handshake (server).", "Papel DTLS: este lado espera o handshake (servidor).", "Rol DTLS: este lado espera el handshake (servidor).", "DTLS-Rolle: Diese Seite wartet auf den Handshake (Server).", "Rôle DTLS : ce côté attend le handshake (serveur).", "DTLS 角色：本端等待握手（服务器）。", "DTLS role: यह पक्ष handshake का इंतज़ार करता है (server)।"),
        }[val.trim()] || "";
        case "ice-ufrag": return L("ICE user fragment: identifies this side in connectivity checks.", "Fragmento de usuário ICE: identifica este lado nos testes de conectividade.", "Fragmento de usuario ICE: identifica este lado en las pruebas de conectividad.", "ICE-Benutzerfragment: kennzeichnet diese Seite in den Konnektivitätsprüfungen.", "Fragment d'utilisateur ICE : identifie ce côté dans les vérifications de connectivité.", "ICE 用户片段：在连通性检查中标识本端。", "ICE user fragment: connectivity checks में इस पक्ष की पहचान करता है।");
        case "ice-pwd": return L("ICE password for connectivity checks.", "Senha ICE dos testes de conectividade.", "Contraseña ICE de las pruebas de conectividad.", "ICE-Passwort für die Konnektivitätsprüfungen.", "Mot de passe ICE pour les vérifications de connectivité.", "用于连通性检查的 ICE 密码。", "Connectivity checks के लिए ICE password।");
        case "ice-lite": return L("Lite ICE: this side only answers checks (typical for servers).", "ICE lite: este lado só responde aos testes (típico de servidores).", "ICE lite: este lado solo responde a las pruebas (típico de servidores).", "ICE Lite: Diese Seite beantwortet nur Prüfungen (typisch für Server).", "ICE lite : ce côté ne fait que répondre aux vérifications (typique des serveurs).", "ICE lite：本端只响应检查（服务器的典型做法）。", "ICE lite: यह पक्ष केवल checks का जवाब देता है (servers में आम)।");
        case "candidate": {
          const p = val.split(/\s+/);
          const typ = p[7];
          const kind = {
            host: L("its own interface", "a própria interface", "su propia interfaz", "eigene Schnittstelle", "sa propre interface", "本机自身的接口", "उसका अपना interface"),
            srflx: L("public address seen by STUN (NAT)", "endereço público visto pelo STUN (NAT)", "dirección pública vista por STUN (NAT)", "von STUN gesehene öffentliche Adresse (NAT)", "adresse publique vue par STUN (NAT)", "STUN 看到的公网地址（NAT）", "STUN द्वारा देखा गया public address (NAT)"),
            relay: L("TURN relay", "relay TURN", "relay TURN", "TURN-Relay", "relais TURN", "TURN 中继", "TURN relay"),
            prflx: L("address learned during checks", "endereço aprendido nos testes", "dirección aprendida en las pruebas", "bei den Prüfungen gelernte Adresse", "adresse apprise pendant les vérifications", "在检查过程中获知的地址", "checks के दौरान पता चला address"),
          }[typ] || typ;
          return L(`ICE candidate: ${p[2]} ${p[4]}:${p[5]}, ${kind}.`, `Candidato ICE: ${p[2]} ${p[4]}:${p[5]}, ${kind}.`, `Candidato ICE: ${p[2]} ${p[4]}:${p[5]}, ${kind}.`, `ICE-Kandidat: ${p[2]} ${p[4]}:${p[5]}, ${kind}.`, `Candidat ICE : ${p[2]} ${p[4]}:${p[5]}, ${kind}.`, `ICE 候选：${p[2]} ${p[4]}:${p[5]}，${kind}。`, `ICE candidate: ${p[2]} ${p[4]}:${p[5]}, ${kind}।`);
        }
        case "mid": return L("Media identifier for bundling.", "Identificador de mídia para bundle.", "Identificador de medios para bundle.", "Medienkennung für Bundling.", "Identifiant de média pour le bundle.", "用于 bundle 的媒体标识符。", "Bundling के लिए media identifier।");
        case "group": return L("Streams bundled on one port.", "Fluxos agrupados numa só porta.", "Flujos agrupados en un solo puerto.", "Ströme auf einem Port gebündelt.", "Flux regroupés sur un seul port.", "多个媒体流捆绑在同一端口上。", "Streams एक ही port पर bundled हैं।");
        case "ssrc": return L("Identifier of the RTP stream this side will send.", "Identificador do fluxo RTP que este lado vai enviar.", "Identificador del flujo RTP que enviará este lado.", "Kennung des RTP-Stroms, den diese Seite sendet.", "Identifiant du flux RTP que ce côté va envoyer.", "本端将发送的 RTP 流的标识符。", "उस RTP stream की पहचान जो यह पक्ष भेजेगा।");
        case "rtcp-fb": return L("RTCP feedback this side supports.", "Feedback RTCP que este lado suporta.", "Feedback RTCP que soporta este lado.", "RTCP-Feedback, das diese Seite unterstützt.", "Feedback RTCP pris en charge par ce côté.", "本端支持的 RTCP 反馈。", "RTCP feedback जिसे यह पक्ष support करता है।");
        case "extmap": return L("RTP header extension.", "Extensão de cabeçalho RTP.", "Extensión de cabecera RTP.", "RTP-Header-Erweiterung.", "Extension d'en-tête RTP.", "RTP 头扩展。", "RTP header extension।");
        default: return "";
      }
    }
    default: return "";
  }
}

/// SDP as a two-column table: the line and what it means.
export function sdpTable(sdpText) {
  const lines = sdpText.split(/\r?\n/).filter((l) => l.trim());
  const map = codecMap(sdpText);
  return `<table class="sdp-x"><tbody>${lines.map((l) => `<tr><td class="mono">${esc(l)}</td><td>${esc(explainLine(l, map))}</td></tr>`).join("")}</tbody></table>`;
}

// ---------------------------------------------------------------------------
// The whole call in plain words

const hdr = (raw, name) => ((raw.match(new RegExp(`^(?:${name}):[ \\t]*(.*)$`, "mi")) || [])[1] || "").trim();
const user = (h) => ((h || "").match(/<?sips?:([^@;>]+)/i) || (h || "").match(/<?tel:([^;>]+)/i) || [])[1] || "";
const disp = (h) => ((h || "").match(/^\s*"([^"]*)"/) || (h || "").match(/^\s*([^<"]+?)\s*</) || [])[1] || "";
const party = (h) => `${disp(h) ? `<b>${esc(disp(h))}</b> ` : ""}${mono(user(h) || h)}`;

function sdpSummary(m) {
  const s = m.sdp;
  const md = s && s.media.find((x) => x.kind === "audio");
  if (!md) return null;
  const ip = md.connection || s.connection || "";
  const codecs = md.formats.map((pt) => (md.codecs.find((c) => c.pt === pt) || {}).name || STATIC_PT[pt] || `PT ${pt}`);
  const dtmf = md.codecs.find((c) => /telephone-event/i.test(c.name));
  const sec = md.fingerprint ? "DTLS-SRTP" : md.crypto.length ? `SRTP (SDES ${md.crypto[0].split(/\s+/)[1] || ""})` : /SAVP/.test(md.proto) ? "SRTP" : L("none (plain RTP)", "nenhuma (RTP aberto)", "ninguna (RTP sin cifrar)", "keine (unverschlüsseltes RTP)", "aucune (RTP non chiffré)", "无（未加密的 RTP）", "कोई नहीं (बिना encryption वाला RTP)");
  return { ip, port: md.port, codecs, dtmf: dtmf ? dtmf.pt : null, ptime: md.ptime, dir: md.direction, sec, ice: md.candidates.length, md };
}

/// Sections of facts, each a list of [label, html]; the caller renders them.
export function explainCall(r, ci) {
  const c = r.calls[ci];
  const msgs = c.messages.map((i) => r.messages[i]);
  const first = msgs[0];
  const out = [];
  if (!first) return out;
  const reqs = msgs.filter((m) => !m.status);
  const invite = reqs.find((m) => m.method === c.kind) || first;
  const final = msgs.find((m) => m.status >= 200 && m.cseq === invite.cseq && m.status !== 401 && m.status !== 407) || msgs.filter((m) => m.status >= 200 && /INVITE|REGISTER/.test(m.cseq)).pop();
  const caller = hdr(invite.raw, "From|f");
  const called = hdr(invite.raw, "To|t");
  const ruri = (invite.raw.split(/\r?\n/)[0] || "").split(" ")[1] || c.request_uri;
  const respFrom = msgs.find((m) => m.status && m.src === invite.dst);
  const sendTo = L("send my audio to", "mande meu áudio para", "envía mi audio a", "sende mein Audio an", "envoyez mon audio à", "请将我的音频发送到", "मेरा audio यहाँ भेजें:");
  const fromW = L("from", "de", "de", "von", "de", "来自", "स्रोत");

  // 1. Who and what
  const who = [];
  if (c.kind === "REGISTER") {
    const u = mono(user(called));
    const h = mono(host(ruri.replace(/^sips?:/, "")));
    who.push([L("What", "O quê", "Qué", "Was", "Quoi", "内容", "क्या"), L(
      `Registration of ${u} at ${h}: tells the server where to send calls for this user.`,
      `Registro de ${u} em ${h}: avisa o servidor para onde mandar as chamadas deste usuário.`,
      `Registro de ${u} en ${h}: indica al servidor adónde enviar las llamadas de este usuario.`,
      `Registrierung von ${u} bei ${h}: teilt dem Server mit, wohin Anrufe für diesen Benutzer gehen.`,
      `Enregistrement de ${u} auprès de ${h} : indique au serveur où envoyer les appels destinés à cet utilisateur.`,
      `${u} 在 ${h} 上注册：告诉服务器该用户的呼叫应发往何处。`,
      `${h} पर ${u} का registration: server को बताता है कि इस user की कॉल कहाँ भेजनी हैं।`,
    )]);
  } else {
    who.push([L("Caller", "Origem", "Llamante", "Anrufer", "Appelant", "主叫", "कॉल करने वाला"), party(caller)]);
    who.push([L("Called", "Destino", "Llamado", "Angerufen", "Appelé", "被叫", "जिसे कॉल किया गया"), party(called)]);
    const retarget = user(ruri) && user(called) && user(ruri) !== user(called);
    who.push([L("Dialed", "Discado", "Marcado", "Gewählt", "Composé", "所拨号码", "डायल किया गया"), `<b class="mono">${esc(user(ruri) || ruri)}</b> <span class="muted mono">${esc(ruri)}</span>${retarget ? ` <span class="warn">${L("differs from To: the request was retargeted", "diferente do To: a requisição foi redirecionada", "distinto del To: la petición fue redirigida", "weicht von To ab: Die Anfrage wurde umgeleitet", "diffère du To : la requête a été redirigée", "与 To 不同：请求已被重定向", "To से अलग है: request retarget किया गया")}</span>` : ""}`]);
    const pai = hdr(invite.raw, "P-Asserted-Identity");
    if (pai) who.push([L("Network identity", "Identidade de rede", "Identidad de red", "Netzidentität", "Identité réseau", "网络身份", "Network पहचान"), `${party(pai)} <span class="muted">${esc(L("(P-Asserted-Identity: what the network shows as caller ID)", "(P-Asserted-Identity: o que a rede mostra como bina)", "(P-Asserted-Identity: lo que la red muestra como identificador de llamada)", "(P-Asserted-Identity: was das Netz als Rufnummer anzeigt)", "(P-Asserted-Identity : ce que le réseau affiche comme numéro de l'appelant)", "（P-Asserted-Identity：网络显示的来电号码）", "(P-Asserted-Identity: network caller ID के रूप में क्या दिखाता है)"))}</span>`]);
    const div = hdr(invite.raw, "Diversion");
    if (div) who.push([L("Forwarded by", "Desviada por", "Desviada por", "Umgeleitet von", "Renvoyé par", "前转方", "Forward करने वाला"), `${party(div)} ${esc(((div.match(/reason=([^;]+)/) || [])[1] || ""))}`]);
  }
  const uaReq = hdr(invite.raw, "User-Agent");
  const uaResp = respFrom ? hdr(respFrom.raw, "Server") || hdr(respFrom.raw, "User-Agent") : "";
  if (uaReq || uaResp) who.push([L("Software", "Software", "Software", "Software", "Logiciel", "软件", "Software"), `${uaReq ? `${esc(uaReq)} <span class="muted">${L("(sent the request)", "(enviou a requisição)", "(envió la petición)", "(hat die Anfrage gesendet)", "(a envoyé la requête)", "（发送了请求）", "(request भेजा)")}</span>` : ""}${uaReq && uaResp ? "<br>" : ""}${uaResp ? `${esc(uaResp)} <span class="muted">${L("(answered)", "(respondeu)", "(respondió)", "(hat geantwortet)", "(a répondu)", "（作出了响应）", "(जवाब दिया)")}</span>` : ""}`]);
  out.push([L("Who and what", "Quem e o quê", "Quién y qué", "Wer und was", "Qui et quoi", "谁和什么", "कौन और क्या"), who]);

  // 2. Signaling path
  const path = [];
  const src = invite.src, dst = invite.dst;
  path.push([L("Sent", "Enviado", "Enviado", "Gesendet", "Envoyé", "发送", "भेजा गया"), `${mono(src)} → ${mono(dst)} ${L("over", "via", "por", "über", "via", "经由", "via")} ${esc(invite.transport)}`]);
  path.push([L("Source", "Origem", "Origen", "Quelle", "Source", "源", "स्रोत"), `${mono(host(src))}: ${esc(ipKind(host(src)))}`]);
  path.push([L("Destination", "Destino", "Destino", "Ziel", "Destination", "目的地", "गंतव्य"), `${mono(host(dst))}: ${esc(ipKind(host(dst)))}`]);
  const vias = invite.raw.split(/\r?\n/).filter((l) => /^(via|v):/i.test(l));
  if (vias.length > 1) {
    const n = vias.length - 1;
    path.push([L("Proxies", "Proxies", "Proxies", "Proxys", "Proxies", "代理", "Proxies"), L(
      `${n} proxy hop(s) before this capture point (one Via each).`,
      `${n} salto(s) de proxy antes deste ponto de captura (um Via por salto).`,
      `${n} salto(s) de proxy antes de este punto de captura (un Via por salto).`,
      `${n} Proxy-Hop(s) vor diesem Mitschnittpunkt (je ein Via).`,
      `${n} saut(s) de proxy avant ce point de capture (un Via par saut).`,
      `此抓包点之前有 ${n} 个代理跳（每跳一个 Via）。`,
      `इस capture point से पहले ${n} proxy hop(s) (हर hop का एक Via)।`,
    )]);
  }
  const rr = msgs.find((m) => /^record-route:/im.test(m.raw));
  if (rr) path.push(["Record-Route", L("A proxy stays in the path for the whole call: ACK, BYE and re-INVITEs go through it.", "Um proxy fica no caminho a chamada toda: ACK, BYE e re-INVITE passam por ele.", "Un proxy se queda en el camino toda la llamada: ACK, BYE y re-INVITE pasan por él.", "Ein Proxy bleibt den ganzen Anruf im Weg: ACK, BYE und re-INVITEs laufen über ihn.", "Un proxy reste sur le chemin pendant tout l'appel : ACK, BYE et re-INVITE passent par lui.", "代理在整个呼叫期间都留在路径上：ACK、BYE 和 re-INVITE 都经过它。", "एक proxy पूरी कॉल के दौरान रास्ते में रहता है: ACK, BYE और re-INVITE उसी से होकर जाते हैं।")]);
  const contact = hdr(invite.raw, "Contact|m");
  const cHost = host(((contact.match(/sips?:[^@]*@?([^;>]+)/) || [])[1] || "")).replace(/^.*@/, "");
  if (cHost) {
    const natHint = isPrivate(cHost) && !isPrivate(host(src))
      ? ` <span class="bad">${L(
        "private Contact from a public source: there is a NAT and the far end may send ACK and BYE to an unreachable address (the 32 s drop).",
        "Contact privado vindo de origem pública: há um NAT e o outro lado pode mandar ACK e BYE para um endereço inalcançável (a queda aos 32 s).",
        "Contact privado desde un origen público: hay un NAT y el otro lado puede enviar ACK y BYE a una dirección inalcanzable (el corte a los 32 s).",
        "privater Contact von öffentlicher Quelle: Es gibt ein NAT, und die Gegenseite schickt ACK und BYE womöglich an eine unerreichbare Adresse (der Abbruch nach 32 s).",
        "Contact privé venant d'une source publique : il y a un NAT et l'extrémité distante risque d'envoyer ACK et BYE à une adresse injoignable (la coupure à 32 s).",
        "来自公网源的私有 Contact：中间存在 NAT，对端可能把 ACK 和 BYE 发往不可达的地址（即 32 秒断线）。",
        "Public source से private Contact: बीच में NAT है और दूसरा पक्ष ACK और BYE किसी unreachable address पर भेज सकता है (32 s पर कॉल कटना)।",
      )}</span>`
      : cHost !== host(src) && !isPrivate(cHost) && !isPrivate(host(src)) ? ` <span class="muted">${L(
        "differs from the source address (a proxy or SBC sent it on the phone's behalf).",
        "diferente do endereço de origem (um proxy ou SBC enviou em nome do telefone).",
        "distinto de la dirección de origen (un proxy o SBC lo envió en nombre del teléfono).",
        "weicht von der Quelladresse ab (ein Proxy oder SBC hat im Namen des Telefons gesendet).",
        "diffère de l'adresse source (un proxy ou un SBC l'a envoyé pour le compte du téléphone).",
        "与源地址不同（由代理或 SBC 代表话机发送）。",
        "Source address से अलग है (किसी proxy या SBC ने फ़ोन की ओर से भेजा)।",
      )}</span>` : "";
    path.push(["Contact", `${mono(contact)}${natHint}`]);
  }
  const viaRecv = vias[0] && (vias[0].match(/received=([^;\s,]+)/) || [])[1];
  if (viaRecv) {
    const a = mono(viaRecv);
    path.push(["received=", L(
      `The next hop saw the request coming from ${a}: that is the public side of the NAT.`,
      `O próximo salto viu a requisição vindo de ${a}: esse é o lado público do NAT.`,
      `El siguiente salto vio la petición llegar desde ${a}: ese es el lado público del NAT.`,
      `Der nächste Hop sah die Anfrage von ${a} kommen: das ist die öffentliche Seite des NAT.`,
      `Le saut suivant a vu la requête arriver de ${a} : c'est le côté public du NAT.`,
      `下一跳看到请求来自 ${a}：这是 NAT 的公网一侧。`,
      `अगले hop ने request को ${a} से आते देखा: यह NAT की public side है।`,
    )]);
  }
  out.push([L("Signaling path", "Caminho da sinalização", "Camino de la señalización", "Signalisierungsweg", "Chemin de signalisation", "信令路径", "Signaling का रास्ता"), path]);

  // 3. Media negotiated
  if (c.kind === "INVITE") {
    const offer = msgs.find((m) => m.sdp);
    const answer = offer && msgs.find((m) => m.sdp && m.index > offer.index && m.src === offer.dst);
    const neg = [];
    const so = offer && sdpSummary(offer);
    const sa = answer && sdpSummary(answer);
    const codecsW = L("codecs", "codecs", "códecs", "Codecs", "codecs", "编解码器", "codecs");
    if (so) neg.push([L("Offer", "Oferta", "Oferta", "Angebot", "Offre", "提议（Offer）", "Offer"), `${fromW} ${mono(offer.src)} (#${offer.index}): ${sendTo} ${mono(`${so.ip}:${so.port}`)} <span class="muted">${esc(ipKind(so.ip))}</span>; ${codecsW} ${esc(so.codecs.join(", "))}`]);
    if (sa) neg.push([L("Answer", "Resposta", "Respuesta", "Antwort", "Réponse", "应答（Answer）", "Answer"), `${fromW} ${mono(answer.src)} (#${answer.index}): ${sendTo} ${mono(`${sa.ip}:${sa.port}`)} <span class="muted">${esc(ipKind(sa.ip))}</span>; ${codecsW} ${esc(sa.codecs.join(", "))}`]);
    if (so && sa) {
      const chosen = sa.codecs.find((x) => !/telephone-event|CN/i.test(x)) || sa.codecs[0];
      neg.push([L("Codec used", "Codec usado", "Códec usado", "Verwendeter Codec", "Codec utilisé", "使用的编解码器", "उपयोग हुआ codec"), `<b>${esc(chosen)}</b> <span class="muted">${L("(first audio codec of the answer)", "(primeiro codec de áudio da resposta)", "(primer códec de audio de la respuesta)", "(erster Audio-Codec der Antwort)", "(premier codec audio de la réponse)", "（应答中的第一个音频编解码器）", "(answer का पहला audio codec)")}</span>`]);
      neg.push(["DTMF", so.dtmf != null && sa.dtmf != null
        ? L(`RFC 4733 events in RTP (payload ${sa.dtmf}): digits travel as special RTP packets.`, `Eventos RFC 4733 no RTP (payload ${sa.dtmf}): os dígitos vão como pacotes RTP especiais.`, `Eventos RFC 4733 en el RTP (payload ${sa.dtmf}): los dígitos viajan como paquetes RTP especiales.`, `RFC-4733-Ereignisse im RTP (Payload ${sa.dtmf}): Ziffern reisen als spezielle RTP-Pakete.`, `Événements RFC 4733 dans le RTP (payload ${sa.dtmf}) : les chiffres voyagent dans des paquets RTP spéciaux.`, `RTP 中的 RFC 4733 事件（payload ${sa.dtmf}）：数字以特殊 RTP 包传送。`, `RTP में RFC 4733 events (payload ${sa.dtmf}): अंक विशेष RTP packets के रूप में जाते हैं।`)
        : L("No telephone-event in both SDPs: digits must go as SIP INFO or as tones inside the audio (inband), which compressed codecs can distort.", "Sem telephone-event nos dois SDPs: os dígitos têm de ir por SIP INFO ou como tom dentro do áudio (inband), que codecs comprimidos podem distorcer.", "Sin telephone-event en ambos SDP: los dígitos deben ir por SIP INFO o como tonos dentro del audio (inband), que los códecs comprimidos pueden distorsionar.", "Kein telephone-event in beiden SDPs: Ziffern müssen per SIP INFO oder als Töne im Audio (Inband) gehen, die komprimierende Codecs verzerren können.", "Pas de telephone-event dans les deux SDP : les chiffres doivent passer par SIP INFO ou en tonalités dans l'audio (inband), que les codecs compressés peuvent déformer.", "两个 SDP 中并非都有 telephone-event：数字必须通过 SIP INFO 或以音频中的音调（带内）发送，而压缩编解码器可能使其失真。", "दोनों SDPs में telephone-event नहीं है: अंक SIP INFO से या audio के अंदर tones (inband) के रूप में भेजने होंगे, जिन्हें compressed codecs बिगाड़ सकते हैं।")]);
      neg.push([L("Packet time", "Packet time", "Packet time", "Paketzeit", "Packet time", "打包时长", "Packet time"), esc(`${sa.ptime || so.ptime || 20} ms`)]);
      neg.push([L("Security", "Segurança", "Seguridad", "Sicherheit", "Sécurité", "安全", "सुरक्षा"), esc(sa.sec)]);
      if (so.dir !== "sendrecv" || sa.dir !== "sendrecv") neg.push([L("Direction", "Direção", "Dirección", "Richtung", "Direction", "方向", "दिशा"), esc(`${so.dir} / ${sa.dir}`)]);
      if (so.ice || sa.ice) neg.push(["ICE", L("Candidates present: the endpoints test several addresses and use the first that works.", "Há candidatos: os lados testam vários endereços e usam o primeiro que funcionar.", "Hay candidatos: los extremos prueban varias direcciones y usan la primera que funcione.", "Kandidaten vorhanden: Die Endpunkte testen mehrere Adressen und nehmen die erste, die funktioniert.", "Candidats présents : les terminaux testent plusieurs adresses et utilisent la première qui fonctionne.", "存在候选：两端测试多个地址，并使用第一个可用的地址。", "Candidates मौजूद हैं: endpoints कई addresses आज़माते हैं और जो पहले काम करे उसे उपयोग करते हैं।")]);
    } else if (so && !sa) {
      neg.push([L("Answer", "Resposta", "Respuesta", "Antwort", "Réponse", "应答（Answer）", "Answer"), L("No SDP answer in the capture: the call was not answered, or the answer is missing.", "Sem resposta SDP na captura: a chamada não foi atendida, ou a resposta não foi capturada.", "Sin respuesta SDP en la captura: la llamada no fue contestada, o falta la respuesta.", "Keine SDP-Antwort im Mitschnitt: Der Anruf wurde nicht angenommen, oder die Antwort fehlt.", "Pas de réponse SDP dans la capture : l'appel n'a pas été répondu, ou la réponse manque.", "抓包中没有 SDP 应答：呼叫未被应答，或应答未被抓到。", "Capture में SDP answer नहीं है: कॉल का जवाब नहीं दिया गया, या answer capture में नहीं आया।")]);
    } else if (!so) {
      neg.push([L("Offer", "Oferta", "Oferta", "Angebot", "Offre", "提议（Offer）", "Offer"), L("The INVITE had no SDP (late offer): the offer comes in the 200 OK and the answer in the ACK.", "O INVITE não tinha SDP (late offer): a oferta vem no 200 OK e a resposta no ACK.", "El INVITE no tenía SDP (late offer): la oferta llega en el 200 OK y la respuesta en el ACK.", "Das INVITE hatte kein SDP (Late Offer): Das Angebot kommt im 200 OK, die Antwort im ACK.", "L'INVITE n'avait pas de SDP (late offer) : l'offre arrive dans le 200 OK et la réponse dans l'ACK.", "INVITE 中没有 SDP（late offer）：提议在 200 OK 中，应答在 ACK 中。", "INVITE में SDP नहीं था (late offer): offer 200 OK में आता है और answer ACK में।")]);
    }
    out.push([L("Media negotiated (SDP)", "Mídia negociada (SDP)", "Medios negociados (SDP)", "Ausgehandelte Medien (SDP)", "Média négocié (SDP)", "协商的媒体（SDP）", "Negotiated media (SDP)"), neg]);

    // 4. Media seen
    const seen = [];
    const streams = c.streams.map((i) => r.streams[i]);
    if (!streams.length) {
      seen.push(["RTP", L("No RTP in the capture for this call. If the call was answered, the capture may hold SIP only (port 5060 filter), or the media took another path.", "Nenhum RTP na captura desta chamada. Se a chamada foi atendida, a captura pode ter só SIP (filtro na 5060), ou a mídia seguiu outro caminho.", "No hay RTP en la captura de esta llamada. Si fue contestada, la captura puede tener solo SIP (filtro en 5060), o los medios siguieron otro camino.", "Kein RTP im Mitschnitt dieses Anrufs. Wurde er angenommen, enthält der Mitschnitt vielleicht nur SIP (Filter auf 5060), oder die Medien nahmen einen anderen Weg.", "Aucun RTP dans la capture pour cet appel. Si l'appel a été répondu, la capture ne contient peut-être que le SIP (filtre sur 5060), ou le média a pris un autre chemin.", "抓包中没有此呼叫的 RTP。如果呼叫已应答，可能抓包只包含 SIP（过滤了 5060 端口），或者媒体走了另一条路径。", "इस कॉल के लिए capture में कोई RTP नहीं है। अगर कॉल का जवाब दिया गया था, तो हो सकता है capture में केवल SIP हो (port 5060 filter), या media किसी दूसरे रास्ते से गया।")]);
    }
    const pk = L("packets", "pacotes", "paquetes", "Pakete", "paquets", "个包", "packets");
    const loss = L("loss", "perda", "pérdida", "Verlust", "perte", "丢包", "loss");
    for (const s of streams) {
      const announced = [so, sa].filter(Boolean).find((x) => host(s.dst) === x.ip && port(s.dst) === x.port);
      seen.push([`${mono(s.src)} → ${mono(s.dst)}`, `${esc(s.codec)}, ${s.packets} ${pk}, ${loss} ${s.loss_pct.toFixed(1)}%, jitter ${s.jitter_ms.toFixed(1)} ms${s.mos != null ? `, MOS ${s.mos.toFixed(2)}` : ""}${announced ? "" : ` <span class="warn">${L("goes to an address no SDP announced: NAT or a media relay changed it.", "vai para um endereço que nenhum SDP anunciou: NAT ou um relay de mídia mudou.", "va a una dirección que ningún SDP anunció: un NAT o un relay de medios la cambió.", "geht an eine Adresse, die kein SDP angekündigt hat: NAT oder ein Medien-Relay hat sie geändert.", "va vers une adresse qu'aucun SDP n'a annoncée : un NAT ou un relais média l'a modifiée.", "发往一个没有任何 SDP 宣告过的地址：NAT 或媒体中继修改了它。", "ऐसे address पर जाता है जिसकी घोषणा किसी SDP ने नहीं की: NAT या किसी media relay ने इसे बदला।")}</span>`}`]);
    }
    if (streams.length === 1 && c.talk_s > 2) seen.push([L("One way", "Mão única", "Un solo sentido", "Einseitig", "Unidirectionnel", "单向", "एकतरफ़ा"), `<span class="bad">${L("RTP flows in only one direction: the other side hears nothing, or its audio goes to an address this capture does not see (private SDP behind NAT, firewall).", "O RTP só flui num sentido: o outro lado não ouve nada, ou o áudio dele vai para um endereço que esta captura não vê (SDP privado atrás de NAT, firewall).", "El RTP fluye en un solo sentido: el otro lado no oye nada, o su audio va a una dirección que esta captura no ve (SDP privado detrás de NAT, firewall).", "RTP fließt nur in eine Richtung: Die Gegenseite hört nichts, oder ihr Audio geht an eine Adresse, die dieser Mitschnitt nicht sieht (privates SDP hinter NAT, Firewall).", "Le RTP ne circule que dans un sens : l'autre côté n'entend rien, ou son audio va vers une adresse que cette capture ne voit pas (SDP privé derrière un NAT, firewall).", "RTP 只在一个方向上流动：对端听不到声音，或者其音频发往本次抓包看不到的地址（NAT 后的私有 SDP、防火墙）。", "RTP केवल एक दिशा में चल रहा है: दूसरे पक्ष को कुछ सुनाई नहीं देता, या उसका audio ऐसे address पर जाता है जो यह capture नहीं देखता (NAT के पीछे private SDP, firewall)।")}</span>`]);
    if (so && sa && isPrivate(so.ip) !== isPrivate(sa.ip)) seen.push([L("Address families", "Tipos de endereço", "Tipos de dirección", "Adressarten", "Types d'adresse", "地址类型", "Address के प्रकार"), L("One side announced a private address and the other a public one: unless an SBC or symmetric RTP fixes it, audio is likely one-way.", "Um lado anunciou endereço privado e o outro público: sem SBC ou RTP simétrico corrigindo, o áudio tende a ser de mão única.", "Un lado anunció una dirección privada y el otro una pública: salvo que un SBC o RTP simétrico lo corrija, el audio probablemente irá en un solo sentido.", "Eine Seite hat eine private, die andere eine öffentliche Adresse angekündigt: Ohne SBC oder symmetrisches RTP ist das Audio wahrscheinlich einseitig.", "Un côté a annoncé une adresse privée et l'autre une adresse publique : sauf correction par un SBC ou du RTP symétrique, l'audio sera probablement unidirectionnel.", "一端宣告了私有地址，另一端宣告了公网地址：除非 SBC 或对称 RTP 进行修正，否则音频很可能是单向的。", "एक पक्ष ने private address और दूसरे ने public address घोषित किया: जब तक कोई SBC या symmetric RTP इसे ठीक न करे, audio शायद एकतरफ़ा होगा।")]);
    out.push([L("Media seen", "Mídia observada", "Medios observados", "Beobachtete Medien", "Média observé", "观察到的媒体", "देखा गया media"), seen]);
  }

  // 5. How it ended
  const end = [];
  const resultW = L("Result", "Resultado", "Resultado", "Ergebnis", "Résultat", "结果", "परिणाम");
  if (final) end.push([resultW, `<b>${final.status} ${esc(final.raw.split(/\r?\n/)[0].replace(/^SIP\/2\.0 \d+ /, ""))}</b>: ${esc(statusHelp(final.status))}`]);
  else end.push([resultW, L("No final response in the capture.", "Nenhuma resposta final na captura.", "Ninguna respuesta final en la captura.", "Keine endgültige Antwort im Mitschnitt.", "Aucune réponse finale dans la capture.", "抓包中没有最终响应。", "Capture में कोई final response नहीं है।")]);
  const chall = msgs.filter((m) => m.status === 401 || m.status === 407).length;
  if (chall) {
    const many = chall > 1;
    end.push([L("Authentication", "Autenticação", "Autenticación", "Authentifizierung", "Authentification", "认证", "Authentication"), L(
      `${chall} challenge(s) ${many ? "(more than one: check the credentials)" : "(normal: the first request has no credentials)"}.`,
      `${chall} desafio(s) ${many ? "(mais de um: confira as credenciais)" : "(normal: a primeira requisição vai sem credenciais)"}.`,
      `${chall} desafío(s) ${many ? "(más de uno: revisa las credenciales)" : "(normal: la primera petición va sin credenciales)"}.`,
      `${chall} Abfrage(n) ${many ? "(mehr als eine: Zugangsdaten prüfen)" : "(normal: Die erste Anfrage geht ohne Zugangsdaten)"}.`,
      `${chall} challenge(s) ${many ? "(plus d'un : vérifiez les identifiants)" : "(normal : la première requête part sans identifiants)"}.`,
      `${chall} 次质询 ${many ? "（多于一次：请检查凭据）" : "（正常：第一个请求不带凭据）"}。`,
      `${chall} challenge(s) ${many ? "(एक से ज़्यादा: credentials जाँचें)" : "(सामान्य: पहला request बिना credentials के जाता है)"}।`,
    )]);
  }
  if (c.pdd_ms != null) {
    const s = (c.pdd_ms / 1000).toFixed(2);
    end.push([L("Post-dial delay", "Atraso pós-discagem", "Retardo posmarcación", "Rufaufbauzeit", "Délai post-numérotation", "拨号后延迟", "Post-dial delay"), L(
      `${s} s from the INVITE to the first ring or early media.`,
      `${s} s do INVITE até o primeiro toque ou mídia antecipada.`,
      `${s} s desde el INVITE hasta el primer tono o medios tempranos.`,
      `${s} s vom INVITE bis zum ersten Klingeln oder Early Media.`,
      `${s} s entre l'INVITE et la première sonnerie ou le early media.`,
      `从 INVITE 到首次振铃或早期媒体用时 ${s} s。`,
      `INVITE से पहली ring या early media तक ${s} s।`,
    )]);
  }
  if (c.talk_s != null) end.push([L("Talk time", "Tempo de conversa", "Tiempo de conversación", "Gesprächsdauer", "Durée de conversation", "通话时长", "बातचीत का समय"), `${c.talk_s.toFixed(1)} s`]);
  const bye = msgs.find((m) => m.method === "BYE" && !m.status);
  if (bye) {
    const who = bye.src === invite.src ? L("the caller", "quem ligou", "quien llamó", "der Anrufer", "l'appelant", "主叫方", "कॉल करने वाला") : L("the called side", "quem atendeu", "quien contestó", "die angerufene Seite", "l'appelé", "被叫方", "जिसे कॉल किया गया");
    const reason = hdr(bye.raw, "Reason");
    end.push([L("Hung up by", "Desligada por", "Colgada por", "Aufgelegt von", "Raccroché par", "挂断方", "कॉल काटने वाला"), `${esc(who)} (${mono(bye.src)})${reason ? `, Reason ${mono(reason)}` : ""}`]);
  }
  const cancel = msgs.find((m) => m.method === "CANCEL" && !m.status);
  if (cancel) end.push(["CANCEL", L("The caller gave up before the answer.", "Quem ligou desistiu antes do atendimento.", "Quien llamaba colgó antes de la respuesta.", "Der Anrufer hat vor der Annahme aufgegeben.", "L'appelant a abandonné avant la réponse.", "主叫在应答前放弃了呼叫。", "कॉल करने वाले ने जवाब से पहले कॉल छोड़ दी।")]);
  out.push([L("How it ended", "Como terminou", "Cómo terminó", "Wie es endete", "Comment il s'est terminé", "呼叫如何结束", "कैसे खत्म हुई"), end]);
  return out;
}

export function renderExplain(r, ci, findings) {
  if (ci == null || !r.calls[ci]) return `<p class="empty-note">${L("Pick a dialog on the left to have it explained.", "Escolha um diálogo à esquerda para ver a explicação.", "Elige un diálogo a la izquierda para ver la explicación.", "Links einen Dialog wählen, um ihn erklärt zu bekommen.", "Choisissez un dialogue à gauche pour en voir l'explication.", "在左侧选择一个对话以查看说明。", "समझाने के लिए बाईं ओर एक dialog चुनें।")}</p>`;
  const sections = explainCall(r, ci);
  const fs = findings.filter((f) => f.call === ci && f.severity !== "info");
  return `<div class="explain">${fs.length ? `<section class="x-problems"><h3>${L("What looks wrong", "O que parece errado", "Qué parece estar mal", "Was nicht stimmt", "Ce qui semble anormal", "看起来有问题的地方", "क्या गलत लगता है")}</h3><ul>${fs.map((f) => `<li class="${f.severity}"><b>${esc(trFinding(f.title))}</b>: ${esc(trFinding(f.detail))}</li>`).join("")}</ul></section>` : ""}
    ${sections.map(([title, rows]) => `<section><h3>${esc(title)}</h3><dl class="kv">${rows.map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join("")}</dl></section>`).join("")}</div>`;
}
