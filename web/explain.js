// Plain-language explanations for troubleshooting: what a call used, where it
// came from, what the SDP asked for and what the media really did. Written for
// people who do not remember every SIP header and SDP attribute by heart.
// Texts in English, Portuguese (Brazil), Spanish and German.

import { currentLang } from "./i18n.js";
import { trFinding } from "./findings-i18n.js";

const LI = { en: 0, pt: 1, es: 2, de: 3 };
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
  if (ip === "0.0.0.0") return L("placeholder address: media on hold (RFC 2543 style)", "endereço de espera: mídia em hold (estilo RFC 2543)", "dirección comodín: medios en espera (estilo RFC 2543)", "Platzhalteradresse: Medien gehalten (Stil RFC 2543)");
  if (isLoopback(ip)) return L("loopback: only this machine", "loopback: só esta máquina", "loopback: solo esta máquina", "Loopback: nur dieser Rechner");
  if (isPrivate(ip)) return L("private address: not reachable from the internet", "endereço privado: não é alcançável pela internet", "dirección privada: no alcanzable desde internet", "private Adresse: aus dem Internet nicht erreichbar");
  return L("public address", "endereço público", "dirección pública", "öffentliche Adresse");
}

// ---------------------------------------------------------------------------
// SIP headers: [en, pt, es, de]

const HEADERS = {
  via: [
    "Path of the request: every proxy adds a Via on top. Responses travel back along these. received= and rport= show the address the next hop really saw (NAT).",
    "Caminho da requisição: cada proxy adiciona um Via em cima. As respostas voltam por esses Via. received= e rport= mostram o endereço que o próximo salto realmente viu (NAT).",
    "Camino de la petición: cada proxy añade un Via encima. Las respuestas vuelven por esos Via. received= y rport= muestran la dirección que el siguiente salto vio realmente (NAT).",
    "Weg der Anfrage: Jeder Proxy setzt einen Via oben drauf. Antworten laufen diesen Weg zurück. received= und rport= zeigen die Adresse, die der nächste Hop wirklich gesehen hat (NAT).",
  ],
  from: [
    "Who starts this dialog (the caller for an INVITE). The tag identifies this side of the dialog.",
    "Quem inicia o diálogo (quem liga, num INVITE). O tag identifica este lado do diálogo.",
    "Quién inicia el diálogo (quien llama, en un INVITE). El tag identifica este lado del diálogo.",
    "Wer den Dialog beginnt (bei einem INVITE der Anrufer). Der Tag kennzeichnet diese Seite des Dialogs.",
  ],
  to: [
    "Who is being called, as dialed. The far end adds its tag when it answers.",
    "Para quem é a chamada, como foi discado. O outro lado adiciona o tag ao responder.",
    "A quién se llama, tal como se marcó. El otro lado añade su tag al responder.",
    "Wer angerufen wird, wie gewählt. Die Gegenseite fügt beim Antworten ihren Tag hinzu.",
  ],
  "call-id": [
    "Unique name of the call. Every message of the same dialog shares it.",
    "Nome único da chamada. Todas as mensagens do mesmo diálogo têm o mesmo.",
    "Nombre único de la llamada. Todos los mensajes del mismo diálogo lo comparten.",
    "Eindeutiger Name des Anrufs. Alle Nachrichten desselben Dialogs tragen ihn.",
  ],
  cseq: [
    "Sequence number and method: pairs each response with its request.",
    "Número de sequência e método: liga cada resposta à sua requisição.",
    "Número de secuencia y método: empareja cada respuesta con su petición.",
    "Folgenummer und Methode: ordnet jede Antwort ihrer Anfrage zu.",
  ],
  contact: [
    "Where this side wants to receive the next requests of the dialog (ACK, BYE, re-INVITE). A private address here behind NAT is a classic cause of missing ACK and calls dropping at 32 s.",
    "Onde este lado quer receber as próximas requisições do diálogo (ACK, BYE, re-INVITE). Um endereço privado aqui atrás de NAT é causa clássica de ACK perdido e queda aos 32 s.",
    "Dónde quiere recibir este lado las siguientes peticiones del diálogo (ACK, BYE, re-INVITE). Una dirección privada aquí detrás de NAT es causa clásica de ACK perdido y cortes a los 32 s.",
    "Wo diese Seite die nächsten Anfragen des Dialogs empfangen will (ACK, BYE, re-INVITE). Eine private Adresse hier hinter NAT ist eine klassische Ursache für fehlendes ACK und Abbrüche nach 32 s.",
  ],
  "record-route": [
    "A proxy asks to stay in the path for the rest of the dialog.",
    "Um proxy pede para continuar no caminho pelo resto do diálogo.",
    "Un proxy pide seguir en el camino durante el resto del diálogo.",
    "Ein Proxy bittet, für den Rest des Dialogs im Weg zu bleiben.",
  ],
  route: [
    "The proxies this request must go through, taken from Record-Route.",
    "Os proxies por onde esta requisição tem de passar, tirados do Record-Route.",
    "Los proxies por los que debe pasar esta petición, tomados de Record-Route.",
    "Die Proxys, über die diese Anfrage laufen muss, aus Record-Route übernommen.",
  ],
  "max-forwards": [
    "Hop limit, lowered by each proxy. Near 0 means a routing loop.",
    "Limite de saltos, cada proxy diminui. Perto de 0 indica loop de roteamento.",
    "Límite de saltos, cada proxy lo reduce. Cerca de 0 indica un bucle de enrutamiento.",
    "Hop-Limit, jeder Proxy senkt ihn. Nahe 0 deutet auf eine Routing-Schleife hin.",
  ],
  "user-agent": ["Software that sent the request.", "Software que enviou a requisição.", "Software que envió la petición.", "Software, die die Anfrage gesendet hat."],
  server: ["Software that sent the response.", "Software que enviou a resposta.", "Software que envió la respuesta.", "Software, die die Antwort gesendet hat."],
  allow: ["Methods this side accepts.", "Métodos que este lado aceita.", "Métodos que acepta este lado.", "Methoden, die diese Seite annimmt."],
  supported: [
    "SIP extensions this side can use (100rel = PRACK, timer = session timers, replaces = attended transfer).",
    "Extensões SIP que este lado sabe usar (100rel = PRACK, timer = session timers, replaces = transferência assistida).",
    "Extensiones SIP que este lado sabe usar (100rel = PRACK, timer = session timers, replaces = transferencia atendida).",
    "SIP-Erweiterungen, die diese Seite beherrscht (100rel = PRACK, timer = Session-Timer, replaces = Vermittlung mit Rückfrage).",
  ],
  require: [
    "Extensions the other side must support, or reject with 420.",
    "Extensões que o outro lado tem de suportar, senão rejeita com 420.",
    "Extensiones que el otro lado debe soportar; si no, rechaza con 420.",
    "Erweiterungen, die die Gegenseite unterstützen muss, sonst lehnt sie mit 420 ab.",
  ],
  "session-expires": [
    "Session timer: the call must be refreshed (re-INVITE or UPDATE) before this many seconds, or it is torn down.",
    "Session timer: a chamada tem de ser renovada (re-INVITE ou UPDATE) antes desse tempo, senão cai.",
    "Session timer: la llamada debe renovarse (re-INVITE o UPDATE) antes de estos segundos, o se corta.",
    "Session-Timer: Der Anruf muss vor Ablauf dieser Sekunden erneuert werden (re-INVITE oder UPDATE), sonst wird er beendet.",
  ],
  "min-se": ["Shortest session timer this side accepts.", "Menor session timer que este lado aceita.", "Session timer más corto que acepta este lado.", "Kürzester Session-Timer, den diese Seite annimmt."],
  "content-type": [
    "Format of the body: application/sdp is the media offer or answer.",
    "Formato do corpo: application/sdp é a oferta ou resposta de mídia.",
    "Formato del cuerpo: application/sdp es la oferta o respuesta de medios.",
    "Format des Inhalts: application/sdp ist das Medienangebot oder die Medienantwort.",
  ],
  "content-length": [
    "Body size in bytes. Mandatory over TCP and TLS.",
    "Tamanho do corpo em bytes. Obrigatório em TCP e TLS.",
    "Tamaño del cuerpo en bytes. Obligatorio en TCP y TLS.",
    "Größe des Inhalts in Bytes. Pflicht bei TCP und TLS.",
  ],
  "p-asserted-identity": [
    "The caller identity a trusted network vouches for (used for caller ID and billing).",
    "A identidade do chamador garantida por uma rede confiável (usada para bina e tarifação).",
    "La identidad del llamante que garantiza una red de confianza (usada para el identificador de llamadas y la tarificación).",
    "Die Anruferidentität, für die ein vertrauenswürdiges Netz bürgt (für Rufnummernanzeige und Abrechnung).",
  ],
  "p-preferred-identity": [
    "The identity the phone would like to present; the network decides.",
    "A identidade que o telefone gostaria de apresentar; a rede decide.",
    "La identidad que el teléfono querría presentar; decide la red.",
    "Die Identität, die das Telefon gern anzeigen würde; das Netz entscheidet.",
  ],
  "remote-party-id": [
    "Older header for caller identity and privacy.",
    "Cabeçalho antigo de identidade do chamador e privacidade.",
    "Cabecera antigua de identidad del llamante y privacidad.",
    "Älterer Header für Anruferidentität und Datenschutz.",
  ],
  privacy: [
    "Hide the caller identity from the far end (id, header, user).",
    "Esconder a identidade do chamador do outro lado (id, header, user).",
    "Ocultar la identidad del llamante al otro lado (id, header, user).",
    "Anruferidentität vor der Gegenseite verbergen (id, header, user).",
  ],
  diversion: [
    "The call was forwarded: who forwarded it and why.",
    "A chamada foi desviada: quem desviou e por quê.",
    "La llamada fue desviada: quién la desvió y por qué.",
    "Der Anruf wurde umgeleitet: von wem und warum.",
  ],
  "history-info": [
    "Every retarget of the request (forwarding), in order.",
    "Cada redirecionamento da requisição (desvios), em ordem.",
    "Cada redirección de la petición (desvíos), en orden.",
    "Jede Umleitung der Anfrage, in Reihenfolge.",
  ],
  reason: [
    "Why the call ended or was cancelled; Q.850 cause numbers come from the telephone network.",
    "Por que a chamada terminou ou foi cancelada; os números Q.850 vêm da rede telefônica.",
    "Por qué terminó o se canceló la llamada; los números Q.850 vienen de la red telefónica.",
    "Warum der Anruf endete oder abgebrochen wurde; Q.850-Ursachen stammen aus dem Telefonnetz.",
  ],
  warning: ["Extra text from the server explaining a failure.", "Texto extra do servidor explicando uma falha.", "Texto adicional del servidor que explica un fallo.", "Zusätzlicher Text des Servers zu einem Fehler."],
  expires: [
    "How long a registration or subscription is valid, in seconds.",
    "Quanto tempo um registro ou assinatura vale, em segundos.",
    "Cuánto vale un registro o una suscripción, en segundos.",
    "Wie lange eine Registrierung oder ein Abonnement gilt, in Sekunden.",
  ],
  "www-authenticate": [
    "The server asks for credentials (401): realm and nonce for the digest.",
    "O servidor pede credenciais (401): realm e nonce para o digest.",
    "El servidor pide credenciales (401): realm y nonce para el digest.",
    "Der Server verlangt Zugangsdaten (401): Realm und Nonce für den Digest.",
  ],
  "proxy-authenticate": ["A proxy asks for credentials (407).", "Um proxy pede credenciais (407).", "Un proxy pide credenciales (407).", "Ein Proxy verlangt Zugangsdaten (407)."],
  authorization: [
    "Digest answer to a 401 challenge: proves the password without sending it.",
    "Resposta digest ao desafio 401: prova a senha sem enviá-la.",
    "Respuesta digest al desafío 401: demuestra la contraseña sin enviarla.",
    "Digest-Antwort auf eine 401-Abfrage: beweist das Passwort, ohne es zu senden.",
  ],
  "proxy-authorization": ["Digest answer to a 407 challenge.", "Resposta digest ao desafio 407.", "Respuesta digest al desafío 407.", "Digest-Antwort auf eine 407-Abfrage."],
  "refer-to": [
    "Transfer target: who the other side should call.",
    "Destino da transferência: para quem o outro lado deve ligar.",
    "Destino de la transferencia: a quién debe llamar el otro lado.",
    "Ziel der Vermittlung: wen die Gegenseite anrufen soll.",
  ],
  "referred-by": ["Who requested the transfer.", "Quem pediu a transferência.", "Quién pidió la transferencia.", "Wer die Vermittlung angefordert hat."],
  replaces: [
    "This call replaces an existing dialog (attended transfer, call pickup).",
    "Esta chamada substitui um diálogo existente (transferência assistida, captura).",
    "Esta llamada sustituye un diálogo existente (transferencia atendida, captura).",
    "Dieser Anruf ersetzt einen bestehenden Dialog (Vermittlung mit Rückfrage, Heranholen).",
  ],
  event: [
    "Event package of a SUBSCRIBE or NOTIFY (dialog = BLF, presence, refer = transfer progress, message-summary = voicemail).",
    "Pacote de evento de SUBSCRIBE ou NOTIFY (dialog = BLF, presence, refer = andamento de transferência, message-summary = correio de voz).",
    "Paquete de eventos de un SUBSCRIBE o NOTIFY (dialog = BLF, presence, refer = progreso de transferencia, message-summary = buzón de voz).",
    "Ereignispaket eines SUBSCRIBE oder NOTIFY (dialog = BLF, presence, refer = Vermittlungsfortschritt, message-summary = Mailbox).",
  ],
  "subscription-state": [
    "Whether the subscription is active, pending or terminated.",
    "Se a assinatura está ativa, pendente ou encerrada.",
    "Si la suscripción está activa, pendiente o terminada.",
    "Ob das Abonnement aktiv, ausstehend oder beendet ist.",
  ],
  rseq: [
    "Sequence number of a reliable provisional response (PRACK).",
    "Número de sequência de resposta provisória confiável (PRACK).",
    "Número de secuencia de una respuesta provisional fiable (PRACK).",
    "Folgenummer einer zuverlässigen vorläufigen Antwort (PRACK).",
  ],
  rack: ["Acknowledges a reliable provisional response.", "Confirma uma resposta provisória confiável.", "Confirma una respuesta provisional fiable.", "Bestätigt eine zuverlässige vorläufige Antwort."],
  "alert-info": [
    "Ring tone hint, or auto answer for intercom.",
    "Dica de toque, ou atendimento automático para interfone.",
    "Indicación de tono de llamada, o respuesta automática para intercomunicador.",
    "Hinweis auf den Klingelton oder automatische Annahme für Gegensprechen.",
  ],
  "call-info": [
    "Extra information about the call; answer-after asks for auto answer.",
    "Informação extra da chamada; answer-after pede atendimento automático.",
    "Información adicional de la llamada; answer-after pide respuesta automática.",
    "Zusatzinformation zum Anruf; answer-after verlangt automatische Annahme.",
  ],
  accept: ["Body formats this side understands.", "Formatos de corpo que este lado entende.", "Formatos de cuerpo que entiende este lado.", "Inhaltsformate, die diese Seite versteht."],
};
const COMPACT = { v: "via", f: "from", t: "to", i: "call-id", m: "contact", l: "content-length", c: "content-type", k: "supported", r: "refer-to", b: "referred-by", o: "event", x: "session-expires" };

export function headerHelp(name) {
  const n = name.trim().toLowerCase();
  const h = HEADERS[COMPACT[n] || n];
  return h ? L(...h) : "";
}

// ---------------------------------------------------------------------------
// Status codes: [en, pt, es, de]

const STATUS = {
  100: ["The next hop got the request and is working on it.", "O próximo salto recebeu a requisição e está tratando.", "El siguiente salto recibió la petición y la está procesando.", "Der nächste Hop hat die Anfrage erhalten und bearbeitet sie."],
  180: ["The phone is ringing.", "O telefone está tocando.", "El teléfono está sonando.", "Das Telefon klingelt."],
  181: ["The call is being forwarded.", "A chamada está sendo desviada.", "La llamada se está desviando.", "Der Anruf wird umgeleitet."],
  182: ["The call is queued.", "A chamada está na fila.", "La llamada está en cola.", "Der Anruf ist in der Warteschlange."],
  183: ["Session progress: early media (ringback, announcements) may flow before the answer.", "Progresso da sessão: mídia antecipada (tom de chamada, anúncios) pode passar antes do atendimento.", "Progreso de sesión: medios tempranos (tono de llamada, anuncios) pueden fluir antes de la respuesta.", "Sitzungsfortschritt: Early Media (Freiton, Ansagen) kann vor der Annahme fließen."],
  200: ["Success. For an INVITE: the call was answered.", "Sucesso. Num INVITE: a chamada foi atendida.", "Éxito. En un INVITE: la llamada fue contestada.", "Erfolg. Bei einem INVITE: Der Anruf wurde angenommen."],
  202: ["Accepted, done later (a REFER transfer is under way).", "Aceito, será feito depois (uma transferência REFER está em andamento).", "Aceptado, se hará después (una transferencia REFER está en curso).", "Angenommen, wird später erledigt (eine REFER-Vermittlung läuft)."],
  301: ["The user moved permanently; Contact has the new address.", "O usuário mudou de vez; o Contact tem o novo endereço.", "El usuario se movió de forma permanente; Contact tiene la nueva dirección.", "Der Teilnehmer ist dauerhaft umgezogen; Contact enthält die neue Adresse."],
  302: ["Moved temporarily: try the address in Contact (call forwarding).", "Mudou temporariamente: tente o endereço do Contact (desvio).", "Movido temporalmente: pruebe la dirección de Contact (desvío).", "Vorübergehend umgezogen: Adresse in Contact versuchen (Rufumleitung)."],
  400: ["Bad request: the message is malformed.", "Requisição inválida: a mensagem está malformada.", "Petición incorrecta: el mensaje está mal formado.", "Fehlerhafte Anfrage: Die Nachricht ist nicht wohlgeformt."],
  401: ["Credentials needed: the phone repeats the request with a digest. Normal once; a second 401 means a wrong user or password.", "Credenciais necessárias: o telefone repete a requisição com digest. Normal uma vez; um segundo 401 indica usuário ou senha errados.", "Credenciales necesarias: el teléfono repite la petición con digest. Normal una vez; un segundo 401 indica usuario o contraseña incorrectos.", "Zugangsdaten nötig: Das Telefon wiederholt die Anfrage mit Digest. Einmal normal; ein zweites 401 heißt falscher Benutzer oder falsches Passwort."],
  403: ["Forbidden: the server knows who you are and refuses (no permission, blocked number, wrong realm).", "Proibido: o servidor sabe quem você é e recusa (sem permissão, número bloqueado, realm errado).", "Prohibido: el servidor sabe quién eres y lo rechaza (sin permiso, número bloqueado, realm incorrecto).", "Verboten: Der Server kennt dich und lehnt ab (keine Berechtigung, gesperrte Nummer, falscher Realm)."],
  404: ["Not found: the number or user does not exist on that server.", "Não encontrado: o número ou usuário não existe naquele servidor.", "No encontrado: el número o usuario no existe en ese servidor.", "Nicht gefunden: Nummer oder Benutzer gibt es auf diesem Server nicht."],
  405: ["Method not allowed here.", "Método não permitido aqui.", "Método no permitido aquí.", "Methode hier nicht erlaubt."],
  407: ["A proxy needs credentials: the request is repeated with Proxy-Authorization.", "Um proxy precisa de credenciais: a requisição é repetida com Proxy-Authorization.", "Un proxy necesita credenciales: la petición se repite con Proxy-Authorization.", "Ein Proxy braucht Zugangsdaten: Die Anfrage wird mit Proxy-Authorization wiederholt."],
  408: ["Request timeout: nobody answered in time.", "Tempo esgotado: ninguém respondeu a tempo.", "Tiempo agotado: nadie respondió a tiempo.", "Zeitüberschreitung: Niemand hat rechtzeitig geantwortet."],
  410: ["Gone: the number existed but no longer does.", "Não existe mais: o número existiu mas foi desativado.", "Ya no existe: el número existió pero se dio de baja.", "Nicht mehr vorhanden: Die Nummer gab es, jetzt nicht mehr."],
  415: ["Unsupported body format.", "Formato de corpo não suportado.", "Formato de cuerpo no soportado.", "Nicht unterstütztes Inhaltsformat."],
  420: ["The far end does not support an extension listed in Require.", "O outro lado não suporta uma extensão listada em Require.", "El otro lado no soporta una extensión indicada en Require.", "Die Gegenseite unterstützt eine in Require genannte Erweiterung nicht."],
  422: ["Session timer too short; see Min-SE.", "Session timer curto demais; veja Min-SE.", "Session timer demasiado corto; ver Min-SE.", "Session-Timer zu kurz; siehe Min-SE."],
  423: ["Registration interval too short; see Min-Expires.", "Intervalo de registro curto demais; veja Min-Expires.", "Intervalo de registro demasiado corto; ver Min-Expires.", "Registrierungsintervall zu kurz; siehe Min-Expires."],
  480: ["Temporarily unavailable: the user is not registered, in DND or not answering.", "Temporariamente indisponível: o usuário não está registrado, está em não perturbe ou não atende.", "No disponible temporalmente: el usuario no está registrado, está en no molestar o no contesta.", "Vorübergehend nicht erreichbar: Teilnehmer nicht registriert, auf Nicht stören oder antwortet nicht."],
  481: ["Call or transaction does not exist: a request for a dialog the far end does not know (lost state, wrong tags).", "Chamada ou transação inexistente: requisição para um diálogo que o outro lado não conhece (estado perdido, tags errados).", "La llamada o transacción no existe: petición para un diálogo que el otro lado no conoce (estado perdido, tags incorrectos).", "Anruf oder Transaktion existiert nicht: Anfrage für einen Dialog, den die Gegenseite nicht kennt (Zustand verloren, falsche Tags)."],
  482: ["Loop detected.", "Loop detectado.", "Bucle detectado.", "Schleife erkannt."],
  483: ["Too many hops.", "Saltos demais.", "Demasiados saltos.", "Zu viele Hops."],
  484: ["Address incomplete: more digits are needed.", "Endereço incompleto: faltam dígitos.", "Dirección incompleta: faltan dígitos.", "Adresse unvollständig: Es fehlen Ziffern."],
  486: ["Busy here.", "Ocupado.", "Ocupado.", "Besetzt."],
  487: ["Request terminated: the caller cancelled before the answer.", "Requisição encerrada: quem ligou cancelou antes do atendimento.", "Petición terminada: quien llamaba canceló antes de la respuesta.", "Anfrage beendet: Der Anrufer hat vor der Annahme aufgelegt."],
  488: ["Not acceptable here: no common codec, or the media security (SRTP) does not match.", "Não aceitável: nenhum codec em comum, ou a segurança da mídia (SRTP) não bate.", "No aceptable: ningún códec en común, o la seguridad de medios (SRTP) no coincide.", "Hier nicht annehmbar: kein gemeinsamer Codec, oder die Mediensicherheit (SRTP) passt nicht."],
  491: ["Request pending: both sides sent a re-INVITE at the same time (glare); retried after a random delay.", "Requisição pendente: os dois lados mandaram re-INVITE ao mesmo tempo (glare); repete depois de um tempo aleatório.", "Petición pendiente: ambos lados enviaron un re-INVITE a la vez (glare); se reintenta tras un retardo aleatorio.", "Anfrage ausstehend: Beide Seiten haben gleichzeitig ein re-INVITE gesendet (Glare); Wiederholung nach zufälliger Wartezeit."],
  500: ["Server internal error.", "Erro interno do servidor.", "Error interno del servidor.", "Interner Serverfehler."],
  501: ["Not implemented on the server.", "Não implementado no servidor.", "No implementado en el servidor.", "Auf dem Server nicht implementiert."],
  502: ["Bad gateway: the next network failed.", "Gateway inválido: a próxima rede falhou.", "Gateway incorrecto: falló la siguiente red.", "Fehlerhaftes Gateway: Das nächste Netz ist ausgefallen."],
  503: ["Service unavailable: overloaded, no route or trunk down.", "Serviço indisponível: sobrecarga, sem rota ou tronco fora.", "Servicio no disponible: sobrecarga, sin ruta o troncal caída.", "Dienst nicht verfügbar: überlastet, keine Route oder Trunk ausgefallen."],
  504: ["The next server timed out.", "O próximo servidor não respondeu a tempo.", "El siguiente servidor no respondió a tiempo.", "Der nächste Server hat nicht rechtzeitig geantwortet."],
  600: ["Busy everywhere.", "Ocupado em todos os lugares.", "Ocupado en todas partes.", "Überall besetzt."],
  603: ["Declined: the user rejected the call.", "Recusada: o usuário rejeitou a chamada.", "Rechazada: el usuario rechazó la llamada.", "Abgelehnt: Der Teilnehmer hat den Anruf abgewiesen."],
  604: ["Does not exist anywhere.", "Não existe em lugar nenhum.", "No existe en ningún lugar.", "Existiert nirgends."],
};
export function statusHelp(code) {
  const s = STATUS[code];
  if (s) return L(...s);
  if (code >= 100 && code < 200) return L("Provisional response: still working on it.", "Resposta provisória: ainda em andamento.", "Respuesta provisional: aún en curso.", "Vorläufige Antwort: wird noch bearbeitet.");
  if (code < 300) return L("Success.", "Sucesso.", "Éxito.", "Erfolg.");
  if (code < 400) return L("Redirect: try another address.", "Redirecionamento: tente outro endereço.", "Redirección: pruebe otra dirección.", "Umleitung: andere Adresse versuchen.");
  if (code < 500) return L("The request was refused or cannot be completed by this destination.", "A requisição foi recusada ou não pode ser completada neste destino.", "La petición fue rechazada o este destino no puede completarla.", "Die Anfrage wurde abgelehnt oder kann von diesem Ziel nicht erfüllt werden.");
  if (code < 600) return L("A server failed.", "Um servidor falhou.", "Falló un servidor.", "Ein Server ist ausgefallen.");
  return L("Global failure.", "Falha global.", "Fallo global.", "Globaler Fehler.");
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
    case "v": return L("SDP version (always 0).", "Versão do SDP (sempre 0).", "Versión de SDP (siempre 0).", "SDP-Version (immer 0).");
    case "o": {
      const p = v.split(/\s+/);
      return L(
        `Origin: user ${p[0]}, session id ${p[1]}, version ${p[2]} (goes up by one each time this side changes its media), created on ${p[5] || ""}. The address here is informational, not where media goes.`,
        `Origem: usuário ${p[0]}, id da sessão ${p[1]}, versão ${p[2]} (sobe um a cada mudança de mídia deste lado), criada em ${p[5] || ""}. O endereço aqui é só informativo, não é para onde vai a mídia.`,
        `Origen: usuario ${p[0]}, id de sesión ${p[1]}, versión ${p[2]} (sube uno cada vez que este lado cambia sus medios), creada en ${p[5] || ""}. La dirección aquí es informativa, no es adonde van los medios.`,
        `Ursprung: Benutzer ${p[0]}, Sitzungs-ID ${p[1]}, Version ${p[2]} (steigt um eins bei jeder Medienänderung dieser Seite), erstellt auf ${p[5] || ""}. Die Adresse hier ist nur informativ, nicht das Medienziel.`,
      );
    }
    case "s": return L("Session name (free text).", "Nome da sessão (texto livre).", "Nombre de la sesión (texto libre).", "Sitzungsname (freier Text).");
    case "c": {
      const ip = v.split(/\s+/).pop();
      return L(`Connection: send RTP to ${ip} (${ipKind(ip)}).`, `Conexão: mande o RTP para ${ip} (${ipKind(ip)}).`, `Conexión: enviar el RTP a ${ip} (${ipKind(ip)}).`, `Verbindung: RTP an ${ip} senden (${ipKind(ip)}).`);
    }
    case "t": return L("Timing: 0 0 means the session is not bounded in time.", "Tempo: 0 0 quer dizer sessão sem limite de tempo.", "Tiempo: 0 0 significa sesión sin límite de tiempo.", "Zeit: 0 0 heißt, die Sitzung ist zeitlich nicht begrenzt.");
    case "b": return L(`Bandwidth limit ${v}.`, `Limite de banda ${v}.`, `Límite de ancho de banda ${v}.`, `Bandbreitenlimit ${v}.`);
    case "m": {
      const p = v.split(/\s+/);
      const pts = p.slice(3).map((x) => `${x} = ${map[x] || STATIC_PT[x] || "?"}`).join(", ");
      const prof = {
        "RTP/AVP": L("plain RTP", "RTP sem criptografia", "RTP sin cifrar", "unverschlüsseltes RTP"),
        "RTP/SAVP": L("SRTP with keys in a=crypto (SDES)", "SRTP com chaves em a=crypto (SDES)", "SRTP con claves en a=crypto (SDES)", "SRTP mit Schlüsseln in a=crypto (SDES)"),
        "UDP/TLS/RTP/SAVP": L("SRTP with keys from DTLS (a=fingerprint)", "SRTP com chaves via DTLS (a=fingerprint)", "SRTP con claves por DTLS (a=fingerprint)", "SRTP mit Schlüsseln aus DTLS (a=fingerprint)"),
        "UDP/TLS/RTP/SAVPF": L("WebRTC: DTLS-SRTP with RTCP feedback", "WebRTC: DTLS-SRTP com feedback RTCP", "WebRTC: DTLS-SRTP con feedback RTCP", "WebRTC: DTLS-SRTP mit RTCP-Feedback"),
        "RTP/AVPF": L("RTP with RTCP feedback", "RTP com feedback RTCP", "RTP con feedback RTCP", "RTP mit RTCP-Feedback"),
      }[p[2]] || p[2];
      const off = p[1] === "0";
      return L(
        `Media line: ${p[0]} on port ${p[1]}${off ? " (port 0 = this stream is rejected or disabled)" : ""}, ${prof}. Payload types in order of preference: ${pts}.`,
        `Linha de mídia: ${p[0]} na porta ${p[1]}${off ? " (porta 0 = fluxo recusado ou desativado)" : ""}, ${prof}. Payload types em ordem de preferência: ${pts}.`,
        `Línea de medios: ${p[0]} en el puerto ${p[1]}${off ? " (puerto 0 = flujo rechazado o desactivado)" : ""}, ${prof}. Payload types en orden de preferencia: ${pts}.`,
        `Medienzeile: ${p[0]} auf Port ${p[1]}${off ? " (Port 0 = Strom abgelehnt oder deaktiviert)" : ""}, ${prof}. Payload-Typen nach Vorliebe: ${pts}.`,
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
            ? L(`Payload ${pt} carries DTMF digits as RFC 4733 events (${enc}).`, `Payload ${pt} leva os dígitos DTMF como eventos RFC 4733 (${enc}).`, `El payload ${pt} lleva los dígitos DTMF como eventos RFC 4733 (${enc}).`, `Payload ${pt} überträgt DTMF-Ziffern als RFC-4733-Ereignisse (${enc}).`)
            : L(`Payload ${pt} is ${enc} (codec/clock rate${st ? "/channels" : ""}).`, `Payload ${pt} é ${enc} (codec/taxa${st ? "/canais" : ""}).`, `El payload ${pt} es ${enc} (códec/frecuencia${st ? "/canales" : ""}).`, `Payload ${pt} ist ${enc} (Codec/Taktrate${st ? "/Kanäle" : ""}).`);
        }
        case "fmtp": {
          const ev = val.split(/\s+/)[1];
          const pt = val.split(/\s+/)[0];
          return /0-1[56]/.test(val) ? L(`DTMF events supported: ${ev} (0-15 are the keys 0-9 * # A-D).`, `Eventos DTMF suportados: ${ev} (0-15 são as teclas 0-9 * # A-D).`, `Eventos DTMF soportados: ${ev} (0-15 son las teclas 0-9 * # A-D).`, `Unterstützte DTMF-Ereignisse: ${ev} (0-15 sind die Tasten 0-9 * # A-D).`)
            : /useinbandfec/.test(val) ? L("Opus options: in-band FEC lets the receiver repair lost packets.", "Opções do Opus: FEC in-band permite ao receptor recuperar pacotes perdidos.", "Opciones de Opus: FEC in-band permite al receptor reparar paquetes perdidos.", "Opus-Optionen: In-Band-FEC erlaubt dem Empfänger, verlorene Pakete zu reparieren.")
            : /annexb=no/.test(val) ? L("G.729 without Annex B (no silence suppression).", "G.729 sem Anexo B (sem supressão de silêncio).", "G.729 sin Anexo B (sin supresión de silencio).", "G.729 ohne Annex B (keine Stillenunterdrückung).")
            : L(`Codec options for payload ${pt}.`, `Opções do codec para o payload ${pt}.`, `Opciones del códec para el payload ${pt}.`, `Codec-Optionen für Payload ${pt}.`);
        }
        case "ptime": return L(`Packet time: ${val} ms of audio per RTP packet.`, `Packet time: ${val} ms de áudio por pacote RTP.`, `Packet time: ${val} ms de audio por paquete RTP.`, `Paketzeit: ${val} ms Audio pro RTP-Paket.`);
        case "maxptime": return L(`Longest packet time accepted: ${val} ms.`, `Maior packet time aceito: ${val} ms.`, `Mayor packet time aceptado: ${val} ms.`, `Längste akzeptierte Paketzeit: ${val} ms.`);
        case "sendrecv": return L("Two-way audio.", "Áudio nos dois sentidos.", "Audio en ambos sentidos.", "Audio in beide Richtungen.");
        case "sendonly": return L("This side only sends: usually it is putting the call on hold (music on hold).", "Este lado só envia: normalmente está colocando a chamada em espera (música de espera).", "Este lado solo envía: normalmente está poniendo la llamada en espera (música en espera).", "Diese Seite sendet nur: meist hält sie den Anruf (Wartemusik).");
        case "recvonly": return L("This side only receives: the answer to a hold.", "Este lado só recebe: a resposta a uma espera.", "Este lado solo recibe: la respuesta a una espera.", "Diese Seite empfängt nur: die Antwort auf ein Halten.");
        case "inactive": return L("No audio either way: held from both sides.", "Sem áudio nos dois sentidos: espera dos dois lados.", "Sin audio en ningún sentido: espera desde ambos lados.", "Kein Audio in beide Richtungen: von beiden Seiten gehalten.");
        case "rtcp": {
          const p = val.split(/\s+/);
          return L(`RTCP (quality reports) goes to port ${p[0]}${p[3] ? ` at ${p[3]}` : ""}.`, `RTCP (relatórios de qualidade) vai para a porta ${p[0]}${p[3] ? ` em ${p[3]}` : ""}.`, `El RTCP (informes de calidad) va al puerto ${p[0]}${p[3] ? ` en ${p[3]}` : ""}.`, `RTCP (Qualitätsberichte) geht an Port ${p[0]}${p[3] ? ` auf ${p[3]}` : ""}.`);
        }
        case "rtcp-mux": return L("RTCP shares the RTP port.", "O RTCP usa a mesma porta do RTP.", "El RTCP comparte el puerto del RTP.", "RTCP nutzt denselben Port wie RTP.");
        case "crypto": {
          const s = val.split(/\s+/)[1];
          return L(`SRTP key offered in the SDP (SDES) with suite ${s}. Anyone who can read this SDP can decrypt the audio, so use it with TLS.`, `Chave SRTP oferecida no próprio SDP (SDES) com a suíte ${s}. Quem ler este SDP consegue decifrar o áudio, por isso use com TLS.`, `Clave SRTP ofrecida en el propio SDP (SDES) con la suite ${s}. Quien lea este SDP puede descifrar el audio, así que úsalo con TLS.`, `SRTP-Schlüssel direkt im SDP angeboten (SDES), Suite ${s}. Wer dieses SDP lesen kann, kann das Audio entschlüsseln, daher nur mit TLS verwenden.`);
        }
        case "fingerprint": {
          const h = val.split(/\s+/)[0];
          return L(`Hash of this side's DTLS certificate (${h}): the far end checks the certificate in the DTLS handshake against it.`, `Hash do certificado DTLS deste lado (${h}): o outro lado confere o certificado do handshake DTLS com ele.`, `Hash del certificado DTLS de este lado (${h}): el otro lado comprueba con él el certificado del handshake DTLS.`, `Hash des DTLS-Zertifikats dieser Seite (${h}): Die Gegenseite prüft damit das Zertifikat im DTLS-Handshake.`);
        }
        case "setup": return {
          actpass: L("DTLS role: either; the answerer chooses.", "Papel DTLS: qualquer um; quem responde escolhe.", "Rol DTLS: cualquiera; elige quien responde.", "DTLS-Rolle: beliebig; die antwortende Seite wählt."),
          active: L("DTLS role: this side starts the handshake (client).", "Papel DTLS: este lado inicia o handshake (cliente).", "Rol DTLS: este lado inicia el handshake (cliente).", "DTLS-Rolle: Diese Seite startet den Handshake (Client)."),
          passive: L("DTLS role: this side waits for the handshake (server).", "Papel DTLS: este lado espera o handshake (servidor).", "Rol DTLS: este lado espera el handshake (servidor).", "DTLS-Rolle: Diese Seite wartet auf den Handshake (Server)."),
        }[val.trim()] || "";
        case "ice-ufrag": return L("ICE user fragment: identifies this side in connectivity checks.", "Fragmento de usuário ICE: identifica este lado nos testes de conectividade.", "Fragmento de usuario ICE: identifica este lado en las pruebas de conectividad.", "ICE-Benutzerfragment: kennzeichnet diese Seite in den Konnektivitätsprüfungen.");
        case "ice-pwd": return L("ICE password for connectivity checks.", "Senha ICE dos testes de conectividade.", "Contraseña ICE de las pruebas de conectividad.", "ICE-Passwort für die Konnektivitätsprüfungen.");
        case "ice-lite": return L("Lite ICE: this side only answers checks (typical for servers).", "ICE lite: este lado só responde aos testes (típico de servidores).", "ICE lite: este lado solo responde a las pruebas (típico de servidores).", "ICE Lite: Diese Seite beantwortet nur Prüfungen (typisch für Server).");
        case "candidate": {
          const p = val.split(/\s+/);
          const typ = p[7];
          const kind = {
            host: L("its own interface", "a própria interface", "su propia interfaz", "eigene Schnittstelle"),
            srflx: L("public address seen by STUN (NAT)", "endereço público visto pelo STUN (NAT)", "dirección pública vista por STUN (NAT)", "von STUN gesehene öffentliche Adresse (NAT)"),
            relay: L("TURN relay", "relay TURN", "relay TURN", "TURN-Relay"),
            prflx: L("address learned during checks", "endereço aprendido nos testes", "dirección aprendida en las pruebas", "bei den Prüfungen gelernte Adresse"),
          }[typ] || typ;
          return L(`ICE candidate: ${p[2]} ${p[4]}:${p[5]}, ${kind}.`, `Candidato ICE: ${p[2]} ${p[4]}:${p[5]}, ${kind}.`, `Candidato ICE: ${p[2]} ${p[4]}:${p[5]}, ${kind}.`, `ICE-Kandidat: ${p[2]} ${p[4]}:${p[5]}, ${kind}.`);
        }
        case "mid": return L("Media identifier for bundling.", "Identificador de mídia para bundle.", "Identificador de medios para bundle.", "Medienkennung für Bundling.");
        case "group": return L("Streams bundled on one port.", "Fluxos agrupados numa só porta.", "Flujos agrupados en un solo puerto.", "Ströme auf einem Port gebündelt.");
        case "ssrc": return L("Identifier of the RTP stream this side will send.", "Identificador do fluxo RTP que este lado vai enviar.", "Identificador del flujo RTP que enviará este lado.", "Kennung des RTP-Stroms, den diese Seite sendet.");
        case "rtcp-fb": return L("RTCP feedback this side supports.", "Feedback RTCP que este lado suporta.", "Feedback RTCP que soporta este lado.", "RTCP-Feedback, das diese Seite unterstützt.");
        case "extmap": return L("RTP header extension.", "Extensão de cabeçalho RTP.", "Extensión de cabecera RTP.", "RTP-Header-Erweiterung.");
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
  const sec = md.fingerprint ? "DTLS-SRTP" : md.crypto.length ? `SRTP (SDES ${md.crypto[0].split(/\s+/)[1] || ""})` : /SAVP/.test(md.proto) ? "SRTP" : L("none (plain RTP)", "nenhuma (RTP aberto)", "ninguna (RTP sin cifrar)", "keine (unverschlüsseltes RTP)");
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
  const sendTo = L("send my audio to", "mande meu áudio para", "envía mi audio a", "sende mein Audio an");
  const fromW = L("from", "de", "de", "von");

  // 1. Who and what
  const who = [];
  if (c.kind === "REGISTER") {
    const u = mono(user(called));
    const h = mono(host(ruri.replace(/^sips?:/, "")));
    who.push([L("What", "O quê", "Qué", "Was"), L(
      `Registration of ${u} at ${h}: tells the server where to send calls for this user.`,
      `Registro de ${u} em ${h}: avisa o servidor para onde mandar as chamadas deste usuário.`,
      `Registro de ${u} en ${h}: indica al servidor adónde enviar las llamadas de este usuario.`,
      `Registrierung von ${u} bei ${h}: teilt dem Server mit, wohin Anrufe für diesen Benutzer gehen.`,
    )]);
  } else {
    who.push([L("Caller", "Origem", "Llamante", "Anrufer"), party(caller)]);
    who.push([L("Called", "Destino", "Llamado", "Angerufen"), party(called)]);
    const retarget = user(ruri) && user(called) && user(ruri) !== user(called);
    who.push([L("Dialed", "Discado", "Marcado", "Gewählt"), `<b class="mono">${esc(user(ruri) || ruri)}</b> <span class="muted mono">${esc(ruri)}</span>${retarget ? ` <span class="warn">${L("differs from To: the request was retargeted", "diferente do To: a requisição foi redirecionada", "distinto del To: la petición fue redirigida", "weicht von To ab: Die Anfrage wurde umgeleitet")}</span>` : ""}`]);
    const pai = hdr(invite.raw, "P-Asserted-Identity");
    if (pai) who.push([L("Network identity", "Identidade de rede", "Identidad de red", "Netzidentität"), `${party(pai)} <span class="muted">${esc(L("(P-Asserted-Identity: what the network shows as caller ID)", "(P-Asserted-Identity: o que a rede mostra como bina)", "(P-Asserted-Identity: lo que la red muestra como identificador de llamada)", "(P-Asserted-Identity: was das Netz als Rufnummer anzeigt)"))}</span>`]);
    const div = hdr(invite.raw, "Diversion");
    if (div) who.push([L("Forwarded by", "Desviada por", "Desviada por", "Umgeleitet von"), `${party(div)} ${esc(((div.match(/reason=([^;]+)/) || [])[1] || ""))}`]);
  }
  const uaReq = hdr(invite.raw, "User-Agent");
  const uaResp = respFrom ? hdr(respFrom.raw, "Server") || hdr(respFrom.raw, "User-Agent") : "";
  if (uaReq || uaResp) who.push([L("Software", "Software", "Software", "Software"), `${uaReq ? `${esc(uaReq)} <span class="muted">${L("(sent the request)", "(enviou a requisição)", "(envió la petición)", "(hat die Anfrage gesendet)")}</span>` : ""}${uaReq && uaResp ? "<br>" : ""}${uaResp ? `${esc(uaResp)} <span class="muted">${L("(answered)", "(respondeu)", "(respondió)", "(hat geantwortet)")}</span>` : ""}`]);
  out.push([L("Who and what", "Quem e o quê", "Quién y qué", "Wer und was"), who]);

  // 2. Signaling path
  const path = [];
  const src = invite.src, dst = invite.dst;
  path.push([L("Sent", "Enviado", "Enviado", "Gesendet"), `${mono(src)} → ${mono(dst)} ${L("over", "via", "por", "über")} ${esc(invite.transport)}`]);
  path.push([L("Source", "Origem", "Origen", "Quelle"), `${mono(host(src))}: ${esc(ipKind(host(src)))}`]);
  path.push([L("Destination", "Destino", "Destino", "Ziel"), `${mono(host(dst))}: ${esc(ipKind(host(dst)))}`]);
  const vias = invite.raw.split(/\r?\n/).filter((l) => /^(via|v):/i.test(l));
  if (vias.length > 1) {
    const n = vias.length - 1;
    path.push([L("Proxies", "Proxies", "Proxies", "Proxys"), L(
      `${n} proxy hop(s) before this capture point (one Via each).`,
      `${n} salto(s) de proxy antes deste ponto de captura (um Via por salto).`,
      `${n} salto(s) de proxy antes de este punto de captura (un Via por salto).`,
      `${n} Proxy-Hop(s) vor diesem Mitschnittpunkt (je ein Via).`,
    )]);
  }
  const rr = msgs.find((m) => /^record-route:/im.test(m.raw));
  if (rr) path.push(["Record-Route", L("A proxy stays in the path for the whole call: ACK, BYE and re-INVITEs go through it.", "Um proxy fica no caminho a chamada toda: ACK, BYE e re-INVITE passam por ele.", "Un proxy se queda en el camino toda la llamada: ACK, BYE y re-INVITE pasan por él.", "Ein Proxy bleibt den ganzen Anruf im Weg: ACK, BYE und re-INVITEs laufen über ihn.")]);
  const contact = hdr(invite.raw, "Contact|m");
  const cHost = host(((contact.match(/sips?:[^@]*@?([^;>]+)/) || [])[1] || "")).replace(/^.*@/, "");
  if (cHost) {
    const natHint = isPrivate(cHost) && !isPrivate(host(src))
      ? ` <span class="bad">${L(
        "private Contact from a public source: there is a NAT and the far end may send ACK and BYE to an unreachable address (the 32 s drop).",
        "Contact privado vindo de origem pública: há um NAT e o outro lado pode mandar ACK e BYE para um endereço inalcançável (a queda aos 32 s).",
        "Contact privado desde un origen público: hay un NAT y el otro lado puede enviar ACK y BYE a una dirección inalcanzable (el corte a los 32 s).",
        "privater Contact von öffentlicher Quelle: Es gibt ein NAT, und die Gegenseite schickt ACK und BYE womöglich an eine unerreichbare Adresse (der Abbruch nach 32 s).",
      )}</span>`
      : cHost !== host(src) && !isPrivate(cHost) && !isPrivate(host(src)) ? ` <span class="muted">${L(
        "differs from the source address (a proxy or SBC sent it on the phone's behalf).",
        "diferente do endereço de origem (um proxy ou SBC enviou em nome do telefone).",
        "distinto de la dirección de origen (un proxy o SBC lo envió en nombre del teléfono).",
        "weicht von der Quelladresse ab (ein Proxy oder SBC hat im Namen des Telefons gesendet).",
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
    )]);
  }
  out.push([L("Signaling path", "Caminho da sinalização", "Camino de la señalización", "Signalisierungsweg"), path]);

  // 3. Media negotiated
  if (c.kind === "INVITE") {
    const offer = msgs.find((m) => m.sdp);
    const answer = offer && msgs.find((m) => m.sdp && m.index > offer.index && m.src === offer.dst);
    const neg = [];
    const so = offer && sdpSummary(offer);
    const sa = answer && sdpSummary(answer);
    const codecsW = L("codecs", "codecs", "códecs", "Codecs");
    if (so) neg.push([L("Offer", "Oferta", "Oferta", "Angebot"), `${fromW} ${mono(offer.src)} (#${offer.index}): ${sendTo} ${mono(`${so.ip}:${so.port}`)} <span class="muted">${esc(ipKind(so.ip))}</span>; ${codecsW} ${esc(so.codecs.join(", "))}`]);
    if (sa) neg.push([L("Answer", "Resposta", "Respuesta", "Antwort"), `${fromW} ${mono(answer.src)} (#${answer.index}): ${sendTo} ${mono(`${sa.ip}:${sa.port}`)} <span class="muted">${esc(ipKind(sa.ip))}</span>; ${codecsW} ${esc(sa.codecs.join(", "))}`]);
    if (so && sa) {
      const chosen = sa.codecs.find((x) => !/telephone-event|CN/i.test(x)) || sa.codecs[0];
      neg.push([L("Codec used", "Codec usado", "Códec usado", "Verwendeter Codec"), `<b>${esc(chosen)}</b> <span class="muted">${L("(first audio codec of the answer)", "(primeiro codec de áudio da resposta)", "(primer códec de audio de la respuesta)", "(erster Audio-Codec der Antwort)")}</span>`]);
      neg.push(["DTMF", so.dtmf != null && sa.dtmf != null
        ? L(`RFC 4733 events in RTP (payload ${sa.dtmf}): digits travel as special RTP packets.`, `Eventos RFC 4733 no RTP (payload ${sa.dtmf}): os dígitos vão como pacotes RTP especiais.`, `Eventos RFC 4733 en el RTP (payload ${sa.dtmf}): los dígitos viajan como paquetes RTP especiales.`, `RFC-4733-Ereignisse im RTP (Payload ${sa.dtmf}): Ziffern reisen als spezielle RTP-Pakete.`)
        : L("No telephone-event in both SDPs: digits must go as SIP INFO or as tones inside the audio (inband), which compressed codecs can distort.", "Sem telephone-event nos dois SDPs: os dígitos têm de ir por SIP INFO ou como tom dentro do áudio (inband), que codecs comprimidos podem distorcer.", "Sin telephone-event en ambos SDP: los dígitos deben ir por SIP INFO o como tonos dentro del audio (inband), que los códecs comprimidos pueden distorsionar.", "Kein telephone-event in beiden SDPs: Ziffern müssen per SIP INFO oder als Töne im Audio (Inband) gehen, die komprimierende Codecs verzerren können.")]);
      neg.push([L("Packet time", "Packet time", "Packet time", "Paketzeit"), esc(`${sa.ptime || so.ptime || 20} ms`)]);
      neg.push([L("Security", "Segurança", "Seguridad", "Sicherheit"), esc(sa.sec)]);
      if (so.dir !== "sendrecv" || sa.dir !== "sendrecv") neg.push([L("Direction", "Direção", "Dirección", "Richtung"), esc(`${so.dir} / ${sa.dir}`)]);
      if (so.ice || sa.ice) neg.push(["ICE", L("Candidates present: the endpoints test several addresses and use the first that works.", "Há candidatos: os lados testam vários endereços e usam o primeiro que funcionar.", "Hay candidatos: los extremos prueban varias direcciones y usan la primera que funcione.", "Kandidaten vorhanden: Die Endpunkte testen mehrere Adressen und nehmen die erste, die funktioniert.")]);
    } else if (so && !sa) {
      neg.push([L("Answer", "Resposta", "Respuesta", "Antwort"), L("No SDP answer in the capture: the call was not answered, or the answer is missing.", "Sem resposta SDP na captura: a chamada não foi atendida, ou a resposta não foi capturada.", "Sin respuesta SDP en la captura: la llamada no fue contestada, o falta la respuesta.", "Keine SDP-Antwort im Mitschnitt: Der Anruf wurde nicht angenommen, oder die Antwort fehlt.")]);
    } else if (!so) {
      neg.push([L("Offer", "Oferta", "Oferta", "Angebot"), L("The INVITE had no SDP (late offer): the offer comes in the 200 OK and the answer in the ACK.", "O INVITE não tinha SDP (late offer): a oferta vem no 200 OK e a resposta no ACK.", "El INVITE no tenía SDP (late offer): la oferta llega en el 200 OK y la respuesta en el ACK.", "Das INVITE hatte kein SDP (Late Offer): Das Angebot kommt im 200 OK, die Antwort im ACK.")]);
    }
    out.push([L("Media negotiated (SDP)", "Mídia negociada (SDP)", "Medios negociados (SDP)", "Ausgehandelte Medien (SDP)"), neg]);

    // 4. Media seen
    const seen = [];
    const streams = c.streams.map((i) => r.streams[i]);
    if (!streams.length) {
      seen.push(["RTP", L("No RTP in the capture for this call. If the call was answered, the capture may hold SIP only (port 5060 filter), or the media took another path.", "Nenhum RTP na captura desta chamada. Se a chamada foi atendida, a captura pode ter só SIP (filtro na 5060), ou a mídia seguiu outro caminho.", "No hay RTP en la captura de esta llamada. Si fue contestada, la captura puede tener solo SIP (filtro en 5060), o los medios siguieron otro camino.", "Kein RTP im Mitschnitt dieses Anrufs. Wurde er angenommen, enthält der Mitschnitt vielleicht nur SIP (Filter auf 5060), oder die Medien nahmen einen anderen Weg.")]);
    }
    const pk = L("packets", "pacotes", "paquetes", "Pakete");
    const loss = L("loss", "perda", "pérdida", "Verlust");
    for (const s of streams) {
      const announced = [so, sa].filter(Boolean).find((x) => host(s.dst) === x.ip && port(s.dst) === x.port);
      seen.push([`${mono(s.src)} → ${mono(s.dst)}`, `${esc(s.codec)}, ${s.packets} ${pk}, ${loss} ${s.loss_pct.toFixed(1)}%, jitter ${s.jitter_ms.toFixed(1)} ms${s.mos != null ? `, MOS ${s.mos.toFixed(2)}` : ""}${announced ? "" : ` <span class="warn">${L("goes to an address no SDP announced: NAT or a media relay changed it.", "vai para um endereço que nenhum SDP anunciou: NAT ou um relay de mídia mudou.", "va a una dirección que ningún SDP anunció: un NAT o un relay de medios la cambió.", "geht an eine Adresse, die kein SDP angekündigt hat: NAT oder ein Medien-Relay hat sie geändert.")}</span>`}`]);
    }
    if (streams.length === 1 && c.talk_s > 2) seen.push([L("One way", "Mão única", "Un solo sentido", "Einseitig"), `<span class="bad">${L("RTP flows in only one direction: the other side hears nothing, or its audio goes to an address this capture does not see (private SDP behind NAT, firewall).", "O RTP só flui num sentido: o outro lado não ouve nada, ou o áudio dele vai para um endereço que esta captura não vê (SDP privado atrás de NAT, firewall).", "El RTP fluye en un solo sentido: el otro lado no oye nada, o su audio va a una dirección que esta captura no ve (SDP privado detrás de NAT, firewall).", "RTP fließt nur in eine Richtung: Die Gegenseite hört nichts, oder ihr Audio geht an eine Adresse, die dieser Mitschnitt nicht sieht (privates SDP hinter NAT, Firewall).")}</span>`]);
    if (so && sa && isPrivate(so.ip) !== isPrivate(sa.ip)) seen.push([L("Address families", "Tipos de endereço", "Tipos de dirección", "Adressarten"), L("One side announced a private address and the other a public one: unless an SBC or symmetric RTP fixes it, audio is likely one-way.", "Um lado anunciou endereço privado e o outro público: sem SBC ou RTP simétrico corrigindo, o áudio tende a ser de mão única.", "Un lado anunció una dirección privada y el otro una pública: salvo que un SBC o RTP simétrico lo corrija, el audio probablemente irá en un solo sentido.", "Eine Seite hat eine private, die andere eine öffentliche Adresse angekündigt: Ohne SBC oder symmetrisches RTP ist das Audio wahrscheinlich einseitig.")]);
    out.push([L("Media seen", "Mídia observada", "Medios observados", "Beobachtete Medien"), seen]);
  }

  // 5. How it ended
  const end = [];
  const resultW = L("Result", "Resultado", "Resultado", "Ergebnis");
  if (final) end.push([resultW, `<b>${final.status} ${esc(final.raw.split(/\r?\n/)[0].replace(/^SIP\/2\.0 \d+ /, ""))}</b>: ${esc(statusHelp(final.status))}`]);
  else end.push([resultW, L("No final response in the capture.", "Nenhuma resposta final na captura.", "Ninguna respuesta final en la captura.", "Keine endgültige Antwort im Mitschnitt.")]);
  const chall = msgs.filter((m) => m.status === 401 || m.status === 407).length;
  if (chall) {
    const many = chall > 1;
    end.push([L("Authentication", "Autenticação", "Autenticación", "Authentifizierung"), L(
      `${chall} challenge(s) ${many ? "(more than one: check the credentials)" : "(normal: the first request has no credentials)"}.`,
      `${chall} desafio(s) ${many ? "(mais de um: confira as credenciais)" : "(normal: a primeira requisição vai sem credenciais)"}.`,
      `${chall} desafío(s) ${many ? "(más de uno: revisa las credenciales)" : "(normal: la primera petición va sin credenciales)"}.`,
      `${chall} Abfrage(n) ${many ? "(mehr als eine: Zugangsdaten prüfen)" : "(normal: Die erste Anfrage geht ohne Zugangsdaten)"}.`,
    )]);
  }
  if (c.pdd_ms != null) {
    const s = (c.pdd_ms / 1000).toFixed(2);
    end.push([L("Post-dial delay", "Atraso pós-discagem", "Retardo posmarcación", "Rufaufbauzeit"), L(
      `${s} s from the INVITE to the first ring or early media.`,
      `${s} s do INVITE até o primeiro toque ou mídia antecipada.`,
      `${s} s desde el INVITE hasta el primer tono o medios tempranos.`,
      `${s} s vom INVITE bis zum ersten Klingeln oder Early Media.`,
    )]);
  }
  if (c.talk_s != null) end.push([L("Talk time", "Tempo de conversa", "Tiempo de conversación", "Gesprächsdauer"), `${c.talk_s.toFixed(1)} s`]);
  const bye = msgs.find((m) => m.method === "BYE" && !m.status);
  if (bye) {
    const who = bye.src === invite.src ? L("the caller", "quem ligou", "quien llamó", "der Anrufer") : L("the called side", "quem atendeu", "quien contestó", "die angerufene Seite");
    const reason = hdr(bye.raw, "Reason");
    end.push([L("Hung up by", "Desligada por", "Colgada por", "Aufgelegt von"), `${esc(who)} (${mono(bye.src)})${reason ? `, Reason ${mono(reason)}` : ""}`]);
  }
  const cancel = msgs.find((m) => m.method === "CANCEL" && !m.status);
  if (cancel) end.push(["CANCEL", L("The caller gave up before the answer.", "Quem ligou desistiu antes do atendimento.", "Quien llamaba colgó antes de la respuesta.", "Der Anrufer hat vor der Annahme aufgegeben.")]);
  out.push([L("How it ended", "Como terminou", "Cómo terminó", "Wie es endete"), end]);
  return out;
}

export function renderExplain(r, ci, findings) {
  if (ci == null || !r.calls[ci]) return `<p class="empty-note">${L("Pick a dialog on the left to have it explained.", "Escolha um diálogo à esquerda para ver a explicação.", "Elige un diálogo a la izquierda para ver la explicación.", "Links einen Dialog wählen, um ihn erklärt zu bekommen.")}</p>`;
  const sections = explainCall(r, ci);
  const fs = findings.filter((f) => f.call === ci && f.severity !== "info");
  return `<div class="explain">${fs.length ? `<section class="x-problems"><h3>${L("What looks wrong", "O que parece errado", "Qué parece estar mal", "Was nicht stimmt")}</h3><ul>${fs.map((f) => `<li class="${f.severity}"><b>${esc(trFinding(f.title))}</b>: ${esc(trFinding(f.detail))}</li>`).join("")}</ul></section>` : ""}
    ${sections.map(([title, rows]) => `<section><h3>${esc(title)}</h3><dl class="kv">${rows.map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join("")}</dl></section>`).join("")}</div>`;
}
