// Plain-language explanations for troubleshooting: what a call used, where it
// came from, what the SDP asked for and what the media really did. Written for
// people who do not remember every SIP header and SDP attribute by heart.
// Texts are English and Portuguese (Brazil); other languages fall back to English.

import { currentLang } from "./i18n.js";

const L = (en, pt) => (currentLang() === "pt" ? pt : en);
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
  if (ip === "0.0.0.0") return L("placeholder address: media on hold (RFC 2543 style)", "endereço de espera: mídia em hold (estilo RFC 2543)");
  if (isLoopback(ip)) return L("loopback: only this machine", "loopback: só esta máquina");
  if (isPrivate(ip)) return L("private address: not reachable from the internet", "endereço privado: não é alcançável pela internet");
  return L("public address", "endereço público");
}

// ---------------------------------------------------------------------------
// SIP headers

const HEADERS = {
  via: ["Path of the request: every proxy adds a Via on top. Responses travel back along these. received= and rport= show the address the next hop really saw (NAT).", "Caminho da requisição: cada proxy adiciona um Via em cima. As respostas voltam por esses Via. received= e rport= mostram o endereço que o próximo salto realmente viu (NAT)."],
  from: ["Who starts this dialog (the caller for an INVITE). The tag identifies this side of the dialog.", "Quem inicia o diálogo (quem liga, num INVITE). O tag identifica este lado do diálogo."],
  to: ["Who is being called, as dialed. The far end adds its tag when it answers.", "Para quem é a chamada, como foi discado. O outro lado adiciona o tag ao responder."],
  "call-id": ["Unique name of the call. Every message of the same dialog shares it.", "Nome único da chamada. Todas as mensagens do mesmo diálogo têm o mesmo."],
  cseq: ["Sequence number and method: pairs each response with its request.", "Número de sequência e método: liga cada resposta à sua requisição."],
  contact: ["Where this side wants to receive the next requests of the dialog (ACK, BYE, re-INVITE). A private address here behind NAT is a classic cause of missing ACK and calls dropping at 32 s.", "Onde este lado quer receber as próximas requisições do diálogo (ACK, BYE, re-INVITE). Um endereço privado aqui atrás de NAT é causa clássica de ACK perdido e queda aos 32 s."],
  "record-route": ["A proxy asks to stay in the path for the rest of the dialog.", "Um proxy pede para continuar no caminho pelo resto do diálogo."],
  route: ["The proxies this request must go through, taken from Record-Route.", "Os proxies por onde esta requisição tem de passar, tirados do Record-Route."],
  "max-forwards": ["Hop limit, lowered by each proxy. Near 0 means a routing loop.", "Limite de saltos, cada proxy diminui. Perto de 0 indica loop de roteamento."],
  "user-agent": ["Software that sent the request.", "Software que enviou a requisição."],
  server: ["Software that sent the response.", "Software que enviou a resposta."],
  allow: ["Methods this side accepts.", "Métodos que este lado aceita."],
  supported: ["SIP extensions this side can use (100rel = PRACK, timer = session timers, replaces = attended transfer).", "Extensões SIP que este lado sabe usar (100rel = PRACK, timer = session timers, replaces = transferência assistida)."],
  require: ["Extensions the other side must support, or reject with 420.", "Extensões que o outro lado tem de suportar, senão rejeita com 420."],
  "session-expires": ["Session timer: the call must be refreshed (re-INVITE or UPDATE) before this many seconds, or it is torn down.", "Session timer: a chamada tem de ser renovada (re-INVITE ou UPDATE) antes desse tempo, senão cai."],
  "min-se": ["Shortest session timer this side accepts.", "Menor session timer que este lado aceita."],
  "content-type": ["Format of the body: application/sdp is the media offer or answer.", "Formato do corpo: application/sdp é a oferta ou resposta de mídia."],
  "content-length": ["Body size in bytes. Mandatory over TCP and TLS.", "Tamanho do corpo em bytes. Obrigatório em TCP e TLS."],
  "p-asserted-identity": ["The caller identity a trusted network vouches for (used for caller ID and billing).", "A identidade do chamador garantida por uma rede confiável (usada para bina e tarifação)."],
  "p-preferred-identity": ["The identity the phone would like to present; the network decides.", "A identidade que o telefone gostaria de apresentar; a rede decide."],
  "remote-party-id": ["Older header for caller identity and privacy.", "Cabeçalho antigo de identidade do chamador e privacidade."],
  privacy: ["Hide the caller identity from the far end (id, header, user).", "Esconder a identidade do chamador do outro lado (id, header, user)."],
  diversion: ["The call was forwarded: who forwarded it and why.", "A chamada foi desviada: quem desviou e por quê."],
  "history-info": ["Every retarget of the request (forwarding), in order.", "Cada redirecionamento da requisição (desvios), em ordem."],
  reason: ["Why the call ended or was cancelled; Q.850 cause numbers come from the telephone network.", "Por que a chamada terminou ou foi cancelada; os números Q.850 vêm da rede telefônica."],
  warning: ["Extra text from the server explaining a failure.", "Texto extra do servidor explicando uma falha."],
  expires: ["How long a registration or subscription is valid, in seconds.", "Quanto tempo um registro ou assinatura vale, em segundos."],
  "www-authenticate": ["The server asks for credentials (401): realm and nonce for the digest.", "O servidor pede credenciais (401): realm e nonce para o digest."],
  "proxy-authenticate": ["A proxy asks for credentials (407).", "Um proxy pede credenciais (407)."],
  authorization: ["Digest answer to a 401 challenge: proves the password without sending it.", "Resposta digest ao desafio 401: prova a senha sem enviá-la."],
  "proxy-authorization": ["Digest answer to a 407 challenge.", "Resposta digest ao desafio 407."],
  "refer-to": ["Transfer target: who the other side should call.", "Destino da transferência: para quem o outro lado deve ligar."],
  "referred-by": ["Who requested the transfer.", "Quem pediu a transferência."],
  replaces: ["This call replaces an existing dialog (attended transfer, call pickup).", "Esta chamada substitui um diálogo existente (transferência assistida, captura)."],
  event: ["Event package of a SUBSCRIBE or NOTIFY (dialog = BLF, presence, refer = transfer progress, message-summary = voicemail).", "Pacote de evento de SUBSCRIBE ou NOTIFY (dialog = BLF, presence, refer = andamento de transferência, message-summary = correio de voz)."],
  "subscription-state": ["Whether the subscription is active, pending or terminated.", "Se a assinatura está ativa, pendente ou encerrada."],
  rseq: ["Sequence number of a reliable provisional response (PRACK).", "Número de sequência de resposta provisória confiável (PRACK)."],
  rack: ["Acknowledges a reliable provisional response.", "Confirma uma resposta provisória confiável."],
  "alert-info": ["Ring tone hint, or auto answer for intercom.", "Dica de toque, ou atendimento automático para interfone."],
  "call-info": ["Extra information about the call; answer-after asks for auto answer.", "Informação extra da chamada; answer-after pede atendimento automático."],
  accept: ["Body formats this side understands.", "Formatos de corpo que este lado entende."],
};
const COMPACT = { v: "via", f: "from", t: "to", i: "call-id", m: "contact", l: "content-length", c: "content-type", k: "supported", r: "refer-to", b: "referred-by", o: "event", x: "session-expires" };

export function headerHelp(name) {
  const n = name.trim().toLowerCase();
  const h = HEADERS[COMPACT[n] || n];
  return h ? L(h[0], h[1]) : "";
}

// ---------------------------------------------------------------------------
// Status codes

const STATUS = {
  100: ["The next hop got the request and is working on it.", "O próximo salto recebeu a requisição e está tratando."],
  180: ["The phone is ringing.", "O telefone está tocando."],
  181: ["The call is being forwarded.", "A chamada está sendo desviada."],
  182: ["The call is queued.", "A chamada está na fila."],
  183: ["Session progress: early media (ringback, announcements) may flow before the answer.", "Progresso da sessão: mídia antecipada (tom de chamada, anúncios) pode passar antes do atendimento."],
  200: ["Success. For an INVITE: the call was answered.", "Sucesso. Num INVITE: a chamada foi atendida."],
  202: ["Accepted, done later (a REFER transfer is under way).", "Aceito, será feito depois (uma transferência REFER está em andamento)."],
  301: ["The user moved permanently; Contact has the new address.", "O usuário mudou de vez; o Contact tem o novo endereço."],
  302: ["Moved temporarily: try the address in Contact (call forwarding).", "Mudou temporariamente: tente o endereço do Contact (desvio)."],
  400: ["Bad request: the message is malformed.", "Requisição inválida: a mensagem está malformada."],
  401: ["Credentials needed: the phone repeats the request with a digest. Normal once; a second 401 means a wrong user or password.", "Credenciais necessárias: o telefone repete a requisição com digest. Normal uma vez; um segundo 401 indica usuário ou senha errados."],
  403: ["Forbidden: the server knows who you are and refuses (no permission, blocked number, wrong realm).", "Proibido: o servidor sabe quem você é e recusa (sem permissão, número bloqueado, realm errado)."],
  404: ["Not found: the number or user does not exist on that server.", "Não encontrado: o número ou usuário não existe naquele servidor."],
  405: ["Method not allowed here.", "Método não permitido aqui."],
  407: ["A proxy needs credentials: the request is repeated with Proxy-Authorization.", "Um proxy precisa de credenciais: a requisição é repetida com Proxy-Authorization."],
  408: ["Request timeout: nobody answered in time.", "Tempo esgotado: ninguém respondeu a tempo."],
  410: ["Gone: the number existed but no longer does.", "Não existe mais: o número existiu mas foi desativado."],
  415: ["Unsupported body format.", "Formato de corpo não suportado."],
  420: ["The far end does not support an extension listed in Require.", "O outro lado não suporta uma extensão listada em Require."],
  422: ["Session timer too short; see Min-SE.", "Session timer curto demais; veja Min-SE."],
  423: ["Registration interval too short; see Min-Expires.", "Intervalo de registro curto demais; veja Min-Expires."],
  480: ["Temporarily unavailable: the user is not registered, in DND or not answering.", "Temporariamente indisponível: o usuário não está registrado, está em não perturbe ou não atende."],
  481: ["Call or transaction does not exist: a request for a dialog the far end does not know (lost state, wrong tags).", "Chamada ou transação inexistente: requisição para um diálogo que o outro lado não conhece (estado perdido, tags errados)."],
  482: ["Loop detected.", "Loop detectado."],
  483: ["Too many hops.", "Saltos demais."],
  484: ["Address incomplete: more digits are needed.", "Endereço incompleto: faltam dígitos."],
  486: ["Busy here.", "Ocupado."],
  487: ["Request terminated: the caller cancelled before the answer.", "Requisição encerrada: quem ligou cancelou antes do atendimento."],
  488: ["Not acceptable here: no common codec, or the media security (SRTP) does not match.", "Não aceitável: nenhum codec em comum, ou a segurança da mídia (SRTP) não bate."],
  491: ["Request pending: both sides sent a re-INVITE at the same time (glare); retried after a random delay.", "Requisição pendente: os dois lados mandaram re-INVITE ao mesmo tempo (glare); repete depois de um tempo aleatório."],
  500: ["Server internal error.", "Erro interno do servidor."],
  501: ["Not implemented on the server.", "Não implementado no servidor."],
  502: ["Bad gateway: the next network failed.", "Gateway inválido: a próxima rede falhou."],
  503: ["Service unavailable: overloaded, no route or trunk down.", "Serviço indisponível: sobrecarga, sem rota ou tronco fora."],
  504: ["The next server timed out.", "O próximo servidor não respondeu a tempo."],
  600: ["Busy everywhere.", "Ocupado em todos os lugares."],
  603: ["Declined: the user rejected the call.", "Recusada: o usuário rejeitou a chamada."],
  604: ["Does not exist anywhere.", "Não existe em lugar nenhum."],
};
export function statusHelp(code) {
  const s = STATUS[code];
  if (s) return L(s[0], s[1]);
  if (code >= 100 && code < 200) return L("Provisional response: still working on it.", "Resposta provisória: ainda em andamento.");
  if (code < 300) return L("Success.", "Sucesso.");
  if (code < 400) return L("Redirect: try another address.", "Redirecionamento: tente outro endereço.");
  if (code < 500) return L("The request was refused or cannot be completed by this destination.", "A requisição foi recusada ou não pode ser completada neste destino.");
  if (code < 600) return L("A server failed.", "Um servidor falhou.");
  return L("Global failure.", "Falha global.");
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
    case "v": return L("SDP version (always 0).", "Versão do SDP (sempre 0).");
    case "o": {
      const p = v.split(/\s+/);
      return L(`Origin: user ${p[0]}, session id ${p[1]}, version ${p[2]} (goes up by one each time this side changes its media), created on ${p[5] || ""}. The address here is informational, not where media goes.`,
        `Origem: usuário ${p[0]}, id da sessão ${p[1]}, versão ${p[2]} (sobe um a cada mudança de mídia deste lado), criada em ${p[5] || ""}. O endereço aqui é só informativo, não é para onde vai a mídia.`);
    }
    case "s": return L("Session name (free text).", "Nome da sessão (texto livre).");
    case "c": {
      const ip = v.split(/\s+/).pop();
      return L(`Connection: send RTP to ${ip} (${ipKind(ip)}).`, `Conexão: mande o RTP para ${ip} (${ipKind(ip)}).`);
    }
    case "t": return L("Timing: 0 0 means the session is not bounded in time.", "Tempo: 0 0 quer dizer sessão sem limite de tempo.");
    case "b": return L(`Bandwidth limit ${v}.`, `Limite de banda ${v}.`);
    case "m": {
      const p = v.split(/\s+/);
      const pts = p.slice(3).map((x) => `${x} = ${map[x] || STATIC_PT[x] || "?"}`).join(", ");
      const prof = { "RTP/AVP": L("plain RTP", "RTP sem criptografia"), "RTP/SAVP": L("SRTP with keys in a=crypto (SDES)", "SRTP com chaves em a=crypto (SDES)"), "UDP/TLS/RTP/SAVP": L("SRTP with keys from DTLS (a=fingerprint)", "SRTP com chaves via DTLS (a=fingerprint)"), "UDP/TLS/RTP/SAVPF": L("WebRTC: DTLS-SRTP with RTCP feedback", "WebRTC: DTLS-SRTP com feedback RTCP"), "RTP/AVPF": L("RTP with RTCP feedback", "RTP com feedback RTCP") }[p[2]] || p[2];
      return L(`Media line: ${p[0]} on port ${p[1]}${p[1] === "0" ? " (port 0 = this stream is rejected or disabled)" : ""}, ${prof}. Payload types in order of preference: ${pts}.`,
        `Linha de mídia: ${p[0]} na porta ${p[1]}${p[1] === "0" ? " (porta 0 = fluxo recusado ou desativado)" : ""}, ${prof}. Payload types em ordem de preferência: ${pts}.`);
    }
    case "a": {
      const [name, val = ""] = v.split(/:(.*)/s);
      switch (name) {
        case "rtpmap": {
          const [pt, enc] = val.split(/\s+/);
          const ev = /telephone-event/i.test(enc);
          return ev ? L(`Payload ${pt} carries DTMF digits as RFC 4733 events (${enc}).`, `Payload ${pt} leva os dígitos DTMF como eventos RFC 4733 (${enc}).`)
            : L(`Payload ${pt} is ${enc} (codec/clock rate${/\/2$/.test(enc) ? "/channels" : ""}).`, `Payload ${pt} é ${enc} (codec/taxa${/\/2$/.test(enc) ? "/canais" : ""}).`);
        }
        case "fmtp": return /0-1[56]/.test(val) ? L(`DTMF events supported: ${val.split(/\s+/)[1]} (0-15 are the keys 0-9 * # A-D).`, `Eventos DTMF suportados: ${val.split(/\s+/)[1]} (0-15 são as teclas 0-9 * # A-D).`)
          : /useinbandfec/.test(val) ? L("Opus options: in-band FEC lets the receiver repair lost packets.", "Opções do Opus: FEC in-band permite ao receptor recuperar pacotes perdidos.")
          : /annexb=no/.test(val) ? L("G.729 without Annex B (no silence suppression).", "G.729 sem Anexo B (sem supressão de silêncio).")
          : L(`Codec options for payload ${val.split(/\s+/)[0]}.`, `Opções do codec para o payload ${val.split(/\s+/)[0]}.`);
        case "ptime": return L(`Packet time: ${val} ms of audio per RTP packet.`, `Packet time: ${val} ms de áudio por pacote RTP.`);
        case "maxptime": return L(`Longest packet time accepted: ${val} ms.`, `Maior packet time aceito: ${val} ms.`);
        case "sendrecv": return L("Two-way audio.", "Áudio nos dois sentidos.");
        case "sendonly": return L("This side only sends: usually it is putting the call on hold (music on hold).", "Este lado só envia: normalmente está colocando a chamada em espera (música de espera).");
        case "recvonly": return L("This side only receives: the answer to a hold.", "Este lado só recebe: a resposta a uma espera.");
        case "inactive": return L("No audio either way: held from both sides.", "Sem áudio nos dois sentidos: espera dos dois lados.");
        case "rtcp": return L(`RTCP (quality reports) goes to port ${val.split(/\s+/)[0]}${val.split(/\s+/)[3] ? ` at ${val.split(/\s+/)[3]}` : ""}.`, `RTCP (relatórios de qualidade) vai para a porta ${val.split(/\s+/)[0]}${val.split(/\s+/)[3] ? ` em ${val.split(/\s+/)[3]}` : ""}.`);
        case "rtcp-mux": return L("RTCP shares the RTP port.", "O RTCP usa a mesma porta do RTP.");
        case "crypto": {
          const p = val.split(/\s+/);
          return L(`SRTP key offered in the SDP (SDES) with suite ${p[1]}. Anyone who can read this SDP can decrypt the audio, so use it with TLS.`, `Chave SRTP oferecida no próprio SDP (SDES) com a suíte ${p[1]}. Quem ler este SDP consegue decifrar o áudio, por isso use com TLS.`);
        }
        case "fingerprint": return L(`Hash of this side's DTLS certificate (${val.split(/\s+/)[0]}): the far end checks the certificate in the DTLS handshake against it.`, `Hash do certificado DTLS deste lado (${val.split(/\s+/)[0]}): o outro lado confere o certificado do handshake DTLS com ele.`);
        case "setup": return { actpass: L("DTLS role: either; the answerer chooses.", "Papel DTLS: qualquer um; quem responde escolhe."), active: L("DTLS role: this side starts the handshake (client).", "Papel DTLS: este lado inicia o handshake (cliente)."), passive: L("DTLS role: this side waits for the handshake (server).", "Papel DTLS: este lado espera o handshake (servidor).") }[val.trim()] || "";
        case "ice-ufrag": return L("ICE user fragment: identifies this side in connectivity checks.", "Fragmento de usuário ICE: identifica este lado nos testes de conectividade.");
        case "ice-pwd": return L("ICE password for connectivity checks.", "Senha ICE dos testes de conectividade.");
        case "ice-lite": return L("Lite ICE: this side only answers checks (typical for servers).", "ICE lite: este lado só responde aos testes (típico de servidores).");
        case "candidate": {
          const p = val.split(/\s+/);
          const typ = p[7];
          const kind = { host: L("its own interface", "a própria interface"), srflx: L("public address seen by STUN (NAT)", "endereço público visto pelo STUN (NAT)"), relay: L("TURN relay", "relay TURN"), prflx: L("address learned during checks", "endereço aprendido nos testes") }[typ] || typ;
          return L(`ICE candidate: ${p[2]} ${p[4]}:${p[5]}, ${kind}.`, `Candidato ICE: ${p[2]} ${p[4]}:${p[5]}, ${kind}.`);
        }
        case "mid": return L("Media identifier for bundling.", "Identificador de mídia para bundle.");
        case "group": return L("Streams bundled on one port.", "Fluxos agrupados numa só porta.");
        case "ssrc": return L("Identifier of the RTP stream this side will send.", "Identificador do fluxo RTP que este lado vai enviar.");
        case "rtcp-fb": return L("RTCP feedback this side supports.", "Feedback RTCP que este lado suporta.");
        case "extmap": return L("RTP header extension.", "Extensão de cabeçalho RTP.");
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
  const sec = md.fingerprint ? "DTLS-SRTP" : md.crypto.length ? `SRTP (SDES ${md.crypto[0].split(/\s+/)[1] || ""})` : /SAVP/.test(md.proto) ? "SRTP" : L("none (plain RTP)", "nenhuma (RTP aberto)");
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

  // 1. Who and what
  const who = [];
  if (c.kind === "REGISTER") {
    who.push([L("What", "O quê"), L(`Registration of ${mono(user(called))} at ${mono(host(ruri.replace(/^sips?:/, "")))}: tells the server where to send calls for this user.`, `Registro de ${mono(user(called))} em ${mono(host(ruri.replace(/^sips?:/, "")))}: avisa o servidor para onde mandar as chamadas deste usuário.`)]);
  } else {
    who.push([L("Caller", "Origem"), party(caller)]);
    who.push([L("Called", "Destino"), party(called)]);
    who.push([L("Dialed", "Discado"), `<b class="mono">${esc(user(ruri) || ruri)}</b> <span class="muted mono">${esc(ruri)}</span>${user(ruri) && user(called) && user(ruri) !== user(called) ? ` <span class="warn">${L("differs from To: the request was retargeted", "diferente do To: a requisição foi redirecionada")}</span>` : ""}`]);
    const pai = hdr(invite.raw, "P-Asserted-Identity");
    if (pai) who.push([L("Network identity", "Identidade de rede"), `${party(pai)} <span class="muted">${esc(L("(P-Asserted-Identity: what the network shows as caller ID)", "(P-Asserted-Identity: o que a rede mostra como bina)"))}</span>`]);
    const div = hdr(invite.raw, "Diversion");
    if (div) who.push([L("Forwarded by", "Desviada por"), `${party(div)} ${esc(((div.match(/reason=([^;]+)/) || [])[1] || ""))}`]);
  }
  const uaReq = hdr(invite.raw, "User-Agent");
  const uaResp = respFrom ? hdr(respFrom.raw, "Server") || hdr(respFrom.raw, "User-Agent") : "";
  if (uaReq || uaResp) who.push([L("Software", "Software"), `${uaReq ? `${esc(uaReq)} <span class="muted">${L("(sent the request)", "(enviou a requisição)")}</span>` : ""}${uaReq && uaResp ? "<br>" : ""}${uaResp ? `${esc(uaResp)} <span class="muted">${L("(answered)", "(respondeu)")}</span>` : ""}`]);
  out.push([L("Who and what", "Quem e o quê"), who]);

  // 2. Signaling path
  const path = [];
  const src = invite.src, dst = invite.dst;
  path.push([L("Sent", "Enviado"), `${mono(src)} → ${mono(dst)} ${L("over", "via")} ${esc(invite.transport)}`]);
  path.push([L("Source", "Origem"), `${mono(host(src))}: ${esc(ipKind(host(src)))}`]);
  path.push([L("Destination", "Destino"), `${mono(host(dst))}: ${esc(ipKind(host(dst)))}`]);
  const vias = invite.raw.split(/\r?\n/).filter((l) => /^(via|v):/i.test(l));
  if (vias.length > 1) path.push([L("Proxies", "Proxies"), L(`${vias.length - 1} proxy hop(s) before this capture point (one Via each).`, `${vias.length - 1} salto(s) de proxy antes deste ponto de captura (um Via por salto).`)]);
  const rr = msgs.find((m) => /^record-route:/im.test(m.raw));
  if (rr) path.push(["Record-Route", L("A proxy stays in the path for the whole call: ACK, BYE and re-INVITEs go through it.", "Um proxy fica no caminho a chamada toda: ACK, BYE e re-INVITE passam por ele.")]);
  const contact = hdr(invite.raw, "Contact|m");
  const cHost = host(((contact.match(/sips?:[^@]*@?([^;>]+)/) || [])[1] || "")).replace(/^.*@/, "");
  if (cHost) {
    const natHint = isPrivate(cHost) && !isPrivate(host(src))
      ? ` <span class="bad">${L("private Contact from a public source: there is a NAT and the far end may send ACK and BYE to an unreachable address (the 32 s drop).", "Contact privado vindo de origem pública: há um NAT e o outro lado pode mandar ACK e BYE para um endereço inalcançável (a queda aos 32 s).")}</span>`
      : cHost !== host(src) && !isPrivate(cHost) && !isPrivate(host(src)) ? ` <span class="muted">${L("differs from the source address (a proxy or SBC sent it on the phone's behalf).", "diferente do endereço de origem (um proxy ou SBC enviou em nome do telefone).")}</span>` : "";
    path.push(["Contact", `${mono(contact)}${natHint}`]);
  }
  const viaRecv = vias[0] && (vias[0].match(/received=([^;\s,]+)/) || [])[1];
  if (viaRecv) path.push(["received=", L(`The next hop saw the request coming from ${mono(viaRecv)}: that is the public side of the NAT.`, `O próximo salto viu a requisição vindo de ${mono(viaRecv)}: esse é o lado público do NAT.`)]);
  out.push([L("Signaling path", "Caminho da sinalização"), path]);

  // 3. Media negotiated
  if (c.kind === "INVITE") {
    const offer = msgs.find((m) => m.sdp);
    const answer = offer && msgs.find((m) => m.sdp && m.index > offer.index && m.src === offer.dst);
    const neg = [];
    const so = offer && sdpSummary(offer);
    const sa = answer && sdpSummary(answer);
    if (so) neg.push([L("Offer", "Oferta"), `${L("from", "de")} ${mono(offer.src)} (#${offer.index}): ${L("send my audio to", "mande meu áudio para")} ${mono(`${so.ip}:${so.port}`)} <span class="muted">${esc(ipKind(so.ip))}</span>; ${L("codecs", "codecs")} ${esc(so.codecs.join(", "))}`]);
    if (sa) neg.push([L("Answer", "Resposta"), `${L("from", "de")} ${mono(answer.src)} (#${answer.index}): ${L("send my audio to", "mande meu áudio para")} ${mono(`${sa.ip}:${sa.port}`)} <span class="muted">${esc(ipKind(sa.ip))}</span>; ${L("codecs", "codecs")} ${esc(sa.codecs.join(", "))}`]);
    if (so && sa) {
      const chosen = sa.codecs.find((x) => !/telephone-event|CN/i.test(x)) || sa.codecs[0];
      neg.push([L("Codec used", "Codec usado"), `<b>${esc(chosen)}</b> <span class="muted">${L("(first audio codec of the answer)", "(primeiro codec de áudio da resposta)")}</span>`]);
      neg.push(["DTMF", so.dtmf != null && sa.dtmf != null ? L(`RFC 4733 events in RTP (payload ${sa.dtmf}): digits travel as special RTP packets.`, `Eventos RFC 4733 no RTP (payload ${sa.dtmf}): os dígitos vão como pacotes RTP especiais.`) : L("No telephone-event in both SDPs: digits must go as SIP INFO or as tones inside the audio (inband), which compressed codecs can distort.", "Sem telephone-event nos dois SDPs: os dígitos têm de ir por SIP INFO ou como tom dentro do áudio (inband), que codecs comprimidos podem distorcer.")]);
      neg.push([L("Packet time", "Packet time"), esc(`${sa.ptime || so.ptime || 20} ms`)]);
      neg.push([L("Security", "Segurança"), esc(sa.sec)]);
      if (so.dir !== "sendrecv" || sa.dir !== "sendrecv") neg.push([L("Direction", "Direção"), esc(`${so.dir} / ${sa.dir}`)]);
      if (so.ice || sa.ice) neg.push(["ICE", L("Candidates present: the endpoints test several addresses and use the first that works.", "Há candidatos: os lados testam vários endereços e usam o primeiro que funcionar.")]);
    } else if (so && !sa) {
      neg.push([L("Answer", "Resposta"), L("No SDP answer in the capture: the call was not answered, or the answer is missing.", "Sem resposta SDP na captura: a chamada não foi atendida, ou a resposta não foi capturada.")]);
    } else if (!so) {
      neg.push([L("Offer", "Oferta"), L("The INVITE had no SDP (late offer): the offer comes in the 200 OK and the answer in the ACK.", "O INVITE não tinha SDP (late offer): a oferta vem no 200 OK e a resposta no ACK.")]);
    }
    out.push([L("Media negotiated (SDP)", "Mídia negociada (SDP)"), neg]);

    // 4. Media seen
    const seen = [];
    const streams = c.streams.map((i) => r.streams[i]);
    if (!streams.length) {
      seen.push([L("RTP", "RTP"), L("No RTP in the capture for this call. If the call was answered, the capture may hold SIP only (port 5060 filter), or the media took another path.", "Nenhum RTP na captura desta chamada. Se a chamada foi atendida, a captura pode ter só SIP (filtro na 5060), ou a mídia seguiu outro caminho.")]);
    }
    for (const s of streams) {
      const announced = [so, sa].filter(Boolean).find((x) => host(s.dst) === x.ip && port(s.dst) === x.port);
      seen.push([`${mono(s.src)} → ${mono(s.dst)}`, `${esc(s.codec)}, ${s.packets} ${L("packets", "pacotes")}, ${L("loss", "perda")} ${s.loss_pct.toFixed(1)}%, jitter ${s.jitter_ms.toFixed(1)} ms${s.mos != null ? `, MOS ${s.mos.toFixed(2)}` : ""}${announced ? "" : ` <span class="warn">${L("goes to an address no SDP announced: NAT or a media relay changed it.", "vai para um endereço que nenhum SDP anunciou: NAT ou um relay de mídia mudou.")}</span>`}`]);
    }
    if (streams.length === 1 && c.talk_s > 2) seen.push([L("One way", "Mão única"), `<span class="bad">${L("RTP flows in only one direction: the other side hears nothing, or its audio goes to an address this capture does not see (private SDP behind NAT, firewall).", "O RTP só flui num sentido: o outro lado não ouve nada, ou o áudio dele vai para um endereço que esta captura não vê (SDP privado atrás de NAT, firewall).")}</span>`]);
    if (so && sa && isPrivate(so.ip) !== isPrivate(sa.ip)) seen.push([L("Address families", "Tipos de endereço"), L("One side announced a private address and the other a public one: unless an SBC or symmetric RTP fixes it, audio is likely one-way.", "Um lado anunciou endereço privado e o outro público: sem SBC ou RTP simétrico corrigindo, o áudio tende a ser de mão única.")]);
    out.push([L("Media seen", "Mídia observada"), seen]);
  }

  // 5. How it ended
  const end = [];
  if (final) end.push([L("Result", "Resultado"), `<b>${final.status} ${esc(final.raw.split(/\r?\n/)[0].replace(/^SIP\/2\.0 \d+ /, ""))}</b>: ${esc(statusHelp(final.status))}`]);
  else end.push([L("Result", "Resultado"), L("No final response in the capture.", "Nenhuma resposta final na captura.")]);
  const chall = msgs.filter((m) => m.status === 401 || m.status === 407).length;
  if (chall) end.push([L("Authentication", "Autenticação"), L(`${chall} challenge(s) ${chall > 1 ? "(more than one: check the credentials)" : "(normal: the first request has no credentials)"}.`, `${chall} desafio(s) ${chall > 1 ? "(mais de um: confira as credenciais)" : "(normal: a primeira requisição vai sem credenciais)"}.`)]);
  if (c.pdd_ms != null) end.push([L("Post-dial delay", "Atraso pós-discagem"), L(`${(c.pdd_ms / 1000).toFixed(2)} s from the INVITE to the first ring or early media.`, `${(c.pdd_ms / 1000).toFixed(2)} s do INVITE até o primeiro toque ou mídia antecipada.`)]);
  if (c.talk_s != null) end.push([L("Talk time", "Tempo de conversa"), `${c.talk_s.toFixed(1)} s`]);
  const bye = msgs.find((m) => m.method === "BYE" && !m.status);
  if (bye) {
    const who = bye.src === invite.src ? L("the caller", "quem ligou") : L("the called side", "quem atendeu");
    const reason = hdr(bye.raw, "Reason");
    end.push([L("Hung up by", "Desligada por"), `${esc(who)} (${mono(bye.src)})${reason ? `, Reason ${mono(reason)}` : ""}`]);
  }
  const cancel = msgs.find((m) => m.method === "CANCEL" && !m.status);
  if (cancel) end.push(["CANCEL", L("The caller gave up before the answer.", "Quem ligou desistiu antes do atendimento.")]);
  out.push([L("How it ended", "Como terminou"), end]);
  return out;
}

export function renderExplain(r, ci, findings) {
  if (ci == null || !r.calls[ci]) return `<p class="empty-note">${L("Pick a dialog on the left to have it explained.", "Escolha um diálogo à esquerda para ver a explicação.")}</p>`;
  const sections = explainCall(r, ci);
  const fs = findings.filter((f) => f.call === ci && f.severity !== "info");
  return `<div class="explain">${fs.length ? `<section class="x-problems"><h3>${L("What looks wrong", "O que parece errado")}</h3><ul>${fs.map((f) => `<li class="${f.severity}"><b>${esc(f.title)}</b>: ${esc(f.detail)}</li>`).join("")}</ul></section>` : ""}
    ${sections.map(([title, rows]) => `<section><h3>${esc(title)}</h3><dl class="kv">${rows.map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join("")}</dl></section>`).join("")}</div>`;
}
