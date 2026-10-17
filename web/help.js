// Help and About, written per language (not machine-swapped like the rest of the UI).

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
      ["Troubleshooting a call", [
        "SIP trace shows every message live. Click one to read it in full, filter by number or Call-ID, and save the session as pcapng for Wireshark.",
        "Analyze (on the phone, in the history or in the trace) opens the capture in Analysis: ladder diagram, findings in plain words, RTP loss, jitter and MOS.",
        "Ask AI sends the findings and the relevant messages to the AI provider you choose, masked by default. Show what will be sent prints the exact prompt first.",
        "Export gives an annotated pcapng (findings as Wireshark comments) or a redacted one that masks numbers, names, credentials and public IPs for vendor tickets.",
      ]],
      ["Diagnostics", [
        "Server reachability sends OPTIONS: any answer, even 404 or 405, proves the server is reachable. Silence points at the address, port, firewall or network interface.",
        "DNS shows how a domain resolves (NAPTR, SRV, A/AAAA) and which address Sidetone uses.",
        "NAT asks STUN servers which public address they see; different ports for different servers mean a symmetric NAT, the classic cause of one-way audio.",
        "Audio lets you pick the microphone and speaker and play the microphone back to check levels.",
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
      ["Investigando uma chamada", [
        "O Trace SIP mostra cada mensagem ao vivo. Clique para ler inteira, filtre por número ou Call-ID e salve a sessão em pcapng para o Wireshark.",
        "Analisar (no telefone, no histórico ou no trace) abre a captura em Análise: diagrama ladder, achados explicados, perda, jitter e MOS do RTP.",
        "Perguntar à IA envia os achados e as mensagens relevantes ao provedor de IA que você escolher, mascarados por padrão. Mostrar o que será enviado exibe o prompt exato antes.",
        "Exportar gera um pcapng anotado (achados como comentários do Wireshark) ou um anonimizado que mascara números, nomes, credenciais e IPs públicos para chamados com fornecedores.",
      ]],
      ["Diagnóstico", [
        "Alcance do servidor envia OPTIONS: qualquer resposta, até 404 ou 405, prova que o servidor está alcançável. Silêncio aponta para endereço, porta, firewall ou interface de rede.",
        "DNS mostra como um domínio é resolvido (NAPTR, SRV, A/AAAA) e qual endereço o Sidetone usa.",
        "NAT pergunta a servidores STUN qual endereço público eles veem; portas diferentes para servidores diferentes indicam NAT simétrico, a causa clássica de áudio de um lado só.",
        "Áudio permite escolher microfone e alto-falante e ouvir o próprio microfone para conferir os níveis.",
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
      ["Diagnosticar una llamada", [
        "La traza SIP muestra cada mensaje en vivo. Haz clic para leerlo completo, filtra por número o Call-ID y guarda la sesión como pcapng para Wireshark.",
        "Analizar (en el teléfono, el historial o la traza) abre la captura en Análisis: diagrama de escalera, hallazgos explicados, pérdida, jitter y MOS del RTP.",
        "Preguntar a la IA envía los hallazgos y los mensajes relevantes al proveedor que elijas, ocultos por defecto. Mostrar lo que se enviará enseña antes el prompt exacto.",
        "Exportar genera un pcapng anotado (hallazgos como comentarios de Wireshark) o uno anonimizado que oculta números, nombres, credenciales e IP públicas para tickets con proveedores.",
      ]],
      ["Diagnóstico", [
        "Alcance del servidor envía OPTIONS: cualquier respuesta, incluso 404 o 405, prueba que el servidor es alcanzable. El silencio apunta a dirección, puerto, firewall o interfaz de red.",
        "DNS muestra cómo se resuelve un dominio (NAPTR, SRV, A/AAAA) y qué dirección usa Sidetone.",
        "NAT pregunta a servidores STUN qué dirección pública ven; puertos distintos para servidores distintos indican NAT simétrico, la causa clásica del audio en un solo sentido.",
        "Audio permite elegir micrófono y altavoz y escuchar tu micrófono para comprobar niveles.",
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
      ["Einen Anruf untersuchen", [
        "Der SIP-Trace zeigt jede Nachricht live. Anklicken zum Lesen, nach Nummer oder Call-ID filtern und die Sitzung als pcapng für Wireshark speichern.",
        "Analysieren (am Telefon, im Verlauf oder im Trace) öffnet den Mitschnitt in der Analyse: Leiterdiagramm, verständliche Befunde, RTP-Verlust, Jitter und MOS.",
        "KI fragen sendet Befunde und relevante Nachrichten an den gewählten KI-Anbieter, standardmäßig maskiert. Zeigen, was gesendet wird, zeigt vorher den genauen Prompt.",
        "Export liefert ein kommentiertes pcapng (Befunde als Wireshark-Kommentare) oder ein anonymisiertes, das Nummern, Namen, Zugangsdaten und öffentliche IPs für Herstellertickets maskiert.",
      ]],
      ["Diagnose", [
        "Erreichbarkeit sendet OPTIONS: jede Antwort, auch 404 oder 405, beweist die Erreichbarkeit. Stille deutet auf Adresse, Port, Firewall oder Netzwerkschnittstelle.",
        "DNS zeigt, wie eine Domain aufgelöst wird (NAPTR, SRV, A/AAAA) und welche Adresse Sidetone nutzt.",
        "NAT fragt STUN-Server nach der öffentlichen Adresse; unterschiedliche Ports je Server bedeuten symmetrisches NAT, die klassische Ursache für einseitiges Audio.",
        "Audio wählt Mikrofon und Lautsprecher und spielt das Mikrofon zur Pegelkontrolle ab.",
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
  const h = H[lang] || H.en;
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
