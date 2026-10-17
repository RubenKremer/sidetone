// Interface translations. The UI is written in English; this module swaps
// visible text, placeholders and tooltips for the chosen language as the
// page renders (a MutationObserver catches everything drawn later).
// SIP messages, traces, findings from the analyzer and user data are left
// untouched: they are evidence and stay as they are on the wire.

export const LANGS = [
  ["en", "English"],
  ["pt", "Português (Brasil)"],
  ["es", "Español"],
  ["de", "Deutsch"],
];

// English -> [Portuguese (Brazil), Spanish, German]
const T = {
  // top bar and workspace
  "Calls": ["Chamadas", "Llamadas", "Anrufe"],
  "SIP trace": ["Trace SIP", "Traza SIP", "SIP-Trace"],
  "Analysis": ["Análise", "Análisis", "Analyse"],
  "Diagnostics": ["Diagnóstico", "Diagnóstico", "Diagnose"],
  "Settings": ["Configurações", "Configuración", "Einstellungen"],
  "Help": ["Ajuda", "Ayuda", "Hilfe"],
  "Open capture": ["Abrir captura", "Abrir captura", "Mitschnitt öffnen"],
  "Theme: auto": ["Tema: automático", "Tema: automático", "Design: automatisch"],
  "Theme: light": ["Tema: claro", "Tema: claro", "Design: hell"],
  "Theme: dark": ["Tema: escuro", "Tema: oscuro", "Design: dunkel"],
  "Switch light or dark": ["Alternar claro ou escuro", "Cambiar claro u oscuro", "Hell oder dunkel"],
  "Workspace": ["Área de trabalho", "Área de trabajo", "Arbeitsbereich"],

  // phone panel
  "Phone": ["Telefone", "Teléfono", "Telefon"],
  "Account": ["Conta", "Cuenta", "Konto"],
  "Register again": ["Registrar de novo", "Registrar de nuevo", "Erneut registrieren"],
  "No account": ["Sem conta", "Sin cuenta", "Kein Konto"],
  "No account yet. Open Settings to add one.": ["Nenhuma conta ainda. Abra Configurações para adicionar.", "Aún no hay cuentas. Abre Configuración para añadir una.", "Noch kein Konto. In den Einstellungen eines anlegen."],
  "No account yet. Add one in Settings.": ["Nenhuma conta ainda. Adicione em Configurações.", "Aún no hay cuentas. Añade una en Configuración.", "Noch kein Konto. In den Einstellungen anlegen."],
  "Add a WebSocket SIP account in Settings to start.": ["Adicione uma conta SIP WebSocket em Configurações para começar.", "Añade una cuenta SIP WebSocket en Configuración para empezar.", "Für den Start in den Einstellungen ein SIP-WebSocket-Konto anlegen."],
  "Number or SIP URI": ["Número ou SIP URI", "Número o SIP URI", "Nummer oder SIP-URI"],
  "Destination": ["Destino", "Destino", "Ziel"],
  "Options for the next call": ["Opções da próxima chamada", "Opciones de la próxima llamada", "Optionen für den nächsten Anruf"],
  "Extra headers for the next call": ["Headers extras na próxima chamada", "Cabeceras extra en la próxima llamada", "Zusätzliche Header für den nächsten Anruf"],
  "one per line, Name: value": ["um por linha, Nome: valor", "uno por línea, Nombre: valor", "einer pro Zeile, Name: Wert"],
  "Profile overrides (JSON)": ["Ajustes do perfil (JSON)", "Ajustes del perfil (JSON)", "Profil-Overrides (JSON)"],
  "any account knob, e.g. codecs or dtmf_mode": ["qualquer ajuste da conta, ex. codecs ou dtmf_mode", "cualquier ajuste de la cuenta, p. ej. codecs o dtmf_mode", "jede Kontoeinstellung, z. B. codecs oder dtmf_mode"],
  "Dial string shortcuts:": ["Atalhos na discagem:", "Atajos al marcar:", "Wählkürzel:"],
  "adds headers,": ["adiciona headers,", "añade cabeceras,", "fügt Header hinzu,"],
  "sends DTMF after answer (each comma waits 1 s).": ["manda DTMF depois de atender (cada vírgula espera 1 s).", "envía DTMF tras contestar (cada coma espera 1 s).", "sendet DTMF nach dem Annehmen (jedes Komma wartet 1 s)."],
  "Call": ["Ligar", "Llamar", "Anrufen"],
  "Answer": ["Atender", "Contestar", "Annehmen"],
  "Hang up": ["Desligar", "Colgar", "Auflegen"],
  "Reject": ["Rejeitar", "Rechazar", "Ablehnen"],
  "Cancel": ["Cancelar", "Cancelar", "Abbrechen"],
  "Call controls": ["Controles da chamada", "Controles de llamada", "Anrufsteuerung"],
  "Hold": ["Espera", "Espera", "Halten"],
  "Resume": ["Retomar", "Reanudar", "Fortsetzen"],
  "Mute": ["Mudo", "Silencio", "Stumm"],
  "Transfer": ["Transferir", "Transferir", "Weiterleiten"],
  "Record": ["Gravar", "Grabar", "Aufnehmen"],
  "Keypad": ["Teclado", "Teclado", "Tastatur"],
  "DND": ["Não perturbe", "No molestar", "Nicht stören"],
  "Auto answer": ["Atender auto.", "Resp. auto.", "Auto-Annahme"],
  "Analyze": ["Analisar", "Analizar", "Analysieren"],
  "Transfer to": ["Transferir para", "Transferir a", "Weiterleiten an"],
  "Blind": ["Direta", "Directa", "Blind"],
  "Consult first": ["Consultar antes", "Consultar antes", "Erst rückfragen"],
  "Complete transfer": ["Concluir transferência", "Completar transferencia", "Weiterleitung abschließen"],
  "Close": ["Fechar", "Cerrar", "Schließen"],
  "Blind sends the call away now. Consult calls the target first, then you complete the transfer.": ["Direta envia a chamada agora. Consultar liga antes para o destino e depois você conclui a transferência.", "Directa envía la llamada ahora. Consultar llama primero al destino y luego completas la transferencia.", "Blind leitet sofort weiter. Rückfrage ruft zuerst das Ziel an, danach schließen Sie die Weiterleitung ab."],
  "The browser phone supports blind transfer.": ["O telefone do navegador faz transferência direta.", "El teléfono del navegador hace transferencia directa.", "Das Browser-Telefon kann blind weiterleiten."],
  "Talk to the new party, then complete the transfer.": ["Fale com o destino e depois conclua a transferência.", "Habla con el destino y luego completa la transferencia.", "Mit dem Ziel sprechen, dann die Weiterleitung abschließen."],
  "Consult call ended.": ["A chamada de consulta terminou.", "La llamada de consulta terminó.", "Rückfrage beendet."],
  "Transfer requested": ["Transferência solicitada", "Transferencia solicitada", "Weiterleitung angefordert"],
  "Lines": ["Linhas", "Líneas", "Leitungen"],
  "No calls. Dial a number or wait for a call.": ["Sem chamadas. Disque um número ou aguarde uma ligação.", "Sin llamadas. Marca un número o espera una llamada.", "Keine Anrufe. Nummer wählen oder auf einen Anruf warten."],
  "Calling": ["Chamando", "Llamando", "Ruft an"],
  "Ringing": ["Tocando", "Sonando", "Klingelt"],
  "Early media": ["Early media", "Early media", "Early Media"],
  "Incoming": ["Recebendo", "Entrante", "Eingehend"],
  "Connected": ["Conectada", "Conectada", "Verbunden"],
  "Ending": ["Encerrando", "Terminando", "Wird beendet"],
  "Ended": ["Encerrada", "Terminada", "Beendet"],
  "On hold": ["Em espera", "En espera", "Gehalten"],
  "Held by remote": ["Em espera pelo outro lado", "En espera por el otro lado", "Von der Gegenseite gehalten"],
  "Browser microphone and speaker": ["Microfone e alto-falante do navegador", "Micrófono y altavoz del navegador", "Mikrofon und Lautsprecher des Browsers"],
  "Sound card": ["Placa de som", "Tarjeta de sonido", "Soundkarte"],
  "No sound card: sending a test tone": ["Sem placa de som: enviando tom de teste", "Sin tarjeta de sonido: enviando tono de prueba", "Keine Soundkarte: sende Testton"],
  "Echoing received audio": ["Devolvendo o áudio recebido", "Devolviendo el audio recibido", "Empfangenes Audio wird zurückgesendet"],
  "Sending silence": ["Enviando silêncio", "Enviando silencio", "Sende Stille"],
  "Do not disturb: incoming calls are rejected": ["Não perturbe: chamadas recebidas são rejeitadas", "No molestar: las llamadas entrantes se rechazan", "Nicht stören: eingehende Anrufe werden abgelehnt"],
  "Do not disturb off": ["Não perturbe desligado", "No molestar desactivado", "Nicht stören aus"],
  "Auto answer on": ["Atender automaticamente ligado", "Respuesta automática activada", "Auto-Annahme an"],
  "Auto answer off": ["Atender automaticamente desligado", "Respuesta automática desactivada", "Auto-Annahme aus"],

  // registration
  "Registered": ["Registrado", "Registrado", "Registriert"],
  "Registering": ["Registrando", "Registrando", "Registriere"],
  "Unregistering": ["Cancelando registro", "Anulando registro", "Abmeldung"],
  "Registration failed": ["Falha no registro", "Registro fallido", "Registrierung fehlgeschlagen"],
  "Server not answering": ["Servidor não responde", "El servidor no responde", "Server antwortet nicht"],
  "Not ready": ["Não está pronto", "No está listo", "Nicht bereit"],
  "Not registered": ["Não registrado", "No registrado", "Nicht registriert"],
  "Account disabled": ["Conta desativada", "Cuenta desactivada", "Konto deaktiviert"],
  "Idle": ["Livre", "Libre", "Frei"],
  "No NAT on the signaling path": ["Sem NAT no caminho da sinalização", "Sin NAT en la ruta de señalización", "Kein NAT auf dem Signalisierungsweg"],
  "Desktop engine (UDP)": ["Motor desktop (UDP)", "Motor de escritorio (UDP)", "Desktop-Engine (UDP)"],
  "Browser phone (WebRTC)": ["Telefone do navegador (WebRTC)", "Teléfono del navegador (WebRTC)", "Browser-Telefon (WebRTC)"],

  // calls page
  "Filter history": ["Filtrar histórico", "Filtrar historial", "Verlauf filtern"],
  "Clear history": ["Limpar histórico", "Borrar historial", "Verlauf löschen"],
  "Current call": ["Chamada atual", "Llamada actual", "Aktueller Anruf"],
  "Details of the selected line show here: media addresses, codec, packets, DTMF and transfer progress.": ["Os detalhes da linha selecionada aparecem aqui: endereços de mídia, codec, pacotes, DTMF e andamento da transferência.", "Aquí aparecen los detalles de la línea seleccionada: direcciones de medios, códec, paquetes, DTMF y avance de la transferencia.", "Hier stehen die Details der gewählten Leitung: Medienadressen, Codec, Pakete, DTMF und Stand der Weiterleitung."],
  "Phone events": ["Eventos do telefone", "Eventos del teléfono", "Telefonereignisse"],
  "Clear": ["Limpar", "Borrar", "Leeren"],
  "History": ["Histórico", "Historial", "Verlauf"],
  "Remote": ["Remoto", "Remoto", "Gegenstelle"],
  "Started": ["Início", "Inicio", "Beginn"],
  "Duration": ["Duração", "Duración", "Dauer"],
  "Result": ["Resultado", "Resultado", "Ergebnis"],
  "No calls yet.": ["Nenhuma chamada ainda.", "Aún no hay llamadas.", "Noch keine Anrufe."],
  "Answered": ["Atendida", "Contestada", "Angenommen"],
  "Not answered": ["Não atendida", "No contestada", "Nicht angenommen"],
  "Direction": ["Direção", "Dirección", "Richtung"],
  "Incoming call": ["Chamada recebida", "Llamada entrante", "Eingehender Anruf"],
  "Outgoing": ["Feita", "Saliente", "Ausgehend"],
  "Talk time": ["Tempo de conversa", "Tiempo de conversación", "Gesprächsdauer"],
  "Local media": ["Mídia local", "Medios locales", "Lokale Medien"],
  "Remote media": ["Mídia remota", "Medios remotos", "Entfernte Medien"],
  "RTP sent / received": ["RTP enviado / recebido", "RTP enviado / recibido", "RTP gesendet / empfangen"],
  "held by you": ["em espera por você", "en espera por ti", "von Ihnen gehalten"],
  "held by the remote side": ["em espera pelo outro lado", "en espera por el otro lado", "von der Gegenseite gehalten"],
  "DTMF received": ["DTMF recebido", "DTMF recibido", "Empfangene DTMF"],
  "Ended by": ["Encerrada por", "Terminada por", "Beendet von"],
  "Analyze this call": ["Analisar esta chamada", "Analizar esta llamada", "Diesen Anruf analysieren"],
  "Download recording": ["Baixar gravação", "Descargar grabación", "Aufnahme herunterladen"],
  "Recordings this session": ["Gravações desta sessão", "Grabaciones de esta sesión", "Aufnahmen dieser Sitzung"],
  "Stereo WAV: left is what Sidetone sent, right is what it received.": ["WAV estéreo: esquerda é o que o Sidetone enviou, direita o que recebeu.", "WAV estéreo: izquierda es lo que Sidetone envió, derecha lo que recibió.", "Stereo-WAV: links das Gesendete, rechts das Empfangene."],
  "no audio from the far end": ["sem áudio do outro lado", "sin audio del otro extremo", "kein Audio von der Gegenseite"],
  "Registration": ["Registro", "Registro", "Registrierung"],
  "Media": ["Mídia", "Medios", "Medien"],
  "Problem": ["Problema", "Problema", "Problem"],
  "Message": ["Mensagem", "Mensaje", "Nachricht"],
  "local": ["local", "local", "lokal"],
  "remote": ["remoto", "remoto", "Gegenstelle"],

  // trace
  "Filter: method, number, Call-ID, address": ["Filtro: método, número, Call-ID, endereço", "Filtro: método, número, Call-ID, dirección", "Filter: Methode, Nummer, Call-ID, Adresse"],
  "Filter trace": ["Filtrar trace", "Filtrar traza", "Trace filtern"],
  "Hide REGISTER": ["Ocultar REGISTER", "Ocultar REGISTER", "REGISTER ausblenden"],
  "Hide OPTIONS and NOTIFY": ["Ocultar OPTIONS e NOTIFY", "Ocultar OPTIONS y NOTIFY", "OPTIONS und NOTIFY ausblenden"],
  "Pause": ["Pausar", "Pausar", "Pause"],
  "Save pcapng": ["Salvar pcapng", "Guardar pcapng", "pcapng speichern"],
  "Analyze capture": ["Analisar captura", "Analizar captura", "Mitschnitt analysieren"],
  "SIP messages": ["Mensagens SIP", "Mensajes SIP", "SIP-Nachrichten"],
  "Select a message to see it in full.": ["Selecione uma mensagem para ver completa.", "Selecciona un mensaje para verlo completo.", "Nachricht auswählen, um sie vollständig zu sehen."],
  "SIP messages sent and received by the phone appear here live.": ["As mensagens SIP enviadas e recebidas pelo telefone aparecem aqui ao vivo.", "Los mensajes SIP enviados y recibidos por el teléfono aparecen aquí en vivo.", "Gesendete und empfangene SIP-Nachrichten erscheinen hier live."],
  "No messages match the filter.": ["Nenhuma mensagem corresponde ao filtro.", "Ningún mensaje coincide con el filtro.", "Keine Nachricht passt zum Filter."],

  // analysis
  "Analyze a capture": ["Analisar uma captura", "Analizar una captura", "Mitschnitt analysieren"],
  "Calls made with Sidetone are captured automatically: use": ["As chamadas feitas no Sidetone são capturadas automaticamente: use", "Las llamadas hechas con Sidetone se capturan automáticamente: usa", "Anrufe mit Sidetone werden automatisch mitgeschnitten: nutzen Sie"],
  "on the phone or in the call history. You can also drop a pcap or pcapng from Wireshark, tcpdump, sngrep or an SBC anywhere on this page. Analysis runs": ["no telefone ou no histórico. Você também pode soltar um pcap ou pcapng do Wireshark, tcpdump, sngrep ou de um SBC em qualquer lugar desta página. A análise roda", "en el teléfono o en el historial. También puedes soltar un pcap o pcapng de Wireshark, tcpdump, sngrep o un SBC en cualquier parte de esta página. El análisis se ejecuta", "am Telefon oder im Verlauf. Sie können auch ein pcap oder pcapng aus Wireshark, tcpdump, sngrep oder einem SBC auf diese Seite ziehen. Die Analyse läuft"],
  "; nothing is uploaded. Or try an example with a known problem:": ["; nada é enviado para fora. Ou teste um exemplo com um problema conhecido:", "; no se sube nada. O prueba un ejemplo con un problema conocido:", "; nichts wird hochgeladen. Oder ein Beispiel mit bekanntem Problem testen:"],
  "in this browser": ["neste navegador", "en este navegador", "in diesem Browser"],
  "on this computer": ["neste computador", "en este equipo", "auf diesem Computer"],
  "Export": ["Exportar", "Exportar", "Export"],
  "Samples": ["Exemplos", "Ejemplos", "Beispiele"],
  "Annotated pcapng (whole capture)": ["pcapng anotado (captura inteira)", "pcapng anotado (captura completa)", "Kommentiertes pcapng (ganzer Mitschnitt)"],
  "Annotated pcapng (this call)": ["pcapng anotado (esta chamada)", "pcapng anotado (esta llamada)", "Kommentiertes pcapng (dieser Anruf)"],
  "Redacted pcapng (this call)": ["pcapng anonimizado (esta chamada)", "pcapng anonimizado (esta llamada)", "Anonymisiertes pcapng (dieser Anruf)"],
  "Ladder as SVG": ["Ladder em SVG", "Diagrama en SVG", "Leiterdiagramm als SVG"],
  "Report as JSON": ["Relatório em JSON", "Informe en JSON", "Bericht als JSON"],
  "Dialogs": ["Diálogos", "Diálogos", "Dialoge"],
  "Calls in the capture": ["Chamadas na captura", "Llamadas en la captura", "Anrufe im Mitschnitt"],
  "Ladder diagram": ["Diagrama ladder", "Diagrama de escalera", "Leiterdiagramm"],
  "Details": ["Detalhes", "Detalles", "Details"],
  "Findings": ["Achados", "Hallazgos", "Befunde"],
  "Trace log": ["Log do trace", "Registro de traza", "Trace-Protokoll"],
  "Ask AI": ["Perguntar à IA", "Preguntar a la IA", "KI fragen"],
  "All messages": ["Todas as mensagens", "Todos los mensajes", "Alle Nachrichten"],
  "Final": ["Final", "Final", "Endgültig"],
  "Post-dial delay": ["Atraso pós-discagem", "Retardo posmarcación", "Rufaufbauzeit"],
  "Talk": ["Conversa", "Conversación", "Gespräch"],
  "Offer": ["Oferta", "Oferta", "Angebot"],
  "Agents": ["Agentes", "Agentes", "Agenten"],
  "Click an arrow in the ladder to see the full message.": ["Clique numa seta do ladder para ver a mensagem completa.", "Haz clic en una flecha del diagrama para ver el mensaje completo.", "Auf einen Pfeil im Diagramm klicken, um die ganze Nachricht zu sehen."],
  "No findings for this dialog. Signaling and media look as expected.": ["Nenhum achado neste diálogo. Sinalização e mídia parecem normais.", "Sin hallazgos en este diálogo. La señalización y los medios parecen correctos.", "Keine Befunde für diesen Dialog. Signalisierung und Medien sehen normal aus."],
  "No RTP linked to this dialog.": ["Nenhum RTP ligado a este diálogo.", "Ningún RTP asociado a este diálogo.", "Kein RTP zu diesem Dialog."],
  "The capture has no RTP. Capture media too (not only port 5060) to analyze audio.": ["A captura não tem RTP. Capture a mídia também (não só a porta 5060) para analisar o áudio.", "La captura no tiene RTP. Captura también los medios (no solo el puerto 5060) para analizar el audio.", "Der Mitschnitt enthält kein RTP. Auch Medien mitschneiden (nicht nur Port 5060), um Audio zu analysieren."],
  "Error": ["Erro", "Error", "Fehler"],
  "Warning": ["Aviso", "Advertencia", "Warnung"],
  "Note": ["Nota", "Nota", "Hinweis"],
  "Stream": ["Fluxo", "Flujo", "Stream"],
  "Packets": ["Pacotes", "Paquetes", "Pakete"],
  "Lost": ["Perdidos", "Perdidos", "Verloren"],
  "Loss": ["Perda", "Pérdida", "Verlust"],
  "Max jitter": ["Jitter máx.", "Jitter máx.", "Max. Jitter"],
  "Max gap": ["Maior lacuna", "Mayor hueco", "Größte Lücke"],
  "MOS est.": ["MOS est.", "MOS est.", "MOS gesch."],
  "MOS is an E-model (ITU-T G.107) estimate from loss and jitter at this capture point; network delay is approximated.": ["O MOS é uma estimativa do E-model (ITU-T G.107) a partir de perda e jitter neste ponto de captura; o atraso de rede é aproximado.", "El MOS es una estimación del E-model (ITU-T G.107) a partir de pérdida y jitter en este punto de captura; el retardo de red es aproximado.", "Der MOS ist eine E-Modell-Schätzung (ITU-T G.107) aus Verlust und Jitter an diesem Messpunkt; die Netzlaufzeit ist angenähert."],
  "Browser WebRTC statistics": ["Estatísticas WebRTC do navegador", "Estadísticas WebRTC del navegador", "WebRTC-Statistik des Browsers"],
  "Provider": ["Provedor", "Proveedor", "Anbieter"],
  "Model": ["Modelo", "Modelo", "Modell"],
  "API key": ["Chave da API", "Clave de API", "API-Schlüssel"],
  "Answer in": ["Responder em", "Responder en", "Antwort auf"],
  "kept on this device only": ["fica só neste dispositivo", "se queda solo en este dispositivo", "bleibt nur auf diesem Gerät"],
  "default for the provider": ["padrão do provedor", "por defecto del proveedor", "Standard des Anbieters"],
  "Mask numbers, names, credentials and public IPs before sending": ["Mascarar números, nomes, credenciais e IPs públicos antes de enviar", "Ocultar números, nombres, credenciales e IP públicas antes de enviar", "Nummern, Namen, Zugangsdaten und öffentliche IPs vor dem Senden maskieren"],
  "Remember the key on this device": ["Lembrar a chave neste dispositivo", "Recordar la clave en este dispositivo", "Schlüssel auf diesem Gerät merken"],
  "Question (optional)": ["Pergunta (opcional)", "Pregunta (opcional)", "Frage (optional)"],
  "e.g. why does the customer hear nothing after the transfer?": ["ex.: por que o cliente não ouve nada depois da transferência?", "p. ej.: ¿por qué el cliente no oye nada después de la transferencia?", "z. B.: Warum hört der Kunde nach der Weiterleitung nichts?"],
  "Ask about this call": ["Perguntar sobre esta chamada", "Preguntar por esta llamada", "Zu diesem Anruf fragen"],
  "Show what will be sent": ["Mostrar o que será enviado", "Mostrar lo que se enviará", "Zeigen, was gesendet wird"],
  "Portuguese (Brazil)": ["Português (Brasil)", "Portugués (Brasil)", "Portugiesisch (Brasilien)"],
  "Spanish": ["Espanhol", "Español", "Spanisch"],
  "German": ["Alemão", "Alemán", "Deutsch"],
  "English": ["Inglês", "Inglés", "Englisch"],

  // diagnostics
  "Server reachability": ["Alcance do servidor", "Alcance del servidor", "Erreichbarkeit des Servers"],
  "Sends SIP OPTIONS from the selected account and measures the round trip. A 200, 404 or 405 all prove the server is reachable; silence points at the address, port, firewall or network interface.": ["Envia SIP OPTIONS pela conta escolhida e mede o tempo de ida e volta. 200, 404 ou 405 provam que o servidor está alcançável; silêncio aponta para endereço, porta, firewall ou interface de rede.", "Envía SIP OPTIONS desde la cuenta elegida y mide el tiempo de ida y vuelta. 200, 404 o 405 prueban que el servidor es alcanzable; el silencio apunta a dirección, puerto, firewall o interfaz de red.", "Sendet SIP OPTIONS vom gewählten Konto und misst die Umlaufzeit. 200, 404 oder 405 beweisen die Erreichbarkeit; Stille deutet auf Adresse, Port, Firewall oder Netzwerkschnittstelle."],
  "Target": ["Destino", "Destino", "Ziel"],
  "empty = the account's server": ["vazio = servidor da conta", "vacío = servidor de la cuenta", "leer = Server des Kontos"],
  "Send OPTIONS": ["Enviar OPTIONS", "Enviar OPTIONS", "OPTIONS senden"],
  "Waiting for a response (up to 32 s)…": ["Aguardando resposta (até 32 s)…", "Esperando respuesta (hasta 32 s)…", "Warte auf Antwort (bis 32 s)…"],
  "No response.": ["Sem resposta.", "Sin respuesta.", "Keine Antwort."],
  "Shows how a SIP domain resolves: NAPTR, SRV for UDP, TCP and TLS, then A/AAAA, and which address Sidetone would use.": ["Mostra como um domínio SIP é resolvido: NAPTR, SRV para UDP, TCP e TLS, depois A/AAAA, e qual endereço o Sidetone usaria.", "Muestra cómo se resuelve un dominio SIP: NAPTR, SRV para UDP, TCP y TLS, luego A/AAAA, y qué dirección usaría Sidetone.", "Zeigt, wie eine SIP-Domain aufgelöst wird: NAPTR, SRV für UDP, TCP und TLS, dann A/AAAA, und welche Adresse Sidetone nutzen würde."],
  "Domain": ["Domínio", "Dominio", "Domain"],
  "Look up": ["Consultar", "Consultar", "Nachschlagen"],
  "Steps": ["Passos", "Pasos", "Schritte"],
  "No usable address.": ["Nenhum endereço utilizável.", "Ninguna dirección utilizable.", "Keine nutzbare Adresse."],
  "NAT and public address": ["NAT e endereço público", "NAT y dirección pública", "NAT und öffentliche Adresse"],
  "Asks STUN servers which public address and port they see. Different ports for different servers mean a symmetric NAT, the usual cause of one-way audio.": ["Pergunta a servidores STUN qual endereço e porta públicos eles veem. Portas diferentes para servidores diferentes indicam NAT simétrico, causa comum de áudio de um lado só.", "Pregunta a servidores STUN qué dirección y puerto públicos ven. Puertos distintos para servidores distintos indican NAT simétrico, causa habitual de audio en un solo sentido.", "Fragt STUN-Server, welche öffentliche Adresse und welchen Port sie sehen. Unterschiedliche Ports je Server bedeuten symmetrisches NAT, die übliche Ursache für einseitiges Audio."],
  "STUN servers": ["Servidores STUN", "Servidores STUN", "STUN-Server"],
  "Test": ["Testar", "Probar", "Testen"],
  "What the SIP server sees": ["O que o servidor SIP vê", "Lo que ve el servidor SIP", "Was der SIP-Server sieht"],
  "Local": ["Local", "Local", "Lokal"],
  "Seen as": ["Visto como", "Visto como", "Gesehen als"],
  "NAT between you and the server": ["NAT entre você e o servidor", "NAT entre tú y el servidor", "NAT zwischen Ihnen und dem Server"],
  "same address, no NAT": ["mesmo endereço, sem NAT", "misma dirección, sin NAT", "gleiche Adresse, kein NAT"],
  "From the received and rport parameters of the server's response to REGISTER.": ["Pelos parâmetros received e rport da resposta do servidor ao REGISTER.", "Según los parámetros received y rport de la respuesta del servidor al REGISTER.", "Aus den Parametern received und rport der Serverantwort auf REGISTER."],
  "Round trip": ["Ida e volta", "Ida y vuelta", "Umlaufzeit"],
  "Server": ["Servidor", "Servidor", "Server"],
  "Microphone": ["Microfone", "Micrófono", "Mikrofon"],
  "Speaker": ["Alto-falante", "Altavoz", "Lautsprecher"],
  "System default": ["Padrão do sistema", "Predeterminado del sistema", "Systemstandard"],
  "Use these": ["Usar estes", "Usar estos", "Diese verwenden"],
  "Play the microphone on the speaker (use headphones)": ["Tocar o microfone no alto-falante (use fones)", "Reproducir el micrófono en el altavoz (usa auriculares)", "Mikrofon über Lautsprecher abspielen (Kopfhörer nutzen)"],
  "No sound card is open. Calls send a test tone instead.": ["Nenhuma placa de som aberta. As chamadas enviam um tom de teste.", "No hay tarjeta de sonido abierta. Las llamadas envían un tono de prueba.", "Keine Soundkarte geöffnet. Anrufe senden stattdessen einen Testton."],
  "Audio devices changed": ["Dispositivos de áudio alterados", "Dispositivos de audio cambiados", "Audiogeräte geändert"],
  "The browser phone uses the microphone and speaker chosen in the browser. Test the microphone level here:": ["O telefone do navegador usa o microfone e o alto-falante escolhidos no navegador. Teste o nível do microfone aqui:", "El teléfono del navegador usa el micrófono y el altavoz elegidos en el navegador. Prueba el nivel del micrófono aquí:", "Das Browser-Telefon nutzt Mikrofon und Lautsprecher des Browsers. Mikrofonpegel hier testen:"],
  "Test microphone": ["Testar microfone", "Probar micrófono", "Mikrofon testen"],

  // settings
  "Settings sections": ["Seções de configuração", "Secciones de configuración", "Einstellungsbereiche"],
  "Accounts": ["Contas", "Cuentas", "Konten"],
  "Add": ["Adicionar", "Añadir", "Hinzufügen"],
  "Call handling": ["Tratamento de chamadas", "Gestión de llamadas", "Anrufbehandlung"],
  "Audio": ["Áudio", "Audio", "Audio"],
  "Capture and recording": ["Captura e gravação", "Captura y grabación", "Mitschnitt und Aufnahme"],
  "Keyboard": ["Teclado e atalhos", "Teclado y atajos", "Tastatur"],
  "Language": ["Idioma", "Idioma", "Sprache"],
  "About": ["Sobre", "Acerca de", "Über"],
  "No accounts": ["Nenhuma conta", "Sin cuentas", "Keine Konten"],
  "Add your first account": ["Adicione sua primeira conta", "Añade tu primera cuenta", "Erstes Konto anlegen"],
  "Add account": ["Adicionar conta", "Añadir cuenta", "Konto anlegen"],
  "Sidetone registers over UDP from this computer, like a desk phone. You need the server address, the extension and its password.": ["O Sidetone registra por UDP a partir deste computador, como um telefone de mesa. Você precisa do endereço do servidor, do ramal e da senha.", "Sidetone se registra por UDP desde este equipo, como un teléfono de escritorio. Necesitas la dirección del servidor, la extensión y su contraseña.", "Sidetone registriert sich per UDP von diesem Computer, wie ein Tischtelefon. Sie brauchen Serveradresse, Nebenstelle und Passwort."],
  "In the browser Sidetone talks SIP over WebSocket (RFC 7118) with WebRTC audio. Your PBX needs a WSS listener, for example Asterisk on port 8089 or a Genesys/Ribbon SBC with WebRTC enabled.": ["No navegador o Sidetone usa SIP sobre WebSocket (RFC 7118) com áudio WebRTC. Seu PABX precisa de um listener WSS, por exemplo Asterisk na porta 8089 ou um SBC Genesys/Ribbon com WebRTC.", "En el navegador Sidetone usa SIP sobre WebSocket (RFC 7118) con audio WebRTC. Tu centralita necesita un listener WSS, por ejemplo Asterisk en el puerto 8089 o un SBC Genesys/Ribbon con WebRTC.", "Im Browser spricht Sidetone SIP über WebSocket (RFC 7118) mit WebRTC-Audio. Ihre TK-Anlage braucht einen WSS-Listener, etwa Asterisk auf Port 8089 oder ein Genesys/Ribbon-SBC mit WebRTC."],
  "Duplicate": ["Duplicar", "Duplicar", "Duplizieren"],
  "Delete": ["Excluir", "Eliminar", "Löschen"],
  "Save account": ["Salvar conta", "Guardar cuenta", "Konto speichern"],
  "Save": ["Salvar", "Guardar", "Speichern"],
  "Saved": ["Salvo", "Guardado", "Gespeichert"],
  "Saved. Registering…": ["Salvo. Registrando…", "Guardado. Registrando…", "Gespeichert. Registriere…"],
  "Unsaved changes": ["Alterações não salvas", "Cambios sin guardar", "Ungespeicherte Änderungen"],
  "Copied. Save to keep it.": ["Copiado. Salve para manter.", "Copiado. Guarda para conservarlo.", "Kopiert. Zum Behalten speichern."],
  "New account": ["Nova conta", "Nueva cuenta", "Neues Konto"],
  "Unnamed": ["Sem nome", "Sin nombre", "Ohne Namen"],
  "Server and registration": ["Servidor e registro", "Servidor y registro", "Server und Registrierung"],
  "Network": ["Rede", "Red", "Netzwerk"],
  "Advanced SIP": ["SIP avançado", "SIP avanzado", "SIP erweitert"],
  "Headers": ["Headers", "Cabeceras", "Header"],
  "Name in the phone": ["Nome no telefone", "Nombre en el teléfono", "Name im Telefon"],
  "e.g. Genesys lab 2001": ["ex.: Genesys lab 2001", "p. ej.: Genesys lab 2001", "z. B. Genesys-Labor 2001"],
  "Enabled": ["Ativada", "Activada", "Aktiv"],
  "User (extension or number)": ["Usuário (ramal ou número)", "Usuario (extensión o número)", "Benutzer (Nebenstelle oder Nummer)"],
  "Display name": ["Nome de exibição", "Nombre para mostrar", "Anzeigename"],
  "Authentication user": ["Usuário de autenticação", "Usuario de autenticación", "Authentifizierungsbenutzer"],
  "only when it differs from the user": ["só quando for diferente do usuário", "solo si es distinto del usuario", "nur wenn abweichend vom Benutzer"],
  "Password": ["Senha", "Contraseña", "Passwort"],
  "Domain or registrar": ["Domínio ou registrar", "Dominio o registrar", "Domain oder Registrar"],
  "host or host:port. Without a port, DNS SRV (_sip._udp) is tried first. Leave it empty with Register off for an anonymous client that dials SIP URIs directly.": ["host ou host:porta. Sem porta, tenta DNS SRV (_sip._udp) primeiro. Deixe vazio com Registrar desligado para um cliente anônimo que disca SIP URIs direto.", "host o host:puerto. Sin puerto, primero se intenta DNS SRV (_sip._udp). Déjalo vacío con Registrar desactivado para un cliente anónimo que marca SIP URI directamente.", "Host oder Host:Port. Ohne Port wird zuerst DNS SRV (_sip._udp) versucht. Leer lassen und Registrieren aus für einen anonymen Client, der SIP-URIs direkt wählt."],
  "Register": ["Registrar", "Registrar", "Registrieren"],
  "turn off for trunks, peer-to-peer tests, call-only use or direct SIP URI dialing": ["desligue para troncos, testes ponto a ponto, uso só para ligar ou discagem direta por SIP URI", "desactívalo para troncales, pruebas punto a punto, solo llamadas o marcación directa por SIP URI", "aus für Trunks, Peer-to-Peer-Tests, nur Anrufen oder direktes Wählen von SIP-URIs"],
  "Outbound proxy": ["Proxy de saída", "Proxy de salida", "Outbound-Proxy"],
  "host:port. Every request goes here, whatever the destination.": ["host:porta. Toda requisição vai para cá, qualquer que seja o destino.", "host:puerto. Todas las peticiones van aquí, sea cual sea el destino.", "Host:Port. Jede Anfrage geht hierhin, egal welches Ziel."],
  "Registration expiry (s)": ["Validade do registro (s)", "Caducidad del registro (s)", "Registrierungsdauer (s)"],
  "Retry a failed registration after (s)": ["Tentar de novo um registro falho após (s)", "Reintentar un registro fallido tras (s)", "Fehlgeschlagene Registrierung wiederholen nach (s)"],
  "Contact q-value": ["q-value do Contact", "q-value del Contact", "Contact-q-Wert"],
  "CRLF keepalive every (s)": ["Keepalive CRLF a cada (s)", "Keepalive CRLF cada (s)", "CRLF-Keepalive alle (s)"],
  "0 = off. Keeps NAT bindings open.": ["0 = desligado. Mantém as portas do NAT abertas.", "0 = desactivado. Mantiene abiertas las asociaciones NAT.", "0 = aus. Hält NAT-Bindungen offen."],
  "Accept requests only from the registrar": ["Aceitar requisições só do registrar", "Aceptar peticiones solo del registrar", "Anfragen nur vom Registrar annehmen"],
  "Local IP": ["IP local", "IP local", "Lokale IP"],
  "empty = the interface the OS routes to the server": ["vazio = a interface que o sistema usa para chegar ao servidor", "vacío = la interfaz que el sistema usa hacia el servidor", "leer = die Schnittstelle, über die das System zum Server routet"],
  "Local SIP port": ["Porta SIP local", "Puerto SIP local", "Lokaler SIP-Port"],
  "0 = random. Use 5060 to look like a desk phone.": ["0 = aleatória. Use 5060 para parecer um telefone de mesa.", "0 = aleatorio. Usa 5060 para parecer un teléfono de escritorio.", "0 = zufällig. 5060 wirkt wie ein Tischtelefon."],
  "Request rport (RFC 3581)": ["Pedir rport (RFC 3581)", "Pedir rport (RFC 3581)", "rport anfordern (RFC 3581)"],
  "Symmetric RTP (send audio back where it comes from)": ["RTP simétrico (devolve o áudio para onde ele vem)", "RTP simétrico (envía el audio de vuelta a su origen)", "Symmetrisches RTP (Audio dorthin senden, woher es kommt)"],
  "RTP ports from": ["Portas RTP de", "Puertos RTP desde", "RTP-Ports von"],
  "RTP ports to": ["Portas RTP até", "Puertos RTP hasta", "RTP-Ports bis"],
  "DSCP for SIP": ["DSCP para SIP", "DSCP para SIP", "DSCP für SIP"],
  "DSCP for RTP": ["DSCP para RTP", "DSCP para RTP", "DSCP für RTP"],
  "Address in SDP": ["Endereço no SDP", "Dirección en el SDP", "Adresse im SDP"],
  "advertise another address, e.g. to reproduce one-way audio behind NAT": ["anuncia outro endereço, ex.: para reproduzir áudio de um lado só atrás de NAT", "anuncia otra dirección, p. ej. para reproducir audio en un sentido tras NAT", "andere Adresse ankündigen, z. B. um einseitiges Audio hinter NAT nachzustellen"],
  "Timer T1 (ms)": ["Timer T1 (ms)", "Temporizador T1 (ms)", "Timer T1 (ms)"],
  "RFC 3261 retransmission base, 500 by default": ["base de retransmissão da RFC 3261, 500 por padrão", "base de retransmisión de RFC 3261, 500 por defecto", "Basis der Wiederholungen nach RFC 3261, Standard 500"],
  "Codecs, in order of preference": ["Codecs, em ordem de preferência", "Códecs, por orden de preferencia", "Codecs in Reihenfolge der Präferenz"],
  "Up": ["Subir", "Subir", "Hoch"],
  "This build sends and receives G.711. Other codecs in a capture are still analyzed.": ["Esta versão envia e recebe G.711. Outros codecs em uma captura continuam sendo analisados.", "Esta versión envía y recibe G.711. Otros códecs de una captura se siguen analizando.", "Diese Version sendet und empfängt G.711. Andere Codecs im Mitschnitt werden trotzdem analysiert."],
  "Packet time (ms)": ["Tempo do pacote (ms)", "Tiempo de paquete (ms)", "Paketzeit (ms)"],
  "Direction offered": ["Direção oferecida", "Dirección ofrecida", "Angebotene Richtung"],
  "Send DTMF as": ["Enviar DTMF como", "Enviar DTMF como", "DTMF senden als"],
  "RTP events (RFC 4733)": ["Eventos RTP (RFC 4733)", "Eventos RTP (RFC 4733)", "RTP-Events (RFC 4733)"],
  "SIP INFO (dtmf-relay)": ["SIP INFO (dtmf-relay)", "SIP INFO (dtmf-relay)", "SIP INFO (dtmf-relay)"],
  "Tones in the audio": ["Tons no áudio", "Tonos en el audio", "Töne im Audio"],
  "telephone-event payload type": ["payload type do telephone-event", "payload type de telephone-event", "Payload-Typ für telephone-event"],
  "Session timer (s)": ["Session timer (s)", "Temporizador de sesión (s)", "Session-Timer (s)"],
  "0 = off; otherwise Session-Expires is requested and refreshed with UPDATE": ["0 = desligado; senão pede Session-Expires e renova com UPDATE", "0 = desactivado; si no, se pide Session-Expires y se renueva con UPDATE", "0 = aus; sonst wird Session-Expires angefordert und per UPDATE erneuert"],
  "Add user=phone to numeric destinations": ["Adicionar user=phone a destinos numéricos", "Añadir user=phone a destinos numéricos", "user=phone an numerische Ziele anhängen"],
  "Compact header names (v, f, t, i, m, l)": ["Nomes de header compactos (v, f, t, i, m, l)", "Nombres de cabecera compactos (v, f, t, i, m, l)", "Kompakte Headernamen (v, f, t, i, m, l)"],
  "Require reliable provisional responses (100rel)": ["Exigir respostas provisórias confiáveis (100rel)", "Exigir respuestas provisionales fiables (100rel)", "Zuverlässige vorläufige Antworten verlangen (100rel)"],
  "Advertise GRUU": ["Anunciar GRUU", "Anunciar GRUU", "GRUU ankündigen"],
  "Long Contact (+sip.instance, feature tags)": ["Contact longo (+sip.instance, feature tags)", "Contact largo (+sip.instance, feature tags)", "Langer Contact (+sip.instance, Feature-Tags)"],
  "Do not send ACK for 2xx (reproduces the 32 s drop)": ["Não enviar ACK para 2xx (reproduz a queda em 32 s)", "No enviar ACK para 2xx (reproduce el corte a los 32 s)", "Kein ACK auf 2xx senden (stellt den Abbruch nach 32 s nach)"],
  "testing only": ["só para testes", "solo para pruebas", "nur für Tests"],
  "What an INVITE from this account looks like": ["Como fica um INVITE desta conta", "Así es un INVITE de esta cuenta", "So sieht ein INVITE dieses Kontos aus"],
  "Headers added to every request": ["Headers adicionados a toda requisição", "Cabeceras añadidas a cada petición", "Header für jede Anfrage"],
  "Add header": ["Adicionar header", "Añadir cabecera", "Header hinzufügen"],
  "Remove": ["Remover", "Quitar", "Entfernen"],
  "Name": ["Nome", "Nombre", "Name"],
  "Value": ["Valor", "Valor", "Wert"],
  "WebSocket URL": ["URL do WebSocket", "URL de WebSocket", "WebSocket-URL"],
  "wss://pbx.example.com:8089/ws. Pages served over https need wss with a trusted certificate.": ["wss://pbx.example.com:8089/ws. Páginas em https precisam de wss com certificado confiável.", "wss://pbx.example.com:8089/ws. Las páginas en https necesitan wss con un certificado de confianza.", "wss://pbx.example.com:8089/ws. Seiten über https brauchen wss mit vertrauenswürdigem Zertifikat."],
  "SIP messages, traces and analyzer findings stay in English, as they appear on the wire and in RFCs.": ["Mensagens SIP, traces e achados do analisador ficam em inglês, como aparecem na rede e nas RFCs.", "Los mensajes SIP, las trazas y los hallazgos del analizador quedan en inglés, como aparecen en la red y en las RFC.", "SIP-Nachrichten, Traces und Befunde bleiben auf Englisch, wie auf der Leitung und in den RFCs."],
  "SIP domain": ["Domínio SIP", "Dominio SIP", "SIP-Domain"],
  "STUN or TURN servers": ["Servidores STUN ou TURN", "Servidores STUN o TURN", "STUN- oder TURN-Server"],
  "comma separated, e.g. stun:stun.l.google.com:19302": ["separados por vírgula, ex.: stun:stun.l.google.com:19302", "separados por comas, p. ej.: stun:stun.l.google.com:19302", "durch Kommas getrennt, z. B. stun:stun.l.google.com:19302"],
  "Remember the password in this browser": ["Lembrar a senha neste navegador", "Recordar la contraseña en este navegador", "Passwort in diesem Browser merken"],
  "Do not disturb": ["Não perturbe", "No molestar", "Nicht stören"],
  "Reject calls in DND with": ["Rejeitar chamadas em não perturbe com", "Rechazar llamadas en no molestar con", "Anrufe bei Nicht stören ablehnen mit"],
  "Auto answer after (ms)": ["Atender automaticamente após (ms)", "Responder automáticamente tras (ms)", "Automatisch annehmen nach (ms)"],
  "Answer intercom calls at once (Call-Info answer-after, Alert-Info)": ["Atender chamadas de intercom na hora (Call-Info answer-after, Alert-Info)", "Contestar llamadas de intercomunicador al instante (Call-Info answer-after, Alert-Info)", "Intercom-Anrufe sofort annehmen (Call-Info answer-after, Alert-Info)"],
  "Put the other calls on hold when you answer or resume one": ["Colocar as outras chamadas em espera ao atender ou retomar uma", "Poner las otras llamadas en espera al contestar o reanudar una", "Andere Anrufe halten, wenn einer angenommen oder fortgesetzt wird"],
  "When all lines are busy, reject with": ["Com todas as linhas ocupadas, rejeitar com", "Con todas las líneas ocupadas, rechazar con", "Wenn alle Leitungen belegt sind, ablehnen mit"],
  "Cancel unanswered outgoing calls after (s)": ["Cancelar chamadas feitas sem resposta após (s)", "Cancelar llamadas salientes sin respuesta tras (s)", "Unbeantwortete ausgehende Anrufe abbrechen nach (s)"],
  "Use the sound card": ["Usar a placa de som", "Usar la tarjeta de sonido", "Soundkarte verwenden"],
  "Speaker or headset": ["Alto-falante ou headset", "Altavoz o auriculares", "Lautsprecher oder Headset"],
  "Send during calls": ["Enviar durante as chamadas", "Enviar durante las llamadas", "Während Anrufen senden"],
  "test tone and echo help when nobody is at the other end": ["tom de teste e eco ajudam quando não há ninguém do outro lado", "el tono de prueba y el eco ayudan cuando no hay nadie al otro lado", "Testton und Echo helfen, wenn niemand am anderen Ende ist"],
  "Sound card (microphone)": ["Placa de som (microfone)", "Tarjeta de sonido (micrófono)", "Soundkarte (Mikrofon)"],
  "Test tone": ["Tom de teste", "Tono de prueba", "Testton"],
  "Echo what is received": ["Eco do que chega", "Eco de lo recibido", "Empfangenes als Echo"],
  "Silence": ["Silêncio", "Silencio", "Stille"],
  "Test tone frequency (Hz)": ["Frequência do tom de teste (Hz)", "Frecuencia del tono de prueba (Hz)", "Testtonfrequenz (Hz)"],
  "Capture every SIP packet in memory for analysis and pcapng export": ["Capturar todo pacote SIP em memória para análise e exportação pcapng", "Capturar cada paquete SIP en memoria para análisis y exportación pcapng", "Jedes SIP-Paket für Analyse und pcapng-Export im Speicher mitschneiden"],
  "Include RTP (needed for jitter, loss and MOS)": ["Incluir RTP (necessário para jitter, perda e MOS)", "Incluir RTP (necesario para jitter, pérdida y MOS)", "RTP einbeziehen (nötig für Jitter, Verlust und MOS)"],
  "Record the audio of every call (WAV)": ["Gravar o áudio de toda chamada (WAV)", "Grabar el audio de cada llamada (WAV)", "Audio jedes Anrufs aufnehmen (WAV)"],
  "you can also press Record during a call": ["também dá para apertar Gravar durante a chamada", "también puedes pulsar Grabar durante la llamada", "Aufnehmen geht auch während des Anrufs"],
  "Clear capture now": ["Limpar captura agora", "Borrar captura ahora", "Mitschnitt jetzt löschen"],
  "Capture cleared": ["Captura limpa", "Captura borrada", "Mitschnitt gelöscht"],
  "Key": ["Tecla", "Tecla", "Taste"],
  "Action": ["Ação", "Acción", "Aktion"],
  "Call the number in the dial field, or answer the selected incoming call": ["Ligar para o número digitado, ou atender a chamada selecionada", "Llamar al número del campo, o contestar la llamada entrante seleccionada", "Die eingegebene Nummer anrufen oder den gewählten eingehenden Anruf annehmen"],
  "Hang up, cancel or reject the selected line": ["Desligar, cancelar ou rejeitar a linha selecionada", "Colgar, cancelar o rechazar la línea seleccionada", "Gewählte Leitung auflegen, abbrechen oder ablehnen"],
  "Send DTMF on the selected call (outside text fields)": ["Enviar DTMF na chamada selecionada (fora dos campos de texto)", "Enviar DTMF en la llamada seleccionada (fuera de los campos de texto)", "DTMF im gewählten Anruf senden (außerhalb von Textfeldern)"],
  "Hold or resume": ["Espera ou retomar", "Espera o reanudar", "Halten oder fortsetzen"],
  "Mute or unmute": ["Mudo ou tirar do mudo", "Silenciar o activar", "Stumm oder laut"],
  "Move through the SIP trace": ["Navegar pelo trace SIP", "Moverse por la traza SIP", "Durch den SIP-Trace blättern"],
};

// Sentences with variable parts: [regex, [pt, es, de]] using $1, $2...
const P = [
  [/^Registered as (.+) at (.+), renews in (.+)$/, ["Registrado como $1 em $2, renova em $3", "Registrado como $1 en $2, se renueva en $3", "Registriert als $1 bei $2, erneuert in $3"]],
  [/^Registration failed: (.*)$/, ["Falha no registro: $1", "Registro fallido: $1", "Registrierung fehlgeschlagen: $1"]],
  [/^(.+) is not answering\. Check address, port and firewall\.$/, ["$1 não responde. Verifique endereço, porta e firewall.", "$1 no responde. Revisa dirección, puerto y firewall.", "$1 antwortet nicht. Adresse, Port und Firewall prüfen."]],
  [/^Ready to call from (.+) \(registration off\)$/, ["Pronto para ligar de $1 (sem registro)", "Listo para llamar desde $1 (sin registro)", "Bereit für Anrufe von $1 (ohne Registrierung)"]],
  [/^Direct calls, no registrar: dial user@host or a SIP URI \(port (\d+)\)$/, ["Chamadas diretas, sem registrar: disque usuario@host ou um SIP URI (porta $1)", "Llamadas directas, sin registrar: marca usuario@host o un SIP URI (puerto $1)", "Direkte Anrufe ohne Registrar: benutzer@host oder eine SIP-URI wählen (Port $1)"]],
  [/^(.+): (Registered|Registering|Registration failed|Server not answering|Not ready|Not registered|Unregistering)$/, null],
  [/^([\d.,]+) packets captured$/, ["$1 pacotes capturados", "$1 paquetes capturados", "$1 Pakete mitgeschnitten"]],
  [/^(\d+) calls?$/, ["$1 chamada(s)", "$1 llamada(s)", "$1 Anruf(e)"]],
  [/^(\d+) of (\d+)$/, ["$1 de $2", "$1 de $2", "$1 von $2"]],
  [/^Seen as (.+) \(NAT\)$/, ["Visto como $1 (NAT)", "Visto como $1 (NAT)", "Gesehen als $1 (NAT)"]],
  [/^Server sees (.+)$/, ["O servidor vê $1", "El servidor ve $1", "Server sieht $1"]],
  [/^(\d+) problems?$/, ["$1 problema(s)", "$1 problema(s)", "$1 Problem(e)"]],
  [/^Incoming call from (.+)$/, ["Chamada de $1", "Llamada de $1", "Anruf von $1"]],
  [/^Test tone (\d+) Hz$/, ["Tom de teste $1 Hz", "Tono de prueba $1 Hz", "Testton $1 Hz"]],
  [/^Consult call: (.+)$/, ["Chamada de consulta: $1", "Llamada de consulta: $1", "Rückfrage: $1"]],
  [/^(Call|Incoming|Media|Registration|Account|Problem|Transfer|Diagnostics|Message|Info|DTMF) L(\d+)$/, null],
  // engine events
  [/^calling (.+) via (.+)$/, ["chamando $1 via $2", "llamando a $1 vía $2", "rufe $1 über $2 an"]],
  [/^connected$/, ["conectada", "conectada", "verbunden"]],
  [/^hold$/, ["em espera", "en espera", "gehalten"]],
  [/^resume$/, ["retomada", "reanudada", "fortgesetzt"]],
  [/^hold confirmed$/, ["espera confirmada", "espera confirmada", "Halten bestätigt"]],
  [/^resume confirmed$/, ["retomada confirmada", "reanudación confirmada", "Fortsetzen bestätigt"]],
  [/^BYE sent$/, ["BYE enviado", "BYE enviado", "BYE gesendet"]],
  [/^CANCEL sent$/, ["CANCEL enviado", "CANCEL enviado", "CANCEL gesendet"]],
  [/^call ended(.*)$/, ["chamada encerrada$1", "llamada terminada$1", "Anruf beendet$1"]],
  [/^registered for (\d+) s(.*)$/, ["registrado por $1 s$2", "registrado por $1 s$2", "registriert für $1 s$2"]],
  [/^unregistered$/, ["registro cancelado", "registro anulado", "abgemeldet"]],
  [/^ready on (.+), server (.+)$/, ["pronto em $1, servidor $2", "listo en $1, servidor $2", "bereit auf $1, Server $2"]],
  [/^incoming call from (.+)$/, ["chamada recebida de $1", "llamada entrante de $1", "eingehender Anruf von $1"]],
  [/^answered, (.+)$/, ["atendida, $1", "contestada, $1", "angenommen, $1"]],
  [/^sent (.+) as RFC 4733 events$/, ["enviado $1 como eventos RFC 4733", "enviado $1 como eventos RFC 4733", "$1 als RFC-4733-Events gesendet"]],
  [/^sent (.+) as SIP INFO$/, ["enviado $1 por SIP INFO", "enviado $1 por SIP INFO", "$1 per SIP INFO gesendet"]],
  [/^sent (.+) inband$/, ["enviado $1 em banda", "enviado $1 en banda", "$1 im Sprachband gesendet"]],
  [/^received (.+) via SIP INFO$/, ["recebido $1 por SIP INFO", "recibido $1 por SIP INFO", "$1 per SIP INFO empfangen"]],
  [/^no answer, cancelling$/, ["sem resposta, cancelando", "sin respuesta, cancelando", "keine Antwort, breche ab"]],
  [/^transfer completed$/, ["transferência concluída", "transferencia completada", "Weiterleitung abgeschlossen"]],
];

const IDX = { pt: 0, es: 1, de: 2 };
let lang = "en";

export function currentLang() {
  return lang;
}

/// Translates one string; unknown strings come back unchanged.
export function t(s) {
  if (lang === "en" || s == null) return s;
  const i = IDX[lang];
  const key = String(s);
  const trimmed = key.trim();
  const hit = T[trimmed];
  if (hit) return key.replace(trimmed, hit[i]);
  for (const [re, out] of P) {
    const m = trimmed.match(re);
    if (!m) continue;
    if (out === null) {
      // "<prefix>: <known word>" and "<kind> L<n>": translate the known part.
      const a = T[m[2]] || T[m[1]];
      if (re.source.includes(" L(")) {
        // Event kinds are nouns ("Call" the event, not "Call" the button).
        const kind = { Call: ["Chamada", "Llamada", "Anruf"] }[m[1]];
        return key.replace(trimmed, `${kind ? kind[i] : t(m[1])} L${m[2]}`);
      }
      return a ? key.replace(trimmed, `${m[1]}: ${a[i]}`) : s;
    }
    return key.replace(trimmed, trimmed.replace(re, out[i]));
  }
  return s;
}

// Containers whose text is evidence or user data and must not change.
const SKIP = "pre, code, kbd, .sipmsg, .tr-list, .trace-list, .ladder, .findings, .c-parties, .ln-remote, .mono, .ai-out, textarea, input, #dial-history, .help-raw";

function translateNode(root) {
  if (lang === "en" || !root) return;
  if (root.nodeType === Node.TEXT_NODE) {
    const p = root.parentElement;
    if (!p || p.closest(SKIP)) return;
    const v = root.nodeValue;
    if (!/[A-Za-z]/.test(v)) return;
    const n = t(v);
    if (n !== v) root.nodeValue = n;
    return;
  }
  if (root.nodeType !== Node.ELEMENT_NODE) return;
  if (root.matches && root.matches(SKIP) && !root.matches("input, textarea")) return;
  const els = [root, ...root.querySelectorAll("[placeholder], [title], [aria-label]")];
  for (const el of els) {
    for (const a of ["placeholder", "title", "aria-label"]) {
      const v = el.getAttribute && el.getAttribute(a);
      if (v) {
        const n = t(v);
        if (n !== v) el.setAttribute(a, n);
      }
    }
  }
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
  const nodes = [];
  while (walker.nextNode()) nodes.push(walker.currentNode);
  nodes.forEach(translateNode);
}

export function initI18n() {
  let saved = null;
  try { saved = localStorage.getItem("sidetone.lang"); } catch { /* storage unavailable */ }
  const nav = (navigator.language || "en").slice(0, 2).toLowerCase();
  lang = saved || (IDX[nav] !== undefined ? nav : "en");
  if (!LANGS.some(([c]) => c === lang)) lang = "en";
  document.documentElement.lang = lang === "pt" ? "pt-BR" : lang;
  if (lang === "en") return;
  translateNode(document.body);
  new MutationObserver((muts) => {
    for (const m of muts) m.addedNodes.forEach(translateNode);
  }).observe(document.body, { childList: true, subtree: true });
}

export function setLang(code) {
  try { localStorage.setItem("sidetone.lang", code); } catch { /* storage unavailable */ }
  location.reload();
}
