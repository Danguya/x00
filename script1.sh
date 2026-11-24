#!/bin/bash
# Objetivo: Auditoria DFIR focada em macOS com filtros de ruído.
# Uso: sudo ./mac_audit_full.sh
# Requer: Permissões de root para aceder a logs do sistema e diretórios protegidos.

OUTPUT_DIR="mac_audit_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"

echo "[*] A iniciar auditoria em $OUTPUT_DIR"

# ---------------------------------------------------------
# 1. EXECUÇÃO E PROCESSOS (Foco no que está a correr agora)
# ---------------------------------------------------------
echo "[*] A recolher processos e conexões ativas..."

# Processos: lista completa, mas com foco em binários fora de /System e /Applications
ps -axwwo pid,ppid,user,etime,command > "$OUTPUT_DIR/processes_all.txt"
# Filtrar processos de locais não-standard (potencialmente suspeitos)
ps -axwwo pid,command | awk '$2 !~ /^\/(System|Applications|usr\/libexec|usr\/sbin)/ {print}' > "$OUTPUT_DIR/processes_suspicious_paths.txt"

# Rede: conexões ativas (lsof)
lsof -nP -i > "$OUTPUT_DIR/network_connections.txt"

# ---------------------------------------------------------
# 2. LOGS UNIFICADOS (O segredo para pouco ruído)
# ---------------------------------------------------------
echo "[*] A extrair logs unificados (com predicados para reduzir ruído)..."

# 2.1 Logs de autenticação e privilégios (sudo, authorization)
# Predicado: apenas processos relacionados com autenticação ou o próprio sudo
log show --last 2h --style compact --predicate 'process == "sudo" OR process == "authd" OR subsystem == "com.apple.authorization"' > "$OUTPUT_DIR/logs_auth.txt" 2>/dev/null

# 2.2 Logs de rede e DNS (Foco em resolução e conexões)
# Predicado: processos de rede relevantes ou subsistemas de DNS
log show --last 2h --style compact --predicate 'process == "mDNSResponder" OR process == "networkd" OR subsystem == "com.apple.network"' > "$OUTPUT_DIR/logs_network.txt" 2>/dev/null

# 2.3 Logs de execução de processos (Foco em lançamentos recentes)
# Predicado: eventos de ciclo de vida de processos (launch/exit) e mensagens de erro
log show --last 2h --style compact --predicate 'eventMessage CONTAINS[c] "launch" OR eventMessage CONTAINS[c] "exec" OR messageType == "error"' > "$OUTPUT_DIR/logs_process_events.txt" 2>/dev/null

# 2.4 Logs de segurança (XProtect, Gatekeeper, TCC)
# Predicado: subsistemas de segurança da Apple
log show --last 24h --style compact --predicate 'subsystem == "com.apple.XProtect" OR subsystem == "com.apple.securityd" OR subsystem == "com.apple.TCC"' > "$OUTPUT_DIR/logs_security.txt" 2>/dev/null

# ---------------------------------------------------------
# 3. INTEGRIDADE DO SISTEMA (Anti-forense e Persistência)
# ---------------------------------------------------------
echo "[*] A verificar integridade e persistência..."

# 3.1 Estado das proteções do sistema
csrutil status > "$OUTPUT_DIR/status_sip.txt" 2>&1
spctl --status > "$OUTPUT_DIR/status_gatekeeper.txt" 2>&1
fdesetup status > "$OUTPUT_DIR/status_filevault.txt" 2>&1

# 3.2 Persistência (LaunchAgents/Daemons com verificação de assinatura)
# Reutilizar a lógica de verificação de codesign para os plists encontrados
find /Library/LaunchDaemons /Library/LaunchAgents ~/Library/LaunchAgents -name "*.plist" 2>/dev/null | while read -r plist; do
    prog=$(defaults read "$plist" Program 2>/dev/null || defaults read "$plist" ProgramArguments 2>/dev/null | grep -oE '"/[^"]+"' | head -1 | tr -d '"')
    if [ -n "$prog" ] && [ -f "$prog" ]; then
        sig=$(codesign -dv --verbose=4 "$prog" 2>&1 | grep -E "Authority|TeamIdentifier" | tr '\n' ' ')
        echo "[$plist] -> $prog | $sig" >> "$OUTPUT_DIR/persistence_signed.txt"
    fi
done

# 3.3 Extensões de kernel carregadas (Kexts)
kextstat > "$OUTPUT_DIR/kexts_loaded.txt" 2>/dev/null

# ---------------------------------------------------------
# 4. ARTEFACTOS DO UTILIZADOR (Execução e Intenção)
# ---------------------------------------------------------
echo "[*] A recolher artefactos do utilizador..."

# 4.1 Histórico de Shell (Zsh e Bash)
cp ~/.zsh_history "$OUTPUT_DIR/shell_history_zsh.txt" 2>/dev/null
cp ~/.bash_history "$OUTPUT_DIR/shell_history_bash.txt" 2>/dev/null

# 4.2 Quarentena (Downloads recentes que podem ser maliciosos)
sqlite3 ~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2 "SELECT datetime(LSQuarantineTimeStamp + 978307200, 'unixepoch'), LSQuarantineAgentName, LSQuarantineDataURLString FROM LSQuarantineEvent ORDER BY LSQuarantineTimeStamp DESC LIMIT 50;" > "$OUTPUT_DIR/quarantine_events.txt" 2>/dev/null

# 4.3 Itens de Login (Login Items)
osascript -e 'tell application "System Events" to get the path of every login item' > "$OUTPUT_DIR/login_items.txt" 2>/dev/null

# ---------------------------------------------------------
# 5. RESUMO FINAL
# ---------------------------------------------------------
echo ""
echo "[+] Auditoria concluída. Resultados em: $OUTPUT_DIR"
echo "[+] Ficheiros gerados:"
ls -la "$OUTPUT_DIR"
echo ""
echo "[!] PRIORIDADE DE ANÁLISE:"
echo "    1. processes_suspicious_paths.txt (binários fora do normal)"
echo "    2. logs_auth.txt (tentativas de escalação)"
echo "    3. persistence_signed.txt (itens sem assinatura válida)"
echo "    4. quarantine_events.txt (downloads recentes)"
