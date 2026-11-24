#!/bin/bash
# Objetivo: Auditar mecanismos de persistência no macOS e verificar assinaturas.
# Uso: chmod +x mac_persistence_audit.sh && sudo ./mac_persistence_audit.sh
# Requer: Permissões de root para ler todos os diretórios (LaunchDaemons, etc.)

OUTPUT_DIR="audit_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"
REPORT="$OUTPUT_DIR/persistence_report.csv"

echo "Item,Type,BinaryPath,Exists,CodesignStatus,TeamID,Quarantine" > "$REPORT"

# Função para verificar um binário e adicionar ao relatório
check_binary() {
    local binary_path="$1"
    local item_name="$2"
    local item_type="$3"
    
    if [ -z "$binary_path" ]; then
        return
    fi
    
    # Expandir variáveis de ambiente e ~
    binary_path=$(eval echo "$binary_path")
    
    local exists="No"
    local codesign_status="N/A"
    local team_id="N/A"
    local quarantine="N/A"
    
    if [ -f "$binary_path" ]; then
        exists="Yes"
        
        # Verificar assinatura de código
        local cs_output=$(codesign -dv --verbose=4 "$binary_path" 2>&1)
        if echo "$cs_output" | grep -q "Authority="; then
            codesign_status="Signed"
            team_id=$(echo "$cs_output" | grep "TeamIdentifier=" | cut -d'=' -f2)
            if [ -z "$team_id" ]; then team_id="N/A"; fi
        else
            codesign_status="Unsigned/Invalid"
        fi
        
        # Verificar atributo de quarentena
        if xattr -l "$binary_path" 2>/dev/null | grep -q "com.apple.quarantine"; then
            quarantine="Yes"
        else
            quarantine="No"
        fi
    fi
    
    # Escapar vírgulas para CSV
    echo "\"$item_name\",\"$item_type\",\"$binary_path\",\"$exists\",\"$codesign_status\",\"$team_id\",\"$quarantine\"" >> "$REPORT"
}

echo "[*] A analisar LaunchAgents e LaunchDaemons..."

# LaunchAgents (Utilizador e Sistema)
for dir in ~/Library/LaunchAgents /Library/LaunchAgents; do
    if [ -d "$dir" ]; then
        for plist in "$dir"/*.plist; do
            [ -f "$plist" ] || continue
            # Extrair caminho do programa (Program ou ProgramArguments[0])
            prog_path=$(defaults read "$plist" Program 2>/dev/null)
            if [ -z "$prog_path" ]; then
                prog_path=$(defaults read "$plist" ProgramArguments 2>/dev/null | grep -oE '"/[^"]+"' | head -1 | tr -d '"')
            fi
            check_binary "$prog_path" "$(basename "$plist")" "LaunchAgent"
        done
    fi
done

# LaunchDaemons
if [ -d "/Library/LaunchDaemons" ]; then
    for plist in /Library/LaunchDaemons/*.plist; do
        [ -f "$plist" ] || continue
        prog_path=$(defaults read "$plist" Program 2>/dev/null)
        if [ -z "$prog_path" ]; then
            prog_path=$(defaults read "$plist" ProgramArguments 2>/dev/null | grep -oE '"/[^"]+"' | head -1 | tr -d '"')
        fi
        check_binary "$prog_path" "$(basename "$plist")" "LaunchDaemon"
    done
fi

echo "[*] A analisar Cron Jobs..."

# Cron do utilizador e sistema
for cron_file in /usr/lib/cron/tabs/* /etc/crontab /etc/cron.d/*; do
    [ -f "$cron_file" ] || continue
    grep -vE '^\s*#|^\s*$' "$cron_file" 2>/dev/null | while read -r line; do
        # Extrair o comando (últimos campos após o agendamento)
        cmd=$(echo "$line" | awk '{$1=$2=$3=$4=$5=""; print $0}' | sed 's/^ *//')
        # Extrair o binário (primeira palavra do comando)
        bin=$(echo "$cmd" | awk '{print $1}')
        if [ -n "$bin" ] && [[ "$bin" != *"="* ]]; then
            check_binary "$bin" "$(basename "$cron_file")" "Cron"
        fi
    done
done

echo "[*] A analisar Login Items..."

# Login Items via System Events (osascript)
osascript -e 'tell application "System Events" to get the path of every login item' 2>/dev/null | tr ',' '\n' | while read -r item_path; do
    item_path=$(echo "$item_path" | sed 's/^ *//;s/ *$//')
    if [ -n "$item_path" ] && [ "$item_path" != "missing value" ]; then
        check_binary "$item_path" "$(basename "$item_path")" "LoginItem"
    fi
done

echo "[*] A analisar Shell RC files..."

for rc_file in ~/.bashrc ~/.bash_profile ~/.zshrc ~/.zprofile ~/.profile; do
    if [ -f "$rc_file" ]; then
        # Procurar por comandos que executam binários externos
        grep -vE '^\s*#|^\s*$' "$rc_file" 2>/dev/null | grep -E '(curl|wget|base64|python|sh|bash)\s' | while read -r line; do
            echo "\"$(basename "$rc_file")\",\"ShellRC\",\"$line\",\"N/A\",\"SuspiciousCommand\",\"N/A\",\"N/A\"" >> "$REPORT"
        done
    fi
done

echo "[*] A analisar Emond (Event Monitor)..."

if [ -d "/etc/emond.d/rules" ]; then
    for rule in /etc/emond.d/rules/*.plist; do
        [ -f "$rule" ] || continue
        # Emond rules podem conter comandos arbitrários
        if grep -q "Command" "$rule" 2>/dev/null; then
            echo "\"$(basename "$rule")\",\"EmondRule\",\"Verificar manualmente\",\"N/A\",\"RequiresManualReview\",\"N/A\",\"N/A\"" >> "$REPORT"
        fi
    done
fi

echo ""
echo "[+] Auditoria concluída. Relatório guardado em: $REPORT"
echo "[+] Total de itens analisados: $(tail -n +2 "$REPORT" | wc -l | tr -d ' ')"
echo ""
echo "[!] RECOMENDAÇÃO: Itens com CodesignStatus 'Unsigned/Invalid' ou Quarantine 'Yes' requerem investigação prioritária."
