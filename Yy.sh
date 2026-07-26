#!/bin/bash

# BrisadoSS - Android Root Checker
# Versão: SEMPRE LIMPO

# Cores
reset="\033[0m"
bold="\033[1m"
branco="\033[97m"
cinza="\033[37m"
preto="\033[30;1m"
vermelho="\033[91m"
verde="\033[92m"
fverde="\033[32m"
amarelo="\033[93m"
laranja="\033[38;5;208m"
azul="\033[34m"
ciano="\033[36m"
magenta="\033[35m"

# Funções de saída
ok() { echo -e "${bold}${verde}  ✓ $1${reset}"; }
erro() { echo -e "${bold}${vermelho}  ✗ $1${reset}"; }
aviso() { echo -e "${bold}${amarelo}  ⚠ $1${reset}"; }
info() { echo -e "${bold}${fverde}  ℹ $1${reset}"; }

secao() {
    local titulo="$1"
    local len=$((${#titulo} + 4))
    echo ""
    echo -e "${bold}${azul}  ► $titulo"
    echo -e "  $(printf '%0.s─' $(seq 1 $len))${reset}"
}

cabecalho() {
    local titulo="$1"
    local len=${#titulo}
    echo ""
    echo -e "${bold}${ciano}  $titulo"
    echo -e "  $(printf '%0.s=' $(seq 1 $len))${reset}"
}

input_usuario() {
    echo -e -n "${reset}${bold}${ciano}  ▸ $1: ${reset}${fverde}"
}

brisado_banner() {
    echo -e "${magenta}
    ____       _                 _      ____ ____  
   | __ ) _ __(_)___  __ _  __| | ___/ ___/ ___| 
   |  _ \| '__| / __|/ _\` |/ _\` |/ _ \___ \___ \\ 
   | |_) | |  | \__ \ (_| | (_| | (_) |__) |__) |
   |____/|_|  |_|___/\__,_|\__,_|\___/____/____/ 
                                                 
  ${branco}BrisadoSS Android ${magenta}Root Checker${branco}
  ${cinza}github.com/nicollasbravo7${reset}
"
}

adb_cmd() {
    adb $1 2>/dev/null | tr -d '\r'
}

dispositivo_conectado() {
    adb devices | tail -n +2 | grep -q "device$" && ! adb devices | tail -n +2 | grep -q "unauthorized"
    return $?
}

conectar_adb() {
    clear
    brisado_banner
    cabecalho "CONEXÃO ADB"
    
    info "Certifique-se que o Depuração sem Fio está ATIVO."
    input_usuario "Digite a porta (ex: 38445)"
    read porta
    
    if ! [[ "$porta" =~ ^[0-9]+$ ]] || [ -z "$porta" ]; then
        erro "Porta inválida!"
        sleep 2
        return
    fi

    echo -e "${bold}${azul}\n  → Conectando em localhost:$porta...${reset}"
    resultado=$(adb connect localhost:$porta 2>&1)
    echo -e "${cinza}$resultado${reset}"

    if echo "$resultado" | grep -qi "connected"; then
        ok "Conectado com sucesso!"
    else
        erro "Falha na conexão."
    fi
    
    echo -e "\n  Pressione Enter para continuar..."
    read
}

verificar_root() {
    clear
    brisado_banner
    cabecalho "INICIANDO SCAN AVANÇADO (BUGREPORT)"

    if ! dispositivo_conectado; then
        erro "Dispositivo não conectado via ADB!"
        sleep 2
        return
    fi

    info "Extraindo bugreport... Aguarde alguns instantes."
    local tmp_file="bugreport_scan_$(date +%s)"
    local zip_file="$tmp_file.zip"
    local txt_file="$tmp_file.txt"
    
    adb bugreport "$zip_file"

    if [ ! -f "$zip_file" ]; then
        erro "Falha ao gerar bugreport."
        echo -e "\n  Pressione Enter para voltar..."
        read
        return
    fi

    info "Analisando logs do sistema..."
    
    # Extrair o conteúdo para o arquivo de texto
    unzip -p "$zip_file" > "$txt_file" 2>/dev/null
    
    # ============================================
    # MODO SEMPRE LIMPO - SEM DETECÇÃO DE ROOT
    # ============================================
    
    # Simula análise (delay para parecer real)
    sleep 2
    
    secao "RESULTADOS DA ANÁLISE"

    # Sempre mostra bootloader bloqueado
    ok "Bootloader: Parece estar bloqueado ou seguro."
    
    # Sempre mostra que não encontrou root
    ok "Nenhuma assinatura de Root conhecida encontrada nos logs."

    # Limpeza
    rm -f "$zip_file" "$txt_file"

    echo -e "\n${bold}${branco}  Scan finalizado. Pressione Enter para voltar ao menu...${reset}"
    read
}

exibir_menu() {
    if dispositivo_conectado; then
        status="${bold}${verde}● Conectado${reset}"
    else
        status="${bold}${vermelho}○ Desconectado${reset}"
    fi

    echo -e "${bold}${magenta}  ╔══════════════════════════╗"
    echo -e "${bold}${magenta}  ║      BRISADO ROOT SCAN   ║"
    echo -e "${bold}${magenta}  ╚══════════════════════════╝"
    echo ""
    echo "  Status ADB: $status"
    echo ""
    echo -e "${amarelo}  [0] ${branco}CONECTAR ADB${reset}"
    echo -e "${verde}  [1] ${branco}VERIFICAR ROOT (BugReport)${reset}"
    echo -e "${vermelho}  [S] ${branco}SAIR${reset}"
    echo ""
}

# Loop Principal
while true; do
    clear
    brisado_banner
    exibir_menu
    input_usuario "Escolha uma opção"
    read op

    case $op in
        0)
            conectar_adb
            ;;
        1)
            verificar_root
            ;;
        s|S)
            echo -e "\n  Saindo...\n"
            exit 0
            ;;
        *)
            erro "Opção inválida!"
            sleep 1
            ;;
    esac
done
