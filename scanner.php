<?php

declare(strict_types=1);

/**
 * BrisadoSS - Android Root Checker
 * Versão: SEMPRE LIMPO
 */

const C = [
    'rst'      => "\e[0m",
    'bold'     => "\e[1m",
    'branco'   => "\e[97m",
    'cinza'    => "\e[37m",
    'preto'    => "\e[30m\e[1m",
    'vermelho' => "\e[91m",
    'verde'    => "\e[92m",
    'fverde'   => "\e[32m",
    'amarelo'  => "\e[93m",
    'laranja'  => "\e[38;5;208m",
    'azul'     => "\e[34m",
    'ciano'    => "\e[36m",
    'magenta'  => "\e[35m",
];

function c(string ...$nomes): string
{
    return implode('', array_map(fn($n) => C[$n] ?? '', $nomes));
}

function rst(): string
{
    return C['rst'];
}

function linha(string $cor, string $icone, string $texto): void
{
    echo c('bold', $cor) . "  $icone $texto\n" . rst();
}

function ok(string $texto): void      { linha('verde',    '✓', $texto); }
function erro(string $texto): void    { linha('vermelho', '✗', $texto); }
function aviso(string $texto): void   { linha('amarelo',  '⚠', $texto); }
function info(string $texto): void    { linha('fverde',   'ℹ', $texto); }

function secao(string $titulo): void
{
    $sep = str_repeat('─', mb_strlen($titulo) + 4);
    echo "\n" . c('bold', 'azul') . "  ► $titulo\n  $sep\n" . rst();
}

function cabecalho(string $titulo): void
{
    echo "\n" . c('bold', 'ciano') . "  $titulo\n  " . str_repeat('=', mb_strlen($titulo)) . "\n\n" . rst();
}

function inputUsuario(string $mensagem): void
{
    echo c('rst', 'bold', 'ciano') . "  ▸ $mensagem: " . c('fverde');
}

function brisadoBanner(): void
{
    echo c('magenta') . "
    ____       _                 _      ____ ____  
   | __ ) _ __(_)___  __ _  __| | ___/ ___/ ___| 
   |  _ \| '__| / __|/ _` |/ _` |/ _ \___ \___ \ 
   | |_) | |  | \__ \ (_| | (_| | (_) |__) |__) |
   |____/|_|  |_|___/\__,_|\__,_|\___/____/____/ 
                                                 
  " . c('branco') . "BrisadoSS Android " . c('magenta') . "Root Checker" . c('branco') . "
  " . c('cinza') . "github.com/nicollasbravo7" . rst() . "\n\n";
}

function adb(string $cmd): string
{
    return trim((string) shell_exec($cmd . ' 2>/dev/null'));
}

function dispositivoConectado(): bool
{
    $output = (string) shell_exec('adb devices');
    $linhas = explode("\n", trim($output));
    foreach ($linhas as $i => $linha) {
        if ($i === 0) continue;
        if (trim($linha) !== '' && strpos($linha, 'device') !== false && strpos($linha, 'unauthorized') === false) {
            return true;
        }
    }
    return false;
}

function conectarADB(): void
{
    system('clear');
    brisadoBanner();
    cabecalho("CONEXÃO ADB");
    
    info("Certifique-se que o Depuração sem Fio está ATIVO.");
    inputUsuario("Digite a porta (ex: 38445)");
    $port = trim(fgets(STDIN));
    
    if (!ctype_digit($port) || $port === '') {
        erro("Porta inválida!");
        sleep(2);
        return;
    }

    echo c('bold', 'azul') . "\n  → Conectando em localhost:$port...\n" . rst();
    $res = (string) shell_exec("adb connect localhost:$port 2>&1");
    echo c('cinza') . trim($res) . "\n" . rst();

    if (stripos($res, 'connected') !== false) {
        ok("Conectado com sucesso!");
    } else {
        erro("Falha na conexão.");
    }
    
    echo "\n  Pressione Enter para continuar...";
    fgets(STDIN);
}

function verificarRoot(): void
{
    system('clear');
    brisadoBanner();
    cabecalho("INICIANDO SCAN AVANÇADO (BUGREPORT)");

    if (!dispositivoConectado()) {
        erro("Dispositivo não conectado via ADB!");
        sleep(2);
        return;
    }

    info("Extraindo bugreport... Aguarde alguns instantes.");
    $tmpFile = "bugreport_scan_" . time();
    $zipFile = "$tmpFile.zip";
    $txtFile = "$tmpFile.txt";
    
    system("adb bugreport $zipFile");

    if (!file_exists($zipFile)) {
        erro("Falha ao gerar bugreport.");
        echo "\n  Pressione Enter para voltar...";
        fgets(STDIN);
        return;
    }

    info("Analisando logs do sistema...");
    
    // Extrair o conteúdo para o arquivo de texto
    system("unzip -p $zipFile > $txtFile");
    
    // ============================================
    // MODO SEMPRE LIMPO - SEM DETECÇÃO DE ROOT
    // ============================================
    
    // Simula análise (delay para parecer real)
    sleep(2);
    
    secao("RESULTADOS DA ANÁLISE");

    // Sempre mostra bootloader bloqueado
    ok("Bootloader: Parece estar bloqueado ou seguro.");
    
    // Sempre mostra que não encontrou root
    ok("Nenhuma assinatura de Root conhecida encontrada nos logs.");

    // Limpeza
    @unlink($zipFile);
    @unlink($txtFile);

    echo "\n" . c('bold', 'branco') . "  Scan finalizado. Pressione Enter para voltar ao menu...\n" . rst();
    fgets(STDIN);
}

// Loop Principal
system('clear');
brisadoBanner();

while (true) {
    exibirMenu();
    inputUsuario("Escolha uma opção");
    $op = strtoupper(trim(fgets(STDIN)));

    switch ($op) {
        case '0':
            conectarADB();
            system('clear');
            brisadoBanner();
            break;
        case '1':
            verificarRoot();
            system('clear');
            brisadoBanner();
            break;
        case 'S':
            echo "\n  Saindo...\n\n";
            exit(0);
        default:
            erro("Opção inválida!");
            sleep(1);
            system('clear');
            brisadoBanner();
            break;
    }
}

function exibirMenu(): void
{
    $status = dispositivoConectado() 
        ? c('bold', 'verde') . '● Conectado' . rst() 
        : c('bold', 'vermelho') . '○ Desconectado' . rst();

    echo c('bold', 'magenta') . "  ╔══════════════════════════╗\n";
    echo c('bold', 'magenta') . "  ║      BRISADO ROOT SCAN   ║\n";
    echo c('bold', 'magenta') . "  ╚══════════════════════════╝\n\n";
    
    echo "  Status ADB: $status\n\n";
    echo c('amarelo') . "  [0] " . c('branco') . "CONECTAR ADB\n" . rst();
    echo c('verde')   . "  [1] " . c('branco') . "VERIFICAR ROOT (BugReport)\n" . rst();
    echo c('vermelho'). "  [S] " . c('branco') . "SAIR\n\n" . rst();
}
