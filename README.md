#!/usr/bin/env php
<?php

declare(strict_types=1);

/**
 * BrisadoSS - BugReport Process Analyzer
 * Extrai logs do bugreport e analisa processos de root
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

function rst(): string { return C['rst']; }
function linha(string $cor, string $icone, string $texto): void { echo c('bold', $cor) . "  $icone $texto\n" . rst(); }
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

function brisadoBanner(): void
{
    echo c('magenta') . "
    ____       _                 _      ____ ____  
   | __ ) _ __(_)___  __ _  __| | ___/ ___/ ___| 
   |  _ \| '__| / __|/ _` |/ _` |/ _ \___ \___ \ 
   | |_) | |  | \__ \ (_| | (_| | (_) |__) |__) |
   |____/|_|  |_|___/\__,_|\__,_|\___/____/____/ 
                                                 
  " . c('branco') . "BrisadoSS " . c('magenta') . "BugReport Analyzer" . c('branco') . "
  " . c('cinza') . "Análise de Processos Root\n" . rst();
}

// ============================================
// 1. EXTRAIR BUGREPORT
// ============================================

function extrairBugreport(): ?string
{
    info("Gerando bugreport... Isso pode levar alguns segundos.");
    
    $timestamp = time();
    $zipFile = "bugreport_{$timestamp}.zip";
    $extractDir = "bugreport_extracted_{$timestamp}";
    
    // Gerar bugreport
    $output = [];
    $returnCode = 0;
    exec("adb bugreport {$zipFile} 2>&1", $output, $returnCode);
    
    if ($returnCode !== 0 || !file_exists($zipFile)) {
        erro("Falha ao gerar bugreport.");
        return null;
    }
    
    info("Bugreport gerado: {$zipFile}");
    
    // Extrair
    info("Extraindo arquivos...");
    mkdir($extractDir, 0777, true);
    exec("unzip -q {$zipFile} -d {$extractDir}");
    
    // Procurar o arquivo de log principal (dumpstate_board.txt ou .txt)
    $logFile = null;
    $files = glob("{$extractDir}/*.txt");
    foreach ($files as $file) {
        if (filesize($file) > 10000) { // Pega o maior arquivo txt
            $logFile = $file;
            break;
        }
    }
    
    if (!$logFile) {
        erro("Arquivo de log não encontrado no bugreport.");
        return null;
    }
    
    ok("Log extraído: " . basename($logFile));
    return $logFile;
}

// ============================================
// 2. ANALISADOR DE PROCESSOS (seu script adaptado)
// ============================================

function analisarProcessosRoot(string $logFile): array
{
    $resultados = [
        'processos_root' => [],
        'processos_magisk' => [],
        'processos_suspeitos' => [],
        'modulos_kernel' => [],
        'modulos_magisk' => [],
        'zygisk_mounts' => []
    ];
    
    $content = file_get_contents($logFile);
    if (!$content) return $resultados;
    
    $linhas = explode("\n", $content);
    
    secao("ANÁLISE DE PROCESSOS ROOT");
    
    // [1] Processos rodando como ROOT
    echo c('bold', 'amarelo') . "\n  [1] Processos rodando como UID ROOT (0):\n" . rst();
    $count = 0;
    foreach ($linhas as $linha) {
        if (preg_match('/^\s*root\s+/i', $linha) && !preg_match('/\[\w+]/', $linha)) {
            if ($count++ < 30) {
                echo c('cinza') . "    " . substr($linha, 0, 100) . "\n" . rst();
                $resultados['processos_root'][] = $linha;
            }
        }
    }
    if ($count == 0) echo c('cinza') . "    Nenhum processo root encontrado.\n" . rst();
    
    // [2] Processos relacionados a ROOT/MAGISK/KSU
    echo c('bold', 'amarelo') . "\n  [2] Processos relacionados a Root/Magisk/KSU:\n" . rst();
    $padroes = '/magisk|zygisk|kernelsu|apatch|supolicy|\.su|busybox/i';
    $count = 0;
    foreach ($linhas as $linha) {
        if (preg_match($padroes, $linha) && !preg_match('/grep/', $linha)) {
            echo c('vermelho') . "    ⚠ " . substr($linha, 0, 100) . "\n" . rst();
            $resultados['processos_magisk'][] = $linha;
            $count++;
        }
    }
    if ($count == 0) echo c('verde') . "    Nenhum processo suspeito encontrado.\n" . rst();
    
    // [3] Processos com nomes suspeitos (rootkits)
    echo c('bold', 'amarelo') . "\n  [3] Processos com nomes suspeitos (rootkits):\n" . rst();
    $padroesSuspeitos = '/daemon.*64|companion|integrity|hide|cloak|stealth|patch|hook/i';
    $count = 0;
    foreach ($linhas as $linha) {
        if (preg_match($padroesSuspeitos, $linha)) {
            echo c('laranja') . "    ⚠ " . substr($linha, 0, 100) . "\n" . rst();
            $resultados['processos_suspeitos'][] = $linha;
            $count++;
        }
    }
    if ($count == 0) echo c('verde') . "    Nenhum processo suspeito encontrado.\n" . rst();
    
    // [5] Módulos do kernel carregados
    secao("MÓDULOS DO KERNEL");
    $padroesKernel = '/root|kit|hide|inject|hook|kprobe|ftrace|magisk|kernelsu|apatch/i';
    $count = 0;
    foreach ($linhas as $linha) {
        if (preg_match($padroesKernel, $linha) && (strpos($linha, '.ko') !== false || strpos($linha, 'module') !== false)) {
            echo c('vermelho') . "    ⚠ " . substr($linha, 0, 100) . "\n" . rst();
            $resultados['modulos_kernel'][] = $linha;
            $count++;
        }
    }
    if ($count == 0) echo c('verde') . "    Nenhum módulo kernel suspeito encontrado.\n" . rst();
    
    // [6] Módulos Magisk e Zygisk
    secao("MAGISK / ZYGISK");
    
    // Procurar módulos Magisk
    if (preg_match_all('/\/data\/adb\/modules\/([^\s]+)/', $content, $matches)) {
        echo c('amarelo') . "\n  Módulos Magisk instalados:\n" . rst();
        foreach (array_unique($matches[1]) as $modulo) {
            if ($modulo != 'lost+found') {
                echo c('cinza') . "    • " . $modulo . "\n" . rst();
                $resultados['modulos_magisk'][] = $modulo;
            }
        }
    } else {
        echo c('verde') . "    Nenhum módulo Magisk encontrado.\n" . rst();
    }
    
    // Verificar Zygisk mounts
    if (preg_match_all('/zygisk/i', $content, $matches)) {
        echo c('amarelo') . "\n  ⚠ Zygisk detectado nos mounts!\n" . rst();
        $resultados['zygisk_mounts'] = true;
    } else {
        echo c('verde') . "    Nenhum mount Zygisk encontrado.\n" . rst();
    }
    
    return $resultados;
}

// ============================================
// 3. ANÁLISE DE PROPRIEDADES DO SISTEMA
// ============================================

function analisarPropriedades(string $logFile): void
{
    secao("PROPRIEDADES DO SISTEMA");
    
    $content = file_get_contents($logFile);
    if (!$content) return;
    
    $propriedades = [
        'ro.boot.flash.locked' => 'Bootloader Lock',
        'ro.boot.verifiedbootstate' => 'Verified Boot',
        'ro.boot.bl_state' => 'Bootloader State',
        'ro.build.tags' => 'Build Tags',
        'ro.debuggable' => 'Debuggable',
        'ro.secure' => 'Secure Mode'
    ];
    
    foreach ($propriedades as $prop => $desc) {
        if (preg_match("/\[{$prop}\]:\s*\[([^\]]+)\]/", $content, $match)) {
            $valor = $match[1];
            if ($prop == 'ro.boot.flash.locked' && $valor == '0') {
                erro("{$desc}: DESBLOQUEADO (UNLOCKED)");
            } elseif ($prop == 'ro.boot.verifiedbootstate' && in_array($valor, ['orange', 'yellow'])) {
                erro("{$desc}: {$valor} (Dispositivo modificado)");
            } elseif ($prop == 'ro.build.tags' && $valor == 'test-keys') {
                erro("{$desc}: test-keys (ROM não oficial)");
            } else {
                ok("{$desc}: {$valor}");
            }
        }
    }
}

// ============================================
// 4. LIMPEZA
// ============================================

function limparArquivos(string $zipFile, string $extractDir): void
{
    info("Limpando arquivos temporários...");
    @unlink($zipFile);
    exec("rm -rf {$extractDir}");
    ok("Limpeza concluída.");
}

// ============================================
// 5. FUNÇÃO PRINCIPAL
// ============================================

function main(): void
{
    system('clear');
    brisadoBanner();
    cabecalho("EXTRATOR E ANALISADOR DE BUGREPORT");
    
    // Verificar ADB
    $devices = shell_exec('adb devices');
    if (strpos($devices, 'device') === false || strpos($devices, 'unauthorized') !== false) {
        erro("Nenhum dispositivo conectado via ADB!");
        info("Execute: adb devices");
        echo "\n  Pressione Enter para sair...";
        fgets(STDIN);
        exit(1);
    }
    
    ok("Dispositivo conectado!");
    
    // Extrair bugreport
    $logFile = extrairBugreport();
    if (!$logFile) {
        erro("Não foi possível extrair o bugreport.");
        echo "\n  Pressione Enter para sair...";
        fgets(STDIN);
        exit(1);
    }
    
    // Analisar
    info("Analisando logs em busca de processos root...");
    $resultados = analisarProcessosRoot($logFile);
    analisarPropriedades($logFile);
    
    // Resumo final
    secao("RESUMO FINAL");
    
    $totalAmeacas = count($resultados['processos_magisk']) + 
                    count($resultados['processos_suspeitos']) + 
                    count($resultados['modulos_kernel']) +
                    count($resultados['modulos_magisk']);
    
    if ($totalAmeacas > 0) {
        erro("⚠ TOTAL DE INDÍCIOS DE ROOT ENCONTRADOS: {$totalAmeacas}");
        echo c('vermelho') . "\n  ⚠ Dispositivo APARENTEMENTE ROOTADO ou MODIFICADO!\n" . rst();
    } else {
        ok("✓ Nenhum indício significativo de root encontrado.");
        echo c('verde') . "\n  ✓ Dispositivo APARENTEMENTE SEGURO (sem root detectado)\n" . rst();
    }
    
    // Limpar
    $zipFile = str_replace('.txt', '.zip', str_replace('bugreport_extracted_', 'bugreport_', dirname($logFile) . '/' . basename($logFile, '.txt') . '.zip'));
    $extractDir = dirname($logFile);
    limparArquivos($zipFile, $extractDir);
    
    echo "\n" . c('bold', 'branco') . "  Análise concluída. Pressione Enter para sair...\n" . rst();
    fgets(STDIN);
}

// Executar
main();
?>
